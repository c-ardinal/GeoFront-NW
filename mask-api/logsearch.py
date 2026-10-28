"""ログ検索 (F1): GET /logsearch/lines | /logsearch/hist | /logsearch/facets -> syslog lines found by a filter.

Filter: host / severity / facility (label equality, values checked; host tokens -> the exact address like every other
selector), a keyword (plain text, case-insensitive) or a restricted regular expression, and a window up to the Loki
retention. The LogQL sent to Loki is the label selector only, built here from those values (mask_api.loki_selector):
the keyword / regex never reaches Loki. It is matched here on the MASKED lines, so it can never find a hidden
address. Regular expressions (check_regex): at most REGEX_MAX characters, no groups with "(?" (lookaround, flags,
named groups), no back references, no repeat inside a repeat, no alternation inside a repeat, at most one
variable-length repeat (* + {m,n}) and with it at most one "?" (four without one): with each line cut to MATCH_MAX
characters one line costs at most ~MATCH_MAX^2 steps (~15 ms measured on an adversarial line), and the scan's time
budget is checked between lines. The highlight reuses the match that decided the line (a regex: that one match; a
plain keyword: its literal occurrences, a linear scan), so nothing is matched again outside the budget.

lines: newest first, `limit` per page; next_before (ns) continues older (end exclusive: the screen drops lines it
already has). hist: lines per time bucket for the window (Loki's count_over_time without a keyword; with one, counted
here on the newest lines the budget allows, marked partial). Two requests at a time; more -> 429.
"""
import json
import math
import os
import re
import threading
import time
import urllib.parse

try:
    from re import _constants as RC, _parser as RP  # Python 3.11+
except ImportError:  # pragma: no cover
    import sre_constants as RC
    import sre_parse as RP

M = None  # mask_api

PAGE_MAX = 200
KEYWORD_MAX = 128
REGEX_MAX = 64
MATCH_MAX = 1024  # characters of a line the keyword / regex is matched on (and highlighted in)
HITS_PER_LINE = 20
BUCKETS = 60
BUDGET_S = 9  # below the proxy's 30 s and the screen's 16 s
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug")
FACILITIES = ("kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp",
              "security", "console", "solaris-cron", *(f"local{i}" for i in range(8)))
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:~\-]{0,127}")
PARAMS = {"host", "severity", "facility", "q", "regex", "from", "to", "before", "limit"}
SLOTS = threading.BoundedSemaphore(2)
RETENTION_S = None  # from mask_api / evidence (LOKI_RETENTION), set in setup()


class Refused(ValueError):
    pass


def setup(mask_module, retention_s):
    global M, RETENTION_S
    M = mask_module
    RETENTION_S = retention_s or 30 * 86400


# ---- the regular expression check -----------------------------------------------------------------------------------

VARIABLE = (RC.MAX_REPEAT, RC.MIN_REPEAT) + ((RC.POSSESSIVE_REPEAT,) if hasattr(RC, "POSSESSIVE_REPEAT") else ())
FORBIDDEN_OPS = {RC.GROUPREF, RC.GROUPREF_EXISTS, RC.ASSERT, RC.ASSERT_NOT} | ({RC.ATOMIC_GROUP} if hasattr(RC, "ATOMIC_GROUP") else set())


def check_regex(pattern):
    """-> compiled pattern (case-insensitive) or Refused with the reason (Japanese, shown on the screen)."""
    if not pattern or len(pattern) > REGEX_MAX:
        raise Refused(f"正規表現は 1〜{REGEX_MAX} 文字にしてください")
    if "(?" in pattern or re.search(r"\\[0-9]", pattern):
        raise Refused("正規表現に (? で始まる書き方 (先読み・後読み・フラグ・名前付き) と後方参照は使えません")
    try:
        tree = RP.parse(pattern)
    except re.error as e:
        raise Refused(f"正規表現の書き方が正しくありません ({e.msg})") from None
    count = {"var": 0, "opt": 0}

    def walk(items, in_repeat):
        for op, av in items:
            if op in FORBIDDEN_OPS:
                raise Refused("正規表現に後方参照・先読み・後読みは使えません")
            if op in VARIABLE:
                lo, hi, sub = av
                if in_repeat:
                    raise Refused("繰り返しの中に繰り返しは書けません")
                if hi is RC.MAXREPEAT or hi - lo > 1 or lo > 64:
                    count["var"] += 1
                elif hi != lo:
                    count["opt"] += 1
                if hi is not RC.MAXREPEAT and hi > 64:
                    raise Refused("{m,n} の n は 64 までです")
                walk(sub, True)
            elif op == RC.SUBPATTERN:
                walk(av[-1], in_repeat)
            elif op == RC.BRANCH:
                if in_repeat:
                    raise Refused("繰り返しの中に | は書けません")
                for b in av[1]:
                    walk(b, in_repeat)
    walk(tree, False)
    if count["var"] > 1 or count["opt"] > (1 if count["var"] else 4):
        raise Refused("長さの決まらない繰り返し (* + {m,n}) は 1 か所までです。? はそれと一緒なら 1 か所、なければ 4 か所までです")
    return re.compile(pattern, re.IGNORECASE)


def matcher(q, is_regex):
    if not q:
        return None
    if len(q) > KEYWORD_MAX or any(ord(c) < 32 for c in q):
        raise Refused(f"語句は 1 行、{KEYWORD_MAX} 文字までです")
    M.check_literal(q)  # the lines are masked: an address could never match anyway; refused like every other filter
    return check_regex(q) if is_regex else re.compile(re.escape(q), re.IGNORECASE)


def hit_spans(rx, is_regex, line):
    """None when the line does not match; else the spans to mark in it (first MATCH_MAX characters): a regex -> the one
    match that decided it (never searched again: a second search could cost as much as the first, outside the budget);
    a plain keyword -> its occurrences, at most HITS_PER_LINE (a literal pattern: linear)."""
    if rx is None:
        return []
    if is_regex:
        m = rx.search(line, 0, MATCH_MAX)
        return None if m is None else [m.span()] if m.end() > m.start() else []
    spans = []
    for m in rx.finditer(line, 0, MATCH_MAX):
        spans.append(m.span())
        if len(spans) >= HITS_PER_LINE:
            break
    return spans or None


def parts_of(line, spans):
    """[[text, hit]] for highlighting, from spans found while matching (no matching here)."""
    out, pos = [], 0
    for a, b in spans:
        if a > pos:
            out.append([line[pos:a], False])
        out.append([line[a:b], True])
        pos = b
    if pos < len(line) or not out:
        out.append([line[pos:], False])
    return out


# ---- request --------------------------------------------------------------------------------------------------------

def _num(v, what):
    try:
        x = float(v)
    except ValueError:
        raise Refused(f"{what}: unix seconds") from None
    if not math.isfinite(x):
        raise Refused(f"{what}: unix seconds")
    return x


def parse(query, now):
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, max_num_fields=16)
    p = dict(pairs)
    if len(p) != len(pairs) or set(p) - PARAMS:
        raise Refused("parameters: " + ", ".join(sorted(PARAMS)) + " (each once)")
    labels = ['job="syslog"']
    host = p.get("host", "")
    if host:
        if not HOST_RE.fullmatch(host):
            raise Refused("host: letters, digits and . _ : ~ - (1 to 128)")
        M.check_literal(host)
        labels.append(f"host={json.dumps(host)}")
    for k, allowed in (("severity", SEVERITIES), ("facility", FACILITIES)):
        if p.get(k):
            if p[k] not in allowed:
                raise Refused(f"{k}: one of " + ", ".join(allowed))
            labels.append(f"{k}={json.dumps(p[k])}")
    if p.get("regex", "0") not in ("0", "1"):
        raise Refused("regex: 0 or 1")
    rx = matcher(p.get("q", ""), p.get("regex") == "1")
    t0, t1 = _num(p.get("from", ""), "from"), min(_num(p.get("to", ""), "to"), now)
    if not (0 < t0 < t1 and t1 - t0 <= RETENTION_S + 3600 and t0 >= now - RETENTION_S - 3600):
        raise Refused(f"window: from < to, within the log retention ({int(RETENTION_S // 86400)} d), not in the future")
    start_ns, end_ns = int(t0 * 1e9), int(t1 * 1e9)
    if p.get("before"):
        if not p["before"].isdigit() or not start_ns < int(p["before"]) <= end_ns:
            raise Refused("before: ns inside the window")
        end_ns = int(p["before"])
    limit = p.get("limit", "100")
    if not limit.isdigit() or not 1 <= int(limit) <= PAGE_MAX:
        raise Refused(f"limit: 1 to {PAGE_MAX}")
    selector = M.loki_selector("{" + ",".join(labels) + "}")  # literal checks + token -> address
    return {"selector": selector, "rx": rx, "regex": rx is not None and p.get("regex") == "1", "from": t0, "to": t1, "start_ns": start_ns, "end_ns": end_ns, "limit": int(limit)}


# ---- lines ----------------------------------------------------------------------------------------------------------

class _Spec:  # what mask_api.settled() reads
    direction = "backward"

    def __init__(self, limit):
        self.limit = limit


def passes(rx, line):
    return rx is None or rx.search(line, 0, MATCH_MAX) is not None  # (counting only: no highlight needed)


def lines(req, get_page=None, page_size=None, budget_s=BUDGET_S):
    get_page = get_page or M.loki_page
    page_size = page_size or M.LOKI_MAX_LINES
    deadline = time.monotonic() + budget_s
    scan = M.Scan(req["selector"], req["start_ns"], req["end_ns"], "backward", get_page, page_size, deadline, M.PAGE_OVERLAP_NS)
    hits, stopped = [], None  # stopped: ts of the first line left unprocessed when the budget ran out mid-page
    for new in scan:
        for st, ts, line in sorted(new, key=lambda e: -e[1]):  # a page is grouped by stream: newest first across them
            if time.monotonic() > deadline:
                stopped = ts
                break
            masked = M.mask_line(st, line)
            spans = hit_spans(req["rx"], req["regex"], masked)
            if spans is not None:
                hits.append((ts, M.mask_json(st), masked, spans))
        if stopped is not None:
            scan.partial.append("time budget used up")
            break
        if len(hits) >= req["limit"] and M.settled(hits, _Spec(req["limit"]), scan, M.PAGE_OVERLAP_NS):
            break
        if scan.scanned >= M.SCAN_MAX_LINES:
            scan.partial.append("line cap reached")
            break
    hits.sort(key=lambda h: -h[0])
    page = hits[:req["limit"]]
    if len(hits) >= req["limit"]:
        nxt = page[-1][0] + 1  # end exclusive: lines sharing the last instant come again (the screen drops repeats)
        if nxt >= req["end_ns"]:
            nxt = page[-1][0]  # one instant holds the whole page: step past it (ponytail: more lines of it are skipped)
    elif stopped is not None:
        nxt = stopped + 1  # the rest of that page, from the first unprocessed line on, comes in the next page
    elif scan.done:
        nxt = None
    else:
        nxt = scan.edge if scan.edge is not None and scan.edge < req["end_ns"] else None
    entries = [{"ts": str(ts), "host": st.get("host", ""), "severity": st.get("severity", ""), "facility": st.get("facility", ""),
                "parts": parts_of(line, spans)} for ts, st, line, spans in page]
    partial = sorted(set(scan.partial))
    return {"entries": entries, "next_before": str(nxt) if nxt and nxt > req["start_ns"] else None, "partial": partial,
            "scanned": scan.scanned}


# ---- histogram ------------------------------------------------------------------------------------------------------

def bucket_step(span):
    return max(60, math.ceil(span / BUCKETS / 60) * 60)


def loki_read(path, params, timeout=BUDGET_S):
    status, body, _ = M.fetch(M.LOKI + path + "?" + urllib.parse.urlencode(params), timeout=timeout)
    obj = json.loads(body)
    if status != 200 or obj.get("status") != "success":
        raise RuntimeError(f"HTTP {status}: {obj.get('error', '')}"[:200])
    return obj["data"]["result"]


def hist_loki(req, step, read=loki_read):
    """lines per bucket from Loki itself (no keyword): bucket i = (t0 + i*step, min(t0 + (i+1)*step, to)]; the last
    bucket is shorter when the window is not a whole number of steps (it never counts past `to`)."""
    t0, t1 = req["from"], req["to"]
    n = math.ceil((t1 - t0) / step)
    full = math.floor((t1 - t0) / step)
    counts = [0] * n
    deadline = time.monotonic() + BUDGET_S  # both queries together within the budget

    def left():
        s = deadline - time.monotonic()
        if s < 0.5:
            raise TimeoutError("time budget used up")
        return s
    if full:
        q = f"sum(count_over_time({req['selector']}[{step}s]))"
        for r in read("/loki/api/v1/query_range", {"query": q, "start": str(int((t0 + step) * 1e9)), "end": str(int((t0 + full * step) * 1e9)),
                                                   "step": f"{step}s"}, left()):
            for t, v in r["values"]:
                i = round((float(t) - t0) / step) - 1
                if 0 <= i < full:
                    counts[i] += int(float(v))
    rest_ms = round((t1 - (t0 + full * step)) * 1000)
    if n > full and rest_ms >= 1:
        q = f"sum(count_over_time({req['selector']}[{rest_ms}ms]))"
        for r in read("/loki/api/v1/query", {"query": q, "time": str(int(t1 * 1e9))}, left()):
            counts[n - 1] += int(float(r["value"][1]))
    return counts, []


def hist_scan(req, step, get_page=None, page_size=None, budget_s=BUDGET_S):
    """with a keyword: count the matching masked lines here, newest first (a partial count keeps the recent buckets)."""
    get_page = get_page or M.loki_page
    page_size = page_size or M.LOKI_MAX_LINES
    t0 = req["from"]
    n = math.ceil((req["to"] - t0) / step)
    counts = [0] * n
    deadline = time.monotonic() + budget_s
    scan = M.Scan(req["selector"], req["start_ns"], int(req["to"] * 1e9), "backward", get_page, page_size, deadline, M.PAGE_OVERLAP_NS)
    for new in scan:
        for st, ts, line in sorted(new, key=lambda e: -e[1]):
            if time.monotonic() > deadline:
                scan.edge = ts  # counted down to here
                break
            if passes(req["rx"], M.mask_line(st, line)):
                i = min(n - 1, max(0, math.ceil((ts / 1e9 - t0) / step) - 1))
                counts[i] += 1
        if time.monotonic() > deadline:
            scan.partial.append("time budget used up")
            break
        if scan.scanned >= M.SCAN_MAX_LINES:
            scan.partial.append("line cap reached")
            break
    if not scan.done and not scan.partial:
        scan.partial.append("stopped early")
    edge = scan.edge / 1e9 if scan.partial and scan.edge else None
    return counts, sorted(set(scan.partial)), edge


def hist(req, **kw):
    step = bucket_step(req["to"] - req["from"])
    if req["rx"] is None:
        counts, partial = hist_loki(req, step)
        edge = None
    else:
        counts, partial, edge = hist_scan(req, step, **kw)
    return {"from": req["from"], "to": req["to"], "step": step, "counts": counts, "partial": partial, "counted_from": edge}


def facets():
    """the facility values Loki has seen for syslog (masked like any answer; they are names, never addresses)."""
    url = M.LOKI + "/loki/api/v1/label/facility/values?" + urllib.parse.urlencode(
        {"query": '{job="syslog"}', "start": str(int((time.time() - RETENTION_S) * 1e9)), "end": str(time.time_ns())})
    status, body, _ = M.fetch(url, timeout=5)
    obj = json.loads(body)
    found = obj.get("data") or [] if status == 200 else []
    return {"severities": list(SEVERITIES), "facilities": [f for f in FACILITIES if f in found], "retention_s": RETENTION_S,
            "limits": {"page": PAGE_MAX, "keyword": KEYWORD_MAX, "regex": REGEX_MAX, "match_chars": MATCH_MAX, "buckets": BUCKETS}}


def js(status, obj):
    return status, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), "application/json"


def handle(method, raw_path):
    if method not in ("GET", "HEAD"):
        return js(405, {"status": "error", "error": "read-only"})
    parts = urllib.parse.urlsplit(raw_path)
    if parts.path == "/logsearch/facets" and not parts.query:
        return js(200, {"status": "success", "data": facets()})
    if parts.path not in ("/logsearch/lines", "/logsearch/hist"):
        return js(403, {"status": "error", "error": "forbidden"})
    try:
        req = parse(parts.query, time.time())
    except (Refused, M.Rejected) as e:
        return js(400, {"status": "error", "errorType": "masked_query", "error": str(e)})
    if not SLOTS.acquire(blocking=False):
        return js(429, {"status": "error", "errorType": "busy", "error": "ログ検索が混んでいます。少し待ってからもう一度"})
    try:
        data = lines(req) if parts.path.endswith("/lines") else hist(req)
        return js(200, {"status": "success", "data": data})
    except RuntimeError as e:
        return js(502, {"status": "error", "error": str(e)})
    finally:
        SLOTS.release()


# ---- self-test (no services: Loki is faked) ---------------------------------------------------------------------

def selftest():
    now = 1_761_470_000.0
    base = f"from={now - 3600}&to={now}"
    q = urllib.parse.quote
    req = parse(f"host=rtx1300&severity=error&q=Rejected&{base}", now)
    assert req["selector"] == '{job="syslog",host="rtx1300",severity="error"}' and req["limit"] == 100, req["selector"]
    tok = M.mask_value("192.0.2.10")
    assert parse(f"host={q(tok)}&{base}", now)["selector"] == '{job="syslog",host="192.0.2.10"}'  # token -> exact address
    # good regular expressions
    for good in ("timeout|refused", "PP\\[0[1-3]\\]", "error.*lan2", "colou?r", "[0-9]{3} ms", "^\\[INSPECT\\]", "(down|up)$", "a{2,64}"):
        check_regex(good)
    # refused: catastrophic or unsupported regexes, injection through every value, raw / partial addresses, windows
    bad_rx = ["(a+)+$", "(a*)*b", "(a|aa)*c", "(x+x+)+y", "(.*a){10}", "a.*b.*c", "(?=a)", "(?<!a)b", "(?i)a", "(?P<n>a)",
              "(a)\\1", "a{1,65}", "x" * 65, "[", "a**", "(ab|cd)+", "a?b?c?d?e?f?",
              "a?a?a?a?a*b", "[a-z]*.?.?.?.?=", "a.?.?.?.?.*b"]  # several "?" around a variable repeat: ~100-200 ms a line
    bad = [f"q={q(r)}&regex=1&{base}" for r in bad_rx]
    bad += [f"host={q('rtx1300\"} |= \"x')}&{base}", f"host={q('a,job=\"notify\"')}&{base}", f"host={q('rtx1300`')}&{base}",
            f"severity=errors&{base}", f"facility={q('local7\"')}&{base}", f"facility=local8&{base}", f"regex=2&q=a&{base}",
            f"q={q('192.0.2.10')}&{base}", f"q=113.50&{base}", f"host=192.0.2.10&{base}", f"host={q('192.0.2.x~000000000000')}&{base}",
            f"q={q('a' + chr(10) + 'b')}&{base}", f"q={'a' * 129}&{base}", f"query={q('{job=\"x\"}')}&{base}", f"host=a&host=b&{base}",
            f"from={now - 40 * 86400}&to={now}", f"from={now}&to={now - 60}", f"from=nan&to={now}", f"before=1&{base}",
            f"before=abc&{base}", f"limit=201&{base}", f"limit=0&{base}"]
    for b in bad:
        try:
            parse(b, now)
            raise AssertionError(b)
        except (Refused, M.Rejected):
            pass
    # the keyword is matched on the masked lines, case-insensitively; highlights; paging older with next_before
    t0n = int((now - 3600) * 1e9)
    raw = [({"job": "syslog", "host": "rtx1300", "severity": "error", "facility": "local7"}, t0n + i * 10**9 * 30,
            f"[INSPECT] LAN2 Rejected TCP 192.168.100.{i}:5000 > 198.51.100.7:443 n={i}") for i in range(100)]

    def page(selector, start, end, limit, timeout, direction="backward"):
        got = sorted((e for e in raw if start <= e[1] < end), key=lambda e: -e[1])
        return got[:limit]
    req = parse(f"q=rejected&limit=30&{base}", now)
    out = lines(req, get_page=page, page_size=40)
    assert len(out["entries"]) == 30 and out["entries"][0]["parts"][1] == ["Rejected", True], out["entries"][0]
    flat = json.dumps(out)
    assert "192.168.100.9" not in flat and "198.51.100.7" not in flat and "198.51.100.x" in flat, flat[:300]  # masked
    assert out["next_before"] == str(raw[70][1] + 1)  # newest first: lines 99..70, continue before 70 (+1, end exclusive)
    req2 = dict(req, end_ns=int(out["next_before"]))
    out2 = lines(req2, get_page=page, page_size=40)
    assert out2["entries"][0]["ts"] == str(raw[70][1]) and len(out2["entries"]) == 30  # the repeat of 70 is dropped by the screen
    assert lines(parse(f"q={q('198.51.100.x:443')}&{base}", now), get_page=page)["entries"]  # masked forms are searchable
    assert not lines(parse(f"q=enx&regex=1&{base}", now), get_page=page)["entries"]
    assert len(lines(parse(f"q={q('n=9[0-9]$')}&regex=1&{base}", now), get_page=page)["entries"]) == 10
    # histogram with a keyword: 60 buckets of one minute, every 30 s line counted once
    h = hist(parse(f"q=lan2&{base}", now), get_page=page, page_size=40)
    assert h["step"] == 60 and len(h["counts"]) == 60 and sum(h["counts"]) == 100 and not h["partial"], h
    # without a keyword (Loki counts): a window of 15.5 min -> 15 full buckets + one of 30 s that ends at `to`
    calls = []

    def read(path, params, timeout):
        assert 0 < timeout <= BUDGET_S
        calls.append((path, params))
        if path.endswith("query_range"):
            return [{"metric": {}, "values": [[str(int(params["start"]) / 1e9 + 60 * k), "2"] for k in range(15)]}]
        return [{"metric": {}, "value": [params["time"], "5"]}]
    r15 = parse(f"from={now - 930}&to={now}", now)
    counts, _ = hist_loki(r15, bucket_step(930), read)
    assert len(counts) == 16 and counts[:15] == [2] * 15 and counts[15] == 5, counts
    assert int(calls[0][1]["end"]) <= int((now - 30) * 1e9) and calls[1][1]["time"] == str(int(now * 1e9)) and "[30000ms]" in calls[1][1]["query"], calls
    calls.clear()
    assert hist_loki(parse(f"from={now - 60.5}&to={now}", now), 60, read)[0][1] == 5 and "[500ms]" in calls[1][1]["query"]  # a fraction counts
    # a page is grouped by stream: processed newest first across streams; a budget cut mid-page continues from the
    # first unprocessed line (nothing older in that page is skipped)
    two = [({"job": "syslog", "host": h}, t0n + i * 10**9, f"x {h} {i}") for h in ("a", "b") for i in range(10)]
    t = {"n": 0}

    def clock():
        t["n"] += 1
        return 0.0 if t["n"] < 8 else 99.0
    real, time.monotonic = time.monotonic, clock
    try:
        cut = lines(parse(f"q=x&{base}", now), get_page=lambda s, a, b, lim, to, d="backward": [e for e in two if a <= e[1] < b], page_size=100, budget_s=50)
    finally:
        time.monotonic = real
    done = {(int(e["ts"]), e["host"]) for e in cut["entries"]}
    nb = int(cut["next_before"])
    assert cut["partial"] == ["time budget used up"] and done and nb - 1 <= min(t for t, _ in done), (nb, done)
    assert all(e[1] < nb for e in two if (e[1], e[0]["host"]) not in done), "an unprocessed line would be skipped"
    # a slow regex can not hold the request: the budget is checked between lines
    slow = parse(f"q={q('a.*b')}&regex=1&{base}", now)
    long_lines = [({"job": "syslog", "host": "x"}, t0n + i, "a" * 5000) for i in range(2000)]
    t = time.monotonic()
    res = lines(slow, get_page=lambda s, a, b, lim, to, d="backward": [e for e in long_lines if a <= e[1] < b][:lim], page_size=5000, budget_s=1)
    assert time.monotonic() - t < 3 and res["entries"] == [], time.monotonic() - t
    # the worst still accepted on lines of one repeated letter: matching + highlighting 200 lines stays inside the budget
    # (the highlight reuses the deciding match: no second search per line)
    for pat, body in (("[a-z]*.?=", "a=" + "a" * 1022), ("a.?.*b", "ab" + "a" * 1022), ("a?a*b", "ab" + "a" * 1022)):
        worst = parse(f"q={q(pat)}&regex=1&limit=200&{base}", now)
        same = [({"job": "syslog", "host": "x"}, t0n + i, body) for i in range(200)]
        t = time.monotonic()
        res = lines(worst, get_page=lambda s, a, b, lim, to, d="backward": [e for e in same if a <= e[1] < b][:lim], page_size=5000, budget_s=2)
        took = time.monotonic() - t
        assert took < 2.5 and res["entries"] and sum(h for e in res["entries"] for _, h in e["parts"]) == len(res["entries"]), (pat, took)
    assert hit_spans(re.compile("lan", re.I), False, "LAN1 lan2 x") == [(0, 3), (5, 8)] and hit_spans(re.compile("q"), False, "abc") is None
    assert handle("POST", "/logsearch/lines")[0] == 405 and handle("GET", "/logsearch/other")[0] == 403
    assert handle("GET", "/logsearch/lines?q=" + q("(a+)+") + "&regex=1&from=1&to=2")[0] == 400
    print(f"logsearch selftest ok ({len(bad)} refused requests, {len(bad_rx)} unsafe regexes)")
