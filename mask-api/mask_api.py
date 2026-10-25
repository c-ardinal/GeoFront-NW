"""Masking read-only proxy between the command-center (nginx) and Prometheus/Loki.

The browser never talks to Prometheus/Loki directly: every /prom/ and /loki/ request goes
through here. Only GET on an allowlisted path is forwarded; every JSON string in the response
(label names/values, log lines, rule expressions) has IPv4 masked to a.b.c.x and MAC addresses
to aa:bb:cc:xx:xx:xx (NFR-09); a value that is exactly one IPv4 becomes a.b.c.x~<opaque token>
so the UI can still tell addresses apart and drill down. IPv6 is not masked (the demo data has none).

Queries cannot test hidden digits:
- Loki: only the shapes the UI sends are accepted (stream selector on known labels with equality,
  optional |= / != line filters, or the two severity count aggregations). Only the selector goes to
  Loki; line filters are applied here to the already-masked lines, so a filter can only ever match
  text the user can already see.
- Prometheus: string literals are only allowed as = / != label-matcher values and must not contain a
  full or partial address (tokens are resolved here); regex matchers and the functions that read or
  copy label text are rejected.

Alertmanager (/am/, from the proxy): the alert and silence lists are read the same way (masked); the one write path
is the silence allowlist (create / extend / expire, for ACK and 抑止), see the "Alertmanager" section.

Run: python mask_api.py            (listens on :8000)
     python mask_api.py --selftest
"""
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

PROM = os.environ.get("PROM_URL", "http://prometheus:9090")
LOKI = os.environ.get("LOKI_URL", "http://loki:3100")
TIMEOUT_S = 12  # below nginx proxy_read_timeout (15 s) so the client gets our error, not nginx's
MAX_BYTES = 32 * 1024 * 1024
LOKI_MAX_LINES = 5000  # Loki's default max_entries_limit_per_query
SCAN_MAX_LINES = 100000  # filtered logs/counts: raw lines read from Loki per request at most (demo 6 h window ~ 67k lines)
SCAN_DEADLINE_S = 9  # total budget for all Loki pages of one filtered request (each page's timeout is cut to what is left), beats nginx's 15 s
COUNT_AGG_GRACE_S = 2  # counting may run this long past the paging budget (9 + 2 s still beats nginx)
PAGE_OVERLAP_NS = 10**9  # filtered scans: each next Loki page re-reads this far back over the last page's edge
MAX_EVALS = 11000  # evaluation points per filtered count query (Loki's own limit)

PROM_QUERY = {"/prom/api/v1/query": PROM + "/api/v1/query", "/prom/api/v1/query_range": PROM + "/api/v1/query_range"}
PROM_PLAIN = {"/prom/api/v1/alerts": PROM + "/api/v1/alerts", "/prom/api/v1/rules": PROM + "/api/v1/rules"}
LOKI_RANGE = "/loki/loki/api/v1/query_range"

IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")
MAC = re.compile(r"\b([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\b")
TOKEN_LEN = 12
# Masked IPv4 as sent to the browser: a.b.c.x, or a.b.c.x~<token> for a value that was exactly one address.
MASKED_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.x(?:~([0-9a-f]{%d}))?\b" % TOKEN_LEN)
MASKED_MAC = re.compile(r"\b([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2xx\2xx\2xx\b")
TOKEN_REF = re.compile(r"\.x~(\w*)")
# What is left of a literal once masked forms are removed must not narrow a hidden part:
# no digit.digit (a partial IPv4 such as "113.50") and no 4+ hex pairs (a partial MAC).
FRAGMENT = re.compile(r"\d\.\d|\b[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){2}\b")

STRING = r'''"(?:[^"\\]|\\.)*"|`[^`]*`|'(?:[^'\\]|\\.)*\''''
# PromQL: regex matchers, and functions that read, copy, sort or hash label text (some experimental).
PROM_FORBIDDEN = re.compile(r"=~|!~|\b(?:label_replace|label_join|sort_by_label|sort_by_label_desc|info|limitk|limit_ratio|count_values)\b")
PROM_MATCHER_LHS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*!?=\s*$")
PROM_LITERAL = re.compile(r"(!=|=)(\s*)(" + STRING + ")")
PROM_TIME = re.compile(r"\d+(?:\.\d+)?[smhdwy]?")

# LogQL: the exact shapes the UI sends.
LOKI_STR = r'"(?:[^"\\]|\\.)*"|`[^`]*`'
LOKI_MATCHER = r"\s*(job|host|severity|facility)\s*=\s*(" + LOKI_STR + r")\s*"
LOKI_MATCHER_NC = r"\s*(?:job|host|severity|facility)\s*=\s*(?:" + LOKI_STR + r")\s*"
LOKI_SEL = r"\{" + LOKI_MATCHER_NC + r"(?:," + LOKI_MATCHER_NC + r")*\}"
LOKI_FILTER = r"\s*(\|=|!=)\s*(" + LOKI_STR + ")"
LOKI_LOG = re.compile(r"\s*(" + LOKI_SEL + r")((?:\s*(?:\|=|!=)\s*(?:" + LOKI_STR + r"))*)\s*")
LOKI_METRIC = re.compile(r"\s*sum\s+by\s*\(\s*(severity|host\s*,\s*severity)\s*\)\s*\(\s*count_over_time\s*\(\s*(" + LOKI_SEL +
                         r")((?:\s*(?:\|=|!=)\s*(?:" + LOKI_STR + r"))*)\s*\[\s*(\d{1,6}[smh])\s*\]\s*\)\s*\)\s*")
LOKI_PARAMS = {"query", "start", "end", "limit", "direction", "step"}

REJECT_MSG = "full or partial IP/MAC addresses, regex matchers and other query forms are not searchable; filter by the masked form (e.g. 192.0.2.x)"
TOKEN_MSG = "unknown or expired address token; reload the page"

# Opaque per-address tokens keep distinct addresses distinct in the UI (rows, keys, drill-downs)
# without revealing them. The key is random per process, so tokens expire on restart.
KEY = secrets.token_bytes(32)
TOKENS = {}  # token -> address; written only by mask_json, from addresses Prometheus/Loki returned
MAX_TOKENS = 65536  # ponytail: no eviction; past this, new addresses get no token and fall back to a.b.c.x


class Rejected(ValueError):
    pass


def mask_text(s):
    return MAC.sub(r"\1\2xx\2xx\2xx", IPV4.sub(r"\1.x", s))


def mask_value(s):
    m = IPV4.fullmatch(s)
    if not m:
        return mask_text(s)
    tok = hmac.new(KEY, s.encode(), hashlib.sha256).hexdigest()[:TOKEN_LEN]
    if tok not in TOKENS and len(TOKENS) >= MAX_TOKENS:
        return m.group(1) + ".x"
    TOKENS[tok] = s
    return f"{m.group(1)}.x~{tok}"


def mask_json(v):
    if isinstance(v, str):
        return mask_value(v)
    if isinstance(v, list):
        return [mask_json(x) for x in v]
    if isinstance(v, dict):
        return {mask_text(k): mask_json(x) for k, x in v.items()}
    return v


# ---- literal checks and masked-form rewriting (shared) ------------------------------------------

def literal_body(lit):
    if lit[0] == "`":
        return lit[1:-1]
    if lit[0] == "'":
        if "\\" in lit:
            raise Rejected("escapes in single-quoted strings are not accepted")
        return lit[1:-1]
    try:
        return json.loads(lit)
    except ValueError:  # Go-only escapes (\x2e, \056) could hide a dot from the checks
        raise Rejected("unsupported string escape") from None


def check_literal(body):
    if IPV4.search(body) or MAC.search(body):
        raise Rejected(REJECT_MSG)
    if FRAGMENT.search(MASKED_MAC.sub(" ", MASKED_IPV4.sub(" ", body))):
        raise Rejected(REJECT_MSG)
    for t in TOKEN_REF.finditer(body):
        if t.group(1) not in TOKENS:
            raise Rejected(TOKEN_MSG)


def _ip_span(m, as_regex):
    a, b, c, tok = m.groups()
    if tok:
        ip = TOKENS.get(tok)
        if not ip or not ip.startswith(f"{a}.{b}.{c}."):
            raise Rejected(TOKEN_MSG)
        return re.escape(ip) if as_regex else ip
    return f"{a}[.]{b}[.]{c}[.][0-9]{{1,3}}"


def _rewrite(text, as_regex):
    """Replace masked forms: tokens -> exact address; plain masks -> prefix regex (regex mode only)."""
    spans = sorted([(m.start(), m.end(), _ip_span(m, as_regex)) for m in MASKED_IPV4.finditer(text)]
                   + [(m.start(), m.end(), "{1}{2}{3}{2}{4}(?:{2}[0-9A-Fa-f]{{2}}){{3}}".format(None, *m.groups()))
                      for m in MASKED_MAC.finditer(text)])
    out, pos = [], 0
    for start, end, rep in spans:
        out.append((re.escape(text[pos:start]) if as_regex else text[pos:start]) + rep)
        pos = end
    out.append(re.escape(text[pos:]) if as_regex else text[pos:])
    return "".join(out)


def matcher(label, op, body):
    """Label matcher upstream: token -> exact address; plain masked form -> prefix regex."""
    has_plain = any(not x.group(4) for x in MASKED_IPV4.finditer(body)) or MASKED_MAC.search(body)
    if has_plain:
        return f"{label}{ {'=': '=~', '!=': '!~'}[op] }{json.dumps(_rewrite(body, as_regex=True))}"
    return f"{label}{op}{json.dumps(_rewrite(body, as_regex=False))}"


# ---- Prometheus -------------------------------------------------------------------------------

def prom_query(q):
    if IPV4.search(q) or MAC.search(q) or PROM_FORBIDDEN.search(q):
        raise Rejected(REJECT_MSG)
    for m in re.finditer(STRING, q):
        if not PROM_MATCHER_LHS.search(q[:m.start()]):
            raise Rejected("string literals are only accepted as label matcher values")
        check_literal(literal_body(m.group(0)))

    def sub(m):  # every literal is a matcher value (checked above); the label name stays in place
        op, _, lit = m.groups()
        body = literal_body(lit)
        if not (MASKED_IPV4.search(body) or MASKED_MAC.search(body)):
            return m.group(0)
        return matcher("", op, body)
    return PROM_LITERAL.sub(sub, q)


def prom_plan(path, params):
    if path in PROM_PLAIN:
        if params:
            raise Rejected("no parameters accepted here")
        return PROM_PLAIN[path], None
    out = []
    for k, v in params:
        if k == "query":
            out.append((k, prom_query(v)))
        elif k in ("time", "start", "end", "step") and PROM_TIME.fullmatch(v):
            out.append((k, v))
        else:
            raise Rejected(f"parameter not accepted: {k[:20]}")
    if not any(k == "query" for k, _ in out):
        raise Rejected("query is required")
    return PROM_QUERY[path] + "?" + urllib.parse.urlencode(out), None


# ---- Loki -------------------------------------------------------------------------------------

def loki_selector(sel):
    parts = []
    for label, lit in re.findall(LOKI_MATCHER, sel[1:-1]):
        body = literal_body(lit)
        check_literal(body)
        parts.append(matcher(label, "=", body))
    return "{" + ",".join(parts) + "}"


def line_filters(rest):
    filters = []
    for op, lit in re.findall(LOKI_FILTER, rest):
        body = literal_body(lit)
        check_literal(body)
        filters.append((op, body))
    return filters


class CountSpec(NamedTuple):
    """sum by (<by>) (count_over_time(<selector> <filters> [range])) evaluated here on masked lines."""
    by: tuple
    selector: str
    filters: list
    first_ns: int
    step_ns: int
    range_ns: int
    evals: int


NS = {"s": 10**9, "m": 60 * 10**9, "h": 3600 * 10**9}


def to_ns(v):  # Loki accepts unix seconds or nanoseconds
    return int(v) * 10**9 if int(v) < 10**12 else int(v)


def count_spec(p, by, selector, filters, rng):
    if not {"start", "end", "step"} <= set(p):
        raise Rejected("start, end and step are required")
    step = re.fullmatch(r"(\d+)([smh]?)", p["step"])
    step_ns = int(step.group(1)) * NS[step.group(2) or "s"]
    range_ns = int(rng[:-1]) * NS[rng[-1]]
    first, last = to_ns(p["start"]), to_ns(p["end"])
    if step_ns <= 0 or last < first or range_ns > 1440 * step_ns:
        raise Rejected("unsupported start/end/step")
    evals = (last - first) // step_ns + 1
    if evals > MAX_EVALS:
        raise Rejected("too many evaluation steps")
    return CountSpec(tuple(x.strip() for x in by.split(",")), selector, filters, first, step_ns, range_ns, evals)


def loki_plan(params):
    p = dict(params)
    if len(p) != len(params) or not set(p) <= LOKI_PARAMS or "query" not in p:
        raise Rejected("unsupported parameters")
    for k in ("start", "end", "limit"):
        if k in p and not p[k].isdigit():
            raise Rejected(f"{k} must be an integer")
    if p.get("direction", "backward") not in ("backward", "forward") or not re.fullmatch(r"\d{1,6}[smh]?", p.get("step", "60")):
        raise Rejected("unsupported direction/step")
    q = p["query"]
    metric = LOKI_METRIC.fullmatch(q)
    if metric:
        by, sel, rest, rng = metric.groups()
        filters = line_filters(rest)
        if filters:
            return None, count_spec(p, by, loki_selector(sel), filters, rng)
        p["query"] = f"sum by ({by}) (count_over_time({loki_selector(sel)}[{rng}]))"
        return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(p), None
    log = LOKI_LOG.fullmatch(q)
    if not log:
        raise Rejected(REJECT_MSG)
    sel, rest = log.groups()
    filters = line_filters(rest)
    limit = min(int(p.get("limit", "100")), LOKI_MAX_LINES)
    direction = p.get("direction", "backward")
    if filters:  # scanned and filtered here on masked text; Loki only ever sees the selector
        end = to_ns(p["end"]) if "end" in p else time.time_ns()
        start = to_ns(p["start"]) if "start" in p else end - 3600 * 10**9
        return None, LogSpec(loki_selector(sel), filters, limit, direction, start, end)
    p["query"] = loki_selector(sel)
    p["limit"] = str(limit)
    return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(p), ([], limit, direction)


def apply_line_filters(obj, filters, limit, direction):
    """Line filters on the masked lines, then the caller's limit in the caller's direction."""
    data = obj.get("data") if isinstance(obj, dict) else None
    if not data or data.get("resultType") != "streams":
        return obj
    keep = [(int(ts), i, ts, line) for i, s in enumerate(data["result"]) for ts, line in s["values"]
            if all((b in line) == (op == "|=") for op, b in filters)]
    keep.sort(key=lambda e: e[0], reverse=direction == "backward")
    values = {}
    for _, i, ts, line in keep[:limit]:
        values.setdefault(i, []).append([ts, line])
    result = [{"stream": data["result"][i]["stream"], "values": v} for i, v in values.items()]
    return {"status": obj.get("status"), "data": {"resultType": "streams", "result": result}}  # stats dropped: they describe the unfiltered fetch


def count_buckets(spec, entries, deadline=None):
    """Loki matrix for sum by (...) (count_over_time(... [range])) at first + k*step, counting
    (labels, ts_ns, masked_line) entries that pass the line filters; window is (t - range, t].
    -> (result, complete). Each line covers a run of evaluation indexes [k_lo, k_hi]; a difference
    array (+1 at k_lo, -1 after k_hi) plus one sweep keeps this O(lines + points) however much
    the windows overlap. Entries come newest first, so stopping at the deadline keeps recent buckets."""
    diffs, complete = {}, True
    for n, (labels, ts, line) in enumerate(entries):
        if deadline is not None and n % 4096 == 0 and time.monotonic() > deadline:
            complete = False
            break
        if not all((b in line) == (op == "|=") for op, b in spec.filters):
            continue
        d = ts - spec.first_ns
        k_lo = max(0, -(-d // spec.step_ns))
        k_hi = min(spec.evals - 1, -(-(d + spec.range_ns) // spec.step_ns) - 1)
        if k_lo > k_hi:
            continue
        diff = diffs.setdefault(tuple(labels.get(b) for b in spec.by), {})
        diff[k_lo] = diff.get(k_lo, 0) + 1
        diff[k_hi + 1] = diff.get(k_hi + 1, 0) - 1
    t = lambda k: (spec.first_ns + k * spec.step_ns) / 10**9
    result = []
    for key, diff in diffs.items():
        values, running, marks = [], 0, sorted(diff)
        for i, k in enumerate(marks[:-1]):
            running += diff[k]
            if running:
                values += [[int(t(j)) if t(j).is_integer() else t(j), str(running)] for j in range(k, marks[i + 1])]
        if values:
            result.append({"metric": {b: v for b, v in zip(spec.by, key) if v is not None}, "values": values})
    return result, complete


def loki_page(selector, start, end, limit, timeout, direction="backward"):
    """One page of raw Loki entries in [start, end) -> [(stream, ts_ns, line)] (unmasked)."""
    url = LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": selector, "start": start, "end": end, "limit": limit, "direction": direction})
    with urllib.request.urlopen(url, timeout=timeout) as r:
        raw = read_capped(r)
    return [(s["stream"], int(ts), line) for s in json.loads(raw)["data"]["result"] for ts, line in s["values"]]


class Scan:
    """Pages a selector's raw lines from Loki in one direction; iterate for lists of new entries.

    A limited Loki page is not strictly the first N lines in its direction (measured: lines < 1 ms
    past a backward page's oldest entry were missing from it), so each next page reaches back
    overlap_ns over the previous page's edge; entries already returned are skipped by their raw
    (stream, ts, line) key, so overlaps and instants split across pages are neither lost nor
    repeated (Loki itself drops exact duplicates). After iteration: done (window exhausted),
    partial (reasons the scan stopped early or may have skipped lines), edge (ts of the last
    scanned edge, for continuing), scanned (raw lines read)."""

    def __init__(self, selector, start, end, direction, get_page, page_size, deadline, overlap_ns):
        self.args = (selector, get_page, page_size, deadline, overlap_ns)
        self.start, self.end, self.backward = start, end, direction == "backward"
        self.lo, self.hi = start, end  # the caller's window [lo, hi): no page request or entry leaves it
        self.done, self.partial, self.edge, self.scanned, self.full = False, [], None, 0, False

    def __iter__(self):
        selector, get_page, page_size, deadline, overlap = self.args
        seen, prev, tight = set(), None, False  # seen is bounded by the callers' line caps
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.partial.append("time budget used up")
                return
            try:
                page = get_page(selector, max(self.start, self.lo), min(self.end, self.hi), page_size,
                                min(TIMEOUT_S, remaining), "backward" if self.backward else "forward")
            except TimeoutError:
                if not self.scanned:
                    raise
                self.partial.append("time budget used up")
                return
            self.scanned += len(page)
            new = []
            for e in page:
                if not self.lo <= e[1] < self.hi:  # defense in depth: Loki should never return these
                    continue
                k = (tuple(sorted(e[0].items())), e[1], e[2])
                if k not in seen:
                    seen.add(k)
                    new.append(e)
            if page:  # set before yielding: a caller that stops here continues after this page, not the last
                edge = min(e[1] for e in page) if self.backward else max(e[1] for e in page)
                self.edge = edge
            self.full = len(page) >= page_size
            yield new
            if len(page) < page_size:
                self.done = True
                return
            if prev is None or (edge < prev if self.backward else edge > prev):  # progress: overlap back
                prev, tight = edge, False
                if self.backward:
                    self.end = edge + 1 + overlap
                else:
                    self.start = edge - overlap
            elif overlap and not tight:  # the overlap alone filled a page: retry without it
                tight = True
                if self.backward:
                    self.end = prev + 1
                else:
                    self.start = prev
            else:  # a full page of one instant: cannot tell whether more lines share it
                self.partial.append("some lines sharing one timestamp may be skipped")
                tight = False
                if self.backward:
                    self.end = prev
                else:
                    self.start = prev + 1


def passes(line, filters):
    return all((b in line) == (op == "|=") for op, b in filters)


def _json(obj):
    return 200, json.dumps(obj, separators=(",", ":")).encode(), "application/json"


def run_count(spec, get_page=loki_page, page_size=LOKI_MAX_LINES, budget_s=SCAN_DEADLINE_S, overlap_ns=PAGE_OVERLAP_NS):
    """Page the selector's lines newest first (so a partial count keeps the recent buckets complete),
    mask them, count here. -> (status, body, ctype)."""
    deadline = time.monotonic() + budget_s
    scan = Scan(spec.selector, spec.first_ns - spec.range_ns + 1, spec.first_ns + (spec.evals - 1) * spec.step_ns + 1,
                "backward", get_page, page_size, deadline, overlap_ns)  # Loki's end is exclusive
    entries = []
    try:
        for new in scan:
            entries += [(mask_json(st), ts, mask_text(line)) for st, ts, line in new]
            if scan.scanned >= SCAN_MAX_LINES:  # raw lines read (overlapping pages re-read some), not deduped
                scan.partial.append("line cap reached")
                break
    except urllib.error.HTTPError as e:
        return (e.code, *masked_body(read_capped(e), e.headers.get("Content-Type")))
    result, complete = count_buckets(spec, entries, deadline + COUNT_AGG_GRACE_S)
    if not complete:
        scan.partial.append("time budget used up")
    data = {"resultType": "matrix", "result": result}
    if scan.partial:
        data["warnings"] = [f"partial count ({', '.join(dict.fromkeys(scan.partial))}): {len(entries)} newest lines of the window counted; older buckets may be low"]
    return _json({"status": "success", "data": data})


class LogSpec(NamedTuple):
    """{selector} |= ... != ... log query, filtered here on masked lines."""
    selector: str
    filters: list
    limit: int
    direction: str
    start_ns: int
    end_ns: int


def settled(hits, spec, scan, overlap_ns):
    """True once the first `limit` hits (in the scan direction) can no longer change: Loki may omit
    lines just inside a full page's edge, and only the next, overlapping page recovers them, so the
    cutoff (the limit-th hit) must lie more than overlap_ns inside the last consumed page's edge."""
    if not scan.full:
        return True
    back = spec.direction == "backward"
    cutoff = sorted((h[0] for h in hits), reverse=back)[spec.limit - 1]
    return scan.edge + overlap_ns < cutoff if back else scan.edge - overlap_ns > cutoff


def run_log(spec, get_page=loki_page, page_size=LOKI_MAX_LINES, budget_s=SCAN_DEADLINE_S, overlap_ns=PAGE_OVERLAP_NS):
    """Scan the selector's lines in the requested direction until `limit` lines pass the filters on
    the masked text, the window ends, or the scan budget/cap runs out. In the last case the reply is
    partial: data.warnings says so and data.scanned_until is the ns timestamp the scan reached
    (continue with end=scanned_until when backward, start=scanned_until+1 when forward). It is the
    outer edge of the last page actually consumed, so a continuation never repeats returned lines;
    ponytail: other lines sharing exactly that ns, not in the page, are not revisited."""
    scan = Scan(spec.selector, spec.start_ns, spec.end_ns, spec.direction, get_page, page_size,
                time.monotonic() + budget_s, overlap_ns)
    hits = []  # (ts, stream, masked line)
    try:
        for new in scan:
            for st, ts, line in new:
                masked = mask_text(line)
                if passes(masked, spec.filters):
                    hits.append((ts, mask_json(st), masked))
            if len(hits) >= spec.limit and settled(hits, spec, scan, overlap_ns):
                break
            if scan.scanned >= SCAN_MAX_LINES:
                scan.partial.append("line cap reached")
                break
    except urllib.error.HTTPError as e:
        return (e.code, *masked_body(read_capped(e), e.headers.get("Content-Type")))
    hits.sort(key=lambda h: h[0], reverse=spec.direction == "backward")
    streams = {}
    for ts, st, line in hits[:spec.limit]:
        streams.setdefault(json.dumps(st, sort_keys=True), {"stream": st, "values": []})["values"].append([str(ts), line])
    data = {"resultType": "streams", "result": list(streams.values())}
    if len(hits) < spec.limit and not scan.done:
        data["warnings"] = [f"partial result ({', '.join(dict.fromkeys(scan.partial)) or 'stopped early'}): scanned {scan.scanned} lines "
                            f"; continue from data.scanned_until"]
        data["scanned_until"] = str(scan.edge if scan.edge is not None else (spec.end_ns if spec.direction == "backward" else spec.start_ns))
    elif scan.partial:  # also when limit was reached: lines skipped earlier in the scan may belong in this page
        data["warnings"] = [f"possible gaps ({', '.join(dict.fromkeys(scan.partial))})"]
    return _json({"status": "success", "data": data})


# ---- routing / HTTP ---------------------------------------------------------------------------

def route(method, raw_path):
    """-> (upstream_url, post_filter, None) or (None, None, (status, message))."""
    if method != "GET":
        return None, None, (405, "method not allowed")
    parts = urllib.parse.urlsplit(raw_path)
    if parts.path not in PROM_QUERY and parts.path not in PROM_PLAIN and parts.path != LOKI_RANGE:
        return None, None, (403, "forbidden")
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    try:
        if any(IPV4.search(v) or MAC.search(v) for _, v in params):
            raise Rejected(REJECT_MSG)
        url, post = loki_plan(params) if parts.path == LOKI_RANGE else prom_plan(parts.path, params)
    except Rejected as e:
        return None, None, (400, str(e))
    return url, post, None


def read_capped(resp):
    body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("upstream response too large")
    return body


def masked_body(raw, content_type, post=None):
    if "json" in (content_type or ""):
        obj = mask_json(json.loads(raw))
        if post:
            obj = apply_line_filters(obj, *post)
        return json.dumps(obj, separators=(",", ":")).encode(), "application/json"
    return mask_text(raw.decode("utf-8", "replace")).encode(), "text/plain; charset=utf-8"


def fetch(url, post=None):
    """-> (status, body bytes, content type), masked (and line-filtered for Loki)."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=TIMEOUT_S) as r:
            status, raw, ctype = r.status, read_capped(r), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        status, raw, ctype = e.code, read_capped(e), e.headers.get("Content-Type")
    return (status, *masked_body(raw, ctype, post if status == 200 else None))


def error_body(status, msg):
    return json.dumps({"status": "error", "errorType": "masked_query" if status == 400 else "proxy", "error": msg}).encode()


ROLE_HEADER = "X-Obs-Role"
ROLES = ("viewer",)  # P1: no authentication layer yet, so no role may unmask anything


def request_role(headers):
    """Role for a request. Insertion point for the future auth layer: the front proxy strips X-Obs-Role from
    clients and only its forward-auth step may set it (caddy/Caddyfile). Until roles that may see more exist
    (SEC-03), every request is a viewer whatever the header says: masking and query restrictions always apply."""
    claimed = (headers.get(ROLE_HEADER) or "").strip().lower()
    return claimed if claimed in ROLES else "viewer"


# ---- Alertmanager (/am/): masked reads, and the only writes: silences (ACK) --------------------------------------------
# Reads: the alert and silence lists, masked like every other response (exact IPv4 values become tokens, so the screens
# can match them to Prometheus' alerts). Writes: create / extend / expire a silence, nothing else. A write must come from
# the command-center itself (same origin + the X-Obs-Csrf header, which a cross-site form cannot send and a cross-site
# script cannot send without a CORS preflight that is never granted), while the screens are on 127.0.0.1 only (or, with
# OBS_OPS_TRUST_ROLE=1, for X-Obs-Role operator / admin from a future authentication layer). Matchers: equality on
# alertname / instance / ifName / severity only (no regex: a silence must name what it mutes), addresses only as tokens
# the screen was given; duration at most 7 days (also counted from an extended silence's start); comment bounded;
# createdBy is always "command-center (<operator>)" and an ACK comment always "ACK by <operator>[: note]". The operator
# is the authentication layer's user (X-Obs-User, only with OBS_OPS_TRUST_ROLE=1), else "local".
# Origins: only the names the proxy answers for (loopback, OBS_PUBLIC_URL's host, the bind address): with the proxy's
# Host allowlist this keeps a DNS-rebinding page (evil.example -> 127.0.0.1) out, even if the proxy rule were removed.

ALERTMANAGER = os.environ.get("ALERTMANAGER_URL", "http://alertmanager:9093")
AM_READ = {"/am/api/v2/alerts": "/api/v2/alerts?active=true&silenced=true&inhibited=true&unprocessed=true",
           "/am/api/v2/silences": "/api/v2/silences"}
AM_OPS = "/am/ops"
AM_SILENCES = "/am/api/v2/silences"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
AM_SILENCE_ID = re.compile(r"/am/api/v2/silence/(" + UUID_RE.pattern + ")")
SILENCE_LABELS = ("alertname", "instance", "ifName", "severity")
SILENCE_MAX_S = 7 * 86400
CLOCK_SLACK_S = 300  # browser vs server clock
COMMENT_MAX = 200
WRITE_MAX_BODY = 8192
CREATED_BY = "command-center"
OPERATOR_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")
USER_HEADER = "X-Obs-User"
OPS_ROLES = ("operator", "admin")
CSRF_HEADER = "X-Obs-Csrf"
WRITES_PER_MIN = 30
_writes = []  # monotonic times of recent writes (rate limit)


def bind_is_local():
    b = os.environ.get("OBS_BIND", "127.0.0.1")
    return b == "localhost" or b.startswith("127.")


def ops_role(headers):
    """operator / admin from the authentication layer, only when the deployment says it has one (never by default)."""
    if os.environ.get("OBS_OPS_TRUST_ROLE") != "1":
        return None
    r = (headers.get(ROLE_HEADER) or "").strip().lower()
    return r if r in OPS_ROLES else None


def operator(headers):
    """Who writes: the authentication layer's user (only when trusted), else "local" (the 127.0.0.1 screen)."""
    if os.environ.get("OBS_OPS_TRUST_ROLE") == "1":
        u = (headers.get(USER_HEADER) or "").strip()
        if OPERATOR_RE.fullmatch(u):
            return u
    return "local"


def is_ours(s):
    by = str(s.get("createdBy", "")) if isinstance(s, dict) else ""
    return by == CREATED_BY or by.startswith(CREATED_BY + " (")


def ack_comment(c, op):
    """An ACK comment names who acknowledged, whatever the client wrote after "ACK"."""
    m = re.match(r"ACK\b[\s:]*(.*)", c)  # the ACK rule is ^ACK\b everywhere (notify-relay ACK_RE, command-center ACK_RE)
    if not m:
        return c
    return (f"ACK by {op}" + (f": {m.group(1)}" if m.group(1) else ""))[:COMMENT_MAX]


def allowed_hosts():
    hosts = {"127.0.0.1", "localhost", "::1"}
    pub = urllib.parse.urlsplit(os.environ.get("OBS_PUBLIC_URL", "")).hostname
    bind = os.environ.get("OBS_BIND", "127.0.0.1")
    if pub:
        hosts.add(pub.lower())
    if bind not in ("", "0.0.0.0"):
        hosts.add(bind.lower())
    return hosts


def writable(headers):
    if bind_is_local():
        return True, "127.0.0.1 only: silences / ACK allowed"
    role = ops_role(headers)
    if role:
        return True, f"role {role}: silences / ACK allowed"
    return False, "LAN 公開中は抑止・確認の操作はできません (認証がありません)"


def same_origin(headers):
    origin, host = headers.get("Origin") or "", headers.get("X-Forwarded-Host") or headers.get("Host") or ""
    o = urllib.parse.urlsplit(origin)
    if o.scheme not in ("http", "https") or not host or headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
        return False
    return (o.hostname or "") in allowed_hosts() and o.netloc.lower() == host.split(",")[0].strip().lower()


def am_time(v, what):
    try:
        d = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", str(v)).replace("Z", "+00:00"))
    except ValueError:
        raise Rejected(f"{what} must be an RFC 3339 time") from None
    if d.tzinfo is None:
        raise Rejected(f"{what} needs a time zone")
    return d.timestamp()


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def silence_matchers(ms):
    if not isinstance(ms, list) or not 1 <= len(ms) <= len(SILENCE_LABELS):
        raise Rejected("matchers: 1 to 4 equality matchers")
    out, names = [], set()
    for m in ms:
        if not isinstance(m, dict) or set(m) - {"name", "value", "isRegex", "isEqual"}:
            raise Rejected("matcher fields: name, value, isRegex, isEqual")
        if m.get("isRegex", False) is not False or m.get("isEqual", True) is not True:
            raise Rejected("only equality matchers (isRegex false, isEqual true) are accepted")
        name, value = m.get("name"), m.get("value")
        if name not in SILENCE_LABELS or name in names:
            raise Rejected(f"matcher names: {', '.join(SILENCE_LABELS)} (each once)")
        if not isinstance(value, str) or not 0 < len(value) <= 128:
            raise Rejected("matcher value: 1 to 128 characters")
        check_literal(value)
        if any(not x.group(4) for x in MASKED_IPV4.finditer(value)) or MASKED_MAC.search(value):
            raise Rejected("a masked address without its token cannot be matched exactly")
        names.add(name)
        out.append({"name": name, "value": _rewrite(value, as_regex=False), "isRegex": False, "isEqual": True})
    if not names & {"alertname", "instance"}:
        raise Rejected("a silence must name the alert (alertname) or the device (instance)")
    return out


def check_comment(c):
    c = c.strip() if isinstance(c, str) else ""
    if not 0 < len(c) <= COMMENT_MAX or any(ord(ch) < 32 for ch in c):
        raise Rejected(f"comment: 1 to {COMMENT_MAX} characters, one line")
    return c


def check_end(v, start, now, began=None):
    """began: an extended silence's start; the 7 days count from there too (no endless extension)."""
    end = am_time(v, "endsAt")
    if not now < end <= now + SILENCE_MAX_S + CLOCK_SLACK_S or end <= start:
        raise Rejected("endsAt: in the future, at most 7 days from now")
    if began is not None and end > began + SILENCE_MAX_S + CLOCK_SLACK_S:
        raise Rejected("endsAt: a silence lasts at most 7 days from its start (make a new one)")
    return end


def silence_body(body, now, existing=None, op="local"):
    """Client body -> the Alertmanager silence to post. New: matchers + endsAt + comment. Extend (id given): endsAt and
    optionally comment; matchers and start stay those of the existing command-center silence."""
    if not isinstance(body, dict) or set(body) - {"id", "matchers", "endsAt", "comment", "createdBy"}:
        raise Rejected("fields: matchers, endsAt, comment (id to extend)")
    if "createdBy" in body:
        raise Rejected("createdBy is set by the server")
    if "id" in body:
        if existing is None:
            raise Rejected("unknown silence")
        if "matchers" in body:
            raise Rejected("an extension keeps the silence's matchers")
        start = am_time(existing["startsAt"], "startsAt")
        comment = ack_comment(check_comment(body["comment"]), op) if "comment" in body else existing.get("comment")
        return {"id": existing["id"], "matchers": existing["matchers"], "startsAt": existing["startsAt"],
                "endsAt": iso(check_end(body.get("endsAt"), max(start, now - CLOCK_SLACK_S), now, began=start)),
                "createdBy": existing.get("createdBy"), "comment": comment}
    return {"matchers": silence_matchers(body.get("matchers")), "startsAt": iso(now), "endsAt": iso(check_end(body.get("endsAt"), now, now)),
            "createdBy": f"{CREATED_BY} ({op})", "comment": ack_comment(check_comment(body.get("comment")), op)}


def am_request(path, method="GET", body=None):
    """-> (status, raw body) from Alertmanager (errors included)."""
    req = urllib.request.Request(ALERTMANAGER + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return r.status, read_capped(r)
    except urllib.error.HTTPError as e:
        return e.code, read_capped(e)


def own_silence(sid):
    """The silence if it exists and was made by the command-center (only those may be extended / expired here)."""
    status, raw = am_request(f"/api/v2/silence/{sid}")
    try:
        s = json.loads(raw) if status == 200 else None
    except ValueError:
        s = None
    if not is_ours(s):
        raise Rejected("unknown silence, or not created by the command-center")
    if (s.get("status") or {}).get("state") == "expired":
        raise Rejected("the silence has already expired")
    return s


def rate_limited(now):
    _writes[:] = [t for t in _writes if now - t < 60]
    if len(_writes) >= WRITES_PER_MIN:
        return True
    _writes.append(now)
    return False


def am_json(status, obj):
    return status, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(), "application/json"


def am_handle(method, raw_path, headers, read_body):
    """/am/... -> (status, body, content type)."""
    parts = urllib.parse.urlsplit(raw_path)
    path = parts.path
    if method in ("GET", "HEAD"):
        if parts.query:
            return am_json(400, {"status": "error", "error": "no parameters accepted here"})
        if path == AM_OPS:
            ok, reason = writable(headers)
            return am_json(200, {"writable": ok, "reason": reason, "max_s": SILENCE_MAX_S, "labels": SILENCE_LABELS})
        if path not in AM_READ:
            return am_json(403, {"status": "error", "error": "forbidden"})
        status, raw = am_request(AM_READ[path])
        return (status, *masked_body(raw, "application/json"))
    is_new = method == "POST" and path == AM_SILENCES
    sid = AM_SILENCE_ID.fullmatch(path) if method == "DELETE" else None
    if not is_new and not sid:
        return am_json(403 if method in ("POST", "DELETE") else 405, {"status": "error", "error": "only silences can be written"})
    ok, reason = writable(headers)
    if not ok:
        return am_json(403, {"status": "error", "errorType": "forbidden", "error": reason})
    if headers.get(CSRF_HEADER) != "1" or not same_origin(headers):
        return am_json(403, {"status": "error", "errorType": "csrf", "error": "cross-site or scripted request refused (same origin + X-Obs-Csrf required)"})
    if rate_limited(time.monotonic()):
        return am_json(429, {"status": "error", "error": "too many changes; wait a minute"})
    try:
        if sid:
            own_silence(sid.group(1))
            status, raw = am_request(f"/api/v2/silence/{sid.group(1)}", "DELETE")
            return am_json(status, {"status": "success" if status == 200 else "error"})
        if "json" not in (headers.get("Content-Type") or ""):
            raise Rejected("Content-Type: application/json required")
        length = headers.get("Content-Length") or "0"
        length = int(length) if length.isdigit() else -1
        if not 0 < length <= WRITE_MAX_BODY:
            raise Rejected("body too large or empty")
        try:
            body = json.loads(read_body(length))
        except ValueError:
            raise Rejected("body is not JSON") from None
        existing = None
        if isinstance(body, dict) and "id" in body:
            if not (isinstance(body["id"], str) and UUID_RE.fullmatch(body["id"])):
                raise Rejected("id: a silence id")
            existing = own_silence(body["id"])
        status, raw = am_request("/api/v2/silences", "POST", silence_body(body, time.time(), existing, operator(headers)))
        return (status, *masked_body(raw, "application/json"))
    except Rejected as e:
        return am_json(400, {"status": "error", "errorType": "rejected", "error": str(e)})


def respond(method, raw_path, headers, read_body):
    """-> (status, body, content type) for one request."""
    _role = request_role(headers)  # always "viewer": masking never depends on it (writes: see writable())
    try:
        if raw_path.startswith("/am/"):
            return am_handle(method, raw_path, headers, read_body)
        url, post, err = route(method, raw_path)
        if err:
            return err[0], error_body(*err), "application/json"
        if isinstance(post, CountSpec):
            return run_count(post)
        if isinstance(post, LogSpec):
            return run_log(post)
        return fetch(url, post)
    except TimeoutError:
        return 504, error_body(504, "upstream timeout"), "application/json"
    except (OSError, ValueError) as e:  # URLError, connection reset, bad/oversize JSON
        print(f"upstream error: {type(e).__name__}", file=sys.stderr)
        return 502, error_body(502, "upstream unavailable"), "application/json"


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        t0 = time.monotonic()
        status, body, ctype = respond(self.command, self.path, self.headers, self.rfile.read)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        note = ""
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                note = " client-gone"
        path = urllib.parse.urlsplit(self.path).path  # never log the query string
        sys.stdout.write(f"{self.command} {path} {status} {int((time.monotonic() - t0) * 1000)}ms{note}\n")
        sys.stdout.flush()

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle

    def log_message(self, *args):  # replaced by the single line in _handle
        pass


# Adversarial probes (also replayed live by the evidence script). Every one must be rejected (400).
LOKI_PROBES = [
    '{job="syslog"} |> "<_>192.<_>168.<_>100.<_>7:<_>"',  # pattern filter (Codex P1)
    '{job="syslog"} !> "<_>.7:<_>"',
    r'{job="syslog"} |~ "192\\.0\\.2\\.1[0-9]"',
    r'{job="syslog"} | regexp "(?P<o>\\d+)"',
    '{job="syslog"} | line_format "{{.x}}"',
    '{job="syslog"} | logfmt',
    '{job="syslog"} | json | dst="x"',
    '{job="syslog",host=~"rtx.*"}',
    '{job="syslog",host!="rtx1300"}',
    '{job="syslog",dst="x"}',
    '{job="syslog"} |= "192.0.2.10"',
    '{job="syslog"} |= `02:00:5e:20:00:01`',
    '{job="syslog"} |= "113.50"',
    r'{job="syslog"} |= "113.50"',
    r'{job="syslog"} |= "113\x2e50"',
    '{job="syslog"} |= \'113.50\'',
    'count_over_time({job="syslog"} |= "x" [5m])',
    'sum by (host) (count_over_time({job="syslog"}[5m]))',
    'sum by (severity) (count_over_time({job="syslog"} |= "113.50" [60s]))',  # filtered counts: same literal rules
    'sum by (severity) (count_over_time({job="syslog"} |= "192.0.2.10" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |= "5e:20:00:01" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |~ "Rej.*" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |> "<_>.7<_>" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |= "x" | logfmt [60s]))',
    r'sum by (severity) (count_over_time({job="syslog"} |= "113.50" [60s]))',
    'sum by (dst) (count_over_time({job="syslog"} |= "x" [60s]))',
    '{job="syslog"} |= "a" or {job="syslog"}',
]
PROM_PROBES = [
    'demo_flow_bytes_total{dst_ip=~"203.*"}',
    'demo_flow_bytes_total{dst_ip!~"203.0.113.5.*"}',
    '{__name__=~"demo.*"}',
    'label_replace(demo_flow_bytes_total, "o", "$1", "dst_ip", ".*[.](.*)")',
    'label_join(demo_flow_bytes_total, "o", "", "dst_ip")',
    'sort_by_label(demo_flow_bytes_total, "dst_ip")',
    'count_values("v", demo_flow_bytes_total)',
    'demo_flow_bytes_total{dst_ip="203.0.113.50"}',
    'demo_flow_bytes_total{dst_ip=`203.0.113.50`}',
    r'demo_flow_bytes_total{dst_ip="203.0.113.50"}',
    r'demo_flow_bytes_total{dst_ip="203\x2e0.113.50"}',
    'demo_flow_bytes_total{dst_ip="203.0.113.5"}',
    'demo_flow_bytes_total{dst_ip="203.0.113.x~000000000000"}',
    'absent(nope{dst_ip="203.0.113.50"})',
    'demo_flow_bytes_total{dst_ip="203.0.113.x"} > on() group_left() vector(1) == bool 1 or "113.50"',
    'info(up)',
    "demo_flow_bytes_total{dst_ip='1.2'}",
]


def am_selftest(tok):
    """/am/: masked reads, the write allowlist and its guards, against a fake Alertmanager."""
    global am_request
    calls, store = [], {}
    sid = "0b9cbd2e-8d2c-4a39-9e0f-4b0c6e6c1a11"

    def fake(path, method="GET", body=None):
        calls.append((method, path, body))
        if path.startswith("/api/v2/alerts"):
            return 200, json.dumps([{"labels": {"alertname": "DeviceDown", "instance": "203.0.113.50"}, "fingerprint": "0123456789abcdef"}]).encode()
        if path == "/api/v2/silences" and method == "POST":
            return 200, json.dumps({"silenceID": sid}).encode()
        if path == f"/api/v2/silence/{sid}":
            return (200, json.dumps(store.get(sid) or {}).encode()) if method == "GET" else (200, b"")
        return 404, b"{}"
    real, am_request = am_request, fake
    env_was = {k: os.environ.get(k) for k in ("OBS_BIND", "OBS_OPS_TRUST_ROLE", "OBS_PUBLIC_URL")}
    try:
        os.environ["OBS_BIND"], os.environ["OBS_OPS_TRUST_ROLE"], os.environ["OBS_PUBLIC_URL"] = "127.0.0.1", "0", "http://127.0.0.1:8080"
        hdr = {"Origin": "http://127.0.0.1:8080", "X-Forwarded-Host": "127.0.0.1:8080", "X-Obs-Csrf": "1", "Content-Type": "application/json",
               "Sec-Fetch-Site": "same-origin"}
        now = time.time()
        good = {"matchers": [{"name": "alertname", "value": "DeviceDown", "isRegex": False, "isEqual": True},
                             {"name": "instance", "value": tok}], "endsAt": iso(now + 3600), "comment": "ACK: looking into it"}

        def post(body, headers=hdr, path=AM_SILENCES, method="POST"):
            raw = json.dumps(body).encode()
            st, out, _ = am_handle(method, path, {**headers, "Content-Length": str(len(raw))}, lambda n: raw[:n])
            return st, json.loads(out or b"null")
        st, out = am_handle("GET", "/am/api/v2/alerts", {}, None)[:2]
        assert st == 200 and b"203.0.113.50" not in out and tok.encode() in out  # masked; same token as Prometheus' alerts
        assert am_handle("GET", "/am/api/v2/alerts?filter=x", {}, None)[0] == 400 and am_handle("GET", "/am/api/v2/status", {}, None)[0] == 403
        assert json.loads(am_handle("GET", AM_OPS, {}, None)[1])["writable"] is True
        st, out = post(good)
        assert st == 200 and out == {"silenceID": sid}, (st, out)
        sent = calls[-1][2]
        assert sent["createdBy"] == "command-center (local)" and sent["matchers"][1] == {"name": "instance", "value": "203.0.113.50", "isRegex": False, "isEqual": True}
        assert abs(am_time(sent["startsAt"], "") - now) < 5 and sent["comment"] == "ACK by local: looking into it", sent
        post({**good, "comment": "ACK by mallory"})
        assert calls[-1][2]["comment"] == "ACK by local: by mallory"  # the operator is never taken from the comment
        post({**good, "comment": "maintenance"})
        assert calls[-1][2]["comment"] == "maintenance"
        # DNS rebinding (reviewer probe): a page on evil.example resolved to 127.0.0.1 - Host and Origin both the attacker's
        for h in ({**hdr, "Origin": "http://evil.example:8080", "X-Forwarded-Host": "evil.example:8080"},
                  {**hdr, "Origin": "http://evil.example:8080", "Host": "evil.example:8080", "X-Forwarded-Host": "evil.example:8080"}):
            assert post(good, h)[0] == 403, h
        assert post(good, {**hdr, "Origin": "http://localhost:8080", "X-Forwarded-Host": "localhost:8080"})[0] == 200
        raw = b"{}"
        for bad_len in ("abc", "-5", "99999999"):
            assert am_handle("POST", AM_SILENCES, {**hdr, "Content-Length": bad_len}, lambda n: raw)[0] == 400, bad_len
        rejected = [
            {**good, "matchers": [{"name": "alertname", "value": "Device.*", "isRegex": True}]},                    # regex matcher
            {**good, "matchers": [{"name": "alertname", "value": "X", "isEqual": False}]},                          # negative matcher
            {**good, "matchers": [{"name": "job", "value": "snmp"}]},                                               # label not allowed
            {**good, "matchers": [{"name": "severity", "value": "critical"}]},                                      # mutes everything critical
            {**good, "matchers": [{"name": "instance", "value": "203.0.113.50"}]},                                  # raw address
            {**good, "matchers": [{"name": "instance", "value": "203.0.113.x"}]},                                   # masked without token
            {**good, "matchers": [{"name": "instance", "value": "203.0.113.x~000000000000"}]},                      # forged token
            {**good, "matchers": []}, {**good, "matchers": [good["matchers"][0]] * 2},
            {**good, "endsAt": iso(now + 8 * 86400)}, {**good, "endsAt": iso(now - 10)}, {**good, "endsAt": "tomorrow"},  # duration
            {**good, "comment": ""}, {**good, "comment": "x" * 201}, {**good, "comment": "a\nb"},
            {**good, "createdBy": "admin"}, {**good, "createdBy": "command-center"}, {**good, "startsAt": iso(now)}, [good],
        ]
        for i, bad in enumerate(rejected):
            st, out = post(bad)
            assert st == 400 and out["errorType"] == "rejected", (i, st, out)
        for h in ({k: v for k, v in hdr.items() if k != "X-Obs-Csrf"}, {**hdr, "Origin": "http://evil.example"},
                  {k: v for k, v in hdr.items() if k != "Origin"}, {**hdr, "Sec-Fetch-Site": "cross-site"}):
            assert post(good, h)[0] == 403 and post(good, h)[1]["errorType"] == "csrf", h
        assert post(good, {**hdr, "Content-Type": "text/plain"})[0] == 400
        assert post(good, path="/am/api/v2/alerts")[0] == 403 and post(good, method="PUT")[0] == 405
        # extend / expire: only the command-center's own, not yet expired silences; matchers are kept
        store[sid] = {"id": sid, "createdBy": "command-center (local)", "comment": "maintenance", "startsAt": iso(now - 600), "endsAt": iso(now + 60),
                      "status": {"state": "active"}, "matchers": [{"name": "instance", "value": "wlx222", "isRegex": False, "isEqual": True}]}
        st, _ = post({"id": sid, "endsAt": iso(now + 7200)})
        assert st == 200 and calls[-1][2]["matchers"] == store[sid]["matchers"] and calls[-1][2]["id"] == sid and calls[-1][2]["startsAt"] == store[sid]["startsAt"]
        assert calls[-1][2]["createdBy"] == "command-center (local)" and calls[-1][2]["comment"] == "maintenance"
        assert post({"id": sid, "endsAt": iso(now + 7200), "matchers": good["matchers"]})[0] == 400
        _writes.clear()  # (the rate limit is tested below)
        store[sid] = {**store[sid], "startsAt": iso(now - 6 * 86400)}  # extensions stop at 7 days from the start
        assert post({"id": sid, "endsAt": iso(now + 2 * 86400)})[0] == 400 and post({"id": sid, "endsAt": iso(now + 86400 - 600)})[0] == 200
        store[sid] = {**store[sid], "startsAt": iso(now - 600)}
        assert am_handle("DELETE", f"/am/api/v2/silence/{sid}", {**hdr, "Origin": "http://evil.example:8080", "X-Forwarded-Host": "evil.example:8080"}, None)[0] == 403
        assert post({"id": "nope", "endsAt": iso(now + 7200)})[0] == 400
        assert am_handle("DELETE", f"/am/api/v2/silence/{sid}", hdr, None)[0] == 200 and calls[-1][:2] == ("DELETE", f"/api/v2/silence/{sid}")
        store[sid] = {**store[sid], "createdBy": "amtool"}
        assert am_handle("DELETE", f"/am/api/v2/silence/{sid}", hdr, None)[0] == 400  # not ours
        assert am_handle("DELETE", "/am/api/v2/silences", hdr, None)[0] == 403
        # LAN exposure: no writes, whatever the headers say; a trusted auth layer's operator role may write
        os.environ["OBS_BIND"] = "192.168.100.10"
        lan = {**hdr, "Origin": "http://192.168.100.10:8080", "X-Forwarded-Host": "192.168.100.10:8080", "X-Obs-Role": "admin"}
        st, out = post(good, lan)
        assert st == 403 and out["errorType"] == "forbidden" and json.loads(am_handle("GET", AM_OPS, lan, None)[1])["writable"] is False
        os.environ["OBS_OPS_TRUST_ROLE"] = "1"
        assert post(good, lan)[0] == 200 and post(good, {**lan, "X-Obs-Role": "viewer"})[0] == 403
        assert post(good, {**lan, "X-Obs-User": "alice"})[0] == 200
        assert calls[-1][2]["createdBy"] == "command-center (alice)" and calls[-1][2]["comment"].startswith("ACK by alice")
        assert post(good, {**lan, "X-Obs-User": "bad user;"})[0] == 200 and calls[-1][2]["createdBy"] == "command-center (local)"
        _writes[:] = [time.monotonic()] * WRITES_PER_MIN
        assert post(good, lan)[0] == 429  # rate limit
        _writes.clear()
    finally:
        am_request = real
        for k, v in env_was.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def selftest():
    q = urllib.parse.quote
    nested = {"status": "success", "data": {"result": [
        {"metric": {"dst_ip": "203.0.113.50", "mac": "02:00:5E:10:00:0A"}, "value": [1, "42"]},
        {"stream": {"host": "rtx1300"}, "values": [["1", "TCP 192.168.100.7:5555 > 192.0.2.10:443 02-00-5e-20-00-01"]]},
    ], "rules": [{"expr": 'x{dst_ip="198.51.100.20"}'}], "v6": "2001:db8::1", "oid": "1.3.6.1.2.1.1.3"}}
    out = json.dumps(mask_json(nested))
    assert not IPV4.search(out) and not MAC.search(out), out
    m = mask_json(nested)["data"]
    tok = m["result"][0]["metric"]["dst_ip"]
    assert re.fullmatch(r"203\.0\.113\.x~[0-9a-f]{12}", tok) and m["result"][0]["metric"]["mac"] == "02:00:5E:xx:xx:xx"
    assert mask_value("203.0.113.50") == tok and mask_value("203.0.113.60") != tok  # stable, and distinct per address
    assert m["result"][1]["values"][0][1] == "TCP 192.168.100.x:5555 > 192.0.2.x:443 02-00-5e-xx-xx-xx"  # no tokens in text
    assert m["result"][0]["value"] == [1, "42"] and m["v6"] == "2001:db8::1"  # IPv6 deliberately untouched
    assert mask_json({"10.0.0.1": 1}) == {"10.0.0.x": 1}

    def plan(p):
        url, post, err = route("GET", p)
        return (urllib.parse.unquote_plus(url) if url else None), post, err
    lq = lambda s, extra="&limit=200": f"{LOKI_RANGE}?query={q(s)}{extra}"
    pq = lambda s: "/prom/api/v1/query?query=" + q(s)

    # every adversarial probe is rejected
    for probe in LOKI_PROBES:
        assert plan(lq(probe))[2][0] == 400, probe
    for probe in PROM_PROBES:
        assert plan(pq(probe))[2][0] == 400, probe
    forged = tok[:-1] + ("0" if tok[-1] != "0" else "1")
    for probe in ('x{dst_ip="%s"}' % forged, 'x{dst_ip="198.51.100.x~%s"}' % tok[-12:]):
        assert plan(pq(probe))[2][0] == 400, probe

    # UI shapes pass; Loki only ever sees the selector
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"} |= `Rejected` != "SSID=home-main"', "&limit=200&start=10&end=20&direction=forward"))
    assert url is None and post == LogSpec('{job="syslog",host="rtx1300"}', [("|=", "Rejected"), ("!=", "SSID=home-main")], 200, "forward", 10 * 10**9, 20 * 10**9)
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"} |= "192.0.2.x" |= "10:443"'))  # Codex suffix probe: allowed, but
    assert url is None and post.filters == [("|=", "192.0.2.x"), ("|=", "10:443")] and "192" not in post.selector  # filtered here
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"}', "&limit=40&direction=forward"))  # no filter: Loki answers directly
    assert 'query={job="syslog",host="rtx1300"}&' in url and "limit=40" in url and post == ([], 40, "forward")
    url, post, _ = plan(lq('sum by (host, severity) (count_over_time({job="syslog"}[900s]))', "&start=1&end=2&step=60"))
    assert post is None and "count_over_time({job=\"syslog\"}[900s])" in url
    # filtered volume counts: planned for local counting on masked lines, never sent to Loki with the filter
    url, spec, _ = plan(lq('sum by (severity) (count_over_time({job="syslog",host="rtx1300"} |= "Rejected" != `TCP` [60s]))',
                           "&start=1761300060&end=1761303600&step=60"))
    assert url is None and spec.selector == '{job="syslog",host="rtx1300"}' and spec.filters == [("|=", "Rejected"), ("!=", "TCP")]
    assert (spec.by, spec.first_ns, spec.step_ns, spec.range_ns, spec.evals) == (("severity",), 1761300060 * 10**9, 60 * 10**9, 60 * 10**9, 60)
    assert plan(lq('sum by (severity) (count_over_time({job="syslog"} |= "x" [60s]))', "&start=1&end=2"))[2][0] == 400  # step required
    assert plan(lq('sum by (severity) (count_over_time({job="syslog"} |= "x" [60s]))', "&start=1&end=99999999&step=1"))[2][0] == 400
    s1 = 10**9
    sp = CountSpec(("host", "severity"), "{}", [("|=", "Rejected")], 120 * s1, 60 * s1, 60 * s1, 3)  # evals at 120, 180, 240
    ent = [({"host": "a", "severity": "info"}, 61 * s1, "Rejected 203.0.113.x"),   # (60,120] -> 120
           ({"host": "a", "severity": "info"}, 120 * s1, "Rejected"),               # boundary: belongs to 120
           ({"host": "a", "severity": "info"}, 121 * s1, "Rejected"),               # -> 180
           ({"host": "b", "severity": "notice"}, 240 * s1, "Rejected"),             # -> 240
           ({"host": "b", "severity": "notice"}, 241 * s1, "Rejected"),             # after last eval: dropped
           ({"host": "a", "severity": "info"}, 150 * s1, "TCP 192.0.2.x:443"),      # filtered out
           ({"host": "a", "severity": "info"}, 59 * s1, "Rejected")]                # before first window: dropped
    got = {tuple(r["metric"].values()): r["values"] for r in count_buckets(sp, ent)[0]}
    assert got == {("a", "info"): [[120, "2"], [180, "1"]], ("b", "notice"): [[240, "1"]]}, got
    wide = sp._replace(by=("severity",), range_ns=120 * s1)  # range > step: a line counts in every window covering it
    assert {tuple(r["metric"].values()): r["values"] for r in count_buckets(wide, ent[:3])[0]} == {("info",): [[120, "2"], [180, "3"], [240, "1"]]}
    hidden = sp._replace(filters=[("|=", "113.x")])  # a filter only ever sees masked text
    assert count_buckets(hidden, [({}, 121 * s1, "UDP 203.0.113.x:9 > 192.168.100.x:161")])[0] == [{"metric": {}, "values": [[180, "1"]]}]
    assert count_buckets(hidden._replace(filters=[("|=", "113.5")]), [({}, 121 * s1, "UDP 203.0.113.x:9")])[0] == []

    def naive(spec, ents):  # reference: every eval point checks every line
        out = {}
        for k in range(spec.evals):
            t = spec.first_ns + k * spec.step_ns
            for labels, ts, line in ents:
                if t - spec.range_ns < ts <= t and all((b in line) == (op == "|=") for op, b in spec.filters):
                    per = out.setdefault(tuple(labels.get(b) for b in spec.by), {})
                    per[k] = per.get(k, 0) + 1
        return {key: [(k, n) for k, n in sorted(per.items())] for key, per in out.items()}
    as_idx = lambda spec, res: {tuple(r["metric"].get(b) for b in spec.by):
                                [(round((float(t) * 10**9 - spec.first_ns) / spec.step_ns), int(v)) for t, v in r["values"]] for r in res}
    rnd = random.Random(7)
    for _ in range(40):
        step_ns = rnd.choice([1, 7, 60]) * s1
        rs = CountSpec(("host", "severity"), "{}", rnd.choice([[], [("|=", "R")], [("!=", "R")]]), 1000 * s1, step_ns,
                       rnd.randint(1, 30) * step_ns // rnd.choice([1, 2, 3]) + rnd.randint(0, 3), rnd.randint(1, 40))
        span = rs.evals * step_ns + rs.range_ns
        ents = [({"host": rnd.choice("ab"), "severity": rnd.choice(["info", "notice"])}, 1000 * s1 - rs.range_ns + rnd.randint(-s1, span + s1),
                 rnd.choice(["R x", "T y"])) for _ in range(rnd.randint(0, 60))]
        ents += [(ents[0][0], 1000 * s1 + rnd.randint(0, rs.evals) * step_ns, "R edge")] if ents else []  # exact eval-point hits
        assert as_idx(rs, count_buckets(rs, ents)[0]) == naive(rs, ents), rs
    heavy = CountSpec(("severity",), "{}", [("|=", "R")], 0, s1, 1440 * s1, 11000)  # Codex case: 1440 s range, 1 s step
    lines = [({"severity": "info"}, rnd.randint(0, 11000 * s1), "R") for _ in range(100000)]
    t0 = time.monotonic()
    res, done = count_buckets(heavy, lines)  # no deadline: the image is also built on slow hardware / under emulation
    took = time.monotonic() - t0
    assert done
    print(f"count_buckets: 100k lines x 11000 points, 1440 s range / 1 s step: {took:.2f}s")
    if os.environ.get("OBS_SELFTEST_PERF") == "1":  # absolute bound only where the hardware is known (local / CI runs)
        assert took < 1.0, took
    assert sum(int(v) for r in res for _, v in r["values"]) > 100000 * 1000  # each line counted in many windows, at O(1) each
    # complexity guard on any hardware: a line's cost must not grow with the number of windows covering it
    # (a per-window loop would make the 1440-step range ~1440x slower than the 1-step one; the difference array ~1x)
    few = lines[:20000]

    def timed(spec):  # best of 3
        best = float("inf")
        for _ in range(3):
            t = time.monotonic()
            count_buckets(spec, few)
            best = min(best, time.monotonic() - t)
        return best
    ratio = timed(heavy) / max(timed(heavy._replace(range_ns=s1)), 1e-6)
    print(f"count_buckets: 1440-step range / 1-step range time ratio {ratio:.1f} (bound 20)")
    assert ratio < 20, ratio
    res, done = count_buckets(heavy, lines, time.monotonic() - 1)  # deadline already past: stops, reports partial
    assert not done and res == []

    # run_count paging against a fake Loki (backward pages of [start, end), newest first)
    def fake_loki(lines, delay=0.0, calls=None, sloppy=0):
        def page(selector, start, end, limit, timeout, direction="backward"):
            if calls is not None:
                calls.append(timeout)
            if delay > timeout:
                time.sleep(timeout)
                raise TimeoutError
            time.sleep(delay)
            back = direction == "backward"
            got = sorted((e for e in lines if start <= e[1] < end), key=lambda e: -e[1] if back else e[1])
            if sloppy and len(got) > limit:  # like real Loki: a full page that skips lines just inside its edge
                cut = got[limit - 1][1]
                got = [e for e in got if not (cut - sloppy < e[1] <= cut if back else cut <= e[1] < cut + sloppy)]
            return got[:limit]
        return page
    one = CountSpec(("severity",), "{}", [("|=", "R")], 10 * s1, 10 * s1, 10 * s1, 1)  # single window (0, 10 s]
    sev = {"severity": "info"}
    run = lambda lines, **kw: json.loads(run_count(one, fake_loki(lines, **{k: v for k, v in kw.items() if k in ("delay", "calls", "sloppy")}),
                                                   **{"overlap_ns": 0, **{k: v for k, v in kw.items() if k in ("page_size", "budget_s", "overlap_ns")}})[1])["data"]
    total = lambda d: sum(int(v) for r in d["result"] for _, v in r["values"])
    four = [(sev, 5 * s1, "R a"), (sev, 4 * s1, "R b"), (sev, 4 * s1, "R c"), (sev, 2 * s1, "R d")]  # Codex case: 2 share the edge
    d = run(four, page_size=3)  # page edge on the ts=4 instant: re-fetched inclusively, deduped, no warning
    assert total(d) == 4 and "warnings" not in d, d
    d = run(four, page_size=2)  # page 1 ends inside the instant (old code counted 3); page 2 is all ts=4 -> conservative warning
    assert total(d) == 4 and "one timestamp" in d["warnings"][0], d
    same = [(sev, 4 * s1, f"R {i}") for i in range(5)]  # more lines in one instant than a page holds
    d = run(same, page_size=2)
    assert 2 <= total(d) <= 5 and "one timestamp" in d["warnings"][0], d
    masked_dupes = [(sev, 6 * s1, "R a"), (sev, 5 * s1, "R b"), (sev, 4 * s1, "R 10.0.0.1"), (sev, 4 * s1, "R 10.0.0.2"),
                    (sev, 3 * s1, "R z")]  # the ts=4 pair is identical after masking: dedupe must use the raw line
    d = run(masked_dupes, page_size=3)
    assert total(d) == 5 and "warnings" not in d, d
    burst = [(sev, 9 * s1 - i * 1000, f"R {i}") for i in range(400)]  # 1 us apart; a page of 50 spans 50 us
    assert total(run(burst, page_size=50, sloppy=3000)) < 400  # without overlap, a sloppy page edge loses lines
    d = run(burst, page_size=50, sloppy=3000, overlap_ns=10000)  # overlap (10 us) > skipped span, < page span
    assert total(d) == 400 and "warnings" not in d, d
    d = run(four, page_size=2, overlap_ns=10**9)  # overlap larger than the data: tight retry, then step past
    assert total(d) == 4, d
    # run_log: keep scanning until `limit` filtered lines, in either direction, across sloppy page edges
    logs = [({"host": "h"}, 100 * s1 + i * 1000, ("Rejected 203.0.113.7" if i % 13 == 0 else "STA x")) for i in range(500)]
    truth = sorted((ts for _, ts, l in logs if "Rejected" in l))
    def run_l(direction, limit, **kw):
        spec = LogSpec("{}", [("|=", "Rejected")], limit, direction, 100 * s1, 101 * s1)
        page = fake_loki(logs, **{k: v for k, v in kw.items() if k in ("delay", "sloppy")})
        return json.loads(run_log(spec, page, **{k: v for k, v in kw.items() if k in ("page_size", "budget_s", "overlap_ns")})[1])["data"]
    got_ts = lambda d: [int(v[0]) for r in d["result"] for v in r["values"]]
    for direction in ("backward", "forward"):
        want = truth[::-1] if direction == "backward" else truth
        for limit in (5, 39, 1000):
            d = run_l(direction, limit, page_size=20, sloppy=3000, overlap_ns=10000)
            assert got_ts(d) == want[:limit] and "warnings" not in d, (direction, limit, d)
    d = run_l("backward", 5, page_size=20)
    assert all(v[1] == "Rejected 203.0.113.x" for r in d["result"] for v in r["values"])  # masked before filtering and returned
    d = run_l("backward", 1000, page_size=20, delay=0.05, budget_s=0.12, overlap_ns=0)  # budget ends mid-window: partial
    assert "partial result" in d["warnings"][0] and len(got_ts(d)) < len(truth), d
    rest = LogSpec("{}", [("|=", "Rejected")], 1000, "backward", 100 * s1, int(d["scanned_until"]))
    more = got_ts(json.loads(run_log(rest, fake_loki(logs), page_size=20, overlap_ns=0)[1])["data"])
    assert sorted(set(got_ts(d)) | set(more)) == truth  # continuing from scanned_until completes the window

    # window bounds: a page narrower than the 1 s overlap must not pull lines from outside [start, end)
    for direction in ("backward", "forward"):
        near = 100 * s1 + (900 * 10**6 if direction == "backward" else 0)  # dense burst at the edge being paged from
        win = [({"host": "h"}, near + i * 1000, "STA burst") for i in range(50)]
        win += [({"host": "h"}, 100 * s1 + 500 * 10**6, "Rejected inside")]
        win += [({"host": "h"}, 101 * s1 + 200 * 10**6, "Rejected after end"), ({"host": "h"}, 100 * s1 - 300 * 10**6, "Rejected before start")]
        spec = LogSpec("{}", [("|=", "Rejected")], 10, direction, 100 * s1, 101 * s1)
        for leaky in (False, True):  # leaky: an upstream that also returns lines outside the requested bounds
            honest = fake_loki(win)
            src = (lambda *a, h=honest: h(*a) + win[-2:]) if leaky else honest  # win[-2:] lie outside the window
            d = json.loads(run_log(spec, src, page_size=20)[1])["data"]
            assert [v[1] for r in d["result"] for v in r["values"]] == ["Rejected inside"], (direction, leaky, d)
    # limit reached on a page that omitted a line near its edge (Codex: matches at 9 and 6, 7 omitted):
    # keep scanning until the overlap has re-covered the cutoff, then pick the true first `limit`
    for direction, kinds in (("backward", {9: "R", 8: "S", 7: "R", 6: "R", 5: "S", 4: "S", 3: "S", 2: "S", 1: "S"}),
                             ("forward", {1: "R", 2: "S", 3: "R", 4: "R", 5: "S", 6: "S", 7: "S", 8: "S", 9: "S"})):
        lines9 = [({"host": "h"}, t * s1, f"{k} {t}") for t, k in kinds.items()]
        spec = LogSpec("{}", [("|=", "R")], 2, direction, 0, 10 * s1)
        d = json.loads(run_log(spec, fake_loki(lines9, sloppy=s1), page_size=3, overlap_ns=2 * s1)[1])["data"]
        want = [9 * s1, 7 * s1] if direction == "backward" else [1 * s1, 3 * s1]
        assert got_ts(d) == want and "warnings" not in d, (direction, d)

    # line cap hit mid-scan: continuing from scanned_until repeats nothing and covers the window
    global SCAN_MAX_LINES
    cap_was, SCAN_MAX_LINES = SCAN_MAX_LINES, 50
    try:
        for direction in ("backward", "forward"):
            lo, hi, out, calls_n = 100 * s1, 101 * s1, [], 0
            while True:
                calls_n += 1
                d = json.loads(run_log(LogSpec("{}", [("|=", "Rejected")], 1000, direction, lo, hi), fake_loki(logs), page_size=20)[1])["data"]
                out += got_ts(d)
                if "scanned_until" not in d:
                    break
                assert "line cap" in d["warnings"][0], d
                if direction == "backward":
                    hi = int(d["scanned_until"])
                else:
                    lo = int(d["scanned_until"]) + 1
            assert calls_n > 2 and len(out) == len(set(out)) and sorted(out) == truth, (direction, calls_n, len(out), len(set(out)))
        dense = [(sev, 5 * s1 + i * 1000, "R") for i in range(500)]  # 1 us apart: every 1 s overlap re-reads lines
        raw_read = []
        base = fake_loki(dense)
        spy = lambda *a: raw_read.append(len(p := base(*a))) or p
        d = json.loads(run_count(one, spy, page_size=20)[1])["data"]
        assert sum(raw_read) <= 50 + 20 and "line cap" in d["warnings"][0], (raw_read, d)  # cap counts raw lines read
    finally:
        SCAN_MAX_LINES = cap_was

    # an instant larger than a page hides a match, later matches still fill the limit: the gap must be reported
    same = [({"host": "h"}, 100 * s1 + 900 * 10**6, l) for l in ("STA a", "STA b", "STA c", "STA d", "Rejected same instant")]
    same += [({"host": "h"}, 100 * s1 + k * 10**8, "Rejected older") for k in (5, 4, 3)]
    d = json.loads(run_log(LogSpec("{}", [("|=", "Rejected")], 3, "backward", 100 * s1, 101 * s1), fake_loki(same), page_size=3, overlap_ns=0)[1])["data"]
    assert len(got_ts(d)) == 3 and "possible gaps" in d["warnings"][0] and "one timestamp" in d["warnings"][0], d
    cs = CountSpec(("severity",), "{}", [("|=", "Rejected")], 101 * s1, s1, 2 * s1, 1)
    d = json.loads(run_count(cs, fake_loki([({"severity": "info"}, ts, l) for _, ts, l in same]), page_size=3, overlap_ns=0)[1])["data"]
    assert "one timestamp" in d["warnings"][0], d
    leak_count = lambda sel, st, en, lim, to, dr="backward": [(sev, 5 * s1, "R in"), (sev, 30 * s1, "R out"), (sev, -5 * s1, "R out")]
    assert total(json.loads(run_count(one, leak_count, page_size=10)[1])["data"]) == 1

    calls = []  # slow upstream: per-page timeout is cut to the remaining budget, result is partial
    d = run([(sev, (9 - i) * s1, f"R {i}") for i in range(9)], page_size=2, delay=0.15, budget_s=0.4, calls=calls)
    assert all(t <= 0.4 for t in calls) and "time budget" in d["warnings"][0] and 2 <= total(d) < 9, (calls, d)
    try:  # nothing fetched within the budget: surfaces as a timeout (504), never past the budget
        t0 = time.monotonic()
        run(four, delay=5, budget_s=0.3)
        raise AssertionError("expected timeout")
    except TimeoutError:
        assert time.monotonic() - t0 < 1

    assert plan(lq('{job="syslog"}', "&limit=40&direction=sideways"))[2][0] == 400
    assert plan(lq('{job="syslog"}', "&limit=40&foo=1"))[2][0] == 400

    # line filters run on masked text: a hidden octet can never match
    streams = {"status": "success", "data": {"resultType": "streams", "stats": {"x": 1}, "result": [
        {"stream": {"host": "a"}, "values": [["3", "TCP 192.168.100.x:4 > 192.0.2.x:443"], ["1", "Rejected 203.0.113.x:23"]]},
        {"stream": {"host": "b"}, "values": [["2", "Rejected 198.51.100.x:23"]]}]}}
    f = lambda flt, lim=10, d="backward": [v[1] for s in apply_line_filters(streams, flt, lim, d)["data"]["result"] for v in s["values"]]
    assert f([("|=", "192.0.2.x"), ("|=", "10:443")]) == []
    assert f([("|=", "Rejected")], 1) == ["Rejected 198.51.100.x:23"]
    assert f([("|=", "Rejected")], 1, "forward") == ["Rejected 203.0.113.x:23"]
    assert f([("!=", "Rejected")]) == ["TCP 192.168.100.x:4 > 192.0.2.x:443"]
    assert "stats" not in apply_line_filters(streams, [], 10, "backward")["data"]

    # Prometheus: UI queries pass, tokens resolve, plain masks become prefix regexes
    assert plan(pq("up"))[0] == PROM + "/api/v1/query?query=up"
    assert plan("/prom/api/v1/alerts")[0] == PROM + "/api/v1/alerts"
    assert plan("/prom/api/v1/alerts?x=1")[2][0] == 400
    assert plan("/prom/api/v1/query_range?query=up&start=1761300000.123&end=1761303600.5&step=15")[0]
    assert plan("/prom/api/v1/query?query=up&time=" + q("10.0.0.1"))[2][0] == 400
    assert plan("/prom/api/v1/query?query=up&foo=bar")[2][0] == 400
    ui = '(sum by (instance) (rate(ifHCInOctets{job="snmp",instance="rtx1300",ifName="lan2"}[1m])) * 8 / 1e6) and on (instance) (up{job="snmp"} == 1)'
    assert plan(pq(ui))[0].endswith(ui)
    assert plan(pq("topk(3, demo_flow_bytes_total) > 1e9"))[0]  # ranking/comparison only see numbers; labels come back masked
    assert plan(pq('rate(x{dst_ip="%s"}[5m])' % tok))[0].endswith('rate(x{dst_ip="203.0.113.50"}[5m])')  # token round trip
    assert plan(pq('sum(rate(x{dst_ip="203.0.113.x"}[5m]))'))[0].endswith('sum(rate(x{dst_ip=~"203[.]0[.]113[.][0-9]{1,3}"}[5m]))')
    assert plan(pq('x{dst_ip!="203.0.113.x"}'))[0].endswith('x{dst_ip!~"203[.]0[.]113[.][0-9]{1,3}"}')

    for path in ("/prom/api/v1/status/config", "/prom/api/v1/query/../admin/tsdb/snapshot", "/loki/loki/api/v1/push", "/loki/loki/api/v1/query"):
        assert plan(path)[2][0] == 403, path
    assert route("POST", pq("up"))[2][0] == 405
    assert request_role({}) == request_role({"X-Obs-Role": "admin"}) == request_role({"X-Obs-Role": " Viewer "}) == "viewer"
    am_selftest(tok)
    print(f"selftest ok ({len(LOKI_PROBES) + len(PROM_PROBES) + 2} adversarial probes rejected)")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        # The UI fires ~50 queries per refresh at once; the stdlib default backlog (5) drops SYNs,
        # which nginx reports as connect timeouts (504).
        ThreadingHTTPServer.request_queue_size = 256
        ThreadingHTTPServer.daemon_threads = True
        ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
