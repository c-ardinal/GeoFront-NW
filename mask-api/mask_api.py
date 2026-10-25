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

Run: python mask_api.py            (listens on :8000)
     python mask_api.py --selftest
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROM = os.environ.get("PROM_URL", "http://prometheus:9090")
LOKI = os.environ.get("LOKI_URL", "http://loki:3100")
TIMEOUT_S = 12  # below nginx proxy_read_timeout (15 s) so the client gets our error, not nginx's
MAX_BYTES = 32 * 1024 * 1024
LOKI_MAX_LINES = 5000  # Loki's default max_entries_limit_per_query
OVERSCAN = 10  # with line filters, fetch limit*OVERSCAN lines (capped) and filter them here

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
                         r")\s*\[\s*(\d{1,6}[smh])\s*\]\s*\)\s*\)\s*")
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
        by, sel, rng = metric.groups()
        p["query"] = f"sum by ({by}) (count_over_time({loki_selector(sel)}[{rng}]))"
        return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(p), None
    log = LOKI_LOG.fullmatch(q)
    if not log:
        raise Rejected(REJECT_MSG)
    sel, rest = log.groups()
    filters = []
    for op, lit in re.findall(LOKI_FILTER, rest):
        body = literal_body(lit)
        check_literal(body)
        filters.append((op, body))
    limit = min(int(p.get("limit", "100")), LOKI_MAX_LINES)
    direction = p.get("direction", "backward")
    p["query"] = loki_selector(sel)
    p["limit"] = str(min(limit * OVERSCAN, LOKI_MAX_LINES) if filters else limit)
    return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(p), (filters, limit, direction)


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


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        t0 = time.monotonic()
        url, post, err = route(self.command, self.path)
        if err:
            status, body, ctype = err[0], error_body(*err), "application/json"
        else:
            try:
                status, body, ctype = fetch(url, post)
            except TimeoutError:
                status, body, ctype = 504, error_body(504, "upstream timeout"), "application/json"
            except (OSError, ValueError) as e:  # URLError, connection reset, bad/oversize JSON
                print(f"upstream error: {type(e).__name__}", file=sys.stderr)
                status, body, ctype = 502, error_body(502, "upstream unavailable"), "application/json"
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
    'sum by (severity) (count_over_time({job="syslog"} |= "x" [15m]))',
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
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"} |= `Rejected` != "SSID=home-main"'))
    assert 'query={job="syslog",host="rtx1300"}&' in url and "limit=2000" in url
    assert post == ([("|=", "Rejected"), ("!=", "SSID=home-main")], 200, "backward")
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"} |= "192.0.2.x" |= "10:443"'))  # Codex suffix probe: allowed, but
    assert post[0] == [("|=", "192.0.2.x"), ("|=", "10:443")] and "192" not in url.split("query=")[1].split("&")[0]  # filtered here
    url, post, _ = plan(lq('sum by (host, severity) (count_over_time({job="syslog"}[900s]))', "&start=1&end=2&step=60"))
    assert post is None and "count_over_time({job=\"syslog\"}[900s])" in url
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
