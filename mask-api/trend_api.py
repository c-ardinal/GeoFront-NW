"""推移 (F1): GET /trend/series -> one metric family over a time range, from server-side PromQL templates only.

The client names a family from FAMILIES and gives scope values (device / interface / destination) and a window; it
never sends PromQL. Each scope value is checked (character set, length, mask_api.check_literal: no full or partial
address, tokens must be ones the screens were given) and put into the template as a JSON string in an equality matcher.
The query then goes through mask_api's own Prometheus path (prom_query: the literal checks again + token -> address)
and comes back masked like every other answer.

Window: from < to (unix s), at most MAX_SPAN_S, not in the future; the step is chosen here so that a series has at
most MAX_POINTS points. Families with many keys (flows by country / ASN / host) keep the TOP_N largest series and sum
the rest into "その他".
GET /trend/families -> the allow-list (names, units, scopes) for the screen.
"""
import json
import math
import re
import time
import urllib.parse

M = None  # mask_api

MAX_POINTS = 600
MAX_SPAN_S = 31 * 86400  # the 30 d preset + slack
MIN_SPAN_S = 300
SCRAPE_S = 30
TOP_N = 8
VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@~+\-]{0,127}")  # inventory names, ifName, tokens (192.0.2.x~...), AS64500
CC_RE = re.compile(r"[A-Z]{2}|Unknown")
SNMP_UP = 'and on (instance) (up{job="snmp"} == 1)'
FLOWS_UP = 'and on () (up{job="flows"} == 1)'


class Refused(ValueError):
    pass


def setup(mask_module):
    global M
    M = mask_module


def lit(v):
    return json.dumps(v)


def sel(scope, keys, base='job="snmp"'):
    parts = [base] if base else []
    parts += [f"{k}={lit(scope[k])}" for k in keys if scope.get(k)]
    return "{" + ",".join(parts) + "}"


def if_pair(metric_in, metric_out, scale):
    """in / out of one interface (ifName given) or summed over a device's interfaces."""
    def build(scope, w):
        s = sel(scope, ("instance", "ifName"))
        if scope.get("ifName"):
            return [("in", "↓ in", f"(rate({metric_in}{s}[{w}]) * {scale}) {SNMP_UP}"),
                    ("out", "↑ out", f"(rate({metric_out}{s}[{w}]) * {scale}) {SNMP_UP}")]
        return [("in", "↓ in (合計)", f"(sum by (instance) (rate({metric_in}{s}[{w}])) * {scale}) {SNMP_UP}"),
                ("out", "↑ out (合計)", f"(sum by (instance) (rate({metric_out}{s}[{w}])) * {scale}) {SNMP_UP}")]
    return build


def per_device(expr):
    """one series per device (or the one device asked for); expr(selector) -> PromQL."""
    return lambda scope, w: [("instance", None, expr(sel(scope, ("instance",)), w))]


def wan_util(scope, w):
    s = sel(scope, ("instance", "ifName"))
    speed = f'(ifHighSpeed{s} * 1e6 > 0)'
    return [("in", "↓ in", f"(rate(ifHCInOctets{s}[{w}]) * 8 * 100 / on (instance, ifName) {speed}) {SNMP_UP}"),
            ("out", "↑ out", f"(rate(ifHCOutOctets{s}[{w}]) * 8 * 100 / on (instance, ifName) {speed}) {SNMP_UP}")]


def flows_by(label):
    def build(scope, w):
        s = sel(scope, ("dst_country", "asn", "src_host"), base="")
        return [(label, None, f"(sum by ({label}) (rate(obs_flow_bytes_total{s}[{w}])) * 8) {FLOWS_UP}")]
    return build


def capture_pps(scope, w):
    return [("rx", "受信 packets/s", f"sum(rate(obs_capture_packets_received_total[{w}]))"),
            ("drop", "NIC の取りこぼし packets/s", f"sum(rate(obs_capture_nic_rx_dropped_total[{w}]))")]


# name -> (title, unit, scope keys allowed, scope keys required, stacked, builder(scope, rate window) -> [(key, label, query)])
# key: a fixed series key, or the label whose values name the series (label None = the label's value)
FAMILIES = {
    "if_bps": ("IF の通信量", "bps", ("instance", "ifName"), ("instance",), False, if_pair("ifHCInOctets", "ifHCOutOctets", 8)),
    "if_errors": ("IF のエラー", "件/分", ("instance", "ifName"), ("instance",), False, if_pair("ifInErrors", "ifOutErrors", 60)),
    "if_drops": ("IF の破棄 (drop)", "件/分", ("instance", "ifName"), ("instance",), False, if_pair("ifInDiscards", "ifOutDiscards", 60)),
    "dev_up": ("機器の UP (1 = UP、0 = DOWN)", "", ("instance",), (), False, per_device(lambda s, w: f"up{s}")),
    "dev_uptime": ("機器の稼働時間", "日", ("instance",), (), False, per_device(lambda s, w: f"(sysUpTime{s} / 100 / 86400) {SNMP_UP}")),
    "wan_util": ("WAN の利用率", "%", ("instance", "ifName"), ("instance", "ifName"), False, wan_util),
    "flow_country": ("通信先の国ごとの量", "bps", ("dst_country", "asn", "src_host"), (), True, flows_by("dst_country")),
    "flow_asn": ("通信先の ASN ごとの量", "bps", ("dst_country", "asn", "src_host"), (), True, flows_by("asn")),
    "flow_host": ("LAN の端末ごとの量", "bps", ("dst_country", "asn", "src_host"), (), True, flows_by("src_host")),
    "wlan_clients": ("無線の端末数", "台", ("instance",), (), False,
                     lambda scope, w: [("instance", None, f"(sum by (instance) (demo_wlan_clients{sel(scope, ('instance',), base='')})) {SNMP_UP}")]),
    "capture_pps": ("パケット取込の量", "packets/s", (), (), False, capture_pps),
    "capture_ring": ("取込リングの使用率", "%", (), (), False,
                     lambda scope, w: [("ring", "リング使用率", "max(obs_capture_ring_bytes / obs_capture_ring_limit_bytes) * 100")]),
}
SCOPE_KEYS = ("instance", "ifName", "dst_country", "asn", "src_host")
PARAMS = {"family", "from", "to", *SCOPE_KEYS}


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
        raise Refused("parameters: family, from, to, " + ", ".join(SCOPE_KEYS) + " (each once)")
    fam = FAMILIES.get(p.get("family", ""))
    if not fam:
        raise Refused("family: one of " + ", ".join(FAMILIES))
    _, _, allowed, required, _, _ = fam
    scope = {}
    for k in SCOPE_KEYS:
        v = p.get(k, "")
        if not v:
            continue
        if k not in allowed:
            raise Refused(f"{k}: not a scope of {p['family']}")
        if not (CC_RE.fullmatch(v) if k == "dst_country" else VALUE_RE.fullmatch(v)):
            raise Refused(f"{k}: letters, digits and . _ : / @ ~ + - (1 to 128)")
        M.check_literal(v)
        scope[k] = v
    missing = [k for k in required if k not in scope]
    if missing:
        raise Refused(f"{p['family']} needs " + ", ".join(missing))
    t0, t1 = _num(p.get("from", ""), "from"), _num(p.get("to", ""), "to")
    t1 = min(t1, now)
    if not (MIN_SPAN_S <= t1 - t0 <= MAX_SPAN_S) or t0 <= 0:
        raise Refused("window: from < to, 5 min to 31 d, not in the future")
    return p["family"], scope, t0, t1


def step_for(span):
    """>= the scrape interval, a multiple of it, and at most MAX_POINTS evaluation points."""
    return max(SCRAPE_S, math.ceil(span / (MAX_POINTS - 1) / SCRAPE_S) * SCRAPE_S)


def queries(family, scope, span):
    step = step_for(span)
    w = f"{max(step + SCRAPE_S, 4 * SCRAPE_S)}s"  # windows overlap by one scrape: no increase falls between two points
    return step, w, FAMILIES[family][5](scope, w)


def read_range(q, t0, t1, step):
    """the masked Prometheus answer through mask_api's own path (literal checks, token -> address, masking)."""
    url = M.PROM + "/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": M.prom_query(q), "start": f"{t0:.3f}", "end": f"{t1:.3f}", "step": str(step)})
    status, body, _ = M.fetch(url)
    obj = json.loads(body)
    if status != 200 or obj.get("status") != "success":
        raise RuntimeError(f"HTTP {status}: {obj.get('error', '')}"[:200])
    return obj["data"]["result"]


def top(series, n=TOP_N):
    """keep the n largest series (by their sum); the rest summed into one "その他" series at the same times."""
    if len(series) <= n:
        return series, False
    ranked = sorted(series, key=lambda s: -sum(v for _, v in s["points"]))
    rest = {}
    for s in ranked[n:]:
        for t, v in s["points"]:
            rest[t] = rest.get(t, 0) + v
    return ranked[:n] + [{"key": "_other", "label": "その他", "points": sorted(rest.items())}], True


def answer(family, scope, t0, t1, read=read_range):
    title, unit, _, _, stacked, _ = FAMILIES[family]
    step, w, qs = queries(family, scope, t1 - t0)
    t0 = t1 - math.floor((t1 - t0) / step) * step  # the grid ends exactly at `to`: the newest values are always in it
    out = []
    for key, label, q in qs:
        for r in read(q, t0, t1, step):
            name = r["metric"].get(key, "") if label is None else label
            pts = [[float(t), float(v)] for t, v in r.get("values", []) if math.isfinite(float(v))]
            if label is None and not name:
                name = "Unknown" if key == "dst_country" else "—"
            out.append({"key": f"{key}={name}" if label is None else key, "label": name, "points": pts})
    out, folded = top(out) if stacked else (out[:TOP_N * 2], len(out) > TOP_N * 2)
    return {"family": family, "title": title, "unit": unit, "stacked": stacked, "scope": scope, "from": t0, "to": t1,
            "step": step, "rate_window": w, "series": out, "folded": folded}


def js(status, obj):
    return status, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), "application/json"


def families():
    return [{"family": k, "title": v[0], "unit": v[1], "scope": list(v[2]), "required": list(v[3]), "stacked": v[4]} for k, v in FAMILIES.items()]


def handle(method, raw_path):
    if method not in ("GET", "HEAD"):
        return js(405, {"status": "error", "error": "read-only"})
    parts = urllib.parse.urlsplit(raw_path)
    if parts.path == "/trend/families" and not parts.query:
        return js(200, {"status": "success", "data": {"families": families(), "max_points": MAX_POINTS, "max_span_s": MAX_SPAN_S}})
    if parts.path != "/trend/series":
        return js(403, {"status": "error", "error": "forbidden"})
    try:
        req = parse(parts.query, time.time())
    except (Refused, M.Rejected) as e:
        return js(400, {"status": "error", "errorType": "masked_query", "error": str(e)})
    try:
        return js(200, {"status": "success", "data": answer(*req)})
    except RuntimeError as e:
        return js(502, {"status": "error", "error": str(e)})


# ---- self-test (no services: reads are faked) -------------------------------------------------------------------

def selftest():
    now = 1_761_470_000.0
    good = f"family=if_bps&instance=rtx1300&ifName=lan2&from={now - 3600}&to={now}"
    fam, scope, t0, t1 = parse(good, now)
    assert fam == "if_bps" and scope == {"instance": "rtx1300", "ifName": "lan2"} and t1 - t0 == 3600
    # every template is valid for mask_api's own PromQL path, for the largest window too
    for f, (_, _, allowed, required, _, _) in FAMILIES.items():
        sc = {k: {"instance": "rtx1300", "ifName": "lan2", "dst_country": "JP", "asn": "AS64500", "src_host": "pc-living"}[k] for k in allowed}
        for span in (3600, MAX_SPAN_S):
            step, _, qs = queries(f, sc, span)
            assert span / step + 1 <= MAX_POINTS, (f, span, step)
            for _, _, q in qs:
                assert M.prom_query(q) == q, (f, q)  # nothing to rewrite, nothing rejected
    tok = M.mask_value("192.0.2.10")  # a device known by its address: the screens only have the token
    _, _, qs = queries("if_bps", {"instance": tok}, 3600)
    assert all('instance="192.0.2.10"' in M.prom_query(q) for _, _, q in qs)  # token -> the exact address upstream
    # refused: unknown family / parameters, injection through any scope value, raw or partial addresses, windows
    bad = [f"family=up&from={now - 3600}&to={now}", f"family=if_bps&from={now - 3600}&to={now}",  # instance required
           good + "&query=up", good + "&instance=x", f"family=capture_pps&instance=rtx1300&from={now - 3600}&to={now}",
           f"family=if_bps&instance={urllib.parse.quote('rtx1300\"}) or vector(1) #')}&from={now - 3600}&to={now}",
           f"family=if_bps&instance={urllib.parse.quote('rtx\"1300')}&from={now - 3600}&to={now}",
           f"family=if_bps&instance={urllib.parse.quote('a{b}')}&from={now - 3600}&to={now}",
           f"family=if_bps&instance={urllib.parse.quote('rtx1300 or up')}&from={now - 3600}&to={now}",
           f"family=if_bps&instance=192.0.2.10&from={now - 3600}&to={now}", f"family=if_bps&instance=113.50&from={now - 3600}&to={now}",
           f"family=if_bps&instance=192.0.2.x~000000000000&from={now - 3600}&to={now}",  # an unknown token
           f"family=flow_country&dst_country=jp&from={now - 3600}&to={now}", f"family=flow_country&dst_country=JP%22&from={now - 3600}&to={now}",
           f"family=flow_asn&src_host={urllib.parse.quote(chr(10) + 'x')}&from={now - 3600}&to={now}",
           f"family=dev_up&from={now - 60}&to={now}", f"family=dev_up&from={now - 40 * 86400}&to={now}", f"family=dev_up&from=nan&to={now}",
           f"family=dev_up&from={now}&to={now - 3600}", f"family=dev_up&from=0&to=600", f"family=dev_up&family=if_bps&from={now - 3600}&to={now}"]
    for b in bad:
        try:
            parse(b, now)
            raise AssertionError(b)
        except (Refused, M.Rejected):
            pass
    assert parse(f"family=dev_up&from={now - 3600}&to={now + 9999}", now)[3] == now  # the end is clipped to now
    # answers from faked reads: labels named by the family's key, the rest folded, non-finite values dropped
    def fake(q, a, b, step):
        if "obs_flow_bytes_total" in q:
            return [{"metric": {"dst_country": c}, "values": [[a, str(i + 1)], [a + step, str(i + 1)]]} for i, c in enumerate("ABCDEFGHIJ")]
        return [{"metric": {"instance": "rtx1300"}, "values": [[a, "1"], [a + step, "NaN"]]}]
    out = answer("flow_country", {}, now - 3600, now, fake)
    assert out["stacked"] and len(out["series"]) == TOP_N + 1 and out["series"][-1]["label"] == "その他" and out["folded"]
    assert out["series"][0]["label"] == "J" and out["series"][-1]["points"][0][1] == 3.0, out["series"]  # A + B folded
    out = answer("if_bps", {"instance": "rtx1300", "ifName": "lan2"}, now - 3600, now, fake)
    assert [s["label"] for s in out["series"]] == ["↓ in", "↑ out"] and out["series"][0]["points"] == [[now - 3600, 1.0]]
    assert handle("POST", "/trend/series")[0] == 405 and handle("GET", "/trend/other")[0] == 403
    assert handle("GET", "/trend/series?family=if_bps&instance=192.0.2.1&from=1&to=1000")[0] == 400
    assert json.loads(handle("GET", "/trend/families")[1])["data"]["families"][0]["family"] == "if_bps"
    print(f"trend selftest ok ({len(FAMILIES)} families, {len(bad)} refused requests)")
