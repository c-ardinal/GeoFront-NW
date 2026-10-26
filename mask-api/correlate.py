"""原因候補 (P5): GET /correlate/events -> what else happened around a moment, ordered by simple, stated rules.

These are correlation CANDIDATES (same time, same device / interface / destination / host), never causes: the screen
always says so, and the rules are returned with the answer so the screen can show them.

Request: at (unix s, the moment: an alert's activation, a surge, a chosen time), from / to (the window, at most
MAX_SPAN_S, not in the future), and the context of the moment (each optional): instance, ifName, host (src_host),
cc, asn, alertname; wan_instance / wan_ifName (the inventory's WAN interface: a surge passes it).

Events in the window, all read through mask-api's own read paths (allowlists, masking; the same answers the screens
get, address tokens included):
  alert    ALERTS{alertstate="firing"}: fired / resolved (Prometheus range query)
  device   up{job="snmp"} changes (DOWN / UP)
  ifstate  ifOperStatus changes (link down / up)
  iferr    interface errors increasing (2 min increase > 0)
  surge    obs_surge:flow_bps:ratio spans (traffic surge detection)
  syslog   lines of severity warning or worse (Loki, one query per severity, newest first, capped)
  notify   notify-relay's records ({job="notify"})
Ordering (order()): relatedness score high -> low (RULES), then time. Bounded: window, points per series, lines per
query, items returned, one time budget; a source that fails or runs out of time is named in data.partial.
"""
import json
import threading
import time
import urllib.parse

M = None  # mask_api: read paths, literal checks

MAX_SPAN_S = 2 * 3600 + 120  # +-60 min around the moment (and a little slack)
STEP_S = 30  # the scrape / evaluation interval
MAX_ITEMS = 300
LINES_PER_SEV = 60
NOTIFY_LINES = 200
BUDGET_S = 10
SEV_BAD = ("emergency", "alert", "critical", "error", "warning")
CTX = ("instance", "ifName", "host", "cc", "asn", "alertname", "wan_instance", "wan_ifName")
PARAMS = {"at", "from", "to", *CTX}
SLOTS = threading.BoundedSemaphore(2)  # two windows at a time; more -> 429

# (score, reason): shown on the screen as the ordering rules
RULES = [
    (3, "同じ IF", "同じ機器の同じインターフェース (急増は WAN の IF を通る通信として WAN の IF と同じとみなす)"),
    (3, "同じ通信先", "同じ通信先 (ASN、無ければ国)"),
    (2, "同じ機器", "同じ機器 (instance / syslog の host)"),
    (2, "同じ端末", "同じ送信元の端末 (src_host)"),
    (0, "同時期", "上のどれにも当たらない: 時間が近いだけ"),
]
RULE_TEXT = [f"関連度 {s}: {name} — {desc}" for s, name, desc in RULES] + [
    "並べ順: 関連度の高い順、同じ関連度の中は時刻の早い順 (画面で時刻順にも切り替えられます)",
    "相関の候補であり、原因と断定するものではありません"]


class Refused(ValueError):
    pass


def setup(mask_module):
    global M
    M = mask_module


# ---- pure logic (selftest) ---------------------------------------------------------------------------------------

def spans(values, step, t0, t1):
    """[(t, v)] (sorted, a range query's evaluation points) -> [(start, end, before, ongoing)]: runs of consecutive
    evaluation points; one missing point ends a run (resolved, then maybe fired again). before: already active at the
    window start; ongoing: present at the window's last evaluation point (less than one step before its end)."""
    out, start, prev = [], None, None
    for t, _ in values:
        if start is None:
            start = t
        elif t - prev > 1.5 * step:
            out.append((start, prev))
            start = t
        prev = t
    if start is not None:
        out.append((start, prev))
    return [(a, b, a - t0 < step, t1 - b < step) for a, b in out]


def changes(values):
    """[(t, v)] -> [(t, old, new)] where the value changed between neighbouring samples."""
    return [(t, a, b) for (_, a), (t, b) in zip(values, values[1:]) if a != b]


def relate(item, ctx):
    """-> (score, reasons) of an item against the moment's context (RULES)."""
    why = []
    inst, ifn = item.get("instance"), item.get("ifName")
    wan = (ctx.get("wan_instance"), ctx.get("wan_ifName")) if ctx.get("wan_instance") and ctx.get("wan_ifName") else None
    here = (ctx.get("instance"), ctx.get("ifName")) if ctx.get("instance") and ctx.get("ifName") else None
    if here and (inst, ifn) == here:
        why.append((3, "同じ IF"))
    elif wan and (item["kind"] == "surge" and here == wan or ctx.get("host") and (inst, ifn) == wan):
        why.append((3, "同じ IF (WAN 経由)"))
    if (ctx.get("asn") and item.get("asn") == ctx["asn"]) or (not ctx.get("asn") and ctx.get("cc") and item.get("cc") == ctx["cc"]):
        why.append((3, "同じ通信先"))
    if ctx.get("instance") and inst == ctx["instance"] and not (here and (inst, ifn) == here):
        why.append((2, "同じ機器"))
    if ctx.get("host") and item.get("host") == ctx["host"]:
        why.append((2, "同じ端末"))
    if not why:
        return 0, ["同時期"]
    return max(s for s, _ in why), [r for _, r in why]


def order(items):
    """Relatedness high -> low, then time (then kind / title, so the order is stable)."""
    return sorted(items, key=lambda i: (-i["score"], i["t"], i["kind"], i["title"]))


def series_events(kind, result, t0, t1, step):
    """Prometheus matrix -> events of one kind."""
    out = []
    for r in result:
        m, vals = r["metric"], [(float(t), v) for t, v in r["values"]]
        base = {k: m[k] for k in ("instance", "ifName") if m.get(k)}
        if kind == "alert":
            labels = {k: v for k, v in m.items() if k not in ("__name__", "alertstate")}
            name = " ".join(x for x in (labels.get("alertname"), labels.get("instance"), labels.get("ifName")) if x)
            for a, b, before, ongoing in spans(vals, step, t0, t1):
                ev = {**base, "kind": "alert", "labels": labels, "severity": labels.get("severity", ""), "alertname": labels.get("alertname", "")}
                out.append({**ev, "t": a, "state": "firing", "before": before, "title": f"{name} 発火" + (" (窓の開始前から)" if before else "")})
                if not ongoing:
                    out.append({**ev, "t": b + step, "state": "resolved", "title": f"{name} 解消"})
        elif kind in ("device", "ifstate"):
            word = {"device": {1: "UP", 0: "DOWN"}, "ifstate": {1: "link UP", 2: "link DOWN"}}[kind]
            what = m.get("instance", "?") + (f" {m['ifName']}" if kind == "ifstate" else "")
            for t, a, b in changes(vals):
                new = word.get(int(float(b)), f"状態 {b}")
                out.append({**base, "kind": kind, "t": t, "state": new, "title": f"{what} {new}"})
        elif kind == "iferr":
            for a, b, before, _ in spans(vals, step, t0, t1):
                peak = max(float(v) for t, v in vals if a <= t <= b)
                out.append({**base, "kind": "iferr", "t": a, "before": before,
                            "title": f"{m.get('instance', '?')} {m.get('ifName', '')} エラー増加 (2 分で最大 {peak:.0f} 件)"})
        elif kind == "surge":
            for a, b, before, ongoing in spans(vals, step, t0, t1):
                peak = max(float(v) for t, v in vals if a <= t <= b)
                who = {k: m[k] for k in ("src_host", "dst_country", "asn") if m.get(k)}
                out.append({"kind": "surge", "t": a, "before": before, "ongoing": ongoing, "host": who.get("src_host", ""),
                            "cc": who.get("dst_country", ""), "asn": who.get("asn", ""),
                            "title": f"急増 {who.get('src_host', '?')} → {who.get('dst_country', '?')} {who.get('asn', '')} (平常の最大 {peak:.1f} 倍)".replace("  ", " ")})
    return out


def loki_events(kind, data):
    out = []
    for s in data["result"]:
        st = s["stream"]
        for ts, line in s["values"]:
            if kind == "syslog":
                out.append({"kind": "syslog", "t": int(ts) / 1e9, "ts": ts, "instance": st.get("host", "?"), "sev": st.get("severity", "?"), "title": line})
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict) or r.get("test"):
                continue
            labels = {k: str(r[k]) for k in ("alertname", "instance", "ifName", "severity") if r.get(k)}
            name = " ".join(x for x in (labels.get("alertname"), labels.get("instance"), labels.get("ifName")) if x)
            out.append({"kind": "notify", "t": int(ts) / 1e9, "labels": labels, **{k: labels[k] for k in ("instance", "ifName", "alertname") if k in labels},
                        "state": str(r.get("status", "")), "title": f"通知 {r.get('receiver', '?')} {r.get('result', '?')}: {name} ({r.get('status', '?')})"})
    return out


# ---- request -------------------------------------------------------------------------------------------------------

def _num(v, what):
    try:
        x = float(v)
    except ValueError:
        raise Refused(f"{what}: unix seconds") from None
    if x != x or x in (float("inf"), float("-inf")):
        raise Refused(f"{what}: unix seconds")
    return x


def parse(query, now):
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, max_num_fields=16)
    p = dict(pairs)
    if len(p) != len(pairs) or set(p) - PARAMS:
        raise Refused("parameters: at, from, to, " + ", ".join(CTX) + " (each once)")
    at, t0, t1 = (_num(p.get(k, ""), k) for k in ("at", "from", "to"))
    if not (0 < t1 - t0 <= MAX_SPAN_S and t0 <= at <= t1 and t1 <= now + 60):
        raise Refused("window: from <= at <= to, at most 2 h, not in the future")
    ctx = {}
    for k in CTX:
        v = p.get(k)
        if not v:
            continue
        if len(v) > 128 or any(ord(c) < 32 for c in v):
            raise Refused(f"{k}: 1 to 128 characters, one line")
        M.check_literal(v)  # no full / partial address; tokens must be ones the screens were given
        ctx[k] = v
    if min(t1, now) <= t0:  # the window starts after "now": nothing to read, and never a window that ends before it starts
        raise Refused("window: it starts in the future")
    return {"at": min(at, now), "from": t0, "to": min(t1, now), "ctx": ctx}


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def left(self):
        return self.deadline - time.monotonic()


def read(path, params, budget):
    left = budget.left()
    if left < 1:
        raise TimeoutError("time budget used up")
    url, post, err = M.route("GET", path + "?" + urllib.parse.urlencode(params))
    if err:
        raise RuntimeError(err[1])
    status, body, _ = M.fetch(url, post, timeout=max(1, min(M.TIMEOUT_S, left)))
    obj = json.loads(body)
    if status != 200 or obj.get("status") == "error":
        raise RuntimeError(f"HTTP {status}: {obj.get('error', '')}"[:200])
    return obj["data"]


PROM_SOURCES = [("alert", 'ALERTS{alertstate="firing"}'), ("device", 'up{job="snmp"}'), ("ifstate", 'ifOperStatus{job="snmp"}'),
                ("iferr", '(increase(ifInErrors{job="snmp"}[2m]) + increase(ifOutErrors{job="snmp"}[2m])) > 0'),
                ("surge", "obs_surge:flow_bps:ratio")]


def collect(req, read_fn=read):
    """-> (events, partial sources)."""
    t0, t1 = req["from"], req["to"]
    budget, events, partial = Budget(BUDGET_S), [], []
    step = max(STEP_S, -(-int(t1 - t0) // 240 // STEP_S) * STEP_S)
    start_ns, end_ns = str(int(t0 * 1e9)), str(int(t1 * 1e9))
    jobs = [(k, "/prom/api/v1/query_range", {"query": q, "start": f"{t0:.3f}", "end": f"{t1:.3f}", "step": str(step)}) for k, q in PROM_SOURCES]
    jobs += [("syslog", "/loki/loki/api/v1/query_range", {"query": f'{{job="syslog",severity="{s}"}}', "start": start_ns, "end": end_ns,
                                                         "limit": str(LINES_PER_SEV), "direction": "backward"}) for s in SEV_BAD]
    jobs.append(("notify", "/loki/loki/api/v1/query_range", {"query": '{job="notify"}', "start": start_ns, "end": end_ns, "limit": str(NOTIFY_LINES), "direction": "backward"}))
    for kind, path, params in jobs:
        try:
            data = read_fn(path, params, budget)
            events += series_events(kind, data["result"], t0, t1, step) if path.startswith("/prom/") else loki_events(kind, data)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as e:  # TimeoutError is an OSError
            partial.append(f"{kind}: {str(e)[:120]}")
    return [e for e in events if t0 - STEP_S <= e["t"] <= t1 + STEP_S], partial


def answer(req, read_fn=read):
    events, partial = collect(req, read_fn)
    for e in events:
        e["score"], e["why"] = relate(e, req["ctx"])
        e["dt"] = round(e["t"] - req["at"], 1)
    items = order(events)
    return {"window": {"from": req["from"], "to": req["to"], "at": req["at"]}, "context": req["ctx"], "rules": RULE_TEXT,
            "items": items[:MAX_ITEMS], "total": len(items), "truncated": len(items) > MAX_ITEMS, "partial": sorted(set(partial)),
            "notice": "相関の候補です (時間が近い・同じ機器などの規則で並べたもの)。原因と断定するものではありません。"}


def js(status, obj):
    return status, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), "application/json"


def handle(method, raw_path):
    if method not in ("GET", "HEAD"):
        return js(405, {"status": "error", "error": "read-only"})
    parts = urllib.parse.urlsplit(raw_path)
    if parts.path != "/correlate/events":
        return js(403, {"status": "error", "error": "forbidden"})
    try:
        req = parse(parts.query, time.time())
    except (Refused, M.Rejected) as e:
        return js(400, {"status": "error", "errorType": "rejected", "error": str(e)})
    if not SLOTS.acquire(blocking=False):
        return js(429, {"status": "error", "errorType": "busy", "error": "原因候補の問い合わせが混んでいます。少し待ってからもう一度"})
    try:
        return js(200, {"status": "success", "data": answer(req)})
    finally:
        SLOTS.release()


# ---- self-test (no services: reads are faked) -------------------------------------------------------------------

def selftest():
    # spans / changes
    v = [(0, "1"), (30, "1"), (60, "1"), (200, "1"), (230, "1")]
    assert spans(v, 30, 0, 250) == [(0, 60, True, False), (200, 230, False, True)], spans(v, 30, 0, 250)
    assert spans(v, 30, 0, 300)[1][3] is False  # last sample 70 s before the end: ended
    assert spans(v, 30, 0, 265)[1][3] is False  # absent at the last evaluation point (260): resolved in the final step
    assert spans([(0, "1"), (30, "1"), (90, "1")], 30, 0, 100) == [(0, 30, True, False), (90, 90, False, True)]  # one missing point: resolved, fired again
    assert changes([(0, "1"), (30, "1"), (60, "0"), (90, "1")]) == [(60, "1", "0"), (90, "0", "1")]
    # relatedness: an alert on rtx1300 lan2 (the WAN interface)
    ctx = {"instance": "rtx1300", "ifName": "lan2", "alertname": "WanHighUtilization", "wan_instance": "rtx1300", "wan_ifName": "lan2"}
    same_if = {"kind": "iferr", "instance": "rtx1300", "ifName": "lan2", "t": 50, "title": "a"}
    same_dev = {"kind": "syslog", "instance": "rtx1300", "t": 10, "title": "b"}
    surge = {"kind": "surge", "host": "pc-living", "cc": "US", "asn": "AS64502", "t": 40, "title": "c"}
    other = {"kind": "device", "instance": "wlx222", "t": 5, "title": "d"}
    assert relate(same_if, ctx) == (3, ["同じ IF"]) and relate(same_dev, ctx) == (2, ["同じ機器"])
    assert relate(surge, ctx) == (3, ["同じ IF (WAN 経由)"]) and relate(other, ctx) == (0, ["同時期"])
    # a surge as the moment: the same destination / host rank first, the WAN interface counts as passed
    sctx = {"host": "pc-living", "cc": "US", "asn": "AS64502", "wan_instance": "rtx1300", "wan_ifName": "lan2"}
    assert relate(surge, sctx) == (3, ["同じ通信先", "同じ端末"]) and relate(same_if, sctx) == (3, ["同じ IF (WAN 経由)"])
    assert relate({"kind": "surge", "host": "pc-x", "cc": "US", "asn": "AS1", "t": 0, "title": ""}, sctx) == (0, ["同時期"])  # same country, other ASN
    assert relate({"kind": "surge", "host": "pc-x", "cc": "US", "t": 0, "title": ""}, {"cc": "US"})[0] == 3  # no ASN in the context: country
    # ordering: score first, then time
    items = []
    for it in (other, same_dev, surge, same_if):
        s, why = relate(it, ctx)
        items.append({**it, "score": s, "why": why})
    assert [i["title"] for i in order(items)] == ["c", "a", "b", "d"], [i["title"] for i in order(items)]
    # events from faked reads: alert fired + resolved, a device DOWN, a surge still on, syslog, notify records
    now = 1_761_470_000.0
    t0, t1 = now - 1200, now

    def fake(path, params, budget):
        q = params["query"]
        if path.startswith("/prom/"):
            grid = [t0 + i * 30 for i in range(41)]
            if q.startswith("ALERTS"):
                return {"result": [{"metric": {"__name__": "ALERTS", "alertname": "DeviceDown", "instance": "wlx222", "severity": "critical", "alertstate": "firing"},
                                    "values": [[t, "1"] for t in grid[10:20]]}]}
            if q.startswith("up"):
                return {"result": [{"metric": {"instance": "wlx222", "job": "snmp"}, "values": [[t, "0" if 8 <= i < 18 else "1"] for i, t in enumerate(grid)]}]}
            if q.startswith("obs_surge"):
                return {"result": [{"metric": {"src_host": "pc-living", "dst_country": "US", "asn": "AS64502"}, "values": [[t, "6.5"] for t in grid[30:]]}]}
            return {"result": []}
        if "notify" in q:
            rec = {"alertname": "DeviceDown", "instance": "wlx222", "severity": "critical", "status": "firing", "receiver": "demo-sink", "result": "ok"}
            return {"result": [{"stream": {"job": "notify"}, "values": [[str(int((t0 + 320) * 1e9)), json.dumps(rec)], [str(int(t0 * 1e9)), "not json"]]}]}
        if 'severity="error"' in q:
            return {"result": [{"stream": {"host": "wlx222", "severity": "error"}, "values": [[str(int((t0 + 250) * 1e9)), "[WLAN] Radio 5GHz: TX failure"]]}]}
        raise TimeoutError("loki slow")
    req = {"at": t0 + 300, "from": t0, "to": t1, "ctx": {"instance": "wlx222", "alertname": "DeviceDown"}}
    out = answer(req, fake)
    kinds = [(i["kind"], i.get("state")) for i in out["items"]]
    assert ("alert", "firing") in kinds and ("alert", "resolved") in kinds and ("device", "DOWN") in kinds and ("device", "UP") in kinds, kinds
    assert ("surge", None) in kinds and ("notify", "firing") in kinds and ("syslog", None) in kinds, kinds
    assert all(i["score"] == 2 for i in out["items"] if i.get("instance") == "wlx222") and out["items"][-1]["kind"] == "surge"  # unrelated last
    assert [i["t"] for i in out["items"] if i["score"] == 2] == sorted(i["t"] for i in out["items"] if i["score"] == 2)
    assert any(p.startswith("syslog: loki slow") for p in out["partial"]) and "原因と断定" in out["notice"]
    # request checks
    good = f"at={now - 60}&from={now - 660}&to={now}"
    assert parse(good, now)["ctx"] == {}
    for bad in (f"at={now}&from={now - 9000}&to={now}", f"at={now + 30}&from={now + 20}&to={now + 50}", f"at={now - 100}&from={now - 60}&to={now - 120}", f"at={now - 900}&from={now - 600}&to={now}", f"at={now}&from={now - 60}&to={now + 3600}",
                good + "&x=1", good + "&instance=192.0.2.1", good + "&host=113.50", f"at=nan&from={now - 60}&to={now}", good + "&cc=a&cc=b"):
        try:
            parse(bad, now)
            raise AssertionError(bad)
        except (Refused, M.Rejected):
            pass
    assert handle("POST", "/correlate/events")[0] == 405 and handle("GET", "/correlate/other")[0] == 403
    assert handle("GET", "/correlate/events?at=1&from=0&to=2&instance=10.0.0.1")[0] == 400
    print(f"correlate selftest ok ({len(out['items'])} events ordered)")
