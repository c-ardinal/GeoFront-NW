"""Evidence export (FR-020): GET /evidence/export -> one zip of already-masked data for a time window and a scope.

Every byte in the zip comes through mask-api's own read paths (mask_api.route + fetch: the Prometheus / Loki allowlists
and masking, pcap_api for packet statistics), then once more through scrub() (address tokens removed, IPv4 / MAC /
IPv6 masked again), so an export can never hold more than the screens show. Never a raw pcap: packet data is only the
P3 statistics JSON of a chosen capture file. File names and manifest carry no address (the zip's name: scope kind
and time only).

Contents: manifest.json (window, scope, filters, sources and versions, this tool's commit (OBS_COMMIT, given at
build time), who and when, every file with its rows / bytes / sha256 / truncation), metrics/*.csv (Prometheus range
queries of the scope), alerts/ALERTS*.csv (+ rule.json for an alert), alerts/notifications.txt (notify-relay's
records, Loki {job="notify"}), logs/syslog.txt (Loki, masked lines), pcap/stats.json (optional), snapshot.png (optional).

Screen snapshot (P6): POST /evidence/export?<the same parameters> with a PNG body (Content-Type image/png) adds
snapshot.png, made in the operator's browser from the screen as shown (command-center js/snapshot.js). It is a write
like the silences: only while the screens are on 127.0.0.1 (or a trusted operator role), same origin + X-Obs-Csrf, the
export's own limits (one at a time, a few per minute); size and dimensions capped; only the PNG's image chunks are
kept (no text / time / EXIF metadata). The manifest records it as browser-generated, with its sha256.

Limits: window <= 7 d, points per series, rows per CSV, log lines, total bytes, one time budget; whatever is cut is
marked "truncated" in the manifest. One export at a time (429 while one runs), a few per minute (429).

GET /evidence/info: retention of Prometheus / Loki (the playback range), the limits and the commit.
"""
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import zipfile
import zlib
from datetime import datetime, timedelta, timezone

M = None  # mask_api (setup): read paths, masking, tokens, operator
P = None  # pcap_api: IPv6 masking

_REV = os.environ.get("OBS_COMMIT") or ""
# a git revision only (it is written into every manifest unmasked, like the digests); anything else is not trusted
COMMIT = _REV if re.fullmatch(r"[0-9a-f]{7,40}", _REV) else "unknown" if not _REV else "unknown (OBS_COMMIT is not a git revision)"
LOKI_RETENTION = os.environ.get("LOKI_RETENTION", "720h")
MAX_RANGE_S = 7 * 86400 + 3600  # the longest playback preset (7 d) plus slack
POINTS = 2000  # per series: the step grows with the window
MAX_ROWS = int(os.environ.get("EVIDENCE_MAX_ROWS", "50000"))  # per CSV
MAX_LINES = int(os.environ.get("EVIDENCE_MAX_LINES", "20000"))  # per log file
MAX_BYTES = int(os.environ.get("EVIDENCE_MAX_MB", "24")) * 2**20  # all files, uncompressed
BUDGET_S = int(os.environ.get("EVIDENCE_TIME_BUDGET", "60"))
PER_MIN = int(os.environ.get("EVIDENCE_PER_MIN", "6"))
PAGE = 5000  # Loki lines per page (its max_entries_limit_per_query)
SNAPSHOT_MAX = int(os.environ.get("EVIDENCE_SNAPSHOT_MAX_MB", "8")) * 2**20  # the PNG body (Caddyfile: request_body)
SNAPSHOT_MAX_SIDE = 8192  # px
UPLOAD_TIMEOUT_S = int(os.environ.get("EVIDENCE_UPLOAD_TIMEOUT", "30"))  # the whole PNG body, once the slot is taken
UPLOAD_CHUNK = 256 * 1024
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}  # the image itself; tEXt / iTXt / zTXt / tIME / eXIf / iCCP ... dropped
JST = timezone(timedelta(hours=9))
SCOPES = ("all", "device", "iface", "dest", "src", "alert")
LABEL_PARAMS = ("instance", "ifName", "cc", "city", "ip", "host", "alertname", "severity")
PARAMS = {"from", "to", "scope", "pcap", "pcap_filter", "max_rows", "max_lines", *LABEL_PARAMS}
NEEDS = {"device": ("instance",), "iface": ("instance", "ifName"), "src": ("host",), "alert": ("alertname",)}

LOCK = threading.Lock()  # concurrency 1
_recent, _recent_lock = [], threading.Lock()
_versions = {"at": 0, "v": None}


class Refused(ValueError):
    pass


def setup(mask_module, pcap_module):
    global M, P
    M, P = mask_module, pcap_module


# ---- masking of everything written --------------------------------------------------------------------------------

TOKEN = re.compile(r"~[0-9a-f]{12}(?![0-9a-f])")  # per-process opaque tokens: meaningless outside the screens


def scrub(s):
    """Text that goes into the zip: tokens dropped, then mask-api's masking once more (IPv4 / MAC / IPv6 incl. ports,
    zones, brackets, embedded IPv4, addresses glued to letters or Japanese), whatever the source already did."""
    return M.mask_text(TOKEN.sub("", s))


def scrub_obj(o):
    """scrub() on every string of a JSON-like value (keys too)."""
    if isinstance(o, str):
        return scrub(o)
    if isinstance(o, list):
        return [scrub_obj(x) for x in o]
    if isinstance(o, dict):
        return {scrub(k): scrub_obj(v) for k, v in o.items()}
    return o


def leaks(text):
    """Raw addresses left in a text (the export check): mask-api's leak detector - written independently of the
    masking and broader than it (any dotted quad, 3+ hex groups joined by : / -, hex words mixing letters and digits) -
    and tokens. A false positive fails the check; it is fixed in the masking, never by loosening the detector."""
    return M.leak_detector(text) + [m.group(0) for m in TOKEN.finditer(text)]


# ---- request checks -----------------------------------------------------------------------------------------------

def _num(v, what):
    try:
        x = float(v)
    except ValueError:
        raise Refused(f"{what}: unix seconds") from None
    if x != x or x in (float("inf"), float("-inf")):
        raise Refused(f"{what}: unix seconds")
    return x


def _int(v, what, cap):
    if not v.isdigit() or not 1 <= int(v) <= cap:
        raise Refused(f"{what}: 1 to {cap}")
    return int(v)


def parse(query, now):
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, max_num_fields=20)
    p = dict(pairs)
    if len(p) != len(pairs) or set(p) - PARAMS:
        raise Refused("parameters: from, to, scope, " + ", ".join(LABEL_PARAMS) + ", pcap, pcap_filter, max_rows, max_lines (each once)")
    t0, t1 = _num(p.get("from", ""), "from"), _num(p.get("to", ""), "to")
    if not 0 < t1 - t0 <= MAX_RANGE_S or t1 > now + 120:
        raise Refused("window: from < to, at most 7 days, not in the future")
    scope = p.get("scope", "all")
    if scope not in SCOPES:
        raise Refused("scope: " + " | ".join(SCOPES))
    labels = {}
    for k in LABEL_PARAMS:
        v = p.get(k)
        if v is None or v == "":
            continue
        if len(v) > 128 or any(ord(c) < 32 for c in v):
            raise Refused(f"{k}: 1 to 128 characters, one line")
        M.check_literal(v)  # no full / partial address; tokens must be ones the screens were given
        labels[k] = v
    if "ip" in labels:  # a destination as the screens have it: IPv4 with its token, or flowd's masked IPv6 forms
        v4 = M.MASKED_IPV4.fullmatch(labels["ip"])
        if not (v4 and v4.group(4) or M.MASKED_V6.fullmatch(labels["ip"])):
            raise Refused("ip: the masked address as the screens show it (a.b.c.x with its token, or <64 bits>::x)")
    for k in NEEDS.get(scope, ()):
        if k not in labels:
            raise Refused(f"scope {scope} needs {k}")
    if scope == "dest" and not ({"ip", "cc"} & set(labels)):
        raise Refused("scope dest needs cc (and city) or ip")
    pcap = p.get("pcap") or None
    flt = p.get("pcap_filter", "")
    if pcap and not P.FILE_ID.fullmatch(pcap):
        raise Refused("pcap: ring:<name> | upload:<name> | demo:<name>, as the file list gives it")
    if flt and not pcap:
        raise Refused("pcap_filter needs pcap")
    return {"from": t0, "to": t1, "scope": scope, "labels": labels, "pcap": pcap, "pcap_filter": flt,
            "max_rows": _int(p["max_rows"], "max_rows", MAX_ROWS) if "max_rows" in p else MAX_ROWS,
            "max_lines": _int(p["max_lines"], "max_lines", MAX_LINES) if "max_lines" in p else MAX_LINES}


# ---- what goes in: queries per scope ------------------------------------------------------------------------------

def step_for(secs):
    return max(15, -(-int(secs) // POINTS // 15) * 15)


def sel(**kv):
    return ",".join(f"{k}={json.dumps(v)}" for k, v in kv.items() if v)


def metric_queries(req, step):
    """[(file stem, PromQL)] for the scope; label values go in as matcher literals (mask-api's checks resolve tokens)."""
    w = f"{max(step + 15, 60)}s"
    L = req["labels"]
    scope = req["scope"]
    up = 'and on (instance) (up{job="snmp"} == 1)'
    out = []
    inst = L.get("instance")
    if scope == "all":
        out += [("targets_up", "up"),
                ("device_in_mbps", f'sum by (instance) (rate(ifHCInOctets{{job="snmp"}}[{w}])) * 8 / 1e6'),
                ("device_out_mbps", f'sum by (instance) (rate(ifHCOutOctets{{job="snmp"}}[{w}])) * 8 / 1e6'),
                ("interface_errors_per_min", f'sum by (instance, ifName) (rate(ifInErrors{{job="snmp"}}[{w}]) + rate(ifOutErrors{{job="snmp"}}[{w}])) * 60'),
                ("flows_by_country_mbps", f"sum by (dst_country, direction) (rate(obs_flow_bytes_total[{w}])) * 8 / 1e6")]
    if inst and scope in ("device", "iface", "alert"):
        s = sel(job="snmp", instance=inst, ifName=L.get("ifName") if scope != "device" else None)
        out += [("up", f"up{{{sel(instance=inst)}}}"),
                ("interface_in_mbps", f"(rate(ifHCInOctets{{{s}}}[{w}]) * 8 / 1e6) {up}"),
                ("interface_out_mbps", f"(rate(ifHCOutOctets{{{s}}}[{w}]) * 8 / 1e6) {up}"),
                ("interface_errors_per_min", f"((rate(ifInErrors{{{s}}}[{w}]) + rate(ifOutErrors{{{s}}}[{w}])) * 60) {up}"),
                ("interface_oper_status", f"ifOperStatus{{{s}}}"),
                ("interface_speed_mbps", f"ifHighSpeed{{{s}}}"),
                ("uptime_s", f"sysUpTime{{{sel(job='snmp', instance=inst)}}} / 100")]
    if scope == "dest":
        s = sel(dst_ip=L["ip"]) if "ip" in L else sel(dst_country=L.get("cc"), dst_city=L.get("city"))
        out.append(("flow_mbps_by_source", f"sum by (src_host, direction) (rate(obs_flow_bytes_total{{{s}}}[{w}])) * 8 / 1e6"))
    if scope == "src":
        out.append(("flow_mbps_by_destination", f"sum by (dst_country, dst_city, dst_ip, direction) (rate(obs_flow_bytes_total{{{sel(src_host=L['host'])}}}[{w}])) * 8 / 1e6"))
    return out


def alert_selector(req):
    L = req["labels"]
    if req["scope"] == "alert":
        s = sel(alertname=L["alertname"], instance=L.get("instance"), ifName=L.get("ifName"), severity=L.get("severity"))
    elif req["scope"] in ("device", "iface"):
        s = sel(instance=L["instance"])
    else:
        s = ""
    return s


def syslog_selector(req):
    host = req["labels"].get("instance") if req["scope"] in ("device", "iface", "alert") else None
    if req["scope"] == "all":
        return '{job="syslog"}'
    return f'{{job="syslog",host={json.dumps(host)}}}' if host else None


# ---- reading through mask-api ---------------------------------------------------------------------------------------

class Stop(Exception):
    """The time budget is used up: what is left is skipped (with this reason), the zip is still built."""


class Gone(Exception):
    """The client went away: the export is abandoned at once (and its slot freed)."""


class Budget:
    def __init__(self, seconds, gone=None):
        self.deadline, self.gone = time.monotonic() + seconds, gone or (lambda: False)

    def left(self):
        if self.gone():
            raise Gone("client disconnected")
        r = self.deadline - time.monotonic()
        if r <= 1:
            raise Stop("time budget used up")
        return r


def _get(path_query, timeout):
    """mask-api's own read path (allowlist, masking) for one URL -> (status, body)."""
    url, post, err = M.route("GET", path_query)
    if err:
        return err[0], M.error_body(*err)
    status, body, _ = M.fetch(url, post, timeout=timeout)
    return status, body


def _pcap_stats(fid, flt, timeout):
    """P3 statistics of one stored file (masked by pcap_api), the analyzer given at most `timeout` seconds. The same
    analysis already running for the screens would make this wait up to its own (longer) timeout: skipped instead."""
    ref, ident = P.file_ref(fid)
    real = P.check_filter(flt)
    with P.STATS.lock:
        busy = (ident, real) in P.STATS.flight and (ident, real) not in P.STATS.d
    if busy:
        raise P.Busy("the same packet analysis is running for the screens; export again when it is done")
    res, tokens = P.STATS.get((ident, real), lambda: P.with_tokens(lambda: P.mask_stats(P.analyzer({"op": "stats", "file": ref, "filter": real}, timeout=timeout))))
    P.reregister(tokens)
    return res


def read(path, params, budget):
    """One read through mask-api's own allowlist + masking -> decoded JSON (raises on refusal / failure)."""
    status, body = _get(path + "?" + urllib.parse.urlencode(params), max(1, min(M.TIMEOUT_S, budget.left())))
    obj = json.loads(body)
    if status != 200 or not isinstance(obj, dict) or obj.get("status") == "error" or "data" not in obj:
        raise RuntimeError(f"HTTP {status}: {obj.get('error') if isinstance(obj, dict) else ''}"[:300] or "answer without data")
    return obj


def jst(t):
    return datetime.fromtimestamp(t, JST).isoformat(timespec="seconds")


def matrix_csv(result, max_rows):
    """Prometheus matrix -> (csv text, rows written, rows available)."""
    keys = sorted({k for r in result for k in r["metric"]})
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["time_unix", "time_jst", *keys, "value"])
    n = total = 0
    for r in sorted(result, key=lambda r: [r["metric"].get(k, "") for k in keys]):
        for t, v in r["values"]:
            total += 1
            if n < max_rows:
                w.writerow([t, jst(float(t)), *[r["metric"].get(k, "") for k in keys], v])
                n += 1
    return buf.getvalue(), n, total


def loki_lines(selector, t0, t1, max_lines, budget):
    """All lines of a selector in [t0, t1], oldest first, through mask-api (masked) -> (entries, truncated, why)."""
    start, end = int(t0 * 1e9), int(t1 * 1e9)
    out, seen = [], set()
    while True:
        try:
            d = read("/loki/loki/api/v1/query_range", {"query": selector, "start": start, "end": end, "limit": PAGE, "direction": "forward"}, budget)["data"]
        except Stop as e:
            if not out:
                raise
            return out, True, str(e)
        page = sorted(((int(ts), s["stream"], line) for s in d["result"] for ts, line in s["values"]), key=lambda e: e[0])
        new = [e for e in page if (e[0], e[2], json.dumps(e[1], sort_keys=True)) not in seen]
        for e in new:
            if len(out) >= max_lines:
                return out, True, f"line cap ({max_lines})"
            out.append(e)
        if len(page) < PAGE:
            return out, False, None
        last = page[-1][0]
        # ponytail: the next page starts at the last instant (Loki's start is inclusive); lines of that instant already
        # taken are skipped by key. A full page of one single instant cannot advance: stop and say so.
        edge = {(e[0], e[2], json.dumps(e[1], sort_keys=True)) for e in page if e[0] == last}
        if last == start:
            return out, True, "a full page of lines sharing one timestamp"
        seen, start = edge, last


def versions(budget):
    if _versions["v"] and time.time() - _versions["at"] < 600:
        return _versions["v"]

    def get(url, key):
        try:
            with urllib.request.urlopen(url, timeout=max(0.5, min(3, budget.left() - 1))) as r:
                obj = json.loads(r.read(65536))
            v = (obj.get("data") or obj).get(key) if isinstance(obj, dict) else None
            return str(v) if v else None
        except (OSError, ValueError, Stop):
            return None
    v = {"prometheus": get(M.PROM + "/api/v1/status/buildinfo", "version") or "unknown",
         "loki": get(M.LOKI + "/loki/api/v1/status/buildinfo", "version") or "unknown",
         "observatory": COMMIT}
    _versions.update(at=time.time(), v=v)
    return v


DUR = re.compile(r"(\d+)(ms|y|w|d|h|m|s)")
DUR_S = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400, "y": 365 * 86400}


def duration_s(text):
    """"30d", "720h", "1w2d", "30d or 10GiB" -> seconds of the time part (None when there is none)."""
    head = (text or "").split(" ")[0]
    parts = DUR.findall(head)
    return sum(int(n) * DUR_S[u] for n, u in parts) if parts and "".join(n + u for n, u in parts) == head else None


def info():
    prom = None
    try:
        with urllib.request.urlopen(M.PROM + "/api/v1/status/runtimeinfo", timeout=3) as r:
            prom = duration_s(json.loads(r.read(65536))["data"].get("storageRetention"))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return {"retention_s": {"prometheus": prom, "loki": duration_s(LOKI_RETENTION)}, "commit": COMMIT,
            "limits": {"max_range_s": MAX_RANGE_S, "max_rows": MAX_ROWS, "max_lines": MAX_LINES, "max_bytes": MAX_BYTES,
                       "time_budget_s": BUDGET_S, "per_min": PER_MIN, "concurrency": 1}}


# ---- the zip --------------------------------------------------------------------------------------------------------

class Zip:
    def __init__(self):
        self.buf = io.BytesIO()
        self.z = zipfile.ZipFile(self.buf, "w", zipfile.ZIP_DEFLATED)
        self.files, self.bytes = [], 0

    def add(self, name, text, **meta):
        data = scrub(text).encode()
        room = MAX_BYTES - self.bytes
        if len(data) > room:
            if name.endswith(".json"):  # a cut JSON would not parse: left out, with the reason
                self.files.append({"name": name, "skipped": True, "reason": f"size cap (all files): {len(data)} bytes, {max(0, room)} left"})
                return
            data = data[:max(0, data.rfind(b"\n", 0, room) + 1)]  # cut at a line end: never half a line / CSV row
            meta = {**meta, "truncated": True, "truncated_by": "size cap (all files)"}
            if "rows" in meta:  # rows actually written
                meta["rows"] = max(0, data.count(b"\n") - (1 if name.endswith(".csv") else 0))
        self.z.writestr(name, data)
        self.bytes += len(data)
        self.files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), **meta})

    def add_binary(self, name, data, **meta):
        """A binary file made elsewhere (the snapshot PNG): stored as is, never cut. -> its sha256, or None (no room)."""
        room = MAX_BYTES - self.bytes
        if len(data) > room:
            self.files.append({"name": name, "skipped": True, "reason": f"size cap (all files): {len(data)} bytes, {max(0, room)} left"})
            return None
        self.z.writestr(name, data, compress_type=zipfile.ZIP_STORED)
        self.bytes += len(data)
        digest = hashlib.sha256(data).hexdigest()
        self.files.append({"name": name, "bytes": len(data), "sha256": digest, **meta})
        return digest

    def close(self, manifest):
        """Everything taken from the sources (scope, queries, reasons, notes) is masked; the digests this module computed
        are added afterwards, untouched (masking would read 64 hex characters as an address)."""
        digests = [f.pop("sha256", None) for f in manifest["files"]]
        snap = dict(manifest.get("snapshot") or {})
        snap_digest = snap.pop("sha256", None)
        manifest = {**manifest, "snapshot": snap}
        sources = dict(manifest["sources"])  # a copy: versions() hands out its cached dict
        rev = sources.pop("observatory", None)
        manifest = scrub_obj({**manifest, "sources": sources})
        manifest["sources"]["observatory"] = rev  # validated at start-up (COMMIT): a git revision or "unknown"
        for f, d in zip(manifest["files"], digests):
            if d:
                f["sha256"] = d
        if snap_digest:
            manifest["snapshot"]["sha256"] = snap_digest
        self.z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode())
        self.z.close()
        return self.buf.getvalue()


def notify_keep(req, wide=None):
    """Notification records of the scope: an alert -> its alertname (+ instance / ifName / severity when given); a
    device / interface -> its instance (+ ifName); other scopes -> all. Records are notify-relay's JSON lines.
    An address-valued label: notify-relay records it with mask-api's token (a.b.c.x~<token>, P6), matched exactly; a
    record without one (written before the relay had the key, or with an older key: mask-api drops tokens that do not
    check out) can only be matched by its a.b.c.x, so it is kept with the whole /24 and wide (a list) gets an entry."""
    L, scope = req["labels"], req["scope"]
    keys = {"alert": ("alertname", "instance", "ifName", "severity"), "device": ("instance",), "iface": ("instance", "ifName")}.get(scope)
    if not keys:
        return lambda e: True
    want = {k: (L[k], scrub(L[k])) for k in keys if L.get(k)}

    def keep(e):
        try:
            r = json.loads(e[2])
        except ValueError:
            return False
        if not isinstance(r, dict):
            return False
        loose = False
        for k, (exact, masked) in want.items():
            got = str(r.get(k, ""))
            if TOKEN.search(exact) and TOKEN.search(got):
                if got != exact:
                    return False
            elif scrub(got) != masked:
                return False
            elif TOKEN.search(exact):
                loose = True
        if loose and wide is not None:
            wide.append(1)
        return True
    return keep


def build(req, headers, now, gone=None, snap=None):
    budget = Budget(BUDGET_S, gone)
    t0, t1, secs = req["from"], req["to"], req["to"] - req["from"]
    step = step_for(secs)
    z, notes, wide = Zip(), [], []

    def skipped(name, why):
        z.files.append({"name": name, "skipped": True, "reason": why[:300]})

    def metrics(stem, q, folder="metrics"):
        name = f"{folder}/{stem}.csv"
        try:
            d = read("/prom/api/v1/query_range", {"query": q, "start": f"{t0:.3f}", "end": f"{t1:.3f}", "step": str(step)}, budget)["data"]
        except (RuntimeError, ValueError, OSError, Stop) as e:
            return skipped(name, str(e))
        text, n, total = matrix_csv(d["result"], req["max_rows"])
        z.add(name, text, source="prometheus", query=q, step_s=step, series=len(d["result"]), rows=n, rows_available=total,
              truncated=n < total, **({"truncated_by": f"row cap ({req['max_rows']})"} if n < total else {}))

    for stem, q in metric_queries(req, step):
        metrics(stem, q)
    a = alert_selector(req)
    metrics("ALERTS", f"ALERTS{{{a}}}" if a else "ALERTS", "alerts")
    metrics("ALERTS_FOR_STATE", f"ALERTS_FOR_STATE{{{a}}}" if a else "ALERTS_FOR_STATE", "alerts")
    if req["scope"] == "alert":
        try:
            rules = [r for g in read("/prom/api/v1/rules", {}, budget)["data"]["groups"] for r in g["rules"] if r.get("name") == req["labels"]["alertname"]]
            z.add("alerts/rule.json", json.dumps([{k: r.get(k) for k in ("name", "query", "duration", "labels", "annotations", "health")} for r in rules],
                                                 ensure_ascii=False, indent=2), source="prometheus /api/v1/rules", rules=len(rules))
        except (RuntimeError, ValueError, OSError, KeyError, Stop) as e:
            skipped("alerts/rule.json", str(e))

    def logs(name, selector, fmt, keep=lambda e: True):
        try:
            got, cut, why = loki_lines(selector, t0, t1, req["max_lines"], budget)
        except (RuntimeError, ValueError, OSError, Stop) as e:
            return skipped(name, str(e))
        rows = [fmt(e) for e in got if keep(e)]
        z.add(name, "".join(r + "\n" for r in rows), source="loki", query=selector, rows=len(rows), truncated=cut, **({"truncated_by": why} if cut else {}))

    sl = syslog_selector(req)
    if sl:
        logs("logs/syslog.txt", sl, lambda e: f"{jst(e[0] / 1e9)}\t{e[1].get('host', '?')}\t{e[1].get('severity', '?')}\t{e[2]}")
    else:
        notes.append("no syslog in this export: a destination / source host has no syslog stream of its own")
    logs("alerts/notifications.txt", '{job="notify"}', lambda e: f"{jst(e[0] / 1e9)}\t{e[2]}", keep=notify_keep(req, wide))
    if wide:
        notes.append(f"{len(wide)} notification record(s) name an address-valued device only as a.b.c.x (no address token: recorded "
                     "before notify-relay had mask-api's key, or with an older key): the records of every device in that /24 are included")
    if req["pcap"]:
        try:
            st = _pcap_stats(req["pcap"], req["pcap_filter"], budget.left() - 1)
            z.add("pcap/stats.json", json.dumps(st, ensure_ascii=False, indent=1), source="pcap analyzer statistics (masked; no packets)",
                  file_kind=req["pcap"].split(":")[0], filter=req["pcap_filter"])
        except (P.Refused, P.Busy, P.AnalyzerDown, ValueError, OSError, Stop) as e:
            skipped("pcap/stats.json", P.mask_message(str(e)))
    snapshot = snapshot_entry(z, snap)  # before "truncated": a snapshot left out under the size cap counts
    if snap is not None:
        snap["included"] = snapshot["included"]  # for the answer's X-Obs-Snapshot header
    manifest = {
        "format": "obs-evidence/1",
        "generated_at": jst(now), "generated_by": M.operator(headers),
        "window": {"from": jst(t0), "to": jst(t1), "from_unix": t0, "to_unix": t1, "seconds": secs, "step_s": step},
        "scope": {"kind": req["scope"], **req["labels"]},
        "filters": {"pcap_filter": req["pcap_filter"]} if req["pcap"] else {},
        "sources": versions(budget),
        "masking": ("label values: IPv4 a.b.c.x, IPv6 <first 64 bits>::x, MAC aa:bb:cc:xx:xx:xx; free text (logs, notes, queries): "
                    "only a standalone IPv4 (+ :port / .port) keeps a.b.c.x and a 6-pair MAC aa:bb:cc:xx:xx:xx, any other "
                    "address-like text becomes x; address tokens removed; no raw packets"),
        "limits": {"max_rows_per_csv": req["max_rows"], "max_log_lines": req["max_lines"], "max_bytes": MAX_BYTES, "time_budget_s": BUDGET_S},
        "truncated": any(f.get("truncated") or f.get("skipped") for f in z.files),
        "snapshot": snapshot,
        "files": z.files, "notes": notes,
    }
    return z.close(manifest)


def snapshot_entry(z, snap):
    """The snapshot PNG into the zip (last: the data files come first under the size cap) -> its manifest entry."""
    if snap is None:
        return {"included": False, "reason": "not requested"}
    digest = z.add_binary("snapshot.png", snap["data"], source="browser", width=snap["width"], height=snap["height"])
    if digest is None:
        return {"included": False, "reason": "size cap (all files)"}
    return {"included": True, "file": "snapshot.png", "generated_by": "browser", "sha256": digest, "bytes": len(snap["data"]),
            "width": snap["width"], "height": snap["height"],
            "note": ("made in the operator's browser from the screen as shown (already masked; there its text was masked once more and "
                     "address tokens removed); the server only checked that it is a PNG and kept its image chunks (no text / time / EXIF "
                     "metadata). It is a picture of the screen, not derived from the data files of this zip")}


def clean_png(data):
    """A PNG from the browser -> {"data": the PNG with only its image chunks, "width", "height"}; Refused otherwise."""
    if not data.startswith(PNG_SIG):
        raise Refused("snapshot: not a PNG")
    out, pos, size, idat = [PNG_SIG], len(PNG_SIG), None, False
    while pos + 12 <= len(data):
        n = int.from_bytes(data[pos:pos + 4], "big")
        kind, end = data[pos + 4:pos + 8], pos + 12 + n
        if end > len(data) or zlib.crc32(data[pos + 4:pos + 8 + n]) != int.from_bytes(data[pos + 8 + n:end], "big"):
            raise Refused("snapshot: damaged PNG")
        if size is None:
            if kind != b"IHDR" or n != 13:
                raise Refused("snapshot: damaged PNG")
            size = (int.from_bytes(data[pos + 8:pos + 12], "big"), int.from_bytes(data[pos + 12:pos + 16], "big"))
            if not all(0 < x <= SNAPSHOT_MAX_SIDE for x in size):
                raise Refused(f"snapshot: at most {SNAPSHOT_MAX_SIDE} x {SNAPSHOT_MAX_SIDE} px")
        idat = idat or kind == b"IDAT"
        if kind in PNG_KEEP:
            out.append(data[pos:end])
        pos = end
        if kind == b"IEND":
            break
    else:
        raise Refused("snapshot: damaged PNG")
    if not idat:
        raise Refused("snapshot: damaged PNG")
    return {"data": b"".join(out), "width": size[0], "height": size[1]}


def upload_length(headers):
    """Content-Length of the snapshot POST when it is within the cap, else None (checked before anything is read)."""
    length = headers.get("Content-Length") or ""
    if headers.get("Transfer-Encoding") or not length.isdigit() or not 0 < int(length) <= SNAPSHOT_MAX:
        return None
    return int(length)


def read_upload(n, read_body, deadline):
    """The PNG body in pieces, at most until deadline (monotonic): a slow or stalled upload cannot keep the export slot.
    -> bytes, or None when it was cut short or too slow (the connection is then closed after the answer)."""
    out, got = [], 0
    while got < n:
        if time.monotonic() > deadline:
            return None
        try:
            chunk = read_body(min(n - got, UPLOAD_CHUNK), deadline)  # one socket read, bounded by the time left
        except OSError:  # TimeoutError: no data for the idle time / the time left (mask_api.Handler)
            return None
        if not chunk:
            return None
        out.append(chunk)
        got += len(chunk)
    return b"".join(out) if time.monotonic() <= deadline else None


def read_snapshot(headers, data):
    if data is None:
        raise Refused(f"snapshot: 1 byte to {SNAPSHOT_MAX // 2**20} MiB, complete, within {UPLOAD_TIMEOUT_S} s")
    return clean_png(data)


def snapshot_refused(headers):
    """The write rules of the silences (mask_api.writable / same_origin) -> an error body, or None."""
    ok, reason = M.writable(headers)
    if not ok:
        return {"status": "error", "errorType": "forbidden",
                "error": reason.replace("抑止・確認の操作", "スナップショット付きの証跡出力") + "。スナップショットなしで出力できます"}
    if headers.get(M.CSRF_HEADER) != "1" or not M.same_origin(headers):
        return {"status": "error", "errorType": "csrf", "error": "cross-site or scripted request refused (same origin + X-Obs-Csrf required)"}
    return None


def filename(req):
    dur = req["to"] - req["from"]
    d = f"{round(dur / 86400)}d" if dur >= 86400 else f"{round(dur / 3600)}h" if dur >= 3600 else f"{max(1, round(dur / 60))}m"
    return f"obs-evidence-{req['scope']}-{datetime.fromtimestamp(req['from'], JST).strftime('%Y%m%d-%H%M')}JST-{d}.zip"


def allow(now):
    with _recent_lock:
        _recent[:] = [t for t in _recent if now - t < 60]
        if len(_recent) >= PER_MIN:
            return False
        _recent.append(now)
        return True


def js(status, obj):
    return status, json.dumps(obj, ensure_ascii=False).encode(), "application/json"


def handle(method, raw_path, headers, gone=None, read_body=None):
    """-> (status, body, content type[, extra headers]). gone(): the client has disconnected (stop, free the slot).
    POST /evidence/export: the same export with the browser's snapshot PNG as the body."""
    parts = urllib.parse.urlsplit(raw_path)
    post = method == "POST" and parts.path == "/evidence/export" and read_body is not None
    if method not in ("GET", "HEAD") and not post:
        return js(405, {"status": "error", "error": "read-only (POST only to /evidence/export, with a snapshot)"})
    # a POST is judged before a byte of its body is read: permission, CSRF, the query, type and size, then the export slot
    # (one at a time) and the rate; only then is the PNG read, in bounded time (a refusal leaves it unread and the
    # connection is closed after the answer)
    if post:
        refused = snapshot_refused(headers)
        if refused:
            return js(403, refused)
    if parts.path == "/evidence/info":
        return js(200, info())
    if parts.path != "/evidence/export":
        return js(403, {"status": "error", "error": "forbidden"})
    now = time.time()
    try:
        req = parse(parts.query, now)
    except (Refused, M.Rejected) as e:
        return js(400, {"status": "error", "errorType": "rejected", "error": str(e)})
    length = upload_length(headers) if post else None
    if post and (headers.get("Content-Type") or "").split(";")[0].strip().lower() != "image/png":
        return js(400, {"status": "error", "errorType": "snapshot", "error": "snapshot: Content-Type image/png required"})
    if post and length is None:
        return js(400, {"status": "error", "errorType": "snapshot", "error": f"snapshot: 1 byte to {SNAPSHOT_MAX // 2**20} MiB (Content-Length)"})
    if not LOCK.acquire(blocking=False):
        return js(429, {"status": "error", "errorType": "busy", "error": "別の証跡出力が実行中です。終わってからもう一度試してください"})
    try:
        if not allow(time.monotonic()):
            return js(429, {"status": "error", "errorType": "rate", "error": "証跡出力の回数が多すぎます。1 分待ってください"})
        snap = None
        if post:
            try:
                snap = read_snapshot(headers, read_upload(length, read_body, time.monotonic() + UPLOAD_TIMEOUT_S))
            except Refused as e:
                return js(400, {"status": "error", "errorType": "snapshot", "error": str(e)})
        try:
            body = build(req, headers, now, gone, snap)
        except Gone as e:
            return js(499, {"status": "error", "error": str(e)})
    finally:
        LOCK.release()
    extra = {"Content-Disposition": f'attachment; filename="{filename(req)}"'}
    if snap is not None:  # the screen says whether the zip really holds it (it may not fit under the size cap)
        extra["X-Obs-Snapshot"] = "included" if snap.get("included") else "omitted (size cap)"
    return 200, body, "application/zip", extra


# ---- self-test (no services needed: reads are faked) -----------------------------------------------------------------

def png_chunk(kind, payload):
    return len(payload).to_bytes(4, "big") + kind + payload + zlib.crc32(kind + payload).to_bytes(4, "big")


def png_fixture(w, h):
    """A valid w x h greyscale PNG (selftest)."""
    raw = b"".join(b"\x00" + b"\x80" * w for _ in range(h))
    return PNG_SIG + png_chunk(b"IHDR", w.to_bytes(4, "big") + h.to_bytes(4, "big") + b"\x08\x00\x00\x00\x00") + \
        png_chunk(b"IDAT", zlib.compress(raw)) + png_chunk(b"IEND", b"")


def selftest():
    global _get, _pcap_stats, MAX_BYTES, BUDGET_S, UPLOAD_TIMEOUT_S
    tok = M.mask_value("203.0.113.50")
    assert scrub(f"a 192.0.2.7 b 203.0.113.x~{tok[-12:]} c 00:11:22:33:44:55 d 2001:db8:1:2:a:b:c:d e fe80::1%eth0 f 2001:db8::x.") \
        == "a 192.0.2.x b 203.0.113.x c 00:11:22:xx:xx:xx d x e x%eth0 f x::x.", scrub("2001:db8:1:2:a:b:c:d")
    assert not leaks(scrub("::ffff:192.168.1.1 10:15:30 3.6.0 2001:db8::1 aa-bb-cc-dd-ee-ff"))
    assert leaks("x 10.0.0.1 y") == ["10.0.0.1"] and leaks("2001:db8::1") and leaks("aa:bb:cc:dd:ee:ff") and not leaks("12:00:00 3.6.0 10:443")
    # P4 review probes 1 / 5: what scrub must mask, leaks must see (raw), and nothing is left after scrub
    raw = ["192.0.2.1が応答なし", "機器192.0.2.1", "host_192.0.2.1", "x192.0.2.1y", "MAC00:11:22:33:44:55", "経由00:11:22:33:44:55です",
           "2001:db8::1", "fe80::1%eth0", "[2001:db8::5]:443", "2001:db8::1が", "addr=2001:db8:0:0:1:2:3:4,", "::ffff:192.0.2.1",
           "192.0.2.1:443", "2001:db8::1/64", "IPv6アドレス2001:db8::abcd", "TCP 2001:db8:10:1:211:22ff:fe33:4455.51000 > x",
           "TCP 2001:db8:10:1:211:22ff:fe33:4455:51000 > x", "src=2001:db8:10:1:211:22ff:fe33:4455/128", "2001:db8:10:1:211:22ff:fe33:4455#53",
           "addr 2001:DB8:10:1:211:22FF:FE33:4455", "fe80::211:22ff:fe33:4455%lan1", "64:ff9b::192.0.2.1", f"t 203.0.113.x~{tok[-12:]}"]
    for x in raw:
        assert leaks(x), x
        assert not leaks(scrub(x)), (x, scrub(x), leaks(scrub(x)))
    assert "4455" not in scrub(" ".join(raw)) and "fe33" not in scrub(" ".join(raw))
    assert duration_s("30d") == 30 * 86400 and duration_s("720h") == 720 * 3600 and duration_s("30d or 10GiB") == 30 * 86400 and duration_s("") is None
    now = 1761470000.0
    bad = ["from=1&to=2&x=1", f"from={now - 9 * 86400}&to={now}", f"from={now}&to={now - 1}", f"from={now - 60}&to={now + 3600}",
           f"from={now - 60}&to={now}&scope=device", f"from={now - 60}&to={now}&scope=all&instance=192.0.2.1",
           f"from={now - 60}&to={now}&scope=dest&ip=192.0.2.x", f"from={now - 60}&to={now}&scope=all&city=113.50",
           f"from={now - 60}&to={now}&scope=all&max_rows=0", f"from={now - 60}&to={now}&scope=all&pcap_filter=tcp",
           f"from=nan&to={now}", f"from={now - 60}&to={now}&scope=all&scope=all", f"from={now - 60}&to={now}&pcap=ring:../../etc/passwd",
           f"from={now - 60}&to={now}&scope=dest&ip=2001:db8::1", f"from={now - 60}&to={now}&scope=dest&ip=2001:db8:1:2::x:1",
           f"from={now - 60}&to={now}&scope=device&instance=" + urllib.parse.quote("[2001:db8::5]:9100"), f"from={now - 60}&to={now}&scope=all&host=fe33:4455"]
    for q in bad:
        try:
            parse(q, now)
            raise AssertionError(q)
        except (Refused, M.Rejected):
            pass
    r = parse(f"from={now - 3600}&to={now}&scope=dest&ip=203.0.113.x~{tok[-12:]}", now)
    assert dict(metric_queries(r, 15))["flow_mbps_by_source"].count(tok[-12:]) == 1
    for v6 in ("2001:db8:1:2::x", "fe80::x", "64:ff9b::192.0.2.x", "2002::x", "2001::x"):  # B1: flowd's masked IPv6 destinations
        r = parse(f"from={now - 3600}&to={now}&scope=dest&ip={urllib.parse.quote(v6)}", now)
        q = dict(metric_queries(r, 15))["flow_mbps_by_source"]
        assert M.prom_query(q).count(f'dst_ip="{v6}"') == 1, (v6, M.prom_query(q))
    assert step_for(3600) == 15 and step_for(7 * 86400) == 315

    # a whole export against faked services: every file scrubbed, caps applied, nothing raw
    notify = [{"alertname": "LinkDown", "instance": "rtx1300", "ifName": "lan1", "severity": "warning", "status": "firing"},
              {"alertname": "LinkDown", "instance": "rtx1300", "ifName": "lan2", "severity": "warning"},
              {"alertname": "DeviceDown", "instance": "wlx222", "severity": "critical"}]
    # P6: notify-relay's records of address-valued devices: with the token (exact match), and an old one without (/24)
    t50, t51 = M.mask_value("203.0.113.50"), M.mask_value("203.0.113.51")
    notify += [{"alertname": "DeviceDown", "instance": t50, "severity": "critical", "receiver": "r50"},
               {"alertname": "DeviceDown", "instance": t51, "severity": "critical", "receiver": "r51"},
               {"alertname": "DeviceDown", "instance": "203.0.113.x", "severity": "critical", "receiver": "rold"}]

    def fake(path, timeout):
        assert 0 < timeout <= M.TIMEOUT_S, timeout
        u = urllib.parse.urlsplit(path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/prom/api/v1/query_range":
            res = [{"metric": {"instance": "192.0.2.9", "ifName": "lan1", "mac": "00:11:22:33:44:55", "v6": "2001:db8::abcd"},
                    "values": [[now - 3600 + i * 15, "1.5"] for i in range(240)]}]
            return 200, json.dumps({"status": "success", "data": {"resultType": "matrix", "result": M.mask_json(res)}}).encode()
        if u.path == "/prom/api/v1/rules":
            return 200, json.dumps({"status": "success", "data": {"groups": [{"rules": [{"name": "LinkDown", "query": "ifOperStatus == 2"}]}]}}).encode()
        if u.path.startswith("/loki/") and "notify" in q["query"]:
            vals = [[str(int(now * 1e9) + i), json.dumps(x)] for i, x in enumerate(notify)]
            return 200, json.dumps({"status": "success", "data": {"resultType": "streams", "result": [{"stream": {"job": "notify"}, "values": vals}]}}).encode()
        if u.path.startswith("/loki/"):
            start = int(q["start"])
            vals = [[str(start + i * 10**9), f"login from 198.51.100.{i % 250} mac 00:11:22:33:44:{i % 90:02d} v6 2001:db8:1:{i:x}::{i:x}.443 機器192.0.2.{i % 9} LinkDown"]
                    for i in range(int(q["limit"]))]
            return 200, json.dumps({"status": "success", "data": {"resultType": "streams", "result": [{"stream": {"host": "rtx1300", "severity": "info"}, "values": M.mask_json(vals)}]}}).encode()
        return 403, b'{"status":"error","error":"forbidden"}'

    def stats(fid, flt, timeout):
        assert timeout > 0
        return {"conv": {"ip": [["192.0.2.x~" + tok[-12:], "2001:db8::x~" + tok[-12:]]]}}
    keep = (_get, _pcap_stats, dict(_versions), MAX_BYTES, BUDGET_S)
    _get, _pcap_stats = fake, stats
    _versions.update(at=time.time(), v={"prometheus": "t", "loki": "t", "observatory": "0123abcd9"})  # a revision masking would eat
    try:
        r = parse(f"from={now - 3600}&to={now}&scope=alert&alertname=LinkDown&instance=rtx1300&ifName=lan1&pcap=demo:demo-home.pcap&max_rows=100&max_lines=12000", now)
        data = build(r, {}, now)
        assert _versions["v"]["observatory"] == "0123abcd9"  # an export does not consume the cached versions
        # size cap: a JSON artifact that does not fit is left out (never cut), a cut text file counts the rows it kept
        MAX_BYTES = 40000
        small = zipfile.ZipFile(io.BytesIO(build(parse(f"from={now - 3600}&to={now}&scope=alert&alertname=LinkDown&instance=rtx1300&pcap=demo:demo-home.pcap", now), {}, now)))
        sm = {x["name"]: x for x in json.loads(small.read("manifest.json"))["files"]}
        cut = next(x for x in sm.values() if x.get("truncated_by") == "size cap (all files)")
        assert cut["rows"] == len(small.read(cut["name"]).decode().splitlines()) - (1 if cut["name"].endswith(".csv") else 0), cut
        assert sm["pcap/stats.json"]["skipped"] and "pcap/stats.json" not in small.namelist(), sm["pcap/stats.json"]
        MAX_BYTES = keep[3]
        # time budget: whatever is left when it runs out is skipped with the reason (packet analysis included)
        BUDGET_S = 0
        late = zipfile.ZipFile(io.BytesIO(build(r, {}, now)))
        lm = json.loads(late.read("manifest.json"))
        assert all(x.get("skipped") and "time budget" in x["reason"] for x in lm["files"]) and lm["truncated"], lm["files"][:2]
        BUDGET_S = keep[4]
        # notification records of an address-valued device: its own token exactly, token-less records by their /24
        dev = zipfile.ZipFile(io.BytesIO(build(parse(f"from={now - 3600}&to={now}&scope=device&instance={t50}", now), {}, now)))
        nt = dev.read("alerts/notifications.txt").decode()
        dm = json.loads(dev.read("manifest.json"))
        assert '"r50"' in nt and '"r51"' not in nt and '"rold"' in nt and "~" not in nt, nt
        assert any("1 notification record(s)" in n for n in dm["notes"]) and dm["snapshot"] == {"included": False, "reason": "not requested"}, dm["notes"]
        # snapshot: PNG checked, metadata chunks dropped, recorded as browser-generated with its sha256
        png = png_fixture(4, 3)
        tagged = png[:33] + png_chunk(b"tEXt", b"Comment\x00192.0.2.10") + png[33:] + b"trailing 192.0.2.10"
        snap = clean_png(tagged)
        assert snap["data"] == png and (snap["width"], snap["height"]) == (4, 3)
        sz = zipfile.ZipFile(io.BytesIO(build(r, {}, now, snap=snap)))
        sman = json.loads(sz.read("manifest.json"))
        assert sz.read("snapshot.png") == png and sman["snapshot"]["included"] and sman["snapshot"]["generated_by"] == "browser"
        assert sman["snapshot"]["sha256"] == hashlib.sha256(png).hexdigest() == next(x for x in sman["files"] if x["name"] == "snapshot.png")["sha256"]
        assert next(x for x in sman["files"] if x["name"] == "snapshot.png")["source"] == "browser"
        for bad_png in (b"GIF89a", png[:20], png[:-12], png.replace(b"IHDR", b"IHDX"), png_fixture(SNAPSHOT_MAX_SIDE + 1, 1),
                        PNG_SIG + png_chunk(b"IHDR", png[16:29]) + png_chunk(b"IEND", b"")):
            try:
                clean_png(bad_png)
                raise AssertionError(bad_png[:40])
            except Refused:
                pass
        MAX_BYTES = 40000
        big = json.loads(zipfile.ZipFile(io.BytesIO(build(r, {}, now, snap=snap))).read("manifest.json"))
        assert big["snapshot"] == {"included": False, "reason": "size cap (all files)"} and big["truncated"], big["snapshot"]
        MAX_BYTES = keep[3]
        # the write rules: 127.0.0.1 only, same origin + X-Obs-Csrf; body checked; GET as before
        env_was = {k: os.environ.get(k) for k in ("OBS_BIND", "OBS_PUBLIC_URL", "OBS_AUTH", "OBS_AUTH_PROXY_KEY")}
        os.environ.update(OBS_BIND="127.0.0.1", OBS_PUBLIC_URL="http://127.0.0.1:8080", OBS_AUTH="0", OBS_AUTH_PROXY_KEY="k" * 40)
        try:
            ok_h = {"Host": "127.0.0.1:8080", "Origin": "http://127.0.0.1:8080", "Sec-Fetch-Site": "same-origin", M.CSRF_HEADER: "1",
                    "Content-Type": "image/png", "Content-Length": str(len(tagged))}
            q = f"/evidence/export?from={time.time() - 60}&to={time.time()}"
            reads = []

            def body(n, deadline=None):
                reads.append(n)
                done = sum(reads[:-1])
                return tagged[done:done + n]

            st, zbytes, ctype, extra = handle("POST", q, ok_h, None, body)
            assert st == 200 and ctype == "application/zip" and zipfile.ZipFile(io.BytesIO(zbytes)).read("snapshot.png") == png
            assert extra["X-Obs-Snapshot"] == "included"
            assert "192.0.2" not in extra["Content-Disposition"]
            _recent.clear()

            def refused_unread(h, path=q, want=None):  # judged before a byte of the body is read
                reads.clear()
                st = handle("POST", path, h, None, body)[0]
                assert not reads and (want is None or st == want), (st, reads, h)
                return st
            refused_unread({**ok_h, M.CSRF_HEADER: ""}, want=403)
            refused_unread({**ok_h, "Origin": "http://evil.example"}, want=403)
            refused_unread({**ok_h, "Content-Type": "image/jpeg"}, want=400)
            refused_unread({**ok_h, "Content-Length": str(SNAPSHOT_MAX + 1)}, want=400)
            refused_unread({**ok_h, "Transfer-Encoding": "chunked"}, want=400)
            refused_unread(ok_h, path="/evidence/export?from=x", want=400)
            assert handle("POST", "/evidence/info", ok_h, None, body)[0] == 405 and handle("PUT", q, ok_h, None, body)[0] == 405
            assert LOCK.acquire(blocking=False)  # the slot is taken: 429 before the body is read
            try:
                refused_unread(ok_h, want=429)
            finally:
                LOCK.release()
            _recent[:] = [time.monotonic()] * PER_MIN
            refused_unread(ok_h, want=429)
            _recent.clear()

            def stalled(n, deadline=None):  # the client stops sending: mask_api.Handler's idle timeout raises TimeoutError
                raise TimeoutError("timed out")
            st, msg, _ = handle("POST", q, ok_h, None, stalled)
            assert st == 400 and "within" in json.loads(msg)["error"] and LOCK.acquire(blocking=False)
            LOCK.release()
            UPLOAD_TIMEOUT_S = -1  # the whole body has a deadline too (a trickle never keeps the slot)
            assert handle("POST", q, ok_h, None, body)[0] == 400 and LOCK.acquire(blocking=False)
            LOCK.release()
            sent = []

            def trickle(n, deadline=None):  # a byte at a time, each well within the idle time: the total deadline ends it
                assert deadline is not None, "the upload is read with its deadline"
                time.sleep(0.01)
                sent.append(1)
                return tagged[len(sent) - 1:len(sent)]
            UPLOAD_TIMEOUT_S = 0.2
            t0 = time.monotonic()
            assert handle("POST", q, ok_h, None, trickle)[0] == 400 and time.monotonic() - t0 < 2 and len(sent) < len(tagged)
            assert LOCK.acquire(blocking=False)
            LOCK.release()
            UPLOAD_TIMEOUT_S = 30
            _recent.clear()
            os.environ["OBS_BIND"] = "192.168.100.10"  # LAN: authentication required; no identity -> no snapshot writes
            lan_h = {**ok_h, "Host": "192.168.100.10:8080", "Origin": "https://192.168.100.10:8080"}
            os.environ["OBS_PUBLIC_URL"] = "https://192.168.100.10:8080"
            st, msg, _ = handle("POST", q, {**lan_h, "X-Obs-Role": "admin", "X-Obs-User": "mallory"}, None, body)
            assert st == 403 and "ログイン" in json.loads(msg)["error"], msg
            viewer = {**lan_h, "X-Obs-Auth": "k" * 40, "X-Obs-User": "alice", "X-Obs-Role": "viewer"}
            st, msg, _ = handle("POST", q, viewer, None, body)
            assert st == 403 and "viewer" in json.loads(msg)["error"], msg
            reads.clear()
            st, zbytes, _, extra = handle("POST", q, {**viewer, "X-Obs-Role": "operator"}, None, body)
            assert st == 200 and extra["X-Obs-Snapshot"] == "included", zbytes[:200]
            assert json.loads(zipfile.ZipFile(io.BytesIO(zbytes)).read("manifest.json"))["generated_by"] == "alice"  # the real user
        finally:
            UPLOAD_TIMEOUT_S = 30
            for k, v in env_was.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            _recent.clear()
        # a client that went away: 499, and the export slot is free again at once
        assert handle("GET", f"/evidence/export?from={time.time() - 60}&to={time.time()}", {}, gone=lambda: True)[0] == 499
        assert LOCK.acquire(blocking=False)
        LOCK.release()
        _recent.clear()
    finally:
        _get, _pcap_stats, MAX_BYTES, BUDGET_S = keep[0], keep[1], keep[3], keep[4]
        _versions.clear()
        _versions.update(keep[2])
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    man = json.loads(zf.read("manifest.json"))
    for n in names:
        text = zf.read(n).decode()
        assert not leaks(text), (n, leaks(text)[:3])
    assert {"metrics/interface_in_mbps.csv", "alerts/ALERTS.csv", "alerts/rule.json", "logs/syslog.txt", "alerts/notifications.txt", "pcap/stats.json", "manifest.json"} <= set(names), names
    f = {x["name"]: x for x in man["files"]}
    assert f["metrics/interface_in_mbps.csv"]["rows"] == 100 and f["metrics/interface_in_mbps.csv"]["truncated"] and man["truncated"]
    assert f["logs/syslog.txt"]["rows"] == 12000 and f["logs/syslog.txt"]["truncated_by"] == "line cap (12000)"
    assert len(zf.read("logs/syslog.txt").decode().splitlines()) == 12000  # pages joined without loss or repeats
    nt = zf.read("alerts/notifications.txt").decode()
    assert f["alerts/notifications.txt"]["rows"] == 1 and '"lan1"' in nt and "DeviceDown" not in nt, nt  # the alert's own records only
    assert "192.0.2" not in filename(r) and filename(r).startswith("obs-evidence-alert-")
    assert man["sources"]["observatory"] == "0123abcd9" and man["scope"]["kind"] == "alert"  # kept outside scrub, like the digests
    for x in man["files"]:  # digests are the real ones (never masked)
        if "sha256" in x:
            assert x["sha256"] == hashlib.sha256(zf.read(x["name"])).hexdigest(), x["name"]
    # concurrency 1 and the per-minute cap
    assert LOCK.acquire(blocking=False)
    try:
        assert handle("GET", f"/evidence/export?from={time.time() - 60}&to={time.time()}", {})[0] == 429
    finally:
        LOCK.release()
    _recent[:] = [time.monotonic()] * PER_MIN
    assert handle("GET", f"/evidence/export?from={time.time() - 60}&to={time.time()}", {})[0] == 429
    _recent.clear()
    assert handle("POST", "/evidence/export", {})[0] == 405 and handle("GET", "/evidence/other", {})[0] == 403
    print(f"evidence selftest ok ({len(names)} files, {len(data)} bytes, {len(bad)} bad requests refused, {len(raw)} leak probes)")
