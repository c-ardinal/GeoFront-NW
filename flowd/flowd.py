"""Flow source: capture files -> per-flow byte counters for Prometheus, in the shape of demo-gen's synthetic flows.

  obs_flow_bytes_total{src_host, dst_ip, dst_country, dst_city, lat, lon, asn, direction}

Input: the capture service's ring files (each closed file once), or one file replayed in a loop (the demo pcap).
The analyzer sandbox dissects them (5-tuple byte counts per second + DHCP / ARP observations); nothing here parses
packets. Each 5-tuple becomes (LAN host, remote address, direction): the LAN side comes from OBS_LAN_CIDRS,
outbound = sent by the LAN host. LAN <-> LAN and broadcast / multicast traffic is not a destination and is skipped.
Bytes are released at their capture time + FLOWD_DELAY_S, so rates are smooth although files arrive in batches.

Host names (src_host): the device inventory, else the DHCP host name seen for the host's MAC, else its reverse-DNS
name (FLOWD_RDNS=1), else the address itself (IPv4: mask-api masks it on every read; IPv6: masked here already).
Remote geography: DB-IP Lite City + ASN (CC BY 4.0, `tools geoip update`), private / documentation / reserved
addresses and lookups without a result are "Unknown" with empty lat / lon (never a guessed location). The demo may
give the documentation addresses of its synthetic pcap the demo locations (FLOWD_DEMO_GEO).

Also exported: the capture service's state (status.json in the capture volume: running, received / dropped
packets, ring usage), the GeoIP databases' versions, and obs_flow_source_up (is the input live).

Run: python flowd.py   |   python flowd.py --selftest
"""
import ipaddress
import json
import math
import os
import re
import socket
import sys
import threading
import time
import types
import unicodedata
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ANALYZER_SOCKET = os.environ.get("ANALYZER_SOCKET", "/run/analyzer/analyzer.sock")
RING = Path(os.environ.get("FLOWD_RING_DIR", "/capture/ring"))
CAPTURE_STATUS = Path(os.environ.get("FLOWD_CAPTURE_STATUS", "/capture/status.json"))
GEOIP_DIR = Path(os.environ.get("GEOIP_DIR", "/geoip"))
HOSTS_FILE = Path(os.environ.get("FLOWD_HOSTS", "/etc/obs-generated/flowd/hosts.json"))
DEMO_GEO = os.environ.get("FLOWD_DEMO_GEO", "")
REPLAY = os.environ.get("FLOWD_REPLAY", "")  # e.g. demo:demo-home.pcap ; empty = follow the capture ring
REPLAY_SCALE = float(os.environ.get("FLOWD_REPLAY_SCALE", "1"))
DELAY_S = float(os.environ.get("FLOWD_DELAY_S", "90"))
MAX_SERIES = int(os.environ.get("FLOWD_MAX_SERIES", "3000"))
IDLE_EXPIRE_S = float(os.environ.get("FLOWD_IDLE_EXPIRE_S", "3600"))
EXPIRE_EVERY_S = 60
TICK_S = 5  # release pending bytes into the counters this often (Prometheus scrapes every 30 s)
RDNS = os.environ.get("FLOWD_RDNS", "0") == "1"
NAMES_MAX = 4096  # host-name maps (DHCP names, IP -> MAC, reverse DNS)
MAX_PENDING = 500000  # scheduled (not yet released) items; bytes beyond go to the overflow series
FILE_RETRIES = 5  # attempts per ring file on busy / timeout / analyzer down, then it is skipped (and counted)
PORT = int(os.environ.get("FLOWD_PORT", "9100"))
STATUS_FRESH_S = 30
GEOIP_FILES = {"city": "dbip-city-lite.mmdb", "asn": "dbip-asn-lite.mmdb"}
DEFAULT_LAN = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
LABELS = ("src_host", "dst_ip", "dst_country", "dst_city", "lat", "lon", "asn", "direction")
OVERFLOW = ("_other", "_other", "Unknown", "", "", "", "", "_other")  # bytes of new flows past FLOWD_MAX_SERIES


def lan_networks(spec):
    nets = []
    for part in (spec or DEFAULT_LAN).split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


LAN = lan_networks(os.environ.get("OBS_LAN_CIDRS", ""))


def addr(s):
    try:
        ip = ipaddress.ip_address(s.split("%")[0])
    except ValueError:
        return None
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip  # ::ffff:a.b.c.d is that IPv4 address


def is_lan(ip):
    return any(ip.version == n.version and ip in n for n in LAN)


def not_a_destination(ip):
    return ip.is_multicast or ip.is_unspecified or ip.is_loopback or (ip.version == 4 and str(ip) == "255.255.255.255")


def label_ip(ip):
    """IPv4 as is (mask-api masks it with a token on every read); IPv6 masked here: its /64 + '::x'."""
    if ip.version == 4:
        return str(ip)
    v4 = str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip in NAT64:
        return "64:ff9b::" + v4.rsplit(".", 1)[0] + ".x"
    if ip in SIX_TO_FOUR or ip in TEREDO:  # an IPv4 address inside the /64: nothing of it is shown
        return ("2002" if ip in SIX_TO_FOUR else "2001") + "::x"
    net = str(ipaddress.IPv6Address(int(ip) >> 64 << 64))
    return (net if net.endswith("::") else net + "::") + "x"


NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")
TEREDO = ipaddress.IPv6Network("2001::/32")


# ---- free text (host names from DHCP / reverse DNS, capture error text) --------------------------------------------
# The rule of the analysis screens (mask-api pcap_api.digit_safe): no part of an address-like thing survives, so a
# DHCP name like "android-0a1b2c3d" or a reverse-DNS name like "ip-192-168-100-23" is shown as "android-x" / "ip-x-x-x-x".
_ARPA_NAME = re.compile(r"(?:[A-Za-z0-9_-]+\.)+(in-addr|ip6)\.arpa(?![A-Za-z0-9-])", re.I)
_BASE64 = re.compile(r"[A-Za-z0-9+/]{6,}==")
_HEXISH = re.compile(r"[0-9A-Fa-f]+")
_HEX_WORD = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]+(?![A-Za-z0-9])")
_HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[A-Fa-f]{2,}(?![0-9A-Fa-f])")


def free_text(s):
    s = unicodedata.normalize("NFKC", s)  # fullwidth -> ASCII; every other Unicode number character -> "0"
    if not s.isascii():
        s = "".join("0" if not c.isascii() and unicodedata.category(c).startswith("N") else c for c in s)
    s = s.replace("\ue001", "").replace("\ue002", "")
    s = _ARPA_NAME.sub(lambda m: "x." + ("\ue001" if m.group(1).lower() == "in-addr" else "\ue002") + ".arpa", s)
    s = _BASE64.sub("x", s)
    s = _HEXISH.sub(lambda m: "x" if any(c.isdigit() for c in m.group(0)) else m.group(0), s)
    s = _HEX_WORD.sub("x", s)
    edge = lambda c: not c.isalnum() or c == "x"
    s = _HEX_TOKEN.sub(lambda m: "x" if edge(m.string[m.start() - 1] if m.start() else " ") or edge(m.string[m.end()] if m.end() < len(m.string) else " ")
                       else m.group(0), s)
    s = re.sub(r"x{2,}", "x", s)
    return s.replace("\ue001", "in-addr").replace("\ue002", "ip6")


# ---- analyzer ------------------------------------------------------------------------------------------------

def analyzer(req, timeout=300):
    """flows request, read as a stream: one JSON line per bucket (bounded by the analyzer's FLOW_KEYS), then the summary.
    -> summary with "buckets"; a stream without its summary is a transient failure."""
    req = {**req, "stream": True}
    buckets = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(ANALYZER_SOCKET)
        s.sendall(json.dumps(req).encode() + b"\n")
        with s.makefile("rb") as f:
            for line in f:
                obj = json.loads(line)
                if isinstance(obj, list):
                    buckets.append(obj)
                    continue
                if "error" in obj:
                    if obj.get("busy") or obj["error"].startswith("timeout"):
                        raise Transient(obj["error"][:200])
                    raise RuntimeError(obj["error"][:200])
                return {**obj, "buckets": buckets}
    raise Transient("analyzer stream ended without its summary")


class Transient(RuntimeError):
    """busy / timeout / analyzer unreachable: try the file again later."""


# ---- GeoIP ----------------------------------------------------------------------------------------------------

class Geo:
    """DB-IP Lite City + ASN (MaxMind DB format), reopened when `tools geoip update` replaces them."""

    def __init__(self, directory=GEOIP_DIR, demo=DEMO_GEO):
        self.dir, self.readers, self.mtimes, self.cache, self.checked = Path(directory), {}, {}, {}, 0.0
        self.demo = json.loads(Path(demo).read_text()) if demo else {}
        self.version = {}

    def refresh(self, now=None):
        now = now or time.time()
        if now - self.checked < 60:
            return
        self.checked = now
        try:
            import maxminddb
        except ImportError:
            return
        for db, fname in GEOIP_FILES.items():
            p = self.dir / fname
            try:
                m = p.stat().st_mtime
            except OSError:
                self.readers.pop(db, None)
                continue
            if self.mtimes.get(db) != m:
                try:
                    self.readers[db] = maxminddb.open_database(str(p), maxminddb.MODE_MMAP)
                    self.mtimes[db] = m
                    self.cache.clear()
                except (OSError, ValueError) as e:
                    print(f"geoip: cannot open {fname}: {e}", file=sys.stderr, flush=True)
                    self.readers.pop(db, None)
        try:
            self.version = json.loads((self.dir / "version.json").read_text())
        except (OSError, ValueError):
            self.version = {}

    def lookup(self, ip):
        """-> (country, city, lat, lon, asn); ("Unknown", "", "", "", asn or "") without a located result."""
        key = str(ip)
        if key in self.demo:
            d = self.demo[key]
            return d["cc"], d.get("city", ""), d.get("lat", ""), d.get("lon", ""), d.get("asn", "")
        if not ip.is_global:  # private, documentation, reserved, shared (CGNAT), ...
            return "Unknown", "", "", "", ""
        if key in self.cache:
            return self.cache[key]
        cc, city, lat, lon, asn = "Unknown", "", "", "", ""
        try:
            rec = self.readers["city"].get(key) if "city" in self.readers else None
            a = self.readers["asn"].get(key) if "asn" in self.readers else None
        except ValueError:
            rec, a = None, None
        if a and a.get("autonomous_system_number"):
            asn = f"AS{a['autonomous_system_number']}"
        loc = (rec or {}).get("location") or {}
        if rec and (rec.get("country") or {}).get("iso_code") and loc.get("latitude") is not None:
            cc = rec["country"]["iso_code"]
            city = ((rec.get("city") or {}).get("names") or {}).get("en", "")
            lat, lon = f"{loc['latitude']:.4f}", f"{loc['longitude']:.4f}"
        out = (cc, city, lat, lon, asn)
        if len(self.cache) > 50000:
            self.cache.clear()
        self.cache[key] = out
        return out

    def metrics(self):
        out = []
        for db in GEOIP_FILES:
            r = self.readers.get(db)
            out.append(("obs_geoip_db_present", {"db": db}, 1 if r else 0))
            if r:
                meta = r.metadata()
                out.append(("obs_geoip_db_info", {"db": db, "source": "DB-IP Lite", "edition": meta.database_type,
                                                  "month": str(self.version.get(db, ""))}, 1))
                out.append(("obs_geoip_db_build_timestamp_seconds", {"db": db}, meta.build_epoch))
        return out


# ---- host names ---------------------------------------------------------------------------------------------

class Names:
    def __init__(self):
        self.inventory, self.rdns = {}, {}
        self.dhcp, self.ip_mac = OrderedDict(), OrderedDict()  # bounded (NAMES_MAX), most recently seen kept
        self.pool = ThreadPoolExecutor(1) if RDNS else None
        self.loaded = 0.0

    def load_inventory(self, now=None):
        now = now or time.time()
        if now - self.loaded < 60:
            return
        self.loaded = now
        try:
            self.inventory = {k: v for k, v in json.loads(HOSTS_FILE.read_text()).items() if NAME_RE.fullmatch(str(v))}
        except (OSError, ValueError):
            self.inventory = {}

    def learn(self, names, ip_mac):
        for m, n in names.items():
            n = free_text(n)
            if NAME_RE.fullmatch(n):
                self.dhcp[m.lower()] = n
                self.dhcp.move_to_end(m.lower())
        for ip, m in ip_mac.items():
            a = addr(ip)
            if a and is_lan(a):  # only LAN hosts are named
                self.ip_mac[ip] = m.lower()
                self.ip_mac.move_to_end(ip)
        for d in (self.dhcp, self.ip_mac):
            while len(d) > NAMES_MAX:
                d.popitem(last=False)
        if len(self.rdns) > NAMES_MAX:
            self.rdns.clear()

    def _rdns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0].split(".")[0]
        except OSError:
            name = ""
        name = free_text(name or "")
        self.rdns[ip] = name if NAME_RE.fullmatch(name) and name != "x" else ""

    def name(self, ip):
        key = str(ip)
        if key in self.inventory:
            return self.inventory[key]
        mac = self.ip_mac.get(key)
        if mac and mac in self.dhcp:
            return self.dhcp[mac]
        if self.pool:
            if key not in self.rdns:
                self.rdns[key] = ""
                self.pool.submit(self._rdns, key)
            if self.rdns.get(key):
                return self.rdns[key]
        return label_ip(ip)

    def host_info(self):
        out = {}
        for ip in set(self.ip_mac) | set(self.inventory):
            a = addr(ip)
            if a and a.version == 4 and is_lan(a):
                n = self.name(a)
                if n != ip:
                    out[ip] = n
        return out


# ---- counters ---------------------------------------------------------------------------------------------------

class Flows:
    def __init__(self, geo, names):
        self.geo, self.names = geo, names
        self.counters, self.seen = {}, {}
        self.pending = deque()  # (release_at, key, bytes), release_at ascending
        self.lock = threading.Lock()
        self.files_ok = self.files_failed = self.files_skipped = self.retries = 0
        self.overflow_bytes = 0.0
        self.last_file = 0.0
        self.expired_at = 0.0

    def key_of(self, src, dst):
        a, b = addr(src), addr(dst)
        if not a or not b or is_lan(a) == is_lan(b):
            return None  # LAN <-> LAN, or neither side on the LAN (transit / misconfigured OBS_LAN_CIDRS)
        lan, remote, direction = (a, b, "outbound") if is_lan(a) else (b, a, "inbound")
        if not_a_destination(remote):
            return None
        cc, city, lat, lon, asn = self.geo.lookup(remote)
        return (self.names.name(lan), label_ip(remote), cc, city, lat, lon, asn, direction)

    def schedule(self, buckets, base, t0, scale=1.0):
        """buckets: analyzer flow rows [sec, src, dst, proto, sport, dport, bytes, pkts]; released at base + (sec - t0)."""
        per = {}
        for sec, src, dst, _p, _sp, _dp, size, _n in buckets:
            k = self.key_of(src, dst)
            if k:
                per[(sec, k)] = per.get((sec, k), 0) + size * scale
        items = sorted(((base + (sec - t0), k, v) for (sec, k), v in per.items()), key=lambda x: x[0])
        with self.lock:
            room = max(0, MAX_PENDING - len(self.pending))
            if len(items) > room:  # bounded: the rest is counted, not scheduled
                self.overflow(sum(v for _, _, v in items[room:]))
                items = items[:room]
            merged = sorted(list(self.pending) + items, key=lambda x: x[0]) if self.pending and items and items[0][0] < self.pending[-1][0] else None
            if merged is not None:
                self.pending = deque(merged)
            else:
                self.pending.extend(items)

    def release(self, now):
        with self.lock:
            while self.pending and self.pending[0][0] <= now:
                _, k, v = self.pending.popleft()
                if k not in self.counters and len(self.counters) >= MAX_SERIES:
                    k = OVERFLOW  # one fixed series: MAX_SERIES (+1) is a hard bound
                    self.overflow_bytes += v
                self.counters[k] = self.counters.get(k, 0.0) + v
                self.seen[k] = now
            if now - self.expired_at < EXPIRE_EVERY_S:  # a scan of every series: not on each tick
                return
            self.expired_at = now
            for k in [k for k, t in self.seen.items() if now - t > IDLE_EXPIRE_S]:
                self.counters.pop(k, None)
                self.seen.pop(k, None)

    def overflow(self, size):
        """Bytes that cannot get their own series (series / pending / analyzer key caps): the one _other series."""
        if size:
            self.overflow_bytes += size
            self.counters[OVERFLOW] = self.counters.get(OVERFLOW, 0.0) + size
            self.seen[OVERFLOW] = time.time()

    def snapshot(self):
        with self.lock:
            return dict(self.counters)


# ---- inputs -------------------------------------------------------------------------------------------------

def capture_status(now=None):
    try:
        st = json.loads(CAPTURE_STATUS.read_text())
    except (OSError, ValueError):
        return None
    st["fresh"] = (now or time.time()) - float(st.get("updated", 0)) < STATUS_FRESH_S
    return st


def closed_ring_files(current):
    """Ring files by time (names restart at _00001 with each dumpcap session), minus the open one; files that vanish
    while listed (dumpcap's ring, prune) are skipped."""
    found = []
    try:
        entries = list(os.scandir(RING))
    except OSError:
        return []
    for e in entries:
        if e.name.endswith((".pcapng", ".pcap")):
            try:
                found.append((e.stat().st_mtime, e.name))
            except OSError:
                continue
    names = [n for _, n in sorted(found)]
    if current is None and names:
        names = names[:-1]  # without a status, the newest file may still be open
    return [n for n in names if n != current]


def process(flows, name, done, attempts, ask=None):
    """One closed ring file. Busy / timeout / analyzer down: retried on later passes (FILE_RETRIES), then skipped
    and counted; other errors (an unreadable file) count as failed. Only then is the file done."""
    ask = ask or analyzer
    try:
        res = ask({"op": "flows", "lane": "flows", "file": {"root": "ring", "name": name}})
    except (OSError, ValueError, Transient) as e:
        attempts[name] = attempts.get(name, 0) + 1
        flows.retries += 1
        if attempts[name] >= FILE_RETRIES:
            done.add(name)
            flows.files_skipped += 1
            print(f"flowd: {name}: skipped after {FILE_RETRIES} attempts: {e}", file=sys.stderr, flush=True)
        return False
    except RuntimeError as e:
        done.add(name)
        flows.files_failed += 1
        print(f"flowd: {name}: {e}", file=sys.stderr, flush=True)
        return False
    done.add(name)
    attempts.pop(name, None)
    flows.names.learn(res["names"], res["ip_mac"])
    flows.schedule(res["buckets"], DELAY_S, 0)
    with flows.lock:
        flows.overflow(res.get("overflow_bytes") or 0)
    flows.files_ok += 1
    flows.last_file = time.time()
    return True


def follow_ring(flows, stop):
    st = capture_status()
    try:  # already there at start: not counted again (by name, so a stat error cannot make one look new)
        done = set(os.listdir(RING)) - {st.get("current") if st else None}
    except OSError:
        done = set()
    attempts = {}
    while not stop.is_set():
        st = capture_status()
        for name in closed_ring_files(st.get("current") if st else None):
            if name not in done:
                process(flows, name, done, attempts)
        try:
            present = set(os.listdir(RING))
        except OSError:  # the ring directory itself is gone (volume recreated)
            present = set()
        done &= present
        attempts = {k: v for k, v in attempts.items() if k in present}
        stop.wait(5)


class Replay:
    def __init__(self):
        self.loaded, self.error = False, None


def replay(flows, ref, stop, state):
    root, _, name = ref.partition(":")
    while not stop.is_set():
        try:
            res = analyzer({"op": "flows", "lane": "flows", "file": {"root": root, "name": name}})
            break
        except (OSError, ValueError, RuntimeError) as e:
            state.error = str(e)
            stop.wait(10)
    else:
        return
    flows.names.learn(res["names"], res["ip_mac"])
    t0 = math.floor(res["t0"])
    span = max(60, math.ceil(res["t1"] - t0 + 1))
    state.loaded, state.error = True, None
    print(f"flowd: replaying {ref} ({len(res['buckets'])} buckets, {span} s loop, x{REPLAY_SCALE})", flush=True)
    start = time.time()
    cycle = 0
    while not stop.is_set():
        base = start + cycle * span
        flows.schedule(res["buckets"], base, t0, REPLAY_SCALE)
        cycle += 1
        stop.wait(max(0, base + span - 30 - time.time()))  # queue the next loop 30 s before this one ends


# ---- exposition ---------------------------------------------------------------------------------------------

def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def series(name, labels, value):
    lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
    return f"{name}{{{lab}}} {value}" if lab else f"{name} {value}"


def render(flows, replay_state, now=None):
    now = now or time.time()
    out = ["# HELP obs_flow_bytes_total Bytes per LAN host, remote address and direction (from packet capture)",
           "# TYPE obs_flow_bytes_total counter"]
    for k, v in sorted(flows.snapshot().items()):
        out.append(series("obs_flow_bytes_total", dict(zip(LABELS, k)), int(v)))
    out.append("# TYPE obs_flow_host_info gauge")
    for ip, n in sorted(flows.names.host_info().items()):
        out.append(series("obs_flow_host_info", {"src_host": n, "ip": ip}, 1))
    st = capture_status(now)
    if REPLAY:
        up = 1 if replay_state.loaded else 0
    else:
        up = 1 if st and st.get("fresh") and st.get("running") else 0
    out += ["# HELP obs_flow_source_up 1 while the flow input is live (capture running / replay loaded)",
            "# TYPE obs_flow_source_up gauge", series("obs_flow_source_up", {"mode": "replay" if REPLAY else "capture"}, up),
            "# TYPE obs_flowd_files_total counter", series("obs_flowd_files_total", {"result": "ok"}, flows.files_ok),
            series("obs_flowd_files_total", {"result": "error"}, flows.files_failed),
            series("obs_flowd_files_total", {"result": "skipped"}, flows.files_skipped),
            "# TYPE obs_flowd_file_retries_total counter", series("obs_flowd_file_retries_total", {}, flows.retries),
            "# HELP obs_flow_overflow_bytes_total Bytes counted in the single _other series because FLOWD_MAX_SERIES was reached",
            "# TYPE obs_flow_overflow_bytes_total counter", series("obs_flow_overflow_bytes_total", {}, int(flows.overflow_bytes))]
    if st:
        limit = float(st.get("ring_limit_bytes") or 0)
        out += ["# TYPE obs_capture_up gauge", series("obs_capture_up", {"iface": free_text(str(st.get("iface") or ""))}, 1 if st.get("fresh") and st.get("running") else 0),
                "# TYPE obs_capture_status_age_seconds gauge", series("obs_capture_status_age_seconds", {}, round(now - float(st.get("updated", 0)), 1)),
                "# TYPE obs_capture_packets_received_total counter", series("obs_capture_packets_received_total", {}, int(st.get("received") or 0)),
                "# HELP obs_capture_nic_rx_dropped_total Packets the capture interface dropped (kernel rx_dropped since capture start)",
                "# TYPE obs_capture_nic_rx_dropped_total counter", series("obs_capture_nic_rx_dropped_total", {}, int(st.get("nic_rx_dropped") or 0)),
                "# HELP obs_capture_dumpcap_dropped_total Packets dumpcap reported dropped (pcap / own buffer); known only when a dumpcap session ends",
                "# TYPE obs_capture_dumpcap_dropped_total counter", series("obs_capture_dumpcap_dropped_total", {}, int(st.get("dumpcap_dropped") or 0)),
                "# TYPE obs_capture_ring_bytes gauge", series("obs_capture_ring_bytes", {}, int(st.get("ring_bytes") or 0)),
                "# TYPE obs_capture_ring_limit_bytes gauge", series("obs_capture_ring_limit_bytes", {}, int(limit)),
                "# TYPE obs_capture_ring_files gauge", series("obs_capture_ring_files", {}, int(st.get("ring_files") or 0)),
                "# TYPE obs_capture_over_limit gauge", series("obs_capture_over_limit", {}, 1 if limit and float(st.get("ring_bytes") or 0) > limit * 1.1 else 0)]
        if st.get("error"):
            out += ["# TYPE obs_capture_error_info gauge", series("obs_capture_error_info", {"reason": free_text(str(st["error"]))[:120]}, 1)]
    out.append("# TYPE obs_geoip_db_present gauge")
    out += [series(n, l, v) for n, l, v in flows.geo.metrics()]
    return "\n".join(out) + "\n"


def main():
    geo, names = Geo(), Names()
    flows, state, stop = Flows(geo, names), Replay(), threading.Event()
    geo.refresh(0)
    names.load_inventory(0)
    if REPLAY:
        threading.Thread(target=replay, args=(flows, REPLAY, stop, state), daemon=True).start()
    else:
        threading.Thread(target=follow_ring, args=(flows, stop), daemon=True).start()

    def tick():
        while True:
            now = time.time()
            flows.release(now)
            geo.refresh(now)
            names.load_inventory(now)
            time.sleep(TICK_S)
    threading.Thread(target=tick, daemon=True).start()

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics":
                body, ctype = render(flows, state).encode(), "text/plain; version=0.0.4"
            elif self.path == "/health":
                body, ctype = b"ok\n", "text/plain"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    print(f"flowd: :{PORT}, input {'replay ' + REPLAY if REPLAY else 'capture ring ' + str(RING)}, LAN {', '.join(map(str, LAN))}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()


def selftest():
    geo = Geo(directory="/nonexistent", demo="")
    geo.demo = {"192.0.2.10": {"cc": "JP", "city": "Tokyo", "lat": "35.6895", "lon": "139.6917", "asn": "AS64500"}}
    names = Names()
    names.learn({"02:00:5E:10:00:17": "pc-living", "02:00:5e:10:00:18": "bad name!"}, {"192.168.100.23": "02:00:5e:10:00:17", "192.168.100.24": "02:00:5e:10:00:18"})
    names.inventory = {"192.168.100.1": "rtx1300"}
    f = Flows(geo, names)
    assert f.key_of("192.168.100.23", "192.0.2.10") == ("pc-living", "192.0.2.10", "JP", "Tokyo", "35.6895", "139.6917", "AS64500", "outbound")
    assert f.key_of("198.51.100.7", "192.168.100.24")[:3] == ("192.168.100.24", "198.51.100.7", "Unknown") and f.key_of("198.51.100.7", "192.168.100.24")[7] == "inbound"
    assert f.key_of("192.168.100.23", "192.168.100.1") is None and f.key_of("192.0.2.1", "198.51.100.1") is None  # LAN-LAN / transit
    assert f.key_of("192.168.100.23", "224.0.0.251") is None and f.key_of("192.168.100.23", "255.255.255.255") is None
    k6 = f.key_of("fe80::1", "2001:db8:1:2:3:4:5:6")
    assert k6[0] == "fe80::x" and k6[1] == "2001:db8:1:2::x" and k6[2] == "Unknown", k6  # IPv6 never leaves unmasked
    assert label_ip(addr("2002:c000:20a::1")) == "2002::x" and label_ip(addr("2001:0:4136:e378:8000:63bf:3fff:fdd2")) == "2001::x"
    assert label_ip(addr("64:ff9b::c000:20a")) == "64:ff9b::192.0.2.x" and str(addr("::ffff:192.0.2.10")) == "192.0.2.10"
    assert geo.lookup(addr("8.8.8.8")) == ("Unknown", "", "", "", "")  # no database: Unknown, never a guess
    f.schedule([[100, "192.168.100.23", "192.0.2.10", "6", "5", "443", 1000, 2], [101, "192.168.100.23", "192.0.2.10", "6", "5", "443", 500, 1]], 1000.0, 100)
    f.release(1000.5)
    assert sum(f.snapshot().values()) == 1000
    f.release(1001)
    assert sum(f.snapshot().values()) == 1500
    f.schedule([[0, "192.168.100.23", "192.0.2.10", "6", "5", "443", 7, 1]], 900.0, 0)  # an earlier batch is merged in order
    assert [p[0] for p in f.pending] == [900.0]
    f.release(1002)
    text = render(f, Replay(), now=1002)
    assert 'obs_flow_bytes_total{src_host="pc-living",dst_ip="192.0.2.10",dst_country="JP",dst_city="Tokyo",lat="35.6895",lon="139.6917",asn="AS64500",direction="outbound"} 1507' in text, text
    assert 'obs_flow_host_info{src_host="pc-living",ip="192.168.100.23"} 1' in text and "192.168.100.24\"} 1" not in text
    assert 'obs_flow_source_up{mode="capture"} 0' in text and 'obs_geoip_db_present{db="city"} 0' in text
    assert esc('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
    global MAX_SERIES
    MAX_SERIES, was = 1, MAX_SERIES
    f.schedule([[1, "192.168.100.23", "192.0.2.99", "6", "5", "443", 9, 1]], 1003.0, 1)
    f.release(1004)
    f.schedule([[1, "192.168.100.24", "192.0.2.98", "17", "5", "53", 4, 1]], 1003.0, 1)
    f.release(1004)
    assert sum(1 for k in f.snapshot() if k == OVERFLOW) == 1 and f.overflow_bytes == 13, f.snapshot()  # one bucket for all hosts
    MAX_SERIES = was
    f.release(1004 + IDLE_EXPIRE_S + 1)
    assert not f.snapshot()  # idle series expire
    assert [str(n) for n in lan_networks("192.168.100.0/24, fd00::/8")] == ["192.168.100.0/24", "fd00::/8"]
    # transient analyzer errors are retried, then skipped and counted; a permanent error is final
    f2, done, att = Flows(geo, Names()), set(), {}

    def busy(req):
        assert req["lane"] == "flows"
        raise Transient("busy: too many analyses running")
    for _ in range(FILE_RETRIES - 1):
        assert not process(f2, "a.pcapng", done, att, busy) and "a.pcapng" not in done
    process(f2, "a.pcapng", done, att, busy)
    assert "a.pcapng" in done and f2.files_skipped == 1 and f2.retries == FILE_RETRIES
    ok_reply = lambda req: {"names": {}, "ip_mac": {"192.168.100.9": "02:00:5e:00:00:09", "198.51.100.1": "02:00:5e:00:00:0a"}, "buckets": []}
    assert process(f2, "b.pcapng", done, att, ok_reply) and f2.files_ok == 1
    assert "192.168.100.9" in f2.names.ip_mac and "198.51.100.1" not in f2.names.ip_mac  # LAN hosts only
    def bad(req):
        raise RuntimeError("tshark: file cut short")
    process(f2, "c.pcapng", done, att, bad)
    assert "c.pcapng" in done and f2.files_failed == 1
    global MAX_PENDING
    MAX_PENDING, keep = 2, MAX_PENDING
    f3 = Flows(geo, Names())
    f3.schedule([[i, "192.168.100.23", "192.0.2.10", "6", "5", "443", 10, 1] for i in range(5)], 0.0, 0)
    assert len(f3.pending) == 2 and f3.overflow_bytes == 30 and f3.counters[OVERFLOW] == 30  # bounded, the rest counted
    MAX_PENDING = keep
    ov = lambda req: {"names": {}, "ip_mac": {}, "buckets": [], "overflow_bytes": 1234, "count": 0}
    assert process(f3, "d.pcapng", set(), {}, ov) and f3.overflow_bytes == 1264
    assert free_text("android-0a1b2c3d") == "android-x" and free_text("pc-living") == "pc-living" and free_text("ip-192-168-100-23") == "ip-x-x-x-x" and free_text("n/wKhkFw==/z") == "x/z" and free_text("b.a.0.ip6.arpa fe80--a-b") == "x.ip6.arpa x--x-x"
    nm = Names()
    nm.learn({"02:00:5e:00:00:31": "esp-ddeeff", "02:00:5e:00:00:32": "phone-a"}, {"192.168.100.31": "02:00:5e:00:00:31"})
    assert nm.dhcp["02:00:5e:00:00:32"] == "phone-x" and nm.dhcp["02:00:5e:00:00:31"] == "esp-x" and nm.name(addr("192.168.100.31")) == "esp-x"
    # every label flowd emits, by kind: a new label must be classified here; free-text ones are masked at the source
    global CAPTURE_STATUS
    import tempfile
    was_st = CAPTURE_STATUS
    with tempfile.TemporaryDirectory() as tmp:
        CAPTURE_STATUS = Path(tmp) / "status.json"
        CAPTURE_STATUS.write_text(json.dumps({"running": True, "updated": 1002, "iface": "enx02005e100017", "received": 5,
                                              "error": "dumpcap: wlx02005e100017 192.168.100.23 failed"}))
        f.names.learn({"02:00:5e:10:00:19": "android-0a1b2c3d"}, {"192.168.100.25": "02:00:5e:10:00:19"})
        f.schedule([[1, "192.168.100.25", "192.0.2.10", "6", "5", "443", 9, 1]], 1003.0, 1)
        f.release(1004)
        meta = types.SimpleNamespace(database_type="DBIP-City-Lite", build_epoch=1790000000)
        f.geo.readers, f.geo.version = {"city": types.SimpleNamespace(metadata=lambda: meta)}, {"city": "2026-10"}
        text = render(f, Replay(), now=1004)
        f.geo.readers, f.geo.version = {}, {}
    CAPTURE_STATUS = was_st
    kinds = {"free": {"src_host", "iface", "reason"}, "address": {"dst_ip", "ip"}, "geo": {"dst_country", "dst_city", "lat", "lon", "asn", "db"},
             "enum": {"direction", "mode", "result"}, "geoip-meta": {"source", "edition", "month"}}
    seen = re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', text)
    assert {k for k, _ in seen} <= set().union(*kinds.values()), {k for k, _ in seen} - set().union(*kinds.values())
    for k, v in seen:
        if k in kinds["free"]:
            is_addr = k == "src_host" and (re.fullmatch(r"[\d.]+", v) or v.endswith("::x") or v.endswith(".x"))
            operator = k == "src_host" and v in f.names.inventory.values()  # inventory names: chosen by the operator
            assert is_addr or operator or free_text(v) == v, (k, v)
    assert "02005e100017" not in text and 'iface="enx"' in text and "android-x" in text, text
    assert 'obs_geoip_db_info{db="city",source="DB-IP Lite",edition="DBIP-City-Lite",month="2026-10"} 1' in text, text
    big = Names()
    big.learn({}, {f"192.168.{i // 250}.{i % 250}": "02:00:5e:00:00:01" for i in range(NAMES_MAX + 100)})
    assert len(big.ip_mac) == NAMES_MAX
    print("flowd selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
