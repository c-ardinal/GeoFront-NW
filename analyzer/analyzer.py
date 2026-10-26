"""Packet analyzer sandbox: runs tshark on stored capture files, one tshark process per request step.

Runs in its own container with no network, a read-only root filesystem, a non-root user and CPU / memory limits;
the capture files are mounted read-only. Clients (mask-api's /pcap/ API, flowd) talk to it over a Unix socket in a
shared volume: one JSON request line, one JSON reply line. Nothing a client sends is ever interpreted by a shell or
passed to tshark except as one argv element: a file is named by (root, basename) and resolved here, a display
filter is only ever the value of -Y. Replies carry RAW addresses: the callers mask (mask-api) or aggregate them
(flowd); the browser never talks to this service.

Ops: ping | fieldtypes {names} | check {filter} | packets {file, filter, max} | detail {file, no}
     | stats {file, filter} | flows {file}

Run: python analyzer.py                 (listens on $ANALYZER_SOCKET)
     python analyzer.py --build-fields  (image build: field classes from `tshark -G fields`)
     python analyzer.py --selftest      (needs tshark and the demo pcap)
"""
import json
import os
import re
import resource
import signal
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

SOCKET = os.environ.get("ANALYZER_SOCKET", "/run/analyzer/analyzer.sock")
ROOTS = {"ring": Path(os.environ.get("ANALYZER_RING", "/capture/ring")), "upload": Path(os.environ.get("ANALYZER_UPLOADS", "/uploads")),
         "demo": Path(os.environ.get("ANALYZER_DEMO", "/demo"))}
FIELD_CLASSES = Path(os.environ.get("ANALYZER_FIELDS", "/app/fieldclass.json"))
FIELD_NAMES = Path(os.environ.get("ANALYZER_FIELD_NAMES", "/app/fieldnames.db"))  # abbreviation -> display name
EMPTY_PCAP = Path(os.environ.get("ANALYZER_EMPTY", "/app/empty.pcap"))
TIMEOUT_S = int(os.environ.get("ANALYZER_TIMEOUT", "60"))
VALIDATE_TIMEOUT_S = max(TIMEOUT_S, int(os.environ.get("ANALYZER_VALIDATE_TIMEOUT", "180")))  # reading a whole upload
CONCURRENCY = int(os.environ.get("ANALYZER_CONCURRENCY", "1"))
# address space per tshark; at most CONCURRENCY screen runs + 1 flowd run at once, so the container limit
# (ANALYZER_MEM) must hold (CONCURRENCY + 1) x this + ~60 MB for the server: 2 x 384 + 60 < 896 MB by default (tshark needs ~320 MB of address space even for a small file)
PROC_MEM_MB = int(os.environ.get("ANALYZER_PROC_MEM_MB", "384"))
MAX_ROWS = int(os.environ.get("ANALYZER_MAX_ROWS", "200000"))
MAX_REQUEST = 64 * 1024
FILTER_MAX = 512
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
FILE_SUFFIXES = (".pcap", ".pcapng", ".cap")
# characters a display filter may contain at all (mask-api applies the real policy; this is defense in depth)
FILTER_CHARS = re.compile(r'[A-Za-z0-9_.:\-~ !=<>&|"(){},/]*')
TOP_N = 1000  # rows per statistics table
ADDRESS_TYPES = {"FT_IPv4", "FT_IPv6", "FT_ETHER", "FT_EUI64", "FT_FCWWN", "FT_AX25", "FT_IPXNET", "FT_VINES"}
BYTES_TYPES = {"FT_BYTES", "FT_UINT_BYTES", "FT_PROTOCOL"}
STRING_TYPES = {"FT_STRING", "FT_STRINGZ", "FT_UINT_STRING", "FT_STRINGZPAD", "FT_STRINGZTRUNC"}

TSHARK = ["tshark", "-n", "-Q"]  # -n: no name resolution of any kind (no DNS, no MAC vendor names); -Q: quiet
FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "ip.proto", "ipv6.nxt", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "eth.src", "eth.dst",
          "arp.src.proto_ipv4", "arp.src.hw_mac", "dhcp.option.hostname", "dhcp.hw.mac_addr", "dhcp.ip.your",
          "dhcp.option.requested_ip_address", "dns.qry.name", "tls.handshake.extensions_server_name", "http.host"]
F = {n: i for i, n in enumerate(FIELDS)}


class Bad(ValueError):
    """A request this service refuses (message goes back to the caller)."""


# ---- field classes (the policy input for mask-api's display filter checks and the masking of detail trees) --------

def build_fields(out=FIELD_CLASSES):
    lines = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, check=True).stdout.splitlines()
    classes, dn = {}, {}
    for line in lines:
        p = line.split("\t")
        if p[0] in ("P", "F") and len(p) >= 3:
            dn.setdefault(p[2], p[1])
        if p[0] == "P" and len(p) >= 3:
            classes[p[2]] = "protocol"
        elif p[0] == "F" and len(p) >= 4:
            kind = ("address" if p[3] in ADDRESS_TYPES else "bytes" if p[3] in BYTES_TYPES else "string" if p[3] in STRING_TYPES else None)
            if kind:
                classes[p[2]] = kind
    out.write_text(json.dumps(classes, separators=(",", ":")))
    FIELD_NAMES.unlink(missing_ok=True)
    with sqlite3.connect(FIELD_NAMES) as db:
        db.execute("CREATE TABLE n (a TEXT PRIMARY KEY, d TEXT NOT NULL)")
        db.executemany("INSERT INTO n VALUES (?, ?)", dn.items())
    EMPTY_PCAP.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
    print(f"field classes: {len(classes)} ({Counter(classes.values())})")


_classes = None


def field_class(name):
    """address | bytes | string | protocol | checksum | other (anything not listed: numbers, booleans, times, ...)."""
    global _classes
    if _classes is None:
        _classes = json.loads(FIELD_CLASSES.read_text())
    if "checksum" in name or name.endswith((".crc", ".fcs")):
        return "checksum"
    return _classes.get(name, "other")


# ---- running tshark ---------------------------------------------------------------------------------------------

def limits(timeout=TIMEOUT_S):
    """In the child, before exec: memory, CPU time, no file writes, no core dumps."""
    mem = PROC_MEM_MB * 2**20
    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    resource.setrlimit(resource.RLIMIT_CPU, (timeout + 5, timeout + 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(args, on_line=None, timeout=TIMEOUT_S):
    """One tshark process: argv list (never a shell). Lines go to on_line (return False to stop early) or are
    collected. -> (lines or None, stopped_early). Raises Bad with tshark's message on failure or timeout."""
    p = subprocess.Popen(TSHARK + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                         env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}, preexec_fn=lambda: limits(timeout))
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    err = []
    def drain():  # read all of stderr (a full pipe would stall tshark), keep the first 8 KiB
        while True:
            chunk = p.stderr.read(65536)
            if not chunk:
                return
            if sum(map(len, err)) < 8192:
                err.append(chunk)
    t_err = threading.Thread(target=drain, daemon=True)
    t_err.start()
    out, stopped = [], False
    try:
        for raw in p.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if on_line is None:
                out.append(line)
            elif on_line(line) is False:
                stopped = True
                p.kill()
                break
    finally:
        p.stdout.close()
        rc = p.wait()
        timed_out = not timer.is_alive() and not stopped
        timer.cancel()
        t_err.join(10)  # the drain ends at EOF, i.e. right after tshark exits: collect the rest of its stderr
    if timed_out or rc == -signal.SIGXCPU:
        raise Bad(f"timeout: tshark ran longer than {timeout} s (narrow the filter or use a smaller file)")
    if rc != 0 and not stopped:
        msg = b"".join(err)[:8192].decode("utf-8", "replace")
        msg = "\n".join(l for l in msg.splitlines() if l.strip() and "Running as user" not in l)[:600]
        raise Bad(msg or f"tshark failed (exit {rc})")
    return (None if on_line else out), stopped


def resolve(ref):
    if not isinstance(ref, dict) or ref.get("root") not in ROOTS or not isinstance(ref.get("name"), str):
        raise Bad("file: {root: ring|upload|demo, name}")
    name = ref["name"]
    if not NAME_RE.fullmatch(name) or not name.endswith(FILE_SUFFIXES):
        raise Bad("file name not accepted")
    path = ROOTS[ref["root"]] / name
    try:
        st = os.lstat(path)
    except OSError:
        raise Bad("no such file") from None
    if not (st.st_mode & 0o170000) == 0o100000:  # regular file only (no symlink, device, fifo)
        raise Bad("not a regular file")
    return str(path)


def display_filter(f):
    f = f or ""
    if not isinstance(f, str) or len(f) > FILTER_MAX or not FILTER_CHARS.fullmatch(f):
        raise Bad("display filter: at most 512 characters of the allowed set")
    return ["-Y", f] if f.strip() else []


def fields_args(fields):
    out = ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f", "-E", "quote=n"]
    for f in fields:
        out += ["-e", f]
    return out


# ---- ops ------------------------------------------------------------------------------------------------------

def op_check(req):
    run(["-r", str(EMPTY_PCAP)] + display_filter(req.get("filter")), timeout=15)
    return {"ok": True}


PKT_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
              "eth.src", "eth.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len",
              "udp.srcport", "udp.dstport", "udp.length", "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code", "arp.opcode",
              "dns.flags.response", "dns.qry.type", "dns.qry.name", "tls.handshake.type", "tls.handshake.extensions_server_name",
              "http.request.method", "http.host", "http.response.code", "dhcp.option.dhcp"]


def op_packets(req, emit=None):
    """Typed fields per packet (PKT_FIELDS, first occurrence each) - never tshark's free-text columns: mask-api builds
    the summary from them. stream=True (and an emit): one JSON line per row as tshark produces it, then the summary
    object; else all rows in one reply. At most ANALYZER_MAX_ROWS rows either way."""
    rows, cap, count = [], min(int(req.get("max") or MAX_ROWS), MAX_ROWS), [0]
    stream = bool(req.get("stream")) and emit is not None
    n = len(PKT_FIELDS)

    def take(line):
        p = line.split("\t")
        if len(p) < n:
            return True
        row = [int(p[0] or 0), float(p[1] or 0), int(p[2] or 0)] + p[3:n]
        count[0] += 1
        if stream:
            emit(row)
        else:
            rows.append(row)
        return count[0] < cap
    _, stopped = run(["-r", resolve(req.get("file"))] + display_filter(req.get("filter")) + fields_args(PKT_FIELDS), take)
    return {"truncated": stopped, "count": count[0]} if stream else {"rows": rows, "truncated": stopped}


def display_names(names):
    """Registry display names (from `tshark -G fields` at image build) for field / protocol abbreviations."""
    names = sorted({n for n in names if n})
    out = {}
    db = sqlite3.connect(f"file:{FIELD_NAMES}?mode=ro&immutable=1", uri=True)
    try:
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            out.update(db.execute(f"SELECT a, d FROM n WHERE a IN ({','.join('?' * len(chunk))})", chunk).fetchall())
    finally:
        db.close()
    return out


def pdml_tree(xml_text):
    """PDML of one packet -> [{n, dn, s, p, z, k, c?, v?, x?, cl}] (hidden fields and generator info dropped).
    dn: the registry's display name; s: tshark's label (free text: mask-api never shows it as is)."""
    root = ET.fromstring(xml_text)
    pkt = root.find("packet")
    if pkt is None:
        raise Bad("no such packet")
    seen = []

    def node(e):
        name = e.get("name") or ""
        if e.get("hide") == "yes" or name == "geninfo":
            return None
        n = {"n": name, "s": e.get("showname") or e.get("show") or "", "k": "proto" if e.tag == "proto" else "field",
             "cl": "proto" if e.tag == "proto" else field_class(name) if name else "other"}
        if e.get("show") is not None and e.tag == "field":
            n["v"] = e.get("show")
        raw = e.get("unmaskedvalue") or e.get("value")  # the field's own bytes: mask-api reveals header bytes only
        if e.tag == "field" and raw and re.fullmatch(r"[0-9a-fA-F]+", raw):  # when they equal the frame's at pos
            n["x"] = raw
        try:
            n["p"], n["z"] = int(e.get("pos") or 0), int(e.get("size") or 0)
        except ValueError:
            n["p"], n["z"] = 0, 0
        seen.append(n)
        kids = [k for k in (node(c) for c in e) if k]
        if kids:
            n["c"] = kids
        return n
    tree = [x for x in (node(c) for c in pkt) if x]
    try:
        dn = display_names(n["n"] for n in seen)
    except sqlite3.Error:
        dn = {}
    for n in seen:
        if n["n"] in dn:
            n["dn"] = dn[n["n"]]
    return tree


def op_detail(req):
    path, no = resolve(req.get("file")), int(req.get("no") or 0)
    if not 0 < no < 2**31:
        raise Bad("no: a frame number")
    sel = ["-r", path, "-Y", f"frame.number == {no}"]
    pdml, _ = run(sel + ["-T", "pdml"])
    raw, _ = run(sel + ["-T", "json", "-x", "-j", "frame"])
    try:
        data = json.loads("\n".join(raw))
        hexs = data[0]["_source"]["layers"]["frame_raw"][0]
    except (ValueError, LookupError, TypeError):
        raise Bad("no such packet") from None
    return {"tree": pdml_tree("\n".join(pdml)), "hex": hexs}


def each_record(path, filt, fn):
    def take(line):
        p = line.split("\t")
        if len(p) >= len(FIELDS):
            fn(p)
    run(["-r", path] + display_filter(filt) + fields_args(FIELDS), take)


def addr_pair(p):
    src, dst = p[F["ip.src"]] or p[F["ipv6.src"]], p[F["ip.dst"]] or p[F["ipv6.dst"]]
    proto = p[F["ip.proto"]] or p[F["ipv6.nxt"]]
    sport = p[F["tcp.srcport"]] or p[F["udp.srcport"]]
    dport = p[F["tcp.dstport"]] or p[F["udp.dstport"]]
    return src, dst, proto, sport, dport


def nice_interval(span):
    for s in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400):
        if span / s <= 120:
            return s
    return 86400


# Memory of this server stays bounded whatever the file holds: every table has a key cap, keys past it are summed
# in one "_other" entry (the masking layer shows it as such); I/O is kept per second (per minute past IO_SECONDS).
STATS_KEYS = 20000
NAME_KEYS = 5000
IO_SECONDS = 172800  # per second up to here, then per hour, at most IO_MAX keys (overflow into the last one)
IO_MAX = IO_SECONDS + 10000
NAME_LEN = 255  # characters of a DNS / SNI / Host value kept
NAME_BYTES = 512 * 1024  # per names table; new names past it are summed in _other
FLOW_KEYS = 50000
HOST_KEYS = 4096
OTHER = "_other"


def slot(d, key, cap, other, make):
    v = d.get(key)
    if v is None:
        if len(d) >= cap:
            key = other
            v = d.get(key)
        if v is None:
            v = d[key] = make()
    return v


def op_stats(req):
    """Every statistics table from one pass, with bounded memory: protocol hierarchy, conversations (IP / TCP / UDP),
    endpoints (IP / Ethernet), I/O per interval, DNS query names, TLS SNI, HTTP Host."""
    phs, conv, ends, names, secs = {}, {"ip": {}, "tcp": {}, "udp": {}}, {"ip": {}, "eth": {}}, {"dns": {}, "sni": {}, "http": {}}, {}
    name_bytes, last_io = {"dns": 0, "sni": 0, "http": 0}, [None]
    total = [0, 0, None, None]

    def conv_add(table, a, b, size, t, other):
        fwd = a <= b
        c = slot(table, (a, b) if fwd else (b, a), STATS_KEYS, other, lambda: [0, 0, 0, 0, t, t])
        i = 0 if fwd else 2
        c[i] += 1
        c[i + 1] += size
        c[5] = t

    def rec(p):
        t, size = float(p[F["frame.time_epoch"]] or 0), int(p[F["frame.len"]] or 0)
        total[0] += 1
        total[1] += size
        total[2] = t if total[2] is None else min(total[2], t)
        total[3] = t if total[3] is None else max(total[3], t)
        sec = int(t) if len(secs) < IO_SECONDS or int(t) in secs else int(t) // 3600 * 3600
        if sec not in secs and len(secs) >= IO_MAX:
            sec = last_io[0]  # hard cap: the rest goes into the last bucket
        last_io[0] = sec
        b = secs.setdefault(sec, [0, 0])
        b[0] += 1
        b[1] += size
        parts = (p[F["frame.protocols"]] or "").split(":")
        for i in range(1, len(parts) + 1):
            x = slot(phs, ":".join(parts[:i]), 2000, OTHER, lambda: [0, 0])
            x[0] += 1
            x[1] += size
        src, dst, proto, sport, dport = addr_pair(p)
        if src and dst:
            conv_add(conv["ip"], src, dst, size, t, (OTHER, OTHER))
            for a, i in ((src, 0), (dst, 2)):
                e = slot(ends["ip"], a, STATS_KEYS, OTHER, lambda: [0, 0, 0, 0])
                e[i] += 1
                e[i + 1] += size
            kind = "tcp" if p[F["tcp.srcport"]] else "udp" if p[F["udp.srcport"]] else None
            if kind:
                conv_add(conv[kind], f"{src}|{sport}", f"{dst}|{dport}", size, t, (OTHER + "|", OTHER + "|"))
        for a, i in ((p[F["eth.src"]], 0), (p[F["eth.dst"]], 2)):
            if a:
                e = slot(ends["eth"], a, STATS_KEYS, OTHER, lambda: [0, 0, 0, 0])
                e[i] += 1
                e[i + 1] += size
        for k, f in (("dns", "dns.qry.name"), ("sni", "tls.handshake.extensions_server_name"), ("http", "http.host")):
            v = p[F[f]][:NAME_LEN]
            if v:
                if v not in names[k] and name_bytes[k] >= NAME_BYTES:
                    v = OTHER
                elif v not in names[k]:
                    name_bytes[k] += len(v)
                c = slot(names[k], v, NAME_KEYS, OTHER, lambda: [0])
                c[0] += 1
    each_record(resolve(req.get("file")), req.get("filter"), rec)
    t0, t1 = total[2] or 0, total[3] or 0
    step = nice_interval(max(1.0, t1 - t0))
    io = defaultdict(lambda: [0, 0])
    for sec, (n, size) in secs.items():
        b = io[int(max(0.0, sec - t0) // step)]
        b[0] += n
        b[1] += size
    top = lambda d, key: sorted(d.items(), key=key, reverse=True)[:TOP_N]
    return {
        "packets": total[0], "bytes": total[1], "t0": t0, "t1": t1,
        "phs": [[k, v[0], v[1]] for k, v in sorted(phs.items())],
        "conv": {k: [[a, b, *v] for (a, b), v in top(d, lambda kv: kv[1][1] + kv[1][3])] for k, d in conv.items()},
        "endpoints": {k: [[a, *v] for a, v in top(d, lambda kv: kv[1][1] + kv[1][3])] for k, d in ends.items()},
        "io": {"step": step, "buckets": io_buckets(io, t0, step)},
        "names": {k: [[name, v[0]] for name, v in top(c, lambda kv: kv[1][0])] for k, c in names.items()},
    }


def io_buckets(io, t0, step):
    """Every bucket between the first and the last (quiet ones as zeros, so the chart shows the gaps), at most IO_MAX."""
    if not io:
        return []
    lo, hi = min(io), max(io)
    hi = min(hi, lo + IO_MAX - 1)
    return [[t0 + i * step, *io.get(i, (0, 0))] for i in range(lo, hi + 1)]


def op_flows(req, emit=None):
    """5-tuple aggregates per second of capture time, for flowd, plus what names hosts: DHCP host names (by MAC),
    DHCP leases and ARP (IP <-> MAC), and the Ethernet source of IP packets. Bounded: at most FLOW_KEYS 5-tuple x
    second keys (bytes past it are only counted: overflow_bytes) and HOST_KEYS names / leases. With emit: one JSON line
    per bucket, then the summary object (flowd reads it as a stream)."""
    buckets, names, ip_mac = {}, {}, {}
    span, over = [None, None], [0]

    def rec(p):
        t, size = float(p[F["frame.time_epoch"]] or 0), int(p[F["frame.len"]] or 0)
        span[0] = t if span[0] is None else min(span[0], t)
        span[1] = t if span[1] is None else max(span[1], t)
        src, dst, proto, sport, dport = addr_pair(p)
        if src and dst:
            key = (int(t), src, dst, proto, sport, dport)
            b = buckets.get(key)
            if b is None:
                if len(buckets) >= FLOW_KEYS:
                    over[0] += size
                    b = None
                else:
                    b = buckets[key] = [0, 0]
            if b is not None:
                b[0] += size
                b[1] += 1
            if p[F["eth.src"]] and p[F["ip.src"]] and src != "0.0.0.0" and (src in ip_mac or len(ip_mac) < HOST_KEYS):
                ip_mac.setdefault(src, p[F["eth.src"]])
        mac, host = p[F["dhcp.hw.mac_addr"]], p[F["dhcp.option.hostname"]]
        if mac and host and (mac in names or len(names) < HOST_KEYS):
            names[mac] = host
        lease = p[F["dhcp.ip.your"]] or p[F["dhcp.option.requested_ip_address"]]
        if mac and lease and lease != "0.0.0.0" and (lease in ip_mac or len(ip_mac) < HOST_KEYS):
            ip_mac[lease] = mac
        a, m = p[F["arp.src.proto_ipv4"]], p[F["arp.src.hw_mac"]]
        if a and m and (a in ip_mac or len(ip_mac) < HOST_KEYS):
            ip_mac[a] = m
    each_record(resolve(req.get("file")), None, rec)
    summary = {"names": names, "ip_mac": ip_mac, "t0": span[0], "t1": span[1], "overflow_bytes": over[0], "count": len(buckets)}
    if emit is None:
        return {"buckets": [[*k, *v] for k, v in buckets.items()], **summary}
    while buckets:
        k, v = buckets.popitem()
        emit([*k, *v])
    return summary


def op_validate(req):
    """Read the whole file (an upload before it is published): any unreadable or cut-short record fails (Bad)."""
    count = [0]

    def take(line):
        count[0] += 1
    run(["-r", resolve(req.get("file")), "-T", "fields", "-e", "frame.number"], take, timeout=VALIDATE_TIMEOUT_S)
    if not count[0]:
        raise Bad("no packets in the file")
    return {"ok": True, "count": count[0]}


def op_fieldtypes(req):
    names = req.get("names")
    if not isinstance(names, list) or len(names) > 64 or not all(isinstance(n, str) and len(n) <= 128 for n in names):
        raise Bad("names: up to 64 field names")
    return {"classes": {n: field_class(n) for n in names}}


OPS = {"ping": lambda r: {"ok": True, "version": TSHARK_VERSION}, "fieldtypes": op_fieldtypes, "check": op_check, "validate": op_validate,
       "packets": op_packets, "detail": op_detail, "stats": op_stats, "flows": op_flows}
LIGHT = {"ping", "fieldtypes"}  # answered without a tshark process: not counted against the concurrency cap
SLOTS = threading.BoundedSemaphore(CONCURRENCY)
FLOW_SLOTS = threading.BoundedSemaphore(1)  # flowd's own lane: the screens can never starve the flow source
TSHARK_VERSION = ""


def answer(req, emit=None):
    op = req.get("op") if isinstance(req, dict) else None
    if op not in OPS:
        return {"error": "unknown op"}
    if op in LIGHT:
        return OPS[op](req)
    slots = FLOW_SLOTS if req.get("lane") == "flows" and op == "flows" else SLOTS
    if not slots.acquire(timeout=2 if slots is SLOTS else 60):
        return {"error": "busy: too many analyses running; try again shortly", "busy": True}
    t0 = time.monotonic()
    try:
        out = op_packets(req, emit) if op == "packets" else op_flows(req, emit) if op == "flows" and req.get("stream") else OPS[op](req)
    finally:
        slots.release()
    out["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
    return out


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(MAX_REQUEST + 1)
        t0 = time.monotonic()
        try:
            if len(line) > MAX_REQUEST:
                raise Bad("request too large")
            req = json.loads(line)
            out = answer(req, lambda row: self.wfile.write(json.dumps(row, separators=(",", ":")).encode() + b"\n"))
        except Bad as e:
            out, req = {"error": str(e)}, locals().get("req")
        except (ValueError, TypeError, KeyError) as e:
            out, req = {"error": f"bad request ({type(e).__name__})"}, None
        self.wfile.write(json.dumps(out, separators=(",", ":")).encode() + b"\n")
        op = req.get("op") if isinstance(req, dict) else "?"
        print(f"{op} {'error' if 'error' in out else 'ok'} {int((time.monotonic() - t0) * 1000)}ms", flush=True)  # never the filter / file


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve():
    global TSHARK_VERSION
    TSHARK_VERSION = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.split("\n")[0].strip()
    Path(SOCKET).unlink(missing_ok=True)
    srv = Server(SOCKET, Handler)
    os.chmod(SOCKET, 0o666)  # the socket volume is shared with mask-api and flowd only
    print(f"analyzer: {TSHARK_VERSION}, socket {SOCKET}, {CONCURRENCY} at a time, timeout {TIMEOUT_S} s", flush=True)
    srv.serve_forever()


def call(req, sock_path=SOCKET, timeout=TIMEOUT_S * 2 + 10):
    """Client side (also used by mask-api / flowd via a copy of these few lines): one request, one reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def selftest():
    demo = {"root": "demo", "name": "demo-home.pcap"}
    for bad in ({"root": "demo", "name": "../etc/passwd"}, {"root": "etc", "name": "x.pcap"}, {"root": "demo", "name": "a.txt"},
                {"root": "demo", "name": "-r.pcap"}):
        try:
            resolve(bad)
            raise AssertionError(bad)
        except Bad:
            pass
    for f in ('ip.src == 1.2.3.4 ; rm', "$(id)", "x" * 513, "frame[0:4] == 00:00", 'a\nb', "lua_script:x"):
        try:
            display_filter(f)
            if ":" in f and "[" not in f and ";" not in f:
                continue  # ':' is allowed (MAC / IPv6 / field names); the policy layer judges it
            raise AssertionError(f)
        except Bad:
            pass
    assert op_check({"filter": "dns"})["ok"]
    try:
        op_check({"filter": "nosuch.field == 1"})
        raise AssertionError("invalid filter accepted")
    except Bad as e:
        assert "nosuch.field" in str(e), e
    rows = op_packets({"file": demo, "filter": "dns"})["rows"]
    assert rows and all(r[3].endswith(":dns") and r[PKT_FIELDS.index("dns.qry.name")] for r in rows), rows[:2]
    d = op_detail({"file": demo, "no": rows[0][0]})
    flat = []
    walk = lambda ns: [flat.append(n) or walk(n.get("c", [])) for n in ns]
    walk(d["tree"])
    src = next(n for n in flat if n["n"] == "ip.src")
    assert src["cl"] == "address" and src["z"] == 4 and d["hex"][src["p"] * 2:src["p"] * 2 + 8] == "c0a86417", src
    assert src.get("x") == "c0a86417", src  # the field's own bytes, for mask-api's frame check
    assert src.get("dn") == "Source Address" and d["tree"][1].get("dn") == "Ethernet II" or d["tree"][1].get("dn"), d["tree"][1].get("dn")
    got = []
    tail = op_packets({"file": demo, "filter": "dns", "stream": True}, got.append)
    assert tail["count"] == len(got) == len(rows) and got[0] == rows[0] and "rows" not in tail
    assert any(n["n"] == "ip.checksum" and n["cl"] == "checksum" for n in flat)
    assert any(n["n"] == "dns.qry.name" and n["cl"] == "string" for n in flat)
    st = op_stats({"file": demo})
    assert st["packets"] == len(op_packets({"file": demo})["rows"]) and any(p[0] == "eth:ethertype:ip:udp:dns" for p in st["phs"])
    assert dict(st["names"]["sni"]) and dict(st["names"]["http"]) and st["conv"]["tcp"] and st["io"]["buckets"]
    streamed = []
    summ = op_flows({"file": demo}, streamed.append)
    assert summ["count"] == len(streamed) and "buckets" not in summ and summ["overflow_bytes"] == 0
    fl = op_flows({"file": demo})
    assert fl["names"]["02:00:5e:10:00:17"] == "pc-living" and fl["ip_mac"]["192.168.100.23"] == "02:00:5e:10:00:17", fl["names"]
    assert any(b[2] == "192.0.2.10" for b in fl["buckets"])
    assert field_class("ip.src") == "address" and field_class("eth.dst") == "address" and field_class("frame") == "protocol"
    assert field_class("tcp.checksum") == "checksum" and field_class("tcp.port") == "other" and field_class("data.data") == "bytes"
    assert op_validate({"file": demo})["count"] == st["packets"]
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:  # a cut-short upload fails validation as a whole
        whole = (ROOTS["demo"] / "demo-home.pcap").read_bytes()
        (Path(tmp) / "cut.pcap").write_bytes(whole[: len(whole) * 2 // 3 + 7])
        was, ROOTS["upload"] = ROOTS["upload"], Path(tmp)
        try:
            op_validate({"file": {"root": "upload", "name": "cut.pcap"}})
            raise AssertionError("cut-short file validated")
        except Bad:
            pass
        finally:
            ROOTS["upload"] = was
    assert io_buckets({0: [1, 10], 3: [2, 20]}, 100.0, 5) == [[100.0, 1, 10], [105.0, 0, 0], [110.0, 0, 0], [115.0, 2, 20]]
    assert io_buckets({}, 0, 1) == [] and len(io_buckets({0: [1, 1], 10**9: [1, 1]}, 0, 1)) == IO_MAX
    print("analyzer selftest ok")


if __name__ == "__main__":
    if "--build-fields" in sys.argv:
        build_fields()
    elif "--selftest" in sys.argv:
        selftest()
    else:
        serve()
