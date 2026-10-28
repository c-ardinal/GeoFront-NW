"""Packet analysis API for the command-center (/pcap/, through the proxy): list capture files, upload / delete a
pcap, and read packet lists, packet details (tree + hex), statistics and display-filter checks - all MASKED.

tshark never runs here: every analysis is a request to the analyzer sandbox (analyzer/analyzer.py: no network,
read-only, non-root) over its Unix socket. This module decides what may be asked and masks what comes back.
Every rule is fail-closed (an allowlist), not a list of known leaks:

- Display filters: pcap_filter.py - an allowlist grammar over curated fields; addresses only as opaque tokens.
- Hex view: every byte is masked unless it belongs to a field on REVEAL (header fields such as ports, flags,
  lengths, type codes; names only when their text cannot hold an address) AND the field's own bytes, as the
  dissector reported them, are exactly the frame's bytes at that offset (so fields from reassembled / decrypted /
  decompressed data, which have offsets into another buffer, never unmask anything). Payloads, byte fields,
  addresses, checksums, unknown and hidden fields stay "xx".
- Address-typed values (by the analyzer's field classes): IPv4 a.b.c.x, IPv6 <its /64>::x, MAC aa:bb:cc:xx:xx:xx,
  each with an opaque token (~<12 hex>, the same tokens mask-api gives Prometheus labels) so rows stay distinct
  and a drill-down can filter on them. The Info column is built from typed fields, tree labels from field names.
- Free text (names, labels without a value, file names, tshark's messages): no part of any address (mask_free).
Unmasking needs the future authentication layer (SEC-03): there is no switch for it here.

Writes (upload, delete an upload) follow the silence rules of mask-api: 127.0.0.1 exposure (or a trusted operator
role), same origin + X-Obs-Csrf, rate limit; size, extension and magic bytes checked, total size and age capped.
Reads that run the analyzer are rate limited per client.
"""
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
import unicodedata
import urllib.parse
from collections import Counter, OrderedDict
from pathlib import Path

import pcap_filter
from pcap_filter import Refused

M = None  # the mask_api module (setup): its token store, masking and write guards are shared

ANALYZER_SOCKET = os.environ.get("ANALYZER_SOCKET", "/run/analyzer/analyzer.sock")
ANALYZER_TIMEOUT_S = int(os.environ.get("ANALYZER_TIMEOUT", "60"))
VALIDATE_TIMEOUT_S = max(ANALYZER_TIMEOUT_S, int(os.environ.get("ANALYZER_VALIDATE_TIMEOUT", "180")))
RING = Path(os.environ.get("PCAP_RING_DIR", "/capture/ring"))
CAPTURE_STATUS = Path(os.environ.get("PCAP_CAPTURE_STATUS", "/capture/status.json"))
UPLOADS = Path(os.environ.get("PCAP_UPLOAD_DIR", "/uploads"))
DEMO = Path(os.environ.get("PCAP_DEMO_DIR", "/demo"))
UPLOAD_MAX = int(os.environ.get("PCAP_UPLOAD_MAX_MB", "50")) * 2**20
UPLOADS_TOTAL_MAX = int(os.environ.get("PCAP_UPLOADS_TOTAL_MB", "200")) * 2**20
KEEP_S = float(os.environ.get("PCAP_KEEP_HOURS", "24")) * 3600
PRUNE_EVERY_S = 600
READS_PER_MIN = int(os.environ.get("PCAP_READS_PER_MIN", "120"))  # analyzer runs per client and minute
PAGE_MAX = 1000
SUFFIXES = (".pcap", ".pcapng", ".cap")
MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
STORED_RE = re.compile(r"u\d{14}-[0-9a-f]{12}\.(?:pcapng|pcap|cap)")  # opaque: nothing of the uploaded name
RING_NAME = re.compile(r"obs-\d{10}_\d{5,}_\d{14}\.pcapng|obs_\d{5,}_\d{14}\.pcapng|demo-home\.pcap")  # generated names
FILE_ID = re.compile(r"(ring|upload|demo):([A-Za-z0-9][A-Za-z0-9._-]{0,127})")

# a MAC only when nothing hex or separator touches it (else e.g. 8 colon groups could be misaligned)
MAC_TEXT = re.compile(r"(?<![0-9A-Za-z:\-.])([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}(?![0-9A-Za-z:\-])")

TOK_V4 = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.x~([0-9a-f]{12})")
TOK_V6 = re.compile(r"([0-9a-f:]*)::x~([0-9a-f]{12})")
TOK_MAC = re.compile(r"((?:[0-9a-f]{2}:){3})xx:xx:xx~([0-9a-f]{12})")

# Hex view reveal-list: header fields whose bytes carry no address and nothing an address could be computed from.
REVEAL = set("""eth.type vlan.priority vlan.dei vlan.id vlan.etype vlan.len
    ip.version ip.hdr_len ip.dsfield ip.dsfield.dscp ip.dsfield.ecn ip.len ip.id ip.flags ip.flags.rb ip.flags.df ip.flags.mf
    ip.frag_offset ip.ttl ip.proto
    ipv6.version ipv6.tclass ipv6.tclass.dscp ipv6.tclass.ecn ipv6.flow ipv6.plen ipv6.nxt ipv6.hlim
    tcp.srcport tcp.dstport tcp.seq_raw tcp.ack_raw tcp.hdr_len tcp.flags tcp.flags.res tcp.flags.ae tcp.flags.cwr tcp.flags.ece
    tcp.flags.urg tcp.flags.ack tcp.flags.push tcp.flags.reset tcp.flags.syn tcp.flags.fin tcp.window_size_value tcp.urgent_pointer
    udp.srcport udp.dstport udp.length icmp.type icmp.code icmp.ident icmp.seq icmpv6.type icmpv6.code
    arp.hw.type arp.proto.type arp.hw.size arp.proto.size arp.opcode
    dns.id dns.flags dns.flags.response dns.flags.opcode dns.flags.authoritative dns.flags.truncated dns.flags.recdesired
    dns.flags.recavail dns.flags.z dns.flags.authenticated dns.flags.checkdisable dns.flags.rcode dns.count.queries
    dns.count.answers dns.count.auth_rr dns.count.add_rr dns.qry.type dns.qry.class dns.resp.type dns.resp.class dns.resp.ttl
    dns.resp.len tls.record.content_type tls.record.version tls.record.length tls.handshake.type tls.handshake.length
    tls.handshake.version ntp.flags ntp.flags.li ntp.flags.vn ntp.flags.mode ntp.stratum ntp.ppoll ntp.precision
    dhcp.type dhcp.hw.type dhcp.hw.len dhcp.hops dhcp.id dhcp.secs dhcp.flags dhcp.option.type dhcp.option.length
    dhcp.option.dhcp""".split())
# names: revealed only when their text is a plain host name (no digit, no ':', unchanged by masking)
REVEAL_NAMES = {"dns.qry.name", "dns.resp.name", "tls.handshake.extensions_server_name", "http.host", "http.request.method"}
PLAIN_NAME = re.compile(r"[A-Za-z._\- ]{1,253}")


def setup(mask_module):
    global M
    M = mask_module
    threading.Thread(target=prune_loop, daemon=True).start()


# ---- masking --------------------------------------------------------------------------------------------------

def token(addr):
    t = hmac.new(M.KEY, addr.encode(), hashlib.sha256).hexdigest()[:M.TOKEN_LEN]
    M.TOKENS[t] = addr  # bounded LRU (mask_api.TokenStore)
    return t


def with_tokens(make):
    """-> (make(), {token: address} of the tokens it made). A cached result keeps its tokens beside it: serving it
    again re-registers them, so the LRU token table cannot expire tokens that a cached list / statistics still shows."""
    got = M.TOKENS.pins.d = {}
    try:
        return make(), got
    finally:
        M.TOKENS.pins.d = None


def reregister(tokens, only=None):
    for t in (tokens if only is None else only):
        if t in tokens:
            M.TOKENS[t] = tokens[t]


TOKEN_IN_TEXT = re.compile(r"~([0-9a-f]{12})")


def v6_base(ip):
    """The visible part of an IPv6 address: its /64, except where an IPv4 address is inside it - IPv4-mapped /
    NAT64 (the IPv4 is masked like any IPv4), 6to4 2002::/16 and Teredo 2001::/32 (IPv4 inside the /64: all hidden)."""
    v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.ipv4_mapped:
        return "::ffff:" + str(v4).rsplit(".", 1)[0] + ".x"
    if ip in ipaddress.IPv6Network("64:ff9b::/96"):
        return "64:ff9b::" + str(v4).rsplit(".", 1)[0] + ".x"
    if ip in ipaddress.IPv6Network("2002::/16"):
        return "2002::x"
    if ip in ipaddress.IPv6Network("2001::/32"):
        return "2001::x"
    net = str(ipaddress.IPv6Address(int(ip) >> 64 << 64))
    return (net if net.endswith("::") else net + "::") + "x"


def mask_v6(a, with_token=True):
    try:
        ip = ipaddress.IPv6Address(a.split("%")[0])
    except ValueError:
        return None
    base = v6_base(ip)
    t = token(str(ip)) if with_token else None
    return f"{base}~{t}" if t else base


def mask_addr(v):
    """One address value (IPv4 / IPv6 / MAC) -> its masked form with a token; anything else -> masked text."""
    v = (v or "").strip()
    if M.IPV4.fullmatch(v):
        return M.mask_value(v)
    if MAC_TEXT.fullmatch(v):
        mac = v.lower().replace("-", ":")
        t = token(mac)
        return mac[:9] + "xx:xx:xx" + (f"~{t}" if t else "")
    if ":" in v:
        m = mask_v6(v)
        if m:
            return m
    return mask_free(v)


# ---- free text: fail-closed -------------------------------------------------------------------------------------
# Free text (anything that is not a typed address field: names, labels without a value, file names, messages) never
# shows any part of an address. After NFKC (fullwidth -> ASCII) and every other Unicode number character -> "0":
# - a reverse-DNS name (...in-addr.arpa / ...ip6.arpa): all labels before the suffix become one "x"
# - a run of 6+ base64 characters ending in "==" (4 / 16 bytes are 6 / 22 chars + "=="), glued prefix included
# - every run of hex characters that holds a digit (any dotted quad in any order, e.g. reversed in DNSBL names)
# - every token of hex characters only, of any length, between non-alphanumerics or the ends ("a", "bad", "cafe",
#   "a-b-c-d", "b.b.a.a"), and a hex-letter run of 2+ touching one ("ESP_DDEEFF", "_ddYamaha")
# Ordinary words get over-masked by design ("a" -> "x"). Typed address fields keep a.b.c.x / <64>::x (mask_addr).
ARPA_NAME = re.compile(r"(?:[A-Za-z0-9_-]+\.)+(in-addr|ip6)\.arpa(?![A-Za-z0-9-])", re.I)
ARPA_KEEP = {"in-addr": "\ue001", "ip6": "\ue002"}  # placeholders: the suffix itself is not masked
BASE64_ADDR = re.compile(r"[A-Za-z0-9+/]{6,}==")
HEXISH = re.compile(r"[0-9A-Fa-f]+")
HEX_WORD = re.compile(r"(?<![A-Za-z0-9])[0-9A-Fa-f]+(?![A-Za-z0-9])")
HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[A-Fa-f]{2,}(?![0-9A-Fa-f])")


def ascii_digits(s):
    s = unicodedata.normalize("NFKC", s)
    if s.isascii():
        return s
    return "".join("0" if not c.isascii() and unicodedata.category(c).startswith("N") else c for c in s)


def digit_safe(s):
    s = ascii_digits(s).replace("\ue001", "").replace("\ue002", "")
    s = ARPA_NAME.sub(lambda m: "x." + ARPA_KEEP[m.group(1).lower()] + ".arpa", s)
    s = BASE64_ADDR.sub("x", s)
    s = HEXISH.sub(lambda m: "x" if any(c.isdigit() for c in m.group(0)) else m.group(0), s)
    s = HEX_WORD.sub("x", s)
    edge = lambda c: not c.isalnum() or c == "x"
    s = HEX_TOKEN.sub(lambda m: "x" if edge(m.string[m.start() - 1] if m.start() else " ") or edge(m.string[m.end()] if m.end() < len(m.string) else " ")
                      else m.group(0), s)
    s = re.sub(r"x{2,}", "x", s)
    return s.replace("\ue001", "in-addr").replace("\ue002", "ip6")


def mask_free(s):
    """Any free text that reaches the client: no part of any address, in any notation (over-masking by design)."""
    return digit_safe(s) if s else s


# + this API's own message words; each holds a non-hex letter, so none can be (a group of) an address
KEEP_WORDS = sorted(set(pcap_filter.FIELDS) | {"contains", "matches", "and", "or", "not", "in", "upload", "demo", "ring", "address",
                                               "damaged", "decode"}, key=len, reverse=True)
KEEP_RE = re.compile(r"(?<![A-Za-z0-9_.])(?:" + "|".join(re.escape(w) for w in KEEP_WORDS) + r")(?![A-Za-z0-9_])")


def mask_message(s):
    """An analyzer / tshark message: free text, but the allowlisted field names and keywords it quotes stay readable."""
    keep = []

    def hold(m):
        keep.append(m.group(0))
        return f"{chr(0xE100 + len(keep) - 1)}"
    s = KEEP_RE.sub(hold, (s or "").replace("", ""))
    return re.sub("(.)", lambda m: keep[ord(m.group(1)) - 0xE100], mask_free(s))


def revealable(n, data):
    """A leaf field's bytes may be shown: on the reveal-list, and its own bytes are the frame's bytes at its offset."""
    name, p, z, raw = n.get("n", ""), n.get("p", 0), n.get("z", 0), (n.get("x") or "").lower()
    if z <= 0 or not raw or p + z > len(data) or data[p:p + z].hex() != raw:
        return False
    if name in REVEAL:
        return True
    v = n.get("v") or ""
    return name in REVEAL_NAMES and bool(PLAIN_NAME.fullmatch(v)) and mask_free(v) == v


# Tree labels are rendered here, never taken from tshark: "<registry display name>: <value>", the value by its type.
# Numbers are shown only for these fields (header fields without address content, frame times / lengths), else "x".
SHOW_VALUES = REVEAL | set("""frame.time frame.time_utc frame.time_epoch frame.time_relative frame.time_delta frame.time_delta_displayed
    frame.number frame.len frame.cap_len frame.encap_type frame.marked frame.ignored frame.offset_shift
    tcp.len tcp.stream udp.stream eth.stream ip.stream ipv6.stream tcp.seq tcp.ack tcp.nxtseq tcp.window_size
    tcp.window_size_scalefactor tcp.time_relative tcp.time_delta tcp.analysis.ack_rtt tcp.analysis.bytes_in_flight
    tcp.analysis.push_bytes_sent tcp.completeness tcp.stream.pnum udp.stream.pnum udp.time_relative udp.time_delta
    dns.time dns.response_to dns.response_in tls.handshake.ciphersuite tls.handshake.extension.type
    tls.handshake.extension.len tls.handshake.extensions_length tls.handshake.session_id_length tls.handshake.cipher_suites_length
    tls.handshake.comp_methods_length tls.handshake.comp_method tls.handshake.extensions_server_name_list_len
    tls.handshake.extensions_server_name_type tls.handshake.extensions_server_name_len http.response.code http.content_length
    http.request.version http.response.version icmpv6.nd.ns.reserved""".split())
BOOLEAN = re.compile(r"True|False")
NUMERIC = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)(?: [A-Za-z]{1,4})?|[A-Z][a-z]{2} \d{1,2}, \d{4} [\d:.]+ [A-Z]{1,5}")


def tree_label(n):
    """One tree line, built from typed data. Nameless text items and labels without a value (tshark's free text)
    go through the digit-safe masker."""
    name, cl, v, dn = n.get("n", ""), n.get("cl"), n.get("v"), n.get("dn")
    if n.get("k") == "proto":
        return dn or mask_free(n.get("s", ""))
    if not name or v is None:
        return mask_free(n.get("s", ""))
    if cl == "address":
        value = mask_addr(v).split("~")[0]
    elif cl == "checksum":
        value = "[masked]"
    elif cl == "bytes":
        value = "[bytes]"
    elif cl == "string":
        value = mask_free(v)
    elif BOOLEAN.fullmatch(v) or (name in SHOW_VALUES and NUMERIC.fullmatch(v)):
        value = v
    else:
        value = "x"
    return f"{dn or name}: {value}"


# The Info column: built from typed fields (analyzer PKT_FIELDS), never tshark's free-text column.
TCP_FLAGS = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))
DHCP_TYPES = {"1": "Discover", "2": "Offer", "3": "Request", "4": "Decline", "5": "ACK", "6": "NAK", "7": "Release", "8": "Inform"}
TLS_TYPES = {"1": "Client Hello", "2": "Server Hello", "4": "New Session Ticket", "11": "Certificate", "16": "Client Key Exchange"}
ICMP_TYPES = {"0": "Echo reply", "3": "Destination unreachable", "5": "Redirect", "8": "Echo request", "11": "Time exceeded"}
PROTO_NAMES = {"eth": "Ethernet", "ip": "IPv4", "ipv6": "IPv6", "arp": "ARP", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
               "icmpv6": "ICMPv6", "dns": "DNS", "mdns": "MDNS", "tls": "TLS", "http": "HTTP", "dhcp": "DHCP", "ntp": "NTP",
               "quic": "QUIC", "ssdp": "SSDP", "igmp": "IGMP", "stun": "STUN", "syslog": "Syslog", "nbns": "NBNS", "snmp": "SNMP"}
PKT = ["protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "eth.src", "eth.dst", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
       "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len", "udp.srcport", "udp.dstport", "udp.length", "icmp.type", "icmp.code",
       "icmpv6.type", "icmpv6.code", "arp.opcode", "dns.flags.response", "dns.qry.type", "dns.qry.name", "tls.handshake.type",
       "tls.handshake.extensions_server_name", "http.request.method", "http.host", "http.response.code", "dhcp.option.dhcp"]
DIGITS = re.compile(r"\d{1,10}")


def packet_summary(row):
    """Analyzer row [no, t, len, *PKT values] -> [no, t, src, dst, protocol, len, info] (masked)."""
    no, t, ln = row[0], row[1], row[2]
    f = dict(zip(PKT, row[3:]))
    num = lambda k: f.get(k) if DIGITS.fullmatch(f.get(k) or "") else None
    layers = [x for x in (f.get("protocols") or "").split(":") if x and x not in ("ethertype", "data")]
    top = layers[-1] if layers else ""
    proto = PROTO_NAMES.get(top, re.sub(r"[^A-Za-z]", "", top).upper()[:12] or "?")
    src = f.get("ip.src") or f.get("ipv6.src") or f.get("arp.src.proto_ipv4") or f.get("eth.src") or ""
    dst = f.get("ip.dst") or f.get("ipv6.dst") or f.get("arp.dst.proto_ipv4") or f.get("eth.dst") or ""
    info = []
    if f.get("arp.opcode"):
        info.append({"1": "request (who has)", "2": "reply (is at)"}.get(f["arp.opcode"], "ARP"))
    if num("tcp.srcport"):
        try:
            flags = int(f.get("tcp.flags") or "0", 16)
        except ValueError:
            flags = 0
        names = [n for b, n in TCP_FLAGS if flags & b]
        info.append(f"{f['tcp.srcport']} → {num('tcp.dstport') or '?'} [{', '.join(names)}] Len={num('tcp.len') or 0}")
    elif num("udp.srcport"):
        info.append(f"{f['udp.srcport']} → {num('udp.dstport') or '?'} Len={num('udp.length') or 0}")
    for k in ("icmp", "icmpv6"):
        if num(f"{k}.type"):
            info.append(f"{ICMP_TYPES.get(f[f'{k}.type'], 'type ' + f[f'{k}.type']) if k == 'icmp' else 'type ' + f[f'{k}.type']} code {num(f'{k}.code') or 0}")
    if f.get("dns.qry.name") or num("dns.qry.type"):
        resp = (f.get("dns.flags.response") or "") in ("1", "True")
        info.append(f"{'response' if resp else 'query'} type {num('dns.qry.type') or '?'} {mask_free(f.get('dns.qry.name') or '')}".strip())
    if num("tls.handshake.type"):
        sni = f.get("tls.handshake.extensions_server_name")
        info.append(TLS_TYPES.get(f["tls.handshake.type"], "Handshake " + f["tls.handshake.type"]) + (f" SNI={mask_free(sni)}" if sni else ""))
    if f.get("http.request.method"):
        info.append(f"{mask_free(f['http.request.method'])} {mask_free(f.get('http.host') or '')}".strip())
    elif num("http.response.code"):
        info.append(f"response {f['http.response.code']}")
    if num("dhcp.option.dhcp"):
        info.append("DHCP " + DHCP_TYPES.get(f["dhcp.option.dhcp"], f["dhcp.option.dhcp"]))
    return [no, t, mask_addr(src) if src else "", mask_addr(dst) if dst else "", proto, ln, " · ".join(info)]


def mask_detail(tree, hexs):
    """Analyzer detail -> masked tree + hex (bytes as 2-char hex, null = masked). Hex: default masked, see REVEAL."""
    data = bytes.fromhex(hexs)
    shown = [False] * len(data)

    def walk(n):
        cl = n.get("cl")
        out = {"n": n.get("n", ""), "s": tree_label(n), "p": n.get("p", 0), "z": n.get("z", 0), "k": n.get("k")}
        if cl == "address" and n.get("v"):
            out["v"] = mask_addr(n["v"])
        # leaves only: a container's range covers its children (a DHCP option's type spans its address value)
        if n.get("k") != "proto" and not n.get("c") and cl not in ("address", "checksum", "bytes") and revealable(n, data):
            for i in range(out["p"], out["p"] + out["z"]):
                shown[i] = True
        if "c" in n:
            out["c"] = [walk(c) for c in n["c"]]
        return out
    masked = [walk(n) for n in tree]
    return {"tree": masked, "bytes": [f"{x:02x}" if s else None for x, s in zip(data, shown)], "masked": shown.count(False)}


def mask_ip_port(v):
    ip, _, port = v.rpartition("|")
    return {"addr": mask_addr(ip), "port": port}


def mask_stats(st):
    names = {}
    for k, rows in st.get("names", {}).items():
        c = Counter()
        for name, n in rows:
            c[mask_free(name)] += n  # names that become equal once masked are merged
        names[k] = c.most_common()
    return {
        "packets": st["packets"], "bytes": st["bytes"], "t0": st["t0"], "t1": st["t1"], "phs": st["phs"], "io": st["io"],
        "conv": {"ip": [[mask_addr(a), mask_addr(b), *v] for a, b, *v in st["conv"]["ip"]],
                 **{k: [[mask_ip_port(a), mask_ip_port(b), *v] for a, b, *v in st["conv"][k]] for k in ("tcp", "udp")}},
        "endpoints": {k: [[mask_addr(a), *v] for a, *v in rows] for k, rows in st["endpoints"].items()},
        "names": names,
    }


# ---- analyzer client ------------------------------------------------------------------------------------------

class AnalyzerDown(RuntimeError):
    pass


class Busy(RuntimeError):
    pass


_client = threading.local()  # the requesting client (rate limit per client)
_reads, _reads_lock = {}, threading.Lock()


def read_budget():
    who = getattr(_client, "who", "local")
    now = time.monotonic()
    with _reads_lock:
        if len(_reads) > 1024:
            _reads.clear()
        times = [t for t in _reads.get(who, []) if now - t < 60]
        if len(times) >= READS_PER_MIN:
            raise Busy("解析の要求が多すぎます。1 分待ってください")
        _reads[who] = times + [now]


def lines_of(req, timeout=None):
    """One request to the analyzer -> its reply lines (decoded JSON), streamed."""
    read_budget()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout or ANALYZER_TIMEOUT_S * 2 + 10)
        s.connect(ANALYZER_SOCKET)
        s.sendall(json.dumps(req).encode() + b"\n")
        f = s.makefile("rb")
    except OSError as e:
        raise AnalyzerDown(f"analyzer unavailable ({type(e).__name__})") from None
    try:
        while True:
            try:
                line = f.readline(64 * 2**20)
            except OSError as e:
                raise AnalyzerDown(f"analyzer unavailable ({type(e).__name__})") from None
            if not line:
                return
            try:
                obj = json.loads(line)
            except ValueError:
                raise AnalyzerDown("analyzer gave no answer") from None
            if isinstance(obj, dict) and "error" in obj:
                if obj.get("busy"):
                    raise Busy(obj["error"])
                raise Refused(mask_message(obj["error"]))
            yield obj
    finally:
        f.close()
        s.close()


def analyzer(req, timeout=None):
    for obj in lines_of(req, timeout):
        return obj
    raise AnalyzerDown("analyzer gave no answer")


_protocols = {}  # name -> is a protocol (bounded)


def protocols_of(names):
    missing = [n for n in names if n not in _protocols]
    if missing:
        if len(_protocols) > 4096:
            _protocols.clear()
        classes = analyzer({"op": "fieldtypes", "names": missing})["classes"]
        _protocols.update({n: classes.get(n) == "protocol" for n in missing})
    return {n for n in names if _protocols.get(n)}


def shown_as_is(v):
    """A filter string value must be content the screens show unchanged (else it could test masked content)."""
    return mask_free(v) == v and mask_free(v.lower()) == v.lower() and mask_free(v.upper()) == v.upper()


def check_filter(text):
    return pcap_filter.check(text, protocols_of, M.TOKENS, shown_as_is)


# ---- files ----------------------------------------------------------------------------------------------------

def ring_current():
    try:
        cur = json.loads(CAPTURE_STATUS.read_text()).get("current")
    except (OSError, ValueError, AttributeError):
        return None
    return cur if isinstance(cur, str) else None


def capture_status():
    try:
        st = json.loads(CAPTURE_STATUS.read_text())
    except (OSError, ValueError):
        return {"state": "none"}
    if not isinstance(st, dict):
        return {"state": "none"}
    num = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    age = time.time() - (num(st.get("updated")) or 0)
    # every string of the status is free text (operator config, dumpcap's messages); numbers only as numbers
    keep = {k: num(st.get(k)) for k in ("snaplen", "files_max", "file_mb", "ring_bytes", "ring_limit_bytes", "received",
                                        "nic_rx_dropped", "dumpcap_dropped", "duration_s")}
    keep["running"] = st.get("running") is True
    keep["iface"] = mask_free(str(st.get("iface") or "")) or None  # predictable names hold the MAC (enx<MAC>, wlx<MAC>)
    keep["filter"] = mask_free(str(st.get("filter") or ""))
    keep["error"] = mask_free(str(st.get("error") or "")) or None
    keep["state"] = "running" if keep["running"] and age < 30 else "stopped"
    keep["age_s"] = round(age)
    return keep


def list_dir(root, kind):
    out = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return out
    for e in entries:
        if not (STORED_RE if kind == "upload" else RING_NAME).fullmatch(e.name):
            continue  # generated names only (ids carry the name): published uploads, never a staging or foreign file
        try:
            if not e.is_file(follow_symlinks=False):
                continue
        except OSError:
            continue
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue  # pruned meanwhile
        name = upload_label(e.name) if kind == "upload" else e.name
        out.append({"id": f"{kind}:{e.name}", "kind": kind, "name": name, "size": st.st_size, "mtime": st.st_mtime})
    return out


def upload_label(stored):
    """An upload's display name: the masked name given at upload time (kept beside it), never part of its id."""
    try:
        return json.loads((UPLOADS / f".{stored}.json").read_text())["name"]
    except (OSError, ValueError, KeyError):
        return "upload"


UPLOAD_LOCK = threading.Lock()  # quota check, pruning and publishing an upload happen as one step


def prune_uploads(need=0, now=None):
    """Age (PCAP_KEEP_HOURS) and total size (PCAP_UPLOADS_TOTAL_MB, leaving room for `need` bytes): oldest first.
    Call with UPLOAD_LOCK held."""
    now = now or time.time()
    files, others = [], []
    try:
        entries = list(os.scandir(UPLOADS))
    except OSError:
        return [], 0
    for e in entries:
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue  # removed meanwhile
        (files if STORED_RE.fullmatch(e.name) else others).append((st.st_mtime, st.st_size, e.path, e.name))
    files.sort(key=lambda x: x[0])
    removed, total = [], sum(f[1] for f in files)
    for mtime, _size, path, name in others:  # stale staging / partial uploads, display names of uploads gone elsewhere
        stale = name.startswith((".part-", "stage-")) and now - mtime > 3600
        orphan = name.startswith(".u") and name.endswith(".json") and not (UPLOADS / name[1:-5]).exists()
        if stale or orphan:
            try:
                os.unlink(path)
            except OSError:
                pass
    files = [f[:3] for f in files]
    for mtime, size, path in files:
        if now - mtime > KEEP_S or total + need > UPLOADS_TOTAL_MAX:
            try:
                os.unlink(path)
                removed.append(upload_label(os.path.basename(path)))
                total -= size
            except OSError:
                pass
            try:
                os.unlink(UPLOADS / f".{os.path.basename(path)}.json")
            except OSError:
                pass
    return removed, total


def prune_loop():
    while True:
        try:
            with UPLOAD_LOCK:
                prune_uploads()
        except OSError:
            pass
        time.sleep(PRUNE_EVERY_S)


def files():
    cur = ring_current()
    ring = list_dir(RING, "ring")
    for f in ring:
        f["recording"] = f["id"] == f"ring:{cur}"
    return {"ring": sorted(ring, key=lambda f: f["mtime"], reverse=True), "upload": sorted(list_dir(UPLOADS, "upload"), key=lambda f: f["mtime"], reverse=True),
            "demo": list_dir(DEMO, "demo"), "capture": capture_status(),
            "limits": {"upload_max": UPLOAD_MAX, "uploads_total_max": UPLOADS_TOTAL_MAX, "keep_hours": KEEP_S / 3600, "filter_max": pcap_filter.FILTER_MAX}}


def file_ref(fid):
    m = FILE_ID.fullmatch(fid or "")
    if not m or not m.group(2).endswith(SUFFIXES):
        raise Refused("file: ring:<name> | upload:<name> | demo:<name>")
    kind, name = m.groups()
    if not (STORED_RE if kind == "upload" else RING_NAME).fullmatch(name):
        raise Refused("file: ring:<name> | upload:<name> | demo:<name>")
    path = {"ring": RING, "upload": UPLOADS, "demo": DEMO}[kind] / name
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        raise Refused("ファイルがありません (保存期間を過ぎて削除されたかもしれません)") from None
    if kind == "ring" and name == ring_current():
        raise Refused("このリングファイルは記録中です。閉じてから (次のファイルに切り替わってから) 開いてください")
    return {"root": kind, "name": name}, (fid, st.st_size, st.st_mtime)


# ---- results cache (one analysis serves many pages) --------------------------------------------------------------

class Lru:
    """Small LRU with single flight: concurrent requests for the same key wait for one computation."""

    def __init__(self, n):
        self.n, self.d, self.lock, self.flight = n, OrderedDict(), threading.Lock(), {}

    def get(self, key, make):
        with self.lock:
            if key in self.d:
                self.d.move_to_end(key)
                return self.d[key]
            ev = self.flight.get(key)
            owner = ev is None
            if owner:
                ev = self.flight[key] = threading.Event()
        if not owner:
            ev.wait(ANALYZER_TIMEOUT_S * 2 + 20)
            with self.lock:
                if key in self.d:
                    return self.d[key]
            if getattr(ev, "error", None) is not None:
                raise ev.error  # the same refusal / timeout the computing request got
            raise Busy("同じ解析が進行中です。もう一度試してください")
        try:
            val = make()
            with self.lock:
                self.d[key] = val
                while len(self.d) > self.n:
                    self.d.popitem(last=False)
            return val
        except Exception as e:
            ev.error = e
            raise
        finally:
            with self.lock:
                self.flight.pop(key, None)
            ev.set()


# Memory: a packet list is kept as one compact JSON string per masked row (~150-250 bytes at most PCAP_MAX_PACKETS
# rows, 100k by default -> ~25 MB per list), streamed from the analyzer line by line; two lists at most.
PACKETS = Lru(2)
STATS = Lru(6)


def packet_rows(fid, filt):
    ref, ident = file_ref(fid)
    real = check_filter(filt)

    def rows_of():
        rows, tail = [], {}
        for obj in lines_of({"op": "packets", "file": ref, "filter": real, "stream": True}):
            if isinstance(obj, list):
                rows.append(json.dumps(packet_summary(obj), separators=(",", ":"), ensure_ascii=False))
            else:
                tail = obj
        if "count" not in tail:  # the stream ended early (analyzer killed / cut): not a complete list
            raise AnalyzerDown("analyzer stopped before the end of the packet list")
        return {"rows": rows, "truncated": bool(tail.get("truncated")), "elapsed_ms": tail.get("elapsed_ms")}

    def make():
        res, tokens = with_tokens(rows_of)
        return {**res, "tokens": tokens}
    return PACKETS.get((ident, real), make)


# ---- HTTP -----------------------------------------------------------------------------------------------------

def js(status, obj):
    return status, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(), "application/json"


def err(status, msg, kind="rejected"):
    return js(status, {"status": "error", "errorType": kind, "error": msg})


def q1(params, k, default=""):
    v = params.get(k, [default])
    if len(v) != 1:
        raise Refused(f"{k}: once")
    return v[0]


def handle(method, raw_path, headers, read_body):
    parts = urllib.parse.urlsplit(raw_path)
    path = parts.path
    _client.who = (headers.get("X-Forwarded-For") or "local").split(",")[0].strip()[:64]
    try:
        params = urllib.parse.parse_qs(parts.query, keep_blank_values=True, max_num_fields=10)
        if method in ("GET", "HEAD"):
            return read(path, params, headers)
        if method == "POST" and path == "/pcap/upload":
            return write(headers, lambda: upload(params, headers, read_body))
        m = re.fullmatch(r"/pcap/upload/(" + STORED_RE.pattern + ")", path)
        if method == "DELETE" and m:
            return write(headers, lambda: delete_upload(m.group(1)))
        return err(405 if path.startswith("/pcap/") else 403, "only uploads can be written")
    except Refused as e:
        return err(400, mask_message(str(e)))
    except Busy as e:
        return err(429, mask_message(str(e)), "busy")
    except AnalyzerDown as e:
        return err(502, mask_message(str(e)), "analyzer")
    except ValueError as e:
        return err(400, f"bad request ({type(e).__name__})")


def read(path, params, headers):
    if path == "/pcap/files":
        return js(200, files())
    if path == "/pcap/ops":
        ok, reason = M.writable(headers)
        return js(200, {"writable": ok, "reason": pcap_reason(reason)})
    if path == "/pcap/check":
        real = check_filter(q1(params, "filter"))
        analyzer({"op": "check", "filter": real}, timeout=30)
        return js(200, {"status": "success", "ok": True})
    if path == "/pcap/packets":
        offset, limit = int(q1(params, "offset", "0")), min(int(q1(params, "limit", "200")), PAGE_MAX)
        if offset < 0 or limit < 1:
            raise Refused("offset / limit")
        res = packet_rows(q1(params, "file"), q1(params, "filter"))
        head = json.dumps({"status": "success", "total": len(res["rows"]), "truncated": res["truncated"], "offset": offset,
                           "elapsed_ms": res["elapsed_ms"]}, separators=(",", ":"))
        page = ",".join(res["rows"][offset:offset + limit])
        reregister(res["tokens"], TOKEN_IN_TEXT.findall(page))
        body = head[:-1] + ',"rows":[' + page + "]}"
        return 200, body.encode(), "application/json"
    if path == "/pcap/packet":
        ref, _ = file_ref(q1(params, "file"))
        no = int(q1(params, "no"))
        res = analyzer({"op": "detail", "file": ref, "no": no})
        return js(200, {"status": "success", "no": no, **mask_detail(res["tree"], res["hex"])})
    if path == "/pcap/stats":
        fid, filt = q1(params, "file"), q1(params, "filter")
        ref, ident = file_ref(fid)
        real = check_filter(filt)
        res, tokens = STATS.get((ident, real), lambda: with_tokens(lambda: mask_stats(analyzer({"op": "stats", "file": ref, "filter": real}))))
        reregister(tokens)
        return js(200, {"status": "success", **res})
    return err(403, "forbidden")


def pcap_reason(reason):
    """mask-api's write-permission reason (worded for silences) -> worded for pcap uploads."""
    return reason.replace("silences / ACK", "pcap uploads").replace("抑止・確認の操作", " pcap のアップロード・削除")


def write(headers, do):
    ok, reason = M.writable(headers)
    if not ok:
        return err(403, pcap_reason(reason), "forbidden")
    if headers.get(M.CSRF_HEADER) != "1" or not M.same_origin(headers):
        return err(403, "cross-site or scripted request refused (same origin + X-Obs-Csrf required)", "csrf")
    if M.rate_limited(time.monotonic()):
        return err(429, "too many changes; wait a minute")
    return do()


def safe_name(name):
    base = os.path.basename(name or "")
    ext = next((s for s in SUFFIXES if base.lower().endswith(s)), None)
    if not ext:
        raise Refused("拡張子は .pcap / .pcapng / .cap だけです")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", base[: -len(ext)]).strip("._-")[:48] or "capture"
    return stem + ext


def upload(params, headers, read_body):
    name = safe_name(q1(params, "name"))
    length = headers.get("Content-Length") or ""
    if not length.isdigit() or int(length) <= 0:
        raise Refused("Content-Length required")
    size = int(length)
    if size > UPLOAD_MAX:
        return err(413, f"ファイルが大きすぎます (上限 {UPLOAD_MAX // 2**20} MB)")
    if size > UPLOADS_TOTAL_MAX:
        return err(413, f"アップロードの合計上限 ({UPLOADS_TOTAL_MAX // 2**20} MB) を超えます")
    head = read_body(min(size, 12))
    if head[:4] not in MAGIC or (head[:4] == b"\x0a\x0d\x0d\x0a" and head[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d")):
        return err(400, "pcap / pcapng ではありません (先頭のマジックバイトが違います)")
    part = UPLOADS / f".part-{secrets.token_hex(8)}"
    stored = f"u{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(6)}{os.path.splitext(name)[1].lower()}"
    try:
        with open(part, "xb") as f:
            f.write(head)
            left = size - len(head)
            while left > 0:
                chunk = read_body(min(left, 1 << 20))
                if not chunk:
                    raise Refused("upload cut short")
                f.write(chunk)
                left -= len(chunk)
        # validated BEFORE anything is evicted for it: a staging name the analyzer can read, never listed
        stage = UPLOADS / f"stage-{secrets.token_hex(8)}{os.path.splitext(name)[1].lower()}"
        os.replace(part, stage)
        try:
            analyzer({"op": "validate", "file": {"root": "upload", "name": stage.name}}, timeout=VALIDATE_TIMEOUT_S + 30)  # every record, to the end
        except (Busy, AnalyzerDown):
            return err(503, "解析器が混雑しているか止まっています。後で再試行してください (既存のアップロードはそのままです)", "busy")
        except Refused as e:
            if str(e).startswith("timeout"):
                return err(413, f"ファイルが大きすぎて {VALIDATE_TIMEOUT_S} 秒以内に最後まで確かめられませんでした (既存のアップロードはそのままです)", "too_large")
            return err(400, f"tshark で読めないファイルです: {mask_message(str(e))[:200]}")
        with UPLOAD_LOCK:  # two uploads at once cannot both pass the quota
            removed, total = prune_uploads(need=size)
            if total + size > UPLOADS_TOTAL_MAX:
                return err(413, f"アップロードの合計上限 ({UPLOADS_TOTAL_MAX // 2**20} MB) を超えます")
            (UPLOADS / f".{stored}.json").write_text(json.dumps({"name": mask_free(name)}))
            os.replace(stage, UPLOADS / stored)
    finally:
        for leftover in [part] + ([stage] if "stage" in locals() else []):
            try:
                os.unlink(leftover)
            except OSError:
                pass
    return js(200, {"status": "success", "id": f"upload:{stored}", "name": mask_free(name), "size": size, "removed": removed})


def delete_upload(stored):
    try:
        with UPLOAD_LOCK:
            os.unlink(UPLOADS / stored)
            (UPLOADS / f".{stored}.json").unlink(missing_ok=True)
    except FileNotFoundError:
        return err(404, "no such upload", "missing")
    return js(200, {"status": "success"})


def kept_any(txt, out, hidden):
    """Must some character at an index in `hidden` survive for mask_free to turn txt into out? Every output char other
    than "x" is an input char kept in order; an "x" stands for one or more replaced (or literal x) input chars."""
    reach = {0}
    for c in out:
        if c == "x":
            reach = set(range(min(reach) + 1, len(txt) + 1))
        else:
            reach = {j + 1 for j in reach if j < len(txt) and txt[j] == c and j not in hidden}
        if not reach:
            return True
    return len(txt) not in reach


def property_test(n, seed=5, verbose=False):
    """Addresses in many notations embedded in random text (filler words hold hex letters too, glued forms included):
    the output holds no digit (outside the kept "ip6.arpa" suffix) and keeps no hex character of the address span at
    all, not even one nibble (kept_any over the span's index set). -> number of failures."""
    import random
    rnd = random.Random(seed)
    words = ["host", "peer", "from", "lease", "zen", "spamhaus", "org", "static", "isp", "example", "net", "via", "ok", "bad",
             "cafe", "face", "fabric", "dead", "beef", "Yamaha", "ESP", "android", "mac", "ip", "a", "b", "e", "fe"]
    seps = list(" _,/;=()[]<>!?'\"-:.")
    hexrun = lambda b: "".join(f"{x:02x}" for x in b)
    fails = 0
    for _ in range(n):
        kind = rnd.choice(["v4", "v6", "mac"])
        if kind == "v4":
            o = [rnd.randint(1, 255) for _ in range(4)]
            q = ".".join(map(str, o))
            rev = ".".join(map(str, reversed(o)))
            num = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
            forms = [("", q, ""), ("", rev, ".zen.spamhaus.org"), ("", rev, ".static.isp.example"), ("", rev, ".in-addr.arpa"),
                     ("::ffff:", q, ""), ("64:ff9b::", q, ""), ("", f"{q}:{rnd.randint(1, 65535)}", ""), ("", str(num), ""),
                     ("0x", hexrun(o), ""), ("", hexrun(o), ""), ("", q.replace(".", "-"), ".lan"), ("", q.replace(".", "%2E"), ""),
                     ("", ".".join(f"0{x:o}" for x in o), ""), ("", base64.b64encode(bytes(o)).decode(), ""), ("x", q, "y"),
                     ("1.3.6.1.4.1.", q, "")] + [("", q.replace(".", c), "") for c in " _,/"]
        elif kind == "v6":
            groups = [f"{rnd.randint(0, 0xffff):x}" for _ in range(4)] + [rnd.choice(["a", "b", "cd", "e1", "fff", f"{rnd.randint(0, 0xfff):x}"]) for _ in range(4)]
            addr = ":".join(groups)
            ip = ipaddress.IPv6Address(addr)
            forms = [("", addr, ""), ("[", addr, "]:443"), ("", addr, "%eth0"), ("src:", addr, ""), ("x", addr, ""), ("", addr.upper(), ""),
                     ("", hexrun(ip.packed), ""), ("", str(ip), ""), ("", ip.reverse_pointer[:-9], ".ip6.arpa"),
                     ("", base64.b64encode(ip.packed).decode(), ""), ("", "-".join(groups), ".ipv6.example"),
                     ("", str(ip).replace(":", "-"), ""), ("fe80--", "-".join(groups[4:]), "")]
        else:
            bs = [rnd.choice([rnd.randint(0, 255), rnd.choice([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xab, 0xcd, 0xef, 0xfe])]) for _ in range(6)]
            hexes = [f"{x:02x}" for x in bs]
            nic = rnd.choice([" ", "_", ",", "/", ":", "-", ""]).join(hexes[3:])
            forms = [("", ":".join(hexes), ""), ("", "-".join(hexes).upper(), ""), ("", hexrun(bs), ""), ("", ".".join("".join(hexes[i:i + 2]) for i in (0, 2, 4)), ""),
                     ("ESP_", nic.upper(), ""), ("MAC ", nic, ""), ("(", nic, ")"), ("", ":".join(hexes) + ":aa:bb", ""), ("Vendor_", nic, "")] + \
                    [("", c.join(hexes), "") for c in " _,/"]
        pre, span, post = rnd.choice(forms)
        sep = lambda: rnd.choice(seps)
        left = "".join(rnd.choice(words) + sep() for _ in range(rnd.randint(0, 3))) + pre
        right = post + "".join(sep() + rnd.choice(words) for _ in range(rnd.randint(0, 3)))
        txt = left + span + right
        hidden = {len(left) + i for i, c in enumerate(span) if c in "0123456789abcdefABCDEF"}
        out = mask_free(txt)
        if re.search(r"\d", out.replace("ip6.arpa", "")) or kept_any(txt, out, hidden):
            fails += 1
            if verbose or fails <= 5:
                print("property test failure:", repr(txt), "->", repr(out))
    return fails


def emitted_selftest():
    """Every string /pcap/files emits, by key: generated ids / names and enums as they are, anything else (status,
    errors, interface, filter, display names) must be what the free-text rule leaves unchanged. A new key fails."""
    global RING, UPLOADS, DEMO, CAPTURE_STATUS
    import tempfile
    was = RING, UPLOADS, DEMO, CAPTURE_STATUS
    with tempfile.TemporaryDirectory() as tmp:
        RING, UPLOADS, DEMO, CAPTURE_STATUS = Path(tmp, "ring"), Path(tmp, "up"), Path(tmp, "demo"), Path(tmp, "status.json")
        for d in (RING, UPLOADS, DEMO):
            d.mkdir()
        (RING / "obs-1761400000_00001_20261025232010.pcapng").write_bytes(b"x")
        (RING / "ring-192.168.100.23.pcapng").write_bytes(b"x")  # not a generated name
        (UPLOADS / "u20261026000000-0123456789ab.pcap").write_bytes(b"x")
        (UPLOADS / ".u20261026000000-0123456789ab.pcap.json").write_text(json.dumps({"name": mask_free("home_192.168.100.23.pcap")}))
        (DEMO / "demo-home.pcap").write_bytes(b"x")
        CAPTURE_STATUS.write_text(json.dumps({"running": True, "updated": time.time(), "iface": "enx02005e100017", "filter": "host 192.168.100.23",
                                              "error": "dumpcap: wlx02005e100017 down", "received": "02005e100017", "current": "x"}))
        out = files()
    RING, UPLOADS, DEMO, CAPTURE_STATUS = was
    generated = {"id": re.compile(r"(?:ring|demo):(?:" + RING_NAME.pattern + r")|upload:" + STORED_RE.pattern), "name": re.compile(RING_NAME.pattern + "|" + STORED_RE.pattern), "kind": re.compile("ring|upload|demo"),
                 "state": re.compile("running|stopped|none")}
    free = {"name", "iface", "filter", "error"}

    def walk(v, key):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, k)
        elif isinstance(v, list):
            for x in v:
                walk(x, key)
        elif isinstance(v, str):
            assert key in generated or key in free, f"unclassified string key {key!r}"
            assert (key in generated and generated[key].fullmatch(v)) or (key in free and mask_free(v) == v), (key, v)
    walk(out, None)
    dumped = json.dumps(out)
    assert "02005e100017" not in dumped and "100.23" not in dumped and len(out["ring"]) == 1 and out["capture"]["iface"] == "enx" and out["capture"]["received"] is None, dumped


def upload_selftest():
    """Uploads: validated before any eviction; analyzer busy -> 503 and nothing removed; opaque ids, masked names."""
    import tempfile
    global UPLOADS, UPLOADS_TOTAL_MAX, analyzer
    was = (UPLOADS, UPLOADS_TOTAL_MAX, analyzer)
    pcap = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000") + b"\0" * 100
    with tempfile.TemporaryDirectory() as tmp:
        UPLOADS, UPLOADS_TOTAL_MAX = Path(tmp), 200
        old = UPLOADS / "u20261026000000-0123456789ab.pcap"
        old.write_bytes(pcap)
        os.utime(old, (time.time() - 60, time.time() - 60))
        mode = {"v": "busy"}

        def fake(req, timeout=None):
            assert req["file"]["name"].startswith("stage-"), req  # validated under the staging name
            if mode["v"] == "busy":
                raise Busy("busy")
            if mode["v"] == "bad":
                raise Refused("tshark: The file appears to be damaged or corrupt.")
            if mode["v"] == "slow":
                raise Refused("timeout: tshark ran longer than 180 s")
            assert req["op"] == "validate", req
            return {"ok": True, "count": 1}
        analyzer = fake
        up = lambda: upload({"name": ["home 192.168.100.23.pcap"]}, {"Content-Length": str(len(pcap))}, io.BytesIO(pcap).read)
        st, body, _ = up()
        assert st == 503 and old.exists() and sorted(os.listdir(tmp)) == [old.name], (st, os.listdir(tmp))  # nothing evicted / left
        mode["v"] = "bad"
        st, body, _ = up()
        assert st == 400 and old.exists() and sorted(os.listdir(tmp)) == [old.name]
        mode["v"] = "slow"
        st, body, _ = up()
        assert st == 413 and b"too_large" in body and old.exists() and sorted(os.listdir(tmp)) == [old.name]
        mode["v"] = "ok"
        st, body, _ = up()
        out = json.loads(body)
        assert st == 200 and not old.exists() and STORED_RE.fullmatch(out["id"].split(":", 1)[1]), out  # the old one made room
        assert "home" not in out["id"] and out["name"] == "home_x.x.x.x.pcap" and list_dir(UPLOADS, "upload")[0]["name"] == out["name"]
    UPLOADS, UPLOADS_TOTAL_MAX, analyzer = was


# ---- selftest (no analyzer needed) ----------------------------------------------------------------------------

def selftest():
    v4 = mask_addr("192.168.100.23")
    assert TOK_V4.fullmatch(v4) and v4 == M.mask_value("192.168.100.23")  # same token as the Prometheus labels
    v6 = mask_addr("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
    assert v6.startswith("2001:db8:1:2::x~") and TOK_V6.fullmatch(v6), v6
    assert mask_addr("fe80::200:5eff:fe10:17").startswith("fe80::x~")
    mac = mask_addr("02:00:5E:10:00:17")
    assert mac.startswith("02:00:5e:xx:xx:xx~") and TOK_MAC.fullmatch(mac)
    t = mask_free("Who has 192.168.100.1? Tell 192.168.100.23 (02:00:5e:10:00:17) fe80::1 PTR 23.100.168.192.in-addr.arpa 12:00:01")
    assert t == "Who has x.x.x.x? Tell x.x.x.x (x:x:x:x:x:x) x::x PTR x.in-addr.arpa x:x:x", t
    for raw, want in (("23.100.168.192.zen.spamhaus.org", "x.x.x.x.zen.spamhaus.org"), ("ESP_DDEEFF", "ESP_x"), ("aa bb cc dd ee ff", "x x x x x x"),
                      ("aa_bb_cc_dd_ee_ff", "x_x_x_x_x_x"), ("(dd,ee,ff)", "(x,x,x)"), ("x2001:db8:1:2:a:b:c:d", "x:x:x:x:x:x:x:x"),
                      ("host wKhkFw== x", "host x x"), ("peer/wY4Dc3XyTT0AzQ//DucDog==\"zen", "x\"zen"), ("ok/66L/HsmD==/lease", "x/lease"), ("１９２.168.100.٢٣", "x.x.x.x"), ("۱۹۲.۱", "x.x"),("www.example.com", "www.example.com"), ("pc-living", "pc-living"),
                      ("2001:db8:c0a8:6417::1", "x:x:x:x::x"), ("fe80::a", "x::x"), ("b.b.a.a.f.e.d.c.0.0.0.0.ip6.arpa", "x.ip6.arpa"), ("2001-db8-1-2-a-b-c-d.ipv6.example", "x-x-x-x-x-x-x-x.ipvx.example"), ("fe80--a-b", "x--x-x"), ("phone-a cafe", "phone-x x"), ("\u2460.\u0f2a", "x.x"), ("zfe80::abcd", "zx::x")):
        assert mask_free(raw) == want, (raw, mask_free(raw))
    assert mask_message('"ip.addr == 2001:db8:1:2::5" is invalid') == '"ip.addr == x:x:x:x::x" is invalid', mask_message('"ip.addr == 2001:db8:1:2::5" is invalid')
    assert mask_message("file: ring:<name> | upload:<name> | demo:<name>") == "file: ring:<name> | upload:<name> | demo:<name>"
    assert mask_addr("::ffff:192.168.100.23").startswith("::ffff:192.168.100.x~")
    assert property_test(3000) == 0
    # hex: default masked; reveal-listed header fields only, and only when their bytes are the frame's own
    frame = bytes(14) + bytes.fromhex("4500003c0001400040060000c0a86417c0002f0a") + b"Host: 192.168.100.5\r\n" + b"\x00\x35"
    f = lambda n, cl, s, p, z, v=None, x=None, **k: {"n": n, "k": "field", "cl": cl, "s": s, "p": p, "z": z, "v": v, "x": x, **k}
    tree = [{"n": "ip", "k": "proto", "cl": "proto", "s": "Internet Protocol Version 4, Src: 192.168.100.23", "p": 14, "z": 20, "c": [
        f("ip.ttl", "other", "Time to Live: 64", 22, 1, "64", "40"),
        f("ip.proto", "other", "Protocol: TCP (6)", 23, 1, "6", "06"),
        f("ip.checksum", "checksum", "Header Checksum: 0x1234", 24, 2, "0x1234", "0000"),
        f("ip.src", "address", "Source Address: 192.168.100.23", 26, 4, "192.168.100.23", "c0a86417"),
        f("ip.dst", "address", "Destination Address: 192.0.47.10", 30, 4, "192.0.47.10", "c0002f0a"),
        f("ip.id", "other", "Identification: 0x9999 (reassembled tvb: bytes differ)", 18, 2, "0x9999", "9999")]},
        f("http.host", "string", "Host: 192.168.100.5", 34, 19, "192.168.100.5", frame[34:53].hex()),
        f("data.data", "bytes", "Data: c0a86417c0a86417", 34, 4, None, frame[34:38].hex()),
        f("udp.dstport", "other", "Destination Port: 53", 55, 2, "53", "0035")]
    d = mask_detail(tree, frame.hex())
    b = d["bytes"]
    assert b[22] == "40" and b[23] == "06" and b[55:57] == ["00", "35"], b[20:24]
    assert all(x is None for x in b[:22]) and all(x is None for x in b[24:55]), b  # addresses, checksum, id (other tvb), payload
    dumped = json.dumps(d)
    assert "192.168.100.23" not in dumped and "1234" not in dumped and "c0a86417" not in dumped and "192.168.100.5" not in dumped
    assert d["tree"][0]["c"][3]["v"] == v4 and d["tree"][0]["s"].endswith("x.x.x.x") and d["tree"][0]["c"][3]["s"] == "ip.src: 192.168.100.x"
    opt = [{**f("dhcp.option.type", "other", "Option: (3) Router", 26, 6, "3", frame[26:32].hex()),
            "c": [f("dhcp.option.length", "other", "Length: 4", 27, 1, "4", frame[27:28].hex()),
                  f("dhcp.option.router", "address", "Router: 192.168.100.23", 28, 4, "192.168.100.23", frame[28:32].hex())]}]
    b3 = mask_detail(opt, frame.hex())["bytes"]
    assert b3[26] is None and b3[27] is not None and all(x is None for x in b3[28:32]), b3[26:32]  # container: children only
    plain = [f("dns.qry.name", "string", "Name: www.example.com", 0, 4, "www.example.com", frame[:4].hex()),
             f("dns.qry.name", "string", "Name: 5.100.168.192.in-addr.arpa", 4, 4, "5.100.168.192.in-addr.arpa", frame[4:8].hex())]
    b2 = mask_detail(plain, frame.hex())["bytes"]
    assert b2[0] is not None and b2[4] is None  # a name with digits stays masked

    n_filter = pcap_filter.selftest(v4, v6, mac, M.TOKENS, shown_as_is)
    for x in ("::ffff:192.168.100.23", "64:ff9b::192.168.100.23", "2002:c0a8:6417::1", "fe80::200:5eff:fe10:17"):
        t = mask_addr(x)  # every masked IPv6 form the screens get is accepted back as a filter token
        assert check_filter(f"ipv6.addr == {t}") == f"ipv6.addr == {ipaddress.IPv6Address(x)}", (t, check_filter(f"ipv6.addr == {t}"))
    lru, calls = Lru(2), []

    def slow():
        calls.append(1)
        time.sleep(0.2)
        return 42
    threads = [threading.Thread(target=lambda: lru.get("k", slow)) for _ in range(5)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(calls) == 1 and lru.get("k", slow) == 42  # single flight
    errs = []

    def failing():
        time.sleep(0.2)
        raise Refused("tshark: bad filter")

    def waiter():
        try:
            lru.get("bad", failing)
        except Exception as e:
            errs.append(type(e).__name__ + ":" + str(e))
    threads = [threading.Thread(target=waiter) for _ in range(3)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errs == ["Refused:tshark: bad filter"] * 3, errs  # waiters get the original error, not "busy"
    upload_selftest()
    emitted_selftest()
    shown, kept = with_tokens(lambda: mask_addr("192.0.2.77"))  # a cached result re-registers its tokens when served
    t = TOKEN_IN_TEXT.findall(shown)
    assert t and kept == {t[0]: "192.0.2.77"}
    M.TOKENS.pop(t[0])
    reregister(kept, t)
    assert M.TOKENS.get(t[0]) == "192.0.2.77"
    assert STORED_RE.fullmatch("u20261026000000-0123456789ab.pcapng") and not STORED_RE.fullmatch("u20261026000000-012345-192.168.1.5.pcap")
    print(f"pcap_api selftest ok ({n_filter} filter probes rejected)")
