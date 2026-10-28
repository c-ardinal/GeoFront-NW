"""Writes demo/demo-home.pcap: 60 s of SYNTHETIC home-network traffic for the demo profile (flowd replays it in a
loop; the analysis screen opens it). Deterministic: the same bytes on every run (`--check` compares with the file).

Addresses: LAN 192.168.100.0/24 (private), locally administered MACs 02:00:5e:..., every Internet peer in the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 5737) and every name under example.com /
example.net / example.org (RFC 2606). Contents: DHCP (with host names), ARP, DNS, NTP, TLS ClientHello with SNI,
HTTP with a Host header, plus bulk TCP. Payloads are filler bytes: nothing here was ever captured from a real network.

  python demo/make_demo_pcap.py            (re)write the file
  python demo/make_demo_pcap.py --check    exit 1 when the file differs from what this script writes
"""
import random
import struct
import sys
from pathlib import Path

OUT = Path(__file__).with_name("demo-home.pcap")
T0 = 1_792_810_800  # 2026-10-24 12:00:00 JST
DURATION = 60
ROUTER = ("192.168.100.1", "02:00:5e:00:00:01")
# name, IPv4, MAC (the names come from DHCP option 12, which is how flowd names them)
HOSTS = [("pc-living", "192.168.100.23"), ("pc-study", "192.168.100.24"), ("phone-a", "192.168.100.31"),
         ("phone-b", "192.168.100.32"), ("tv-living", "192.168.100.40"), ("tablet-kids", "192.168.100.41")]
HOSTS = [(n, ip, f"02:00:5e:10:00:{int(ip.split('.')[-1]):02x}") for n, ip in HOSTS]
# remote peer, name, weight (relative bytes) - the same peers as demo-gen's synthetic flows
PEERS = [("192.0.2.10", "www.example.com", 8), ("192.0.2.20", "media.example.com", 4), ("192.0.2.30", "cdn.example.net", 6),
         ("192.0.2.40", "api.example.net", 5), ("198.51.100.10", "video.example.org", 3), ("198.51.100.20", "sg.example.org", 3),
         ("198.51.100.30", "de.example.com", 2), ("198.51.100.40", "uk.example.com", 2), ("198.51.100.50", "nl.example.net", 1),
         ("203.0.113.10", "kr.example.org", 2), ("203.0.113.20", "au.example.com", 1), ("203.0.113.30", "hk.example.net", 2),
         ("203.0.113.40", "ie.example.org", 1), ("203.0.113.50", "unknown-a.example.com", 2), ("203.0.113.60", "unknown-b.example.net", 1)]
NTP_SERVER = "198.51.100.123"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def mac_b(m):
    return bytes(int(x, 16) for x in m.split(":"))


def ip_b(a):
    return bytes(int(x) for x in a.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(src, dst, ethertype, payload):
    return mac_b(dst) + mac_b(src) + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0, ip_b(src), ip_b(dst))
    return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:] + payload


def l4_csum(src, dst, proto, seg):
    return csum(ip_b(src) + ip_b(dst) + struct.pack("!BBH", 0, proto, len(seg)) + seg)


def udp(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    c = l4_csum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", c) + seg[8:]


def tcp(src, dst, sport, dport, seq, ack, flags, data=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 64240, 0, 0) + data
    return seg[:16] + struct.pack("!H", l4_csum(src, dst, 6, seg)) + seg[18:]


def dns_name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"


def dns_query(qid, name):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_answer(qid, name, addr):
    return (struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)
            + struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + ip_b(addr))


def tls_client_hello(sni, rng):
    name = sni.encode()
    ext_sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = (b"\x03\x03" + bytes(rng.getrandbits(8) for _ in range(32)) + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
            + b"\x01\x00" + struct.pack("!H", len(ext_sni)) + ext_sni)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_data(n, rng):
    return b"\x17\x03\x03" + struct.pack("!H", n) + bytes(rng.getrandbits(8) for _ in range(n))


def dhcp(op, xid, mac, yiaddr, msg_type, hostname, requested=None):
    opts = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
    if requested:
        opts += bytes([50, 4]) + ip_b(requested)
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    if op == 2:
        opts += bytes([54, 4]) + ip_b(ROUTER[0]) + bytes([51, 4]) + struct.pack("!I", 86400) + bytes([1, 4, 255, 255, 255, 0])
        opts += bytes([3, 4]) + ip_b(ROUTER[0]) + bytes([6, 4]) + ip_b(ROUTER[0])
    opts += b"\xff"
    return (struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0x8000) + b"\0" * 4 + ip_b(yiaddr) + b"\0" * 8
            + mac_b(mac) + b"\0" * 10 + b"\0" * 192 + opts)


def arp(op, smac, sip, tmac, tip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac_b(smac) + ip_b(sip) + mac_b(tmac) + ip_b(tip)


def ntp_packet(mode, t):
    secs = int(t) + 2_208_988_800
    return bytes([(4 << 3) | mode, 2 if mode == 4 else 0, 6, 0xEC]) + b"\0" * 8 + b"\0" * 24 + struct.pack("!II", secs, 0)


def build():
    rng = random.Random(20261024)
    pkts = []  # (time, frame)
    ident = [1]

    def add(t, frame):
        pkts.append((t, frame))

    def ip_frame(t, smac, dmac, src, dst, proto, payload):
        ident[0] += 1
        add(t, eth(smac, dmac, 0x0800, ipv4(src, dst, proto, payload, ident[0])))

    # DHCP (renewals with host names) and ARP at the start
    for i, (name, ip, mac) in enumerate(HOSTS):
        t = T0 + 0.2 + i * 0.4
        xid = rng.getrandbits(32)
        ip_frame(t, mac, BROADCAST_MAC, "0.0.0.0", "255.255.255.255", 17, udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp(1, xid, mac, "0.0.0.0", 3, name, ip)))
        ip_frame(t + 0.01, ROUTER[1], mac, ROUTER[0], ip, 17, udp(ROUTER[0], ip, 67, 68, dhcp(2, xid, mac, ip, 5, name)))
        add(t + 0.05, eth(mac, BROADCAST_MAC, 0x0806, arp(1, mac, ip, "00:00:00:00:00:00", ROUTER[0])))
        add(t + 0.06, eth(ROUTER[1], mac, 0x0806, arp(2, ROUTER[1], ROUTER[0], mac, ip)))
    # NTP from two hosts
    for i, (_, ip, mac) in enumerate(HOSTS[:2]):
        t = T0 + 3 + i
        ip_frame(t, mac, ROUTER[1], ip, NTP_SERVER, 17, udp(ip, NTP_SERVER, 123, 123, ntp_packet(3, t)))
        ip_frame(t + 0.03, ROUTER[1], mac, NTP_SERVER, ip, 17, udp(NTP_SERVER, ip, 123, 123, ntp_packet(4, t)))
    # sessions: DNS lookup, TCP handshake, TLS ClientHello (SNI) or HTTP request, then bulk data, FIN
    total_w = sum(p[2] for p in PEERS)
    for k in range(48):
        name, ip, mac = HOSTS[k % len(HOSTS)]
        peer, host, w = rng.choices(PEERS, weights=[p[2] for p in PEERS])[0]
        t = T0 + 5 + k * 1.1 + rng.random() * 0.3
        qid = rng.getrandbits(16)
        sport = 49152 + rng.randrange(16000)
        ip_frame(t, mac, ROUTER[1], ip, ROUTER[0], 17, udp(ip, ROUTER[0], sport, 53, dns_query(qid, host)))
        ip_frame(t + 0.01, ROUTER[1], mac, ROUTER[0], ip, 17, udp(ROUTER[0], ip, 53, sport, dns_answer(qid, host, peer)))
        http = k % 7 == 3
        dport = 80 if http else 443
        cs, ss = rng.getrandbits(32), rng.getrandbits(32)
        t += 0.02
        ip_frame(t, mac, ROUTER[1], ip, peer, 6, tcp(ip, peer, sport, dport, cs, 0, 0x02))
        ip_frame(t + 0.03, ROUTER[1], mac, peer, ip, 6, tcp(peer, ip, dport, sport, ss, cs + 1, 0x12))
        ip_frame(t + 0.031, mac, ROUTER[1], ip, peer, 6, tcp(ip, peer, sport, dport, cs + 1, ss + 1, 0x10))
        hello = (f"GET /index.html HTTP/1.1\r\nHost: {host}\r\nUser-Agent: demo-agent/1.0\r\nAccept: */*\r\n\r\n".encode()
                 if http else tls_client_hello(host, rng))
        ip_frame(t + 0.032, mac, ROUTER[1], ip, peer, 6, tcp(ip, peer, sport, dport, cs + 1, ss + 1, 0x18, hello))
        cs += 1 + len(hello)
        ss += 1
        n_down = max(2, int(7 * w / total_w * len(PEERS)))
        for j in range(n_down):  # download segments with a few uploads in between
            tt = t + 0.06 + j * 0.012
            data = tls_data(rng.randrange(900, 1380), rng) if not http else bytes(rng.getrandbits(8) for _ in range(1200))
            ip_frame(tt, ROUTER[1], mac, peer, ip, 6, tcp(peer, ip, dport, sport, ss, cs, 0x10, data))
            ss += len(data)
            if j % 4 == 3:
                up = tls_data(rng.randrange(80, 300), rng) if not http else b""
                ip_frame(tt + 0.001, mac, ROUTER[1], ip, peer, 6, tcp(ip, peer, sport, dport, cs, ss, 0x18 if up else 0x10, up))
                cs += len(up)
        tt = t + 0.06 + n_down * 0.012
        ip_frame(tt, mac, ROUTER[1], ip, peer, 6, tcp(ip, peer, sport, dport, cs, ss, 0x11))
        ip_frame(tt + 0.03, ROUTER[1], mac, peer, ip, 6, tcp(peer, ip, dport, sport, ss, cs + 1, 0x11))
        ip_frame(tt + 0.031, mac, ROUTER[1], ip, peer, 6, tcp(ip, peer, sport, dport, cs + 1, ss + 1, 0x10))
    # inbound probes from the Internet (blocked by the router in real life; shown as inbound flows here)
    for i in range(4):
        src = PEERS[9 + i][0]
        name, ip, mac = HOSTS[4]
        ip_frame(T0 + 20 + i * 9, ROUTER[1], mac, src, ip, 6, tcp(src, ip, 40000 + i, 8080, rng.getrandbits(32), 0, 0x02))
    pkts.sort(key=lambda p: p[0])
    assert pkts[-1][0] < T0 + DURATION, "the replay loop assumes the capture fits in DURATION seconds"
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for t, frame in pkts:
        sec = int(t)
        out.append(struct.pack("<IIII", sec, int(round((t - sec) * 1e6)) % 1_000_000, len(frame), len(frame)) + frame)
    return b"".join(out)


if __name__ == "__main__":
    data = build()
    if "--check" in sys.argv:
        same = OUT.exists() and OUT.read_bytes() == data
        print("demo pcap up to date" if same else "demo pcap differs from the generator: run python demo/make_demo_pcap.py")
        sys.exit(0 if same else 1)
    OUT.write_bytes(data)
    print(f"wrote {OUT.name}: {len(data)} bytes")
