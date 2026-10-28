"""SYNTHETIC traffic for the testbed (service testbed-traffic): lets the capture profile's path (dumpcap ring ->
flowd -> Prometheus) be checked on a Linux host without a real LAN. Every packet goes to a documentation address
(RFC 5737) or to the compose network's DNS resolver; nothing answers, nothing leaves a real network in a useful way.

  python traffic.py [--once]
"""
import random
import socket
import sys
import time

PEERS = ["192.0.2.10", "192.0.2.30", "198.51.100.20", "198.51.100.40", "203.0.113.10", "203.0.113.50"]
NAMES = ["www.example.com", "cdn.example.net", "api.example.org"]


def burst(rng):
    sent = 0
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in PEERS:
        for _ in range(rng.randint(2, 6)):
            u.sendto(rng.randbytes(rng.randint(200, 1200)), (ip, 443))  # QUIC-like UDP
            sent += 1
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.setblocking(False)
        t.connect_ex((ip, 443))  # a SYN (no answer: documentation address)
        t.close()
        sent += 1
    for name in NAMES:
        try:
            socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        except OSError:
            pass
        sent += 1
    u.close()
    return sent


if __name__ == "__main__":
    rng = random.Random()
    while True:
        n = burst(rng)
        if "--once" in sys.argv:
            print(f"sent {n} packets")
            break
        time.sleep(1)
