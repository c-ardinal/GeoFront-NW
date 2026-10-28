"""Synthetic demo devices (DEMO DATA, not observed reality): the device drivers' demo.json (drivers/*/demo.json, in the
image at /drivers; today YAMAHA RTX1300 / WLX413 / WLX222).

- GET /snmp?target=<dev>&module=if_mib  snmp_exporter-compatible exposition (module=lldp: LLDP neighbours only)
- GET /flows                            demo_flow_bytes_total counters
- GET /fault/{down,wanspike,logburst,counter_reset,status}
- RFC3164 syslog over UDP to $SYSLOG_HOST:$SYSLOG_PORT
"""
import json
import math
import os
import random
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MBPS = 1_000_000 / 8  # bytes/s per Mbps


def load_demo(root):
    """drivers/*/demo.json (sorted by driver) -> (devices, log pool per device, error log pool of all drivers)."""
    devices, logs, errors = {}, {}, []
    for f in sorted(Path(root).glob("*/demo.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        for name, dev in d["devices"].items():
            devices[name] = dev
            logs[name] = [tuple(x) for x in d["logs"]]
        errors += [tuple(x) for x in d.get("error_logs", [])]
    if not devices:
        sys.exit(f"no demo devices in {root}/*/demo.json")
    return devices, logs, errors


DEMO, LOGS, ERR_LOGS = load_demo(os.environ.get("DEMO_DRIVERS", "/drivers"))
# ifIndex, ifName, ifDescr, ifHighSpeed (Mbps), operStatus (1 up, 2 down)
DEVICES = {n: [tuple(i) for i in d["interfaces"]] for n, d in DEMO.items()}
SSIDS = {n: d["ssids"] for n, d in DEMO.items() if d.get("ssids")}
ROUTER = next(n for n, d in DEMO.items() if "wan_if" in d)  # its WAN port carries the demo's traffic
DOWN_TARGET = list(DEMO)[-1]  # the automatic "down" fault
SRC_HOSTS = ["pc-living", "pc-study", "phone-a", "phone-b", "tv-living", "tablet-kids"]
# dst_ip (documentation ranges only), country, city, lat, lon, asn, weight
DESTS = [
    ("192.0.2.10", "JP", "Tokyo", "35.6895", "139.6917", "AS64500", 8),
    ("192.0.2.20", "JP", "Osaka", "34.6937", "135.5023", "AS64501", 4),
    ("192.0.2.30", "US", "Ashburn", "39.0438", "-77.4874", "AS64502", 6),
    ("192.0.2.40", "US", "San Jose", "37.3382", "-121.8863", "AS64503", 5),
    ("198.51.100.10", "US", "Seattle", "47.6062", "-122.3321", "AS64504", 3),
    ("198.51.100.20", "SG", "Singapore", "1.3521", "103.8198", "AS64505", 3),
    ("198.51.100.30", "DE", "Frankfurt", "50.1109", "8.6821", "AS64506", 2),
    ("198.51.100.40", "GB", "London", "51.5072", "-0.1276", "AS64507", 2),
    ("198.51.100.50", "NL", "Amsterdam", "52.3676", "4.9041", "AS64508", 1),
    ("203.0.113.10", "KR", "Seoul", "37.5665", "126.9780", "AS64509", 2),
    ("203.0.113.20", "AU", "Sydney", "-33.8688", "151.2093", "AS64510", 1),
    ("203.0.113.30", "HK", "Hong Kong", "22.3193", "114.1694", "AS64511", 2),
    ("203.0.113.40", "IE", "Dublin", "53.3498", "-6.2603", "AS64512", 1),
    ("203.0.113.50", "Unknown", "", "", "", "", 2),
    ("203.0.113.60", "Unknown", "", "", "", "", 1),
]
SEVERITY = {"err": 3, "warning": 4, "notice": 5, "info": 6}


class State:
    def __init__(self, now, seed=None):
        self.rng = random.Random(seed)
        self.lock = threading.Lock()
        self.last = now
        self.boot = {d: now - self.rng.uniform(3, 40) * 86400 for d in DEVICES}
        self.octets = {d: {i[0]: [0.0, 0.0] for i in ifs} for d, ifs in DEVICES.items()}
        self.errors = {d: {i[0]: [0, 0] for i in ifs} for d, ifs in DEVICES.items()}
        self.flows = {(s, d[0], dirn): 0.0 for s in SRC_HOSTS for d in DESTS for dirn in ("inbound", "outbound")}
        self.down_until = {d: 0.0 for d in DEVICES}
        self.wanspike_until = 0.0
        self.logburst_until = 0.0
        self.noise = 1.0

    # ---- simulation -------------------------------------------------------
    def wan_rates(self, now):
        """(down_Mbps, up_Mbps) for the RTX WAN port."""
        if now < self.wanspike_until:
            return 900 + 130 * (self.noise - 1), 120 * self.noise  # 861..939 Mbps, stays under link speed
        slow = 0.5 + 0.5 * math.sin(2 * math.pi * now / 900)
        down = (40 + 180 * slow) * self.noise
        return down, down * 0.18

    def iface_rates(self, dev, now):
        """bytes/s (in, out) per ifIndex."""
        down, up = self.wan_rates(now)
        d = DEMO[dev]
        if "wan_if" in d:  # router: WAN in = download, its LAN ports carry it the other way
            return {i[0]: (down * MBPS, up * MBPS) if i[0] == d["wan_if"] else (up * MBPS, down * MBPS) for i in DEVICES[dev]}
        ap = d["ap"]
        w = [down * ap["share"] * f for _, f in ap["radios"]]
        u = [up * ap["share"] * f for _, f in ap["radios"]]
        # wlan in = from stations (upload); the uplink's in = from the router (download)
        rates = {ap["uplink"]: (sum(w) * MBPS, sum(u) * MBPS)}
        rates.update({idx: (u[k] * MBPS, w[k] * MBPS) for k, (idx, _) in enumerate(ap["radios"])})
        return rates

    def advance(self, now):
        with self.lock:
            dt = max(0.0, now - self.last)
            self.last = now
            self.noise = min(1.3, max(0.7, self.noise + self.rng.uniform(-0.05, 0.05)))
            burst = now < self.logburst_until
            for dev, ifs in DEVICES.items():
                rates = self.iface_rates(dev, now)
                for idx, *_rest, oper in ifs:
                    if oper != 1:
                        continue
                    jitter = self.rng.uniform(0.97, 1.03)
                    self.octets[dev][idx][0] += rates[idx][0] * dt * jitter
                    self.octets[dev][idx][1] += rates[idx][1] * dt * jitter
                    if self.rng.random() < (0.5 if burst else 0.002) * dt:
                        self.errors[dev][idx][self.rng.randint(0, 1)] += self.rng.randint(1, 4)
            down, up = self.wan_rates(now)
            total_w = sum(d[6] for d in DESTS) * len(SRC_HOSTS)
            for (src, ip, dirn) in self.flows:
                w = next(d[6] for d in DESTS if d[0] == ip)
                rate = (down if dirn == "inbound" else up) * MBPS * w / total_w
                self.flows[(src, ip, dirn)] += rate * dt * self.rng.uniform(0.5, 1.5)

    def counter_reset(self, dev, now):
        with self.lock:
            self.boot[dev] = now
            self.octets[dev] = {k: [0.0, 0.0] for k in self.octets[dev]}
            self.errors[dev] = {k: [0, 0] for k in self.errors[dev]}

    def is_down(self, dev, now):
        return now < self.down_until.get(dev, 0)

    # ---- rendering ----------------------------------------------------------
    def render_snmp(self, dev, now, module="if_mib"):
        if dev not in DEVICES:
            return 400, "unknown target\n"
        if self.is_down(dev, now):
            return 503, "demo fault: target unreachable\n"
        if module == "lldp":
            return 200, render_lldp(dev)
        out = []
        with self.lock:
            out.append("# HELP sysUpTime The time (in hundredths of a second) since the network management portion of the system was last re-initialized. - 1.3.6.1.2.1.1.3")
            out.append("# TYPE sysUpTime gauge")
            out.append(f"sysUpTime {int((now - self.boot[dev]) * 100)}")
            out.append("# TYPE sysName gauge")
            out.append(f'sysName{{sysName="{dev}"}} 1')
            series = {"ifHCInOctets": [], "ifHCOutOctets": [], "ifInErrors": [], "ifOutErrors": [],
                      "ifHighSpeed": [], "ifOperStatus": []}
            for idx, name, descr, speed, oper in DEVICES[dev]:
                lbl = f'{{ifDescr="{descr}",ifIndex="{idx}",ifName="{name}"}}'
                o, e = self.octets[dev][idx], self.errors[dev][idx]
                series["ifHCInOctets"].append(f"ifHCInOctets{lbl} {int(o[0])}")
                series["ifHCOutOctets"].append(f"ifHCOutOctets{lbl} {int(o[1])}")
                series["ifInErrors"].append(f"ifInErrors{lbl} {e[0]}")
                series["ifOutErrors"].append(f"ifOutErrors{lbl} {e[1]}")
                series["ifHighSpeed"].append(f"ifHighSpeed{lbl} {speed}")
                series["ifOperStatus"].append(f"ifOperStatus{lbl} {oper}")
        for name, lines in series.items():
            kind = "counter" if "Octets" in name or "Errors" in name else "gauge"
            out.append(f"# TYPE {name} {kind}")
            out.extend(lines)
        if dev in SSIDS:
            out.append("# HELP demo_wlan_clients SYNTHETIC associated client count (WLX MIB availability unconfirmed)")
            out.append("# TYPE demo_wlan_clients gauge")
            base = DEMO[dev]["clients_base"]
            for ssid in SSIDS[dev]:
                for band in ("2.4GHz", "5GHz"):
                    n = max(0, base + int(2 * math.sin(now / 300 + len(ssid) + len(band))))
                    out.append(f'demo_wlan_clients{{band="{band}",ssid="{ssid}"}} {n}')
        return 200, "\n".join(out) + "\n"

    def render_flows(self):
        out = ["# HELP demo_flow_bytes_total SYNTHETIC flow bytes; geo fields are fake GeoIP estimates",
               "# TYPE demo_flow_bytes_total counter"]
        geo = {d[0]: d for d in DESTS}
        with self.lock:
            for (src, ip, dirn), v in sorted(self.flows.items()):
                _, cc, city, lat, lon, asn, _w = geo[ip]
                out.append(f'demo_flow_bytes_total{{src_host="{src}",dst_ip="{ip}",dst_country="{cc}",'
                           f'dst_city="{city}",lat="{lat}",lon="{lon}",asn="{asn}",direction="{dirn}"}} {int(v)}')
        return "\n".join(out) + "\n"

    def status(self, now):
        return {"down": {d: round(t - now) for d, t in self.down_until.items() if t > now},
                "wanspike_s": max(0, round(self.wanspike_until - now)),
                "logburst_s": max(0, round(self.logburst_until - now))}

    # ---- syslog ---------------------------------------------------------------
    def syslog_lines(self, now):
        burst = now < self.logburst_until
        lines = []
        for dev in DEVICES:
            if self.is_down(dev, now):
                continue
            n = sum(self.rng.random() < 0.7 for _ in range(10 if burst else 1))
            for _ in range(n):
                pool = LOGS[dev]
                if burst and self.rng.random() < 0.4:
                    pool = ERR_LOGS
                sev, tpl = self.rng.choice(pool)
                msg = tpl.format(a=self.rng.randint(2, 250), p=self.rng.randint(1024, 65535))
                pri = 23 * 8 + SEVERITY[sev]  # facility local7
                g = time.gmtime(now)  # RFC3164 day is space-padded
                ts = f"{time.strftime('%b', g)} {g.tm_mday:2d} {time.strftime('%H:%M:%S', g)}"
                lines.append(f"<{pri}>{ts} {dev} {msg}")
        return lines


# LLDP neighbours (snmp/lldp.yml's shape): local ifIndex, remote sysName, remote port id / desc. wlx222 answers none, so
# the demo map shows one link confirmed by LLDP (rtx1300 - wlx413) and one from the inventory only (rtx1300 - wlx222).
LLDP = {n: [tuple(x) for x in d.get("lldp", [])] for n, d in DEMO.items()}


def render_lldp(dev):
    names = {i[0]: i[1] for i in DEVICES[dev]}
    out = ["# HELP lldpRemSysName SYNTHETIC LLDP-MIB lldpRemTable (demo)", "# TYPE lldpRemSysName gauge"]
    for n, (port, sysname, rport, rdesc) in enumerate(LLDP[dev], 1):
        out.append(f'lldpRemSysName{{lldpLocPortId="{names[port]}",lldpRemIndex="{n}",lldpRemLocalPortNum="{port}",'
                   f'lldpRemPortDesc="{rdesc}",lldpRemPortId="{rport}",lldpRemSysName="{sysname}",lldpRemTimeMark="0"}} 1')
    return "\n".join(out) + "\n"


STATE = State(time.time())


def syslog_loop(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        for line in STATE.syslog_lines(time.time()):
            try:
                sock.sendto(line.encode(), (host, port))
            except OSError as e:  # alloy not up yet / DNS not ready
                print(f"syslog send failed: {e}", file=sys.stderr)
                break
        time.sleep(1)


def tick_loop():
    while True:
        STATE.advance(time.time())
        time.sleep(1)


def auto_fault_loop(interval):
    cycle = [("down", {"target": DOWN_TARGET, "seconds": 120}), ("wanspike", {"seconds": 150}),
             ("logburst", {"seconds": 60}), ("counter_reset", {"target": ROUTER})]
    i = 0
    while True:
        time.sleep(interval)
        name, args = cycle[i % len(cycle)]
        print(f"auto fault: {name} {args}", flush=True)
        apply_fault(name, {k: str(v) for k, v in args.items()})
        i += 1


def apply_fault(name, q):
    now = time.time()
    secs = float(q.get("seconds", "120"))
    target = q.get("target", "")
    if name == "down":
        if target not in DEVICES:
            return 400, "target must be one of " + ",".join(DEVICES)
        STATE.down_until[target] = now + secs
    elif name == "wanspike":
        STATE.wanspike_until = now + secs
    elif name == "logburst":
        STATE.logburst_until = now + secs
    elif name == "counter_reset":
        if target not in DEVICES:
            return 400, "target must be one of " + ",".join(DEVICES)
        STATE.counter_reset(target, now)
    elif name != "status":
        return 404, "unknown fault"
    return 200, str(STATE.status(now))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/snmp":
            code, body = STATE.render_snmp(q.get("target", ""), time.time(), q.get("module", "if_mib"))
        elif u.path == "/flows":
            code, body = 200, STATE.render_flows()
        elif u.path.startswith("/fault/"):
            code, body = apply_fault(u.path[len("/fault/"):], q)
            body += "\n"
        else:
            code, body = 404, "endpoints: /snmp?target=&module=if_mib, /flows, /fault/{down,wanspike,logburst,counter_reset,status}\n"
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def selftest():
    t0 = 1_800_000_000.0
    s = State(t0, seed=1)
    snap = lambda: [v for d in s.octets.values() for io in d.values() for v in io]
    prev = snap()
    for k in range(1, 30):
        s.advance(t0 + k * 15)
        cur = snap()
        assert all(c >= p for c, p in zip(cur, prev)), "counters must be monotonic"
        prev = cur
    assert s.octets["rtx1300"][2][0] > 0
    s.counter_reset("rtx1300", t0 + 500)
    assert s.octets["rtx1300"][2] == [0.0, 0.0]
    code, body = s.render_snmp("rtx1300", t0 + 500)
    assert code == 200 and "sysUpTime 0\n" in body, "reset must restart sysUpTime"
    s.down_until["wlx222"] = t0 + 600
    assert s.render_snmp("wlx222", t0 + 550)[0] == 503
    assert s.render_snmp("wlx222", t0 + 601)[0] == 200
    assert all(" wlx222 " not in line for line in s.syslog_lines(t0 + 550))
    unknown = [l for l in s.render_flows().splitlines() if 'dst_country="Unknown"' in l]
    assert unknown and all('lat="",lon=""' in l for l in unknown), "Unknown must have empty lat/lon"
    assert 'demo_wlan_clients{' in s.render_snmp("wlx413", t0)[1]
    s.wanspike_until, s.noise = t0 + 900, 1.3
    assert 800 < s.wan_rates(t0 + 800)[0] * 1.03 < 1000, "spike must exceed 80% but stay under link speed"
    assert s.syslog_lines(t0)[0].startswith("<")
    lldp = s.render_snmp("wlx413", t0, "lldp")[1]
    assert 'lldpRemSysName="rtx1300"' in lldp and 'lldpLocPortId="lan1"' in lldp and "ifHCInOctets" not in lldp
    assert "lldpRemSysName{" not in s.render_snmp("wlx222", t0, "lldp")[1] and s.render_snmp("wlx222", t0 + 550, "lldp")[0] == 503
    print("selftest OK")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    threading.Thread(target=tick_loop, daemon=True).start()
    threading.Thread(target=syslog_loop, args=(os.environ.get("SYSLOG_HOST", "alloy"),
                                               int(os.environ.get("SYSLOG_PORT", "514"))), daemon=True).start()
    if os.environ.get("DEMO_AUTO_FAULTS", "0") == "1":
        interval = int(os.environ.get("DEMO_AUTO_FAULT_INTERVAL", "240"))
        threading.Thread(target=auto_fault_loop, args=(interval,), daemon=True).start()
    print("demo-gen listening on :9116 (SYNTHETIC DATA)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 9116), Handler).serve_forever()


if __name__ == "__main__":
    main()
