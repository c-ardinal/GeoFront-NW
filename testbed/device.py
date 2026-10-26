"""Testbed device: an SNMP agent simulator (snmpsim, SNMPv3 authPriv) plus a YAMAHA-style syslog sender
running in one container, so SNMP answers and syslog lines come from the same address like a real device.

Used only by the `testbed` compose profile to exercise the prod path (snmp-exporter -> Prometheus,
Alloy -> Loki) without hardware. It is NOT a model of RTX/WLX firmware: the interface tables mirror
demo-gen's, only standard MIB-II / IF-MIB / LLDP-MIB objects are simulated (no YAMAHA private MIB; whether RTX/WLX
answer LLDP-MIB at all is unconfirmed), and the syslog
lines are the "yamaha" fixtures from testbed/fixtures/syslog.jsonl (PRI only, no timestamp/host/tag).

Env: TB_DEVICE (rtx1300 | wlx413), SNMP_V3_USER / SNMP_V3_AUTH_PASS / SNMP_V3_PRIV_PASS /
SNMP_V3_AUTH_PROTO / SNMP_V3_PRIV_PROTO, SNMP_COMMUNITY (optional v2c), SYSLOG_HOST, SYSLOG_PORT,
SYSLOG_INTERVAL (s).

Run: python device.py            (simulator + sender)
     python device.py --health   (healthcheck: simulator process alive)
     python device.py --selftest
"""
import json
import os
import random
import socket
import subprocess
import sys
import time
from pathlib import Path

DATA_DIR = Path("/tmp/snmpdata")
PID_FILE = Path("/tmp/snmpsim.pid")
FIXTURES = Path(os.environ.get("TB_FIXTURES", "/fixtures/syslog.jsonl"))
SNMP_PORT = 1161
# ifIndex, ifName, ifDescr, ifHighSpeed (Mbps), operStatus (1 up, 2 down), in/out bytes per second
INTERFACES = {
    "rtx1300": [(1, "lan1", "LAN1 (LAN)", 1000, 1, 2_000_000, 9_000_000), (2, "lan2", "LAN2 (WAN)", 1000, 1, 9_000_000, 2_000_000),
                (3, "lan3", "LAN3", 1000, 2, 0, 0)],
    "wlx413": [(1, "lan1", "LAN1", 1000, 1, 4_000_000, 1_000_000), (2, "wlan0", "WLAN 2.4GHz", 300, 1, 250_000, 900_000),
               (3, "wlan1", "WLAN 5GHz", 1200, 1, 700_000, 3_000_000)],
}
MODEL = {"rtx1300": "rtx", "wlx413": "wlx"}
# LLDP-MIB lldpRemTable (read-only, for the network map's LLDP path): local ifIndex, remote sysName, remote port id / desc.
# rtx1300 also sees a neighbour that is not in the inventory (an LLDP-only node on the map).
LLDP = {"rtx1300": [(1, "wlx413", "lan1", "LAN1"), (1, "sw-lab01", "port8", "GigabitEthernet 8")],
        "wlx413": [(1, "rtx1300", "lan1", "LAN1 (LAN)")]}
SYS_DESCR = {"rtx1300": "TESTBED simulated router (not real firmware)", "wlx413": "TESTBED simulated access point (not real firmware)"}


def snmprec(device):
    """snmpsim data file: sysDescr/sysUpTime/sysName, ifTable and ifXTable with counters that grow at a fixed rate."""
    rows = [("1.3.6.1.2.1.1.1.0", "4", SYS_DESCR[device]),
            ("1.3.6.1.2.1.1.3.0", "67:numeric", "rate=100,initial=%d" % random.randint(10**7, 10**8)),
            ("1.3.6.1.2.1.1.5.0", "4", device),
            ("1.3.6.1.2.1.2.1.0", "2", str(len(INTERFACES[device])))]
    for idx, name, descr, speed, oper, rx, tx in INTERFACES[device]:
        rows += [(f"1.3.6.1.2.1.2.2.1.1.{idx}", "2", str(idx)),
                 (f"1.3.6.1.2.1.2.2.1.2.{idx}", "4", descr),
                 (f"1.3.6.1.2.1.2.2.1.7.{idx}", "2", "1"),
                 (f"1.3.6.1.2.1.2.2.1.8.{idx}", "2", str(oper)),
                 (f"1.3.6.1.2.1.2.2.1.14.{idx}", "65", "0"),
                 (f"1.3.6.1.2.1.2.2.1.20.{idx}", "65", "0"),
                 (f"1.3.6.1.2.1.31.1.1.1.1.{idx}", "4", name),
                 (f"1.3.6.1.2.1.31.1.1.1.6.{idx}", "70:numeric", f"rate={rx},initial=1000"),
                 (f"1.3.6.1.2.1.31.1.1.1.10.{idx}", "70:numeric", f"rate={tx},initial=1000"),
                 (f"1.3.6.1.2.1.31.1.1.1.15.{idx}", "66", str(speed)),
                 (f"1.3.6.1.2.1.31.1.1.1.18.{idx}", "4", "")]
    lldp_rem, lldp_loc = "1.0.8802.1.1.2.1.4.1.1", "1.0.8802.1.1.2.1.3.7.1"
    for i, (port, sysname, rport, rdesc) in enumerate(LLDP.get(device, []), 1):
        ix = f"0.{port}.{i}"  # lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex
        rows += [(f"{lldp_rem}.4.{ix}", "2", "5"), (f"{lldp_rem}.6.{ix}", "2", "5"),  # chassis / port id subtypes
                 (f"{lldp_rem}.7.{ix}", "4", rport), (f"{lldp_rem}.8.{ix}", "4", rdesc), (f"{lldp_rem}.9.{ix}", "4", sysname)]
    for port in sorted({p for p, *_ in LLDP.get(device, [])}):
        name = next(n for i, n, *_ in INTERFACES[device] if i == port)
        rows += [(f"{lldp_loc}.2.{port}", "2", "5"), (f"{lldp_loc}.3.{port}", "4", name)]
    key =lambda r: tuple(int(p) for p in r[0].split("."))  # snmpsim needs lexicographic OID order
    return "".join(f"{oid}|{typ}|{val}\n" for oid, typ, val in sorted(rows, key=key))


def responder_args(env):
    args = ["snmpsim-command-responder", f"--data-dir={DATA_DIR}", f"--agent-udpv4-endpoint=0.0.0.0:{SNMP_PORT}",
            "--v3-user", env["SNMP_V3_USER"], "--v3-auth-key", env["SNMP_V3_AUTH_PASS"],
            "--v3-auth-proto", env.get("SNMP_V3_AUTH_PROTO", "SHA"),
            "--v3-priv-key", env["SNMP_V3_PRIV_PASS"], "--v3-priv-proto", env.get("SNMP_V3_PRIV_PROTO", "AES")]
    if not env.get("SNMP_COMMUNITY"):
        args.append("--v3-only")
    return args


def data_name():
    """snmpsim data file name = v2c community = SNMPv3 context name it answers."""
    return os.environ.get("SNMP_COMMUNITY") or "public"


def responder(argv):
    """snmpsim's command responder, also answering the empty SNMPv3 context. snmpsim serves v3 only under the
    context named after a data file and unregisters the default (empty) one; snmp_exporter (and most managers)
    queries the empty context, so it is bound to the same data file here."""
    from pysnmp.entity.rfc3413 import context
    from snmpsim.commands import responder as cli
    register = context.SnmpContext.register_context_name

    def register_also_default(self, name, instrum):
        register(self, name, instrum)
        if name == data_name():
            register(self, b"", instrum)
    context.SnmpContext.register_context_name = register_also_default
    sys.argv = ["snmpsim-command-responder", *argv]
    sys.exit(cli.main())


def fixture_lines(model):
    rows = [json.loads(line) for line in FIXTURES.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r["raw"] for r in rows if r["model"] == model and r["form"] == "yamaha"]


def main():
    device = os.environ["TB_DEVICE"]
    if device not in INTERFACES:
        sys.exit(f"TB_DEVICE must be one of {sorted(INTERFACES)}")
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / f"{data_name()}.snmprec").write_text(snmprec(device), encoding="ascii")
    sim = subprocess.Popen([sys.executable, __file__, "--responder", *responder_args(os.environ)[1:]])
    PID_FILE.write_text(str(sim.pid))
    lines = fixture_lines(MODEL[device])
    host, port = os.environ.get("SYSLOG_HOST", "alloy"), int(os.environ.get("SYSLOG_PORT", "514"))
    interval = float(os.environ.get("SYSLOG_INTERVAL", "5"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"testbed {device}: SNMP on udp/{SNMP_PORT}, sending {len(lines)} fixture lines to {host}:{port} every {interval}s", flush=True)
    i = 0
    while sim.poll() is None:
        try:
            sock.sendto(lines[i % len(lines)].encode(), (host, port))
        except OSError as e:  # alloy not up yet / restarting: keep the simulator running
            print(f"syslog send failed: {e}", file=sys.stderr, flush=True)
        i += 1
        time.sleep(interval)
    sys.exit(f"snmpsim exited with {sim.returncode}")


def health():
    pid = int(PID_FILE.read_text())
    os.kill(pid, 0)  # raises if the simulator is gone


def selftest():
    rec = snmprec("rtx1300").splitlines()
    oids = [tuple(int(p) for p in r.split("|")[0].split(".")) for r in rec]
    assert oids == sorted(oids) and len(oids) == len(set(oids))
    assert any(r.startswith("1.3.6.1.2.1.31.1.1.1.6.2|70:numeric|rate=9000000") for r in rec)
    assert "1.3.6.1.2.1.1.5.0|4|rtx1300" in rec
    assert "1.0.8802.1.1.2.1.4.1.1.9.0.1.1|4|wlx413" in rec and "1.0.8802.1.1.2.1.3.7.1.3.1|4|lan1" in rec  # LLDP-MIB
    assert "1.0.8802.1.1.2.1.4.1.1.9.0.1.1|4|rtx1300" in snmprec("wlx413").splitlines()
    env = {"SNMP_V3_USER": "u", "SNMP_V3_AUTH_PASS": "a" * 8, "SNMP_V3_PRIV_PASS": "p" * 8}
    assert "--v3-only" in responder_args(env) and "--v3-only" not in responder_args({**env, "SNMP_COMMUNITY": "c"})
    for model in ("rtx", "wlx"):
        ls = fixture_lines(model)
        assert ls and all(l.startswith("<") and ">" in l for l in ls)
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    elif sys.argv[1:2] == ["--responder"]:
        responder(sys.argv[2:])
    elif "--health" in sys.argv:
        health()
    else:
        main()
