"""Packet capture (profile `capture`, off by default): dumpcap into a bounded ring of pcapng files, plus a status file
for flowd (which exports it to Prometheus) and the analysis screen.

  /capture/ring/obs-<session>_NNNNN_<time>.pcapng   at most CAPTURE_FILES files / CAPTURE_FILES x CAPTURE_FILE_MB in all
                                                    (also across dumpcap sessions), a new file at least every
                                                    CAPTURE_FILE_SECONDS; the file dumpcap has open is the "current" one
  /capture/status.json                              running, interface, received packets, drops, ring usage, error

Drops, honestly: dumpcap's ring files carry no statistics and dumpcap reports its own / pcap buffer drops only when a
session ends (dumpcap_dropped, summed over ended sessions). Live, only the interface's kernel rx_dropped counter is
available (nic_rx_dropped: packets the NIC / driver dropped, which the capture never saw either).

Only on a Linux host with host networking (the container sees the host's interfaces): Docker Desktop (Windows /
macOS) runs containers in a VM whose "host" is not your LAN, so this exits with an explanation there
(CAPTURE_ALLOW_VM=1 overrides it, for testing the pipeline inside a VM only). Nothing here changes the router:
a mirror port, if used, is configured by hand (spec G4). dumpcap only writes packets; it never dissects them.

Run: python capture.py   |   python capture.py --selftest
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(os.environ.get("CAPTURE_DIR", "/capture"))
RING = BASE / "ring"
STATUS = BASE / "status.json"
IFACE = os.environ.get("CAPTURE_IFACE", "").strip()
BPF = os.environ.get("CAPTURE_BPF", "").strip()
SNAPLEN = os.environ.get("CAPTURE_SNAPLEN", "1514").strip()
FILE_MB = os.environ.get("CAPTURE_FILE_MB", "20").strip()
FILES = os.environ.get("CAPTURE_FILES", "20").strip()
FILE_SECONDS = os.environ.get("CAPTURE_FILE_SECONDS", "60").strip()
KEEP_HOURS = os.environ.get("CAPTURE_KEEP_HOURS", "24").strip()
ALLOW_VM = os.environ.get("CAPTURE_ALLOW_VM", "0") == "1"
PREFIX = "obs"
LOOP_S = 2
EXIT_CONFIG = 3  # configuration / platform error: compose restarts it a few times (on-failure), then gives up


class ConfigError(Exception):
    pass


def check_config():
    """-> dict of validated settings, or ConfigError (Japanese + English message)."""
    out = {}
    for key, val, lo, hi in (("snaplen", SNAPLEN, 64, 262144), ("file_mb", FILE_MB, 1, 2000), ("files", FILES, 2, 1000),
                             ("duration_s", FILE_SECONDS, 10, 86400)):
        if not val.isdigit() or not lo <= int(val) <= hi:
            raise ConfigError(f"CAPTURE_{key.upper()} は {lo}..{hi} の整数です (got {val!r})")
        out[key] = int(val)
    try:
        out["keep_s"] = float(KEEP_HOURS) * 3600
    except ValueError:
        raise ConfigError(f"CAPTURE_KEEP_HOURS は数値です (got {KEEP_HOURS!r})") from None
    if len(BPF) > 1024 or any(ord(c) < 32 for c in BPF):
        raise ConfigError("CAPTURE_BPF: 1 行、1024 文字まで")
    out["limit"] = int(out["files"] * out["file_mb"] * 1e6 * 1.05)  # dumpcap's kB are 1000 bytes; 5 % for the last block
    return out


def platform_problem(osrelease, net_names):
    """Docker Desktop / WSL / a VM: the 'host' network is the VM's, not the LAN."""
    if re.search(r"microsoft|wsl|linuxkit", osrelease, re.I) or "services1" in net_names:
        return ("Docker Desktop (Windows / macOS) または WSL 上ではキャプチャできません: コンテナの host network は VM 内部のネットワークのため、"
                "LAN のパケットは参照不可です。Linux ホスト (Raspberry Pi / 小型 PC) の Docker Engine で稼働させてください。"
                " / Packet capture needs a Linux host with Docker Engine; under Docker Desktop / WSL the host network is a VM's"
                " (CAPTURE_ALLOW_VM=1 only to test the pipeline inside the VM).")
    return None


def interfaces():
    try:
        return sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []


def check_iface(names):
    if not IFACE:
        raise ConfigError(f"CAPTURE_IFACE を .env に設定してください (本ホストのインターフェース: {', '.join(names) or 'なし'})")
    if not re.fullmatch(r"[A-Za-z0-9._@:-]{1,15}", IFACE) or IFACE not in names:
        raise ConfigError(f"インターフェース {IFACE!r} が存在しません (存在: {', '.join(names) or 'なし'})。"
                          " host network での稼働 (compose の network_mode: host) も確認してください")


def check_bpf():
    if not BPF:
        return
    p = subprocess.run(["dumpcap", "-i", IFACE, "-f", BPF, "-d"], capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        msg = " ".join(l for l in p.stderr.splitlines() if l.strip() and "Running as user" not in l)[:300]
        raise ConfigError(f"CAPTURE_BPF をコンパイルできません: {msg}")


# ---- counters (received / dropped) ---------------------------------------------------------------------------
# dumpcap's ring files carry no statistics blocks, and it reports its kernel / own drops only when it stops. Live:
# the captured count it prints on stderr ("Packets: N") and the interface's rx_dropped counter (drops before the
# capture saw the packets). Each dumpcap exit adds its final "received/dropped (pcap:N/dumpcap:N/...)" line.
PACKETS = re.compile(r"Packets(?: captured)?: (\d+)")
FINAL = re.compile(r"received/dropped on interface [^:]*: (\d+)/(\d+)")


def parse_stderr(text):
    """-> (last captured count or None, [(received, dropped)] of the final lines)."""
    counts = PACKETS.findall(text)
    return (int(counts[-1]) if counts else None), [(int(a), int(b)) for a, b in FINAL.findall(text)]


def if_dropped(iface):
    try:
        return int(Path(f"/sys/class/net/{iface}/statistics/rx_dropped").read_text())
    except (OSError, ValueError):
        return 0


# ---- supervisor -----------------------------------------------------------------------------------------------

def load_totals():
    """(received, dumpcap_dropped) of earlier runs, from the last status.json: the counters survive restarts."""
    try:
        st = json.loads(STATUS.read_text())
        return tuple(max(0, int(st.get(k) or 0)) for k in ("received", "dumpcap_dropped"))
    except (OSError, ValueError, TypeError, AttributeError):
        return 0, 0


def write_status(st):
    """Statuses without the totals carry the last written ones forward (a config error must not reset them)."""
    if "received" not in st or "dumpcap_dropped" not in st:
        st = {**dict(zip(("received", "dumpcap_dropped"), load_totals())), **st}
    tmp = STATUS.with_name(".status.json.tmp")
    tmp.write_text(json.dumps(st))
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATUS)


def ring_files():
    """-> [(name, bytes, mtime, mode)] oldest first (by time: names carry a per-session prefix and a counter that
    dumpcap restarts with every session and that grows past five digits)."""
    out = []
    for e in os.scandir(RING):
        if e.is_file(follow_symlinks=False) and e.name.startswith(PREFIX) and e.name.endswith(".pcapng"):
            try:
                st = e.stat()
            except OSError:
                continue  # removed between listing and stat (dumpcap's own ring, tools capture prune)
            out.append((e.name, st.st_size, st.st_mtime, st.st_mode))
    return sorted(out, key=lambda f: (f[2], f[0]))


def open_file(pid):
    """The ring file the running dumpcap has open (from /proc/<pid>/fd), or None."""
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if os.path.dirname(target) == str(RING) and target.endswith(".pcapng"):
                return os.path.basename(target)
    except OSError:
        pass
    return None


def prune_plan(files, current, now, cfg):
    """Files to delete: older than the keep time, then the oldest while the ring (all sessions) holds more than
    CAPTURE_FILES files or more than its byte limit. The file dumpcap is writing is never deleted."""
    gone = {f[0] for f in files if f[0] != current and now - f[2] > cfg["keep_s"]}
    left = [f for f in files if f[0] not in gone]
    count, total = len(left), sum(f[1] for f in left)
    for name, size, _m, _mode in left:  # oldest first
        if count <= cfg["files"] and total <= cfg["limit"]:
            break
        if name == current:
            continue
        gone.add(name)
        count, total = count - 1, total - size
    return gone


def housekeeping(cfg, now, current):
    """chmod for the readers, keep time, file / byte caps across sessions. -> (ring bytes, ring files)."""
    files = ring_files()
    for name, _size, _mtime, mode in files:
        if mode & 0o044 != 0o044:
            try:
                os.chmod(RING / name, 0o644)  # flowd / analyzer / mask-api read it (dumpcap creates files owner-only)
            except FileNotFoundError:
                pass
    for name in prune_plan(files, current, now, cfg):
        (RING / name).unlink(missing_ok=True)
    files = ring_files()
    return sum(f[1] for f in files), len(files)


def dumpcap_argv(cfg, session):
    """session: a per-run id in the file names (obs-<session>_NNNNN_<time>.pcapng), so runs never collide."""
    argv = ["dumpcap", "-i", IFACE, "-s", str(cfg["snaplen"]), "-b", f"filesize:{cfg['file_mb'] * 1000}",
            "-b", f"files:{cfg['files']}", "-b", f"duration:{cfg['duration_s']}", "-w", str(RING / f"{PREFIX}-{session}.pcapng")]
    return argv + (["-f", BPF] if BPF else [])


def fail(msg, cfg=None):
    print(f"[capture] ERROR: {msg}", file=sys.stderr, flush=True)
    BASE.mkdir(parents=True, exist_ok=True)
    write_status({"running": False, "updated": time.time(), "iface": IFACE, "filter": BPF, "error": msg[:400],
                  **({"ring_limit_bytes": cfg["limit"]} if cfg else {})})
    sys.exit(EXIT_CONFIG)


def run():
    try:
        cfg = check_config()
    except ConfigError as e:
        fail(str(e))
    names = interfaces()
    try:
        osrelease = Path("/proc/sys/kernel/osrelease").read_text().strip()
    except OSError:
        osrelease = ""
    problem = platform_problem(osrelease, names)
    if problem and not ALLOW_VM:
        fail(problem, cfg)
    if problem:
        print("[capture] WARNING: CAPTURE_ALLOW_VM=1 - capturing inside a VM (pipeline test only; this is not the LAN)", file=sys.stderr, flush=True)
    try:
        check_iface(names)
        check_bpf()
    except ConfigError as e:
        fail(str(e), cfg)
    except (OSError, subprocess.SubprocessError) as e:
        fail(f"dumpcap を実行できません: {e}", cfg)
    RING.mkdir(parents=True, exist_ok=True)
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    signal.signal(signal.SIGINT, lambda *_: stopping.append(1))
    base_recv, base_drop = load_totals()  # totals of earlier dumpcap runs and containers (each run counts from 0)
    captured, if_drop0 = 0, if_dropped(IFACE)
    err, proc, backoff, started, errlog = None, None, 2, None, None
    print(f"[capture] {' '.join(dumpcap_argv(cfg, '<session>'))}", flush=True)
    while not stopping:
        now = time.time()
        if proc is None:
            # a file, not a pipe (a chatty dumpcap can never block on it), appended so it can be truncated under it
            errlog = open("/tmp/dumpcap.err", "a+")
            errlog.truncate(0)
            proc = subprocess.Popen(dumpcap_argv(cfg, int(now)), stdout=subprocess.DEVNULL, stderr=errlog)
            started, err, captured = now, None, 0
        errlog.seek(0)
        text = errlog.read()
        n_cap, finals = parse_stderr(text)
        captured = n_cap if n_cap is not None else captured
        if proc.poll() is not None:
            tail = " ".join(l for l in text[-4000:].replace("\r", "\n").splitlines() if l.strip() and "Running as user" not in l
                            and not PACKETS.fullmatch(l.strip()))[-300:]
            errlog.close()
            err = f"dumpcap stopped (exit {proc.returncode}): {tail}"
            print(f"[capture] {err}; restarting in {backoff} s", file=sys.stderr, flush=True)
            base_recv += max([captured] + [r for r, _ in finals])
            base_drop += sum(d for _, d in finals)
            proc = None
            write_status({"running": False, "updated": now, "iface": IFACE, "filter": BPF, "error": err, "ring_limit_bytes": cfg["limit"],
                          "received": base_recv, "dumpcap_dropped": base_drop})
            time.sleep(backoff)
            backoff = min(60, backoff * 2)
            continue
        elif now - started > 60:
            backoff = 2
        if len(text) > 64 * 1024:
            errlog.truncate(0)  # only "Packets: N" progress lines accumulate while dumpcap runs
        files = ring_files()
        current = open_file(proc.pid) or (files[-1][0] if files else None)
        size, n = housekeeping(cfg, now, current)
        write_status({"running": True, "updated": now, "started": started, "iface": IFACE, "filter": BPF, "snaplen": cfg["snaplen"],
                      "current": current, "files_max": cfg["files"], "file_mb": cfg["file_mb"], "duration_s": cfg["duration_s"],
                      "ring_bytes": size, "ring_files": n, "ring_limit_bytes": cfg["limit"],
                      "received": base_recv + captured, "nic_rx_dropped": max(0, if_dropped(IFACE) - if_drop0),
                      "dumpcap_dropped": base_drop, "error": err})
        time.sleep(LOOP_S)
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if proc:  # the stopped session's final statistics (dumpcap prints them on SIGTERM) join the totals
        errlog.seek(0)
        n_cap, finals = parse_stderr(errlog.read())
        errlog.close()
        base_recv += max([n_cap if n_cap is not None else captured] + [r for r, _ in finals])
        base_drop += sum(d for _, d in finals)
    write_status({"running": False, "updated": time.time(), "iface": IFACE, "filter": BPF, "error": "stopped", "ring_limit_bytes": cfg["limit"],
                  "received": base_recv, "dumpcap_dropped": base_drop})


def selftest():
    assert platform_problem("5.15.167.4-microsoft-standard-WSL2", ["eth0"]) and platform_problem("6.10.14-linuxkit", ["eth0"])
    assert platform_problem("6.6.51+rpt-rpi-2712", ["eth0", "lo", "services1"])  # Docker Desktop's VM interface
    assert platform_problem("6.6.51+rpt-rpi-2712", ["eth0", "lo", "wlan0"]) is None
    cfg = check_config()
    assert cfg["limit"] == int(20 * 20 * 1e6 * 1.05) and dumpcap_argv(cfg, 7)[-2:] == ["-w", str(RING / "obs-7.pcapng")] or BPF
    # ring caps across sessions: by time (a new session restarts at _00001; counters pass 99999), never the open file
    small = {**cfg, "files": 3, "limit": 250, "keep_s": 1000}
    fl = [("obs-100_99999_x.pcapng", 100, 10.0, 0), ("obs-100_100000_x.pcapng", 100, 20.0, 0), ("obs-200_00001_x.pcapng", 100, 30.0, 0),
          ("obs-200_00002_x.pcapng", 10, 40.0, 0)]
    assert prune_plan(fl, "obs-200_00002_x.pcapng", 50.0, small) == {"obs-100_99999_x.pcapng"}  # 4 files > 3, 310 B > 250
    assert prune_plan(fl, "obs-100_99999_x.pcapng", 50.0, {**small, "limit": 10}) == {"obs-100_100000_x.pcapng", "obs-200_00001_x.pcapng", "obs-200_00002_x.pcapng"}
    assert prune_plan(fl, None, 2000.0, small) == {f[0] for f in fl}  # keep time
    assert open_file(999999999) is None
    # counters from dumpcap's stderr (progress lines with \r, final statistics when it stops)
    err = "Capturing on 'eth0'\nFile: /x_1.pcapng\n\rPackets: 1 \rPackets: 42 File: /x_2.pcapng\n\rPackets captured: 52\n" \
          "Packets received/dropped on interface 'eth0': 60/8 (pcap:8/dumpcap:0/flushed:0/ps_ifdrop:0) (86.7%)\n"
    assert parse_stderr(err) == (52, [(60, 8)]) and parse_stderr("Capturing on 'eth0'") == (None, [])
    assert if_dropped("no-such-if") == 0
    global STATUS
    import tempfile
    was = STATUS
    with tempfile.TemporaryDirectory() as tmp:  # totals survive a restart and a status without them
        STATUS = Path(tmp) / "status.json"
        assert load_totals() == (0, 0)
        write_status({"running": False, "received": 60, "dumpcap_dropped": 8})
        write_status({"running": False, "error": "config"})
        assert load_totals() == (60, 8) and json.loads(STATUS.read_text())["error"] == "config"
        STATUS.write_text("[1]")
        assert load_totals() == (0, 0)
    STATUS = was
    print("capture selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        run()
