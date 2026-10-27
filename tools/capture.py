"""Packet capture / GeoIP housekeeping for the tools container (pure logic; obs.py has the commands).

GeoIP: DB-IP "IP to City Lite" and "IP to ASN Lite" in MaxMind DB format, monthly files
  https://download.db-ip.com/free/dbip-{city|asn}-lite-YYYY-MM.mmdb.gz
licensed CC BY 4.0 (attribution: "IP Geolocation by DB-IP", https://db-ip.com). The current month is tried first,
then the previous one (a new month's file appears some days into the month).
"""
import gzip
import json
import os
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

GEOIP_URL = "https://download.db-ip.com/free/dbip-{db}-lite-{month}.mmdb.gz"
GEOIP_DBS = {"city": "dbip-city-lite.mmdb", "asn": "dbip-asn-lite.mmdb"}
GEOIP_MAX_BYTES = 600 * 2**20  # uncompressed; the city file is ~130 MB today
GEOIP_STALE_DAYS = 45
MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
RING_SUFFIXES = (".pcapng", ".pcap")


def months(now):
    t = time.gmtime(now)
    prev = (t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12)
    return [f"{t.tm_year:04d}-{t.tm_mon:02d}", f"{prev[0]:04d}-{prev[1]:02d}"]


def is_mmdb(path):
    size = path.stat().st_size
    with open(path, "rb") as f:
        f.seek(max(0, size - 128 * 1024))
        return MMDB_MARKER in f.read()


def download(url, dest, opener=urllib.request.urlopen, timeout=60):
    """url (.mmdb.gz) -> dest (uncompressed), bounded; raises OSError / ValueError."""
    tmp = dest.with_name(f".{dest.name}.part")
    try:
        with opener(urllib.request.Request(url, headers={"User-Agent": "geofront-nw-tools"}), timeout=timeout) as r, \
                gzip.GzipFile(fileobj=r) as gz, open(tmp, "wb") as out:
            total = 0
            while True:
                chunk = gz.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > GEOIP_MAX_BYTES:
                    raise ValueError("file larger than expected")
                out.write(chunk)
        if not is_mmdb(tmp):
            raise ValueError("not a MaxMind DB file")
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)


def geoip_version(directory):
    try:
        return json.loads((Path(directory) / "version.json").read_text())
    except (OSError, ValueError):
        return {}


def geoip_update(directory, now=None, force=False, opener=urllib.request.urlopen, log=print):
    """-> (ok, version dict). Skips a database already at the newest available month unless force."""
    now = now or time.time()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ver = geoip_version(directory)
    ok = True
    for db, fname in GEOIP_DBS.items():
        cands = months(now)
        if not force and ver.get(db) == cands[0] and (directory / fname).exists():
            log(f"[OK] {db}: {ver[db]} (最新。--force で取り直し)")
            continue
        got = None
        for month in cands:
            url = GEOIP_URL.format(db=db, month=month)
            try:
                download(url, directory / fname, opener)
                got = month
                break
            except urllib.error.HTTPError as e:
                log(f"  {url}: HTTP {e.code}")
            except (OSError, ValueError) as e:
                log(f"  {url}: {type(e).__name__}: {e}")
        if got:
            ver[db] = got
            log(f"[OK] {db}: {got} ({(directory / fname).stat().st_size / 2**20:.0f} MiB)")
        else:
            ok = False
            log(f"[NG] {db}: ダウンロードできませんでした (前の版があればそのまま使います)")
    ver.update({"updated": int(now), "source": "DB-IP Lite", "license": "CC BY 4.0", "attribution": ATTRIBUTION})
    tmp = directory / ".version.json.tmp"
    tmp.write_text(json.dumps(ver, indent=1))
    os.chmod(tmp, 0o644)
    os.replace(tmp, directory / "version.json")
    return ok, ver


def geoip_rows(directory, now=None):
    """-> [(db, month, file MiB, age days or None, state)] for `geoip status` / `check`."""
    now = now or time.time()
    ver, rows = geoip_version(directory), []
    for db, fname in GEOIP_DBS.items():
        p = Path(directory) / fname
        if not p.exists():
            rows.append((db, "—", "—", None, "なし (国は Unknown になります: tools geoip update)"))
            continue
        month = ver.get(db, "?")
        try:  # age from the month the file is for (DB-IP builds it at the start of that month)
            age = (now - time.mktime(time.strptime(month + "-01", "%Y-%m-%d"))) / 86400
        except ValueError:
            age = (now - p.stat().st_mtime) / 86400
        state = f"古い ({GEOIP_STALE_DAYS} 日超): tools geoip update" if age > GEOIP_STALE_DAYS else "OK"
        rows.append((db, month, f"{p.stat().st_size / 2**20:.0f}", round(age), state))
    return rows


# ---- capture ring / uploads --------------------------------------------------------------------------------------

def capture_status(directory, now=None):
    """status.json of the capture service -> dict with 'state' (running / stopped / none) and 'age_s'."""
    now = now or time.time()
    try:
        st = json.loads((Path(directory) / "status.json").read_text())
    except (OSError, ValueError):
        return {"state": "none"}
    age = now - float(st.get("updated", 0))
    st["age_s"] = round(age)
    st["state"] = "running" if st.get("running") and age < 30 else "stopped"
    return st


def capture_files(directory):
    """-> [(name, bytes, mtime)] of the ring (or an upload directory), oldest first."""
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return []
    out = []
    for e in entries:
        try:
            if e.is_file(follow_symlinks=False) and e.name.endswith(RING_SUFFIXES + (".cap",)):
                st = e.stat(follow_symlinks=False)
                out.append((e.name, st.st_size, st.st_mtime))
        except OSError:
            continue  # removed between listing and stat (ring rotation, prune)
    return sorted(out, key=lambda x: x[2])


def prune_plan(files, now, keep_s, total_max=None, current=None):
    """Files to delete: older than keep_s, then the oldest while the total exceeds total_max. Never `current`."""
    total = sum(f[1] for f in files)
    out = []
    for name, size, mtime in files:  # oldest first
        if name == current:
            continue
        if now - mtime > keep_s or (total_max is not None and total > total_max):
            out.append(name)
            total -= size
    return out


def prune(directory, names):
    removed = 0
    for n in names:
        try:
            (Path(directory) / n).unlink()
            removed += 1
        except OSError:
            pass
    return removed


def busy_ring_files(directory):
    """Ring files that may be open for writing now: the status' current file and the newest one (the status can lag a
    rotation), while capture runs."""
    st = capture_status(directory)
    if st["state"] != "running":
        return set()
    ring = capture_files(Path(directory) / "ring")
    return {n for n in (st.get("current"), ring[-1][0] if ring else None) if isinstance(n, str)}


def stage_closed(src, dst, capture_volume=False):
    """Copy a capture / uploads volume to dst for a backup while the services run: files that vanish meanwhile
    (ring rotation, retention) are skipped, and so are ring files open for writing (checked again before each copy)
    and unfinished uploads (.part-*, stage-*). Modes: dirs 0755, files 0644 (the readers run as other users).
    dst always exists afterwards (an empty volume gives an empty tree). -> files copied"""
    src, dst = Path(src), Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    copied = 0
    for root, _dirs, names in os.walk(src):
        for name in names:
            if name.startswith((".part-", "stage-")) or (capture_volume and name in busy_ring_files(src)):
                continue
            target = dst / Path(root).relative_to(src) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(Path(root) / name, target)
                os.chmod(target, 0o644)
                copied += 1
            except FileNotFoundError:
                pass
    for d in [dst, *(d for d in dst.rglob("*") if d.is_dir())]:
        os.chmod(d, 0o755)
    return copied


def selftest():
    import io
    import tempfile
    assert months(time.mktime((2026, 1, 15, 0, 0, 0, 0, 0, 0))) == ["2026-01", "2025-12"]
    files = [("a", 10, 100.0), ("b", 10, 200.0), ("c", 10, 300.0), ("cur", 10, 400.0)]
    assert prune_plan(files, 1000, keep_s=750) == ["a", "b"]
    assert prune_plan(files, 1000, keep_s=10**6, total_max=25, current="cur") == ["a", "b"]
    assert prune_plan(files, 1000, keep_s=0, current="cur") == ["a", "b", "c"]
    with tempfile.TemporaryDirectory() as tmp:
        good = gzip.compress(b"\0" * 1000 + MMDB_MARKER + b"meta")
        calls = []

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.close()

        def opener(req, timeout=0):
            calls.append(req.full_url)
            if "2026-02" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
            return Resp(good if "city" in req.full_url or "asn" in req.full_url else b"")
        now = time.mktime((2026, 2, 2, 0, 0, 0, 0, 0, 0))
        ok, ver = geoip_update(tmp, now=now, opener=opener, log=lambda *_: None)
        assert ok and ver["city"] == ver["asn"] == "2026-01" and len(calls) == 4, (ok, ver, calls)
        assert is_mmdb(Path(tmp, "dbip-city-lite.mmdb")) and not list(Path(tmp).glob(".*part"))
        rows = geoip_rows(tmp, now=now + 50 * 86400)
        assert rows[0][4].startswith("古い") and rows[0][1] == "2026-01"
        bad = lambda req, timeout=0: Resp(gzip.compress(b"not a database"))
        ok, ver = geoip_update(tmp, now=now, opener=bad, force=True, log=lambda *_: None)
        assert not ok and is_mmdb(Path(tmp, "dbip-city-lite.mmdb")), "a bad download keeps the previous file"
        Path(tmp, "status.json").write_text(json.dumps({"running": True, "updated": now - 5}))
        assert capture_status(tmp, now)["state"] == "running" and capture_status(tmp, now + 60)["state"] == "stopped"
        assert capture_status(tmp + "/nope")["state"] == "none"
        vol, out = Path(tmp, "vol"), Path(tmp, "out")
        (vol / "ring").mkdir(parents=True)
        for i, n in enumerate(("obs-1_00001_a.pcapng", "obs-1_00002_b.pcapng", "obs-1_00003_c.pcapng")):
            (vol / "ring" / n).write_bytes(b"x")
            os.utime(vol / "ring" / n, (now + i, now + i))
        (vol / ".part-1").write_bytes(b"x")
        (vol / "status.json").write_text(json.dumps({"running": True, "updated": time.time(), "current": "obs-1_00002_b.pcapng"}))
        assert stage_closed(vol, out, capture_volume=True) == 2  # current and newest left out
        assert sorted(p.name for p in out.rglob("*")) == ["obs-1_00001_a.pcapng", "ring", "status.json"]
        assert all(oct(p.stat().st_mode & 0o777) in ("0o755", "0o644", "0o666", "0o777") for p in out.rglob("*"))
        empty = Path(tmp, "empty-out")
        assert stage_closed(Path(tmp, "no-such-volume"), empty) == 0 and empty.is_dir()
    print("capture/geoip selftest ok")
