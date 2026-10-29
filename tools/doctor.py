"""`tools doctor` (H1): preflight before `docker compose up` / `tools check`. Nothing here talks to a device.

Pure assessments, each -> (state, detail, fix) with state OK / WARN / NG; obs.cmd_doctor gathers the inputs (the host's
Docker version, NTP state and busy ports come from scripts/doctor.sh, which runs this in the tools container).
"""
import re
import ssl
import time

OK, WARN, NG = "OK", "WARN", "NG"
ENGINE_MIN = (25, 0)  # healthcheck start_interval
COMPOSE_MIN = (2, 20)  # depends_on required: false (optional setup steps)
MEM_OK, MEM_MIN = 3.5 * 2**30, 1.8 * 2**30  # Raspberry Pi 4 4 GB defaults (docs/operations.md); below MEM_MIN the limits cannot fit
DISK_MIN = 2 * 2**30
CLOCK_SLACK_S = 3600
CERT_SOON_S = 30 * 86400


def version_tuple(text):
    m = re.search(r"(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def engine(ver):
    v = version_tuple(ver)
    if v is None:
        return WARN, "不明 (コンテナからは見えません)", "scripts/doctor.sh で実行するとホストの Docker を確認します"
    if v < ENGINE_MIN:
        return NG, f"Docker Engine {ver} (25 以上が必要: healthcheck の start_interval)", "Docker Engine を更新 (https://docs.docker.com/engine/install/)"
    return OK, f"Docker Engine {ver}", ""


def compose(ver):
    v = version_tuple(ver)
    if v is None:
        return WARN, "不明", "scripts/doctor.sh で実行するとホストの compose を確認します"
    if v < COMPOSE_MIN:
        return NG, f"docker compose {ver} (2.20 以上が必要)", "compose plugin を更新 (apt install docker-compose-plugin など)"
    return OK, f"docker compose {ver}", ""


def arch(machine):
    m = (machine or "").lower()
    if m in ("x86_64", "amd64"):
        return OK, "amd64", ""
    if m in ("aarch64", "arm64"):
        return OK, "arm64", ""
    return NG, f"{machine or '不明'} (64 bit の amd64 / arm64 のみ)", "64 bit の OS (Raspberry Pi OS 64-bit など) にしてください"


def memory(total):
    gib = f"{total / 2**30:.1f} GiB"
    if total >= MEM_OK:
        return OK, gib, ""
    if total >= MEM_MIN:
        return WARN, f"{gib} (既定の上限は 4 GB 向け)", ".env の PROM_MEM / LOKI_MEM などを小さく"
    return NG, f"{gib} (足りません)", "4 GB 以上のホストにしてください"


def disk(path, free, need):
    detail = f"{path}: 空き {free / 2**30:.1f} GiB (見込み {need / 2**30:.1f} GiB)"
    if free < DISK_MIN:
        return NG, detail, "空きを 2 GiB 以上に (docker system prune、古い backups/ の削除など)"
    if free < need:
        return WARN, detail, "PROM_RETENTION_SIZE / LOKI_RETENTION / CAPTURE_FILES を小さくするか、空きを増やしてください"
    return OK, detail, ""


def size_bytes(text):
    """Prometheus' retention size (0 / 512MB / 8GB ...) -> bytes (0 = unbounded / unknown)."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGT]?i?B)?", (text or "0").strip(), re.I)
    if not m:
        return 0
    unit = (m.group(2) or "B").upper().replace("I", "")
    return int(float(m.group(1)) * 1024 ** "BKMGT".index(unit[0]))


def disk_need(values):
    """Bytes the bounded stores may grow to: capture ring + uploads + Prometheus' size cap (or 4 GiB when unbounded)."""
    num = lambda k, d: int(values.get(k) or d) if str(values.get(k) or d).isdigit() else int(d)
    need = size_bytes(values.get("PROM_RETENTION_SIZE")) or 4 * 2**30
    need += 2**30  # Loki 30 d of a few devices' syslog, images' scratch
    if values.get("OBS_CAPTURE") == "1":
        need += num("CAPTURE_FILES", 20) * num("CAPTURE_FILE_MB", 20) * 2**20
    return need + num("PCAP_UPLOADS_TOTAL_MB", 200) * 2**20


def clock(now, reference, ntp):
    """reference: the newest mtime of the checked-out repository (a clock behind it is certainly wrong: a Pi has no RTC)."""
    if reference and now < reference - CLOCK_SLACK_S:
        return NG, (f"時刻 {time.strftime('%Y-%m-%d %H:%M', time.localtime(now))} がリポジトリのファイル "
                    f"({time.strftime('%Y-%m-%d %H:%M', time.localtime(reference))}) より前です"), \
            "NTP で合わせてください (timedatectl set-ntp true。ネットワーク接続後に timedatectl で synchronized: yes)"
    if ntp == "no":
        return WARN, "NTP の同期が済んでいません (timedatectl)", "sudo timedatectl set-ntp true、同期まで待つ (証明書・ログの時刻がずれます)"
    return OK, "NTP 同期済み" if ntp == "yes" else "大きなずれはありません (NTP の状態は不明)", ""


def decode_cert(path):
    """-> (notBefore, notAfter, names) of a PEM certificate, or None (stdlib only: no openssl CLI in the image)."""
    try:
        d = ssl._ssl._test_decode_cert(str(path))  # noqa: SLF001 - the only stdlib PEM parser
    except (OSError, ssl.SSLError, ValueError, AttributeError):
        return None
    names = [v for k, v in d.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    return ssl.cert_time_to_seconds(d["notBefore"]), ssl.cert_time_to_seconds(d["notAfter"]), names


def certificate(root, leaves, hosts, now):
    """The proxy's own CA (caddy-data) and the screens' certificate for each host. Created at the first start."""
    if root is None:
        return WARN, "まだありません (初回の起動で proxy が作ります)", "起動後に docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./obs-root.crt で端末に登録"
    nb, na, _ = root
    if now < nb:
        return NG, "ルート証明書の開始日時が未来です (時刻のずれ)", "時刻を合わせてから docker compose restart proxy"
    if now > na:
        return NG, "ルート証明書の期限切れ", "caddy-data を作り直し、端末に登録し直してください"
    missing = [h for h in hosts if not any(h in names and lb <= now < la for lb, la, names in leaves)]
    if missing:
        return WARN, f"ルート証明書 OK (期限 {time.strftime('%Y-%m-%d', time.localtime(na))})。{', '.join(missing)} の証明書はまだ/期限切れ", \
            "proxy が起動時・期限前に自動で作ります (docker compose up -d)"
    soon = " (残り 30 日未満)" if na - now < CERT_SOON_S else ""
    return OK, f"ルート証明書 期限 {time.strftime('%Y-%m-%d', time.localtime(na))}{soon}、{', '.join(hosts)} の証明書あり", ""


WILDCARD = ("0.0.0.0", "*", "::", "[::]", "")


def listeners(text):
    """'tcp:0.0.0.0:8080 udp:[::]:514 ...' (scripts/doctor.sh, from ss) -> {(proto, addr, port)}."""
    out = set()
    for item in (text or "").split():
        proto, _, rest = item.partition(":")
        addr, _, port = rest.rpartition(":")
        if port.isdigit():
            out.add((proto[:3].lower(), addr.split("%")[0], int(port)))
    return out


def ports(wanted, busy, measured, own=frozenset()):
    """wanted: [(proto, addr, port)] this stack publishes; busy: listeners() of the host (measured False = unknown);
    own: listeners() its own running containers publish (in use by itself, not a clash)."""
    if not measured:
        return WARN, "確認していません", "scripts/doctor.sh で実行するとホストのポートの衝突を確認します"
    clash = sorted({f"{p}/{a}:{n}" for p, a, n in wanted if (p, a, n) not in own for bp, ba, bn in busy
                    if bp == p and bn == n and (ba == a or ba in WILDCARD or a in WILDCARD)})
    if clash:
        return NG, f"使用中: {', '.join(clash)}", "そのポートを使うものを止めるか、.env の OBS_PORT / SYSLOG_PORT / PROM_LOCAL_PORT を変える"
    mine = sum(w in own for w in wanted)
    return OK, ", ".join(f"{p}/{a}:{n}" for p, a, n in wanted) + (f" は空き (うち {mine} 個はこのスタックが使用中)" if mine else " は空き"), ""


def selftest():
    assert engine("24.0.7")[0] == NG and engine("25.0.3")[0] == OK and engine("29.1.3")[0] == OK and engine("")[0] == WARN
    assert compose("v2.40.3-desktop.1")[0] == OK and compose("2.12.2")[0] == NG and compose("Docker Compose version v2.20.0")[0] == OK
    assert arch("aarch64")[0] == OK and arch("x86_64")[0] == OK and arch("armv7l")[0] == NG
    assert memory(4 * 10**9)[0] == OK and memory(2 * 2**30)[0] == WARN and memory(2**30)[0] == NG
    assert size_bytes("8GB") == 8 * 2**30 and size_bytes("512MB") == 512 * 2**20 and size_bytes("0") == 0 and size_bytes("x") == 0
    assert disk_need({"PROM_RETENTION_SIZE": "1GB", "PCAP_UPLOADS_TOTAL_MB": "0"}) == 2 * 2**30
    assert disk_need({"PROM_RETENTION_SIZE": "1GB", "PCAP_UPLOADS_TOTAL_MB": "0", "OBS_CAPTURE": "1"}) == 2 * 2**30 + 400 * 2**20
    assert disk("/", 2**30, 2**31)[0] == NG and disk("/", 3 * 2**30, 4 * 2**30)[0] == WARN and disk("/", 9 * 2**30, 4 * 2**30)[0] == OK
    now = 1_800_000_000
    assert clock(now, now - 10, "yes")[0] == OK and clock(now - 2 * 86400, now, "yes")[0] == NG and clock(now, now, "no")[0] == WARN
    assert clock(now, None, "")[0] == OK
    root = (now - 10, now + 3650 * 86400, [])
    assert certificate(None, [], ["192.0.2.10"], now)[0] == WARN
    assert certificate((now + 99, now + 999, []), [], [], now)[0] == NG and certificate((now - 9, now - 1, []), [], [], now)[0] == NG
    assert certificate(root, [(now - 5, now + 3600, ["192.0.2.10"])], ["192.0.2.10"], now)[0] == OK
    assert certificate(root, [(now - 5, now - 1, ["192.0.2.10"])], ["192.0.2.10"], now)[0] == WARN
    want = [("tcp", "127.0.0.1", 8080), ("udp", "0.0.0.0", 514)]
    assert ports(want, set(), False)[0] == WARN and ports(want, set(), True)[0] == OK
    assert ports(want, listeners("udp:[::]:514 tcp:127.0.0.53%lo:53"), True)[0] == NG
    own = listeners("tcp:127.0.0.1:8080")  # proxy up, alloy down, something else on 514: still a clash
    assert ports(want, listeners("tcp:127.0.0.1:8080 udp:0.0.0.0:514"), True, own)[0] == NG
    assert ports(want, listeners("tcp:127.0.0.1:8080"), True, own)[0] == OK
    assert ports(want, listeners("tcp:0.0.0.0:8080"), True)[0] == NG and ports(want, listeners("tcp:192.0.2.20:8080 udp:*:5353"), True)[0] == OK
