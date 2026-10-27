"""Leak scan: data that must never be committed (scripts/leak-scan.sh runs this).

  python scripts/leak_scan.py [--tree] [--staged] [--history] [--all] [--selftest]
    --tree     (default) the files `git add -A` would commit: tracked + untracked that are not ignored
    --staged   the index (the pre-commit hook: what the commit records, also when the working tree differs)
    --history  every commit of every ref: `git log -p --all` (added lines, commit messages) and every path ever added
    --all      --tree and --history

Findings (NG fails, WARN is reported only):
  path     .env / *.env / .env.* (not *.example), keys and certificates, pcap / pcapng (not the synthetic demo),
           SQLite / *.db, *.mmdb, site config (inventory/devices.yaml, alerting/receivers.yaml), Authelia users, backups
  ipv4     anything but documentation (RFC 5737), loopback, 0.0.0.0/8 / broadcast / netmasks, multicast, link-local,
           the compose subnets 172.31.253.0/24 and the well-known special-purpose blocks written as CIDR;
           192.168.100.0/24 (YAMAHA's factory default, used as an example) is WARN
  ipv6     global addresses outside 2001:db8::/32 (RFC 3849); unique-local (fc00::/7) is WARN
  mac      universally administered (burned-in) MACs outside 00:00:5e:00:53:xx (RFC 7042), also as xxxx.xxxx.xxxx;
           locally administered is WARN, except the synthetic 02:00:5e:* the demo and the tests use
  secret   private key / certificate blocks, well-known token formats, argon2 hashes, assignments of passwords /
           secrets / tokens / communities / webhook URLs with a literal value (KEY=value, KEY: value, lowercase YAML
           keys; not ${...}, <...>, dummy...)
Exceptions, always per line (also in the history): a line with the marker "leak-scan: allow", or an exact
(path, line) entry of scripts/leak-allow.txt; testbed/testbed.env (DUMMY credentials) and demo/demo-home.pcap
(synthetic) are not scanned.
Values are printed masked (the output may end up in a public CI log): IPv4 to its first two octets.
Exit: 0 no NG, 1 NG found, 2 error.
"""
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "leak-scan: allow"

ALLOW_PATHS = {  # tracked on purpose (reason); not scanned
    "testbed/testbed.env": "DUMMY credentials of the simulated devices (stated in the file)",
    "demo/demo-home.pcap": "synthetic demo capture (demo/make_demo_pcap.py --check rebuilds it byte for byte)",
}
ALLOW_FILE = ROOT / "scripts/leak-allow.txt"


def load_allow(path=ALLOW_FILE):
    """'<path>TAB<exact line, stripped>TAB# leak-scan: allow ...' lines -> {(path, line)}."""
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines() if path.exists() else []:
        parts = line.split("\t")
        if len(parts) >= 2 and not line.startswith("#"):
            out.add((parts[0], parts[1].strip()))
    return out


BAD_PATH = re.compile(
    r"(^|/)(\.env|\.env\.(?!example$)[^/]*|[^/]+\.env|[^/]+\.(pem|key|crt|cer|der|p12|pfx|jks|kdbx|pcap|pcapng|cap|"
    r"sqlite|sqlite3|db|mmdb)|id_(rsa|dsa|ecdsa|ed25519)|users_database\.yml|obs-backup-[^/]*)$"
    r"|^(inventory/devices\.yaml|alerting/receivers\.yaml|backups/.+)$", re.I)

DOC4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
OK4 = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "0.0.0.0/8", "255.255.255.255/32", "224.0.0.0/4",
                                          "169.254.0.0/16", "172.31.253.0/24")]
WARN4 = [ipaddress.ip_network("192.168.100.0/24")]
# special-purpose blocks (RFC 6890 and the like) as they are written in range definitions: not a site's address
WELL_KNOWN_NETS = {ipaddress.ip_network(n) for n in (
    "0.0.0.0/0", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::/0", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "2002::/16", "2001::/32", "2001:db8::/32")}
DOC6 = ipaddress.ip_network("2001:db8::/32")

RUN4 = re.compile(r"(?<![\w.])\d+(?:\.\d+)+(?:/\d{1,2})?(?![\w])", re.A)
CAND6 = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:]*::|(?:[0-9A-Fa-f]{1,4}:){7})[0-9A-Fa-f:.]{2,45}(?<!\.)(?:/\d{1,3})?(?![\w:])", re.A)
MAC = re.compile(r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])", re.A)
MAC_DOTTED = re.compile(r"(?<![\w.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![\w.])", re.A)
BLOCK = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY|CERTIFICATE)-----")
TOKENS = re.compile(r"xox[abprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{40,}|AKIA[0-9A-Z]{16}"
                    r"|hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"
                    r"|discord(?:app)?\.com/api/webhooks/\d+/[\w-]+|\$argon2id?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}")
# KEY=value / KEY: value with an upper-case key (the prefix is optional: PASSWORD=, TOKEN=, WEBHOOK_URL= alone too)
ASSIGN = re.compile(r"(?<![\w$])((?:[A-Z][A-Z0-9_]*_)?(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|PROXY_KEY|STORAGE_KEY|"
                    r"COMMUNITY|WEBHOOK_URL))(?:=|:[ \t]+)[\"']?([^\s\"'`;,)]*)", re.A)
# lower-case YAML / JSON keys: password: value, "token": "value"
# (the key starts the line or a {...} / list item, the value has a digit: not prose such as "token: address")
YAML_KEY = re.compile(r"(?:^|[{,]|-[ \t])[ \t]*[\"']?((?:[a-z][a-z0-9_]*_)?(?:password|passwd|secret|token|community|api_key|"
                      r"webhook_url|priv_password))[\"']?:[ \t]+[\"']?([^\s\"'`;,)}]*\d[^\s\"'`;,)}]*)", re.A)
PLACEHOLDER = re.compile(r"dummy|example|testbed|e2e|change-?me|x{3,}|placeholder|redacted|your[-_]|<|\.\.\.|^\W", re.I)
NOT_SECRET = ("admin", "true", "false", "none", "null", "required", "optional")


def mask(kind, v):
    if kind == "ipv4":
        return ".".join(v.split(".")[:2]) + ".x.x"
    if kind == "ipv6":
        return v.split(":")[0] + ":..."
    if kind == "mac":
        return v[:8] + ":xx:xx:xx" if "." not in v else v[:4] + ".xxxx.xxxx"
    return v[:3] + "..."


def ipv4_level(run):
    """A dotted-number run -> (level, value) or None (OIDs, versions, masked forms)."""
    addr, _, plen = run.partition("/")
    parts = addr.split(".")
    if len(parts) == 5 and int(parts[4]) > 255:  # YAMAHA's address.port
        addr, parts = ".".join(parts[:4]), parts[:4]
    if len(parts) != 4 or any(int(p) > 255 or (len(p) > 1 and p[0] == "0") for p in parts):
        return None
    ip = ipaddress.IPv4Address(addr)
    if plen:
        try:
            net = ipaddress.ip_network(run, strict=False)
            if net in WELL_KNOWN_NETS and net.network_address == ip:
                return None
        except ValueError:
            return None
    if any(ip in n for n in DOC4 + OK4) or is_netmask(ip):
        return None
    return ("WARN" if any(ip in n for n in WARN4) else "NG"), addr


def is_netmask(ip):
    b = int(ip)
    return b != 0 and ((~b & 0xFFFFFFFF) + 1) & (~b & 0xFFFFFFFF) == 0


def ipv6_level(tok):
    addr, _, plen = tok.partition("/")
    groups = [g for g in addr.split(":") if g]
    if len(groups) < 3 and len(groups[0] if groups else "") < 3:  # a::b, [::2], ::5: code, not an address
        return None
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return None
    if plen:
        try:
            if ipaddress.ip_network(tok, strict=False) in WELL_KNOWN_NETS:
                return None
        except ValueError:
            return None
    if ip in DOC6 or ip.ipv4_mapped or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        return None
    if ip in ipaddress.ip_network("64:ff9b::/96"):  # NAT64 of an IPv4: judged as that IPv4
        lv = ipv4_level(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
        return lv and (lv[0], addr)
    if ip in ipaddress.ip_network("fc00::/7"):
        return "WARN", addr
    return ("NG", addr) if ip.is_global else None


def mac_level(m):
    h = re.sub(r"[^0-9a-f]", "", m.lower())
    v = ":".join(h[i:i + 2] for i in range(0, 12, 2))
    if v in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or v.startswith(("00:00:5e:00:53:", "01:00:5e:", "33:33:", "02:00:5e:")):
        return None
    first = int(v[:2], 16)
    if first & 1:  # group address
        return None
    return ("WARN" if first & 2 else "NG"), m


def literal_secret(v):
    return len(v) >= 6 and not v.startswith(("$", "{", "%", "(", "[")) and not PLACEHOLDER.search(v) and v.lower() not in NOT_SECRET


def scan_line(line):
    """-> [(level, kind, value)] for one line of text."""
    if MARK in line:
        return []
    out = []
    for m in RUN4.finditer(line):
        lv = ipv4_level(m.group(0))
        if lv:
            out.append((lv[0], "ipv4", lv[1]))
    for m in CAND6.finditer(line):
        lv = ipv6_level(m.group(0))
        if lv:
            out.append((lv[0], "ipv6", lv[1]))
    for m in [*MAC.finditer(line), *MAC_DOTTED.finditer(line)]:
        lv = mac_level(m.group(0))
        if lv:
            out.append((lv[0], "mac", lv[1]))
    for m in BLOCK.finditer(line):
        out.append(("NG", "secret", m.group(1).lower()))
    for m in TOKENS.finditer(line):
        out.append(("NG", "secret", m.group(0)))
    for rx in (ASSIGN, YAML_KEY):
        for m in rx.finditer(line):
            if literal_secret(m.group(2)):
                out.append(("NG", "secret", f"{m.group(1)}={m.group(2)}"))
    return out


def path_level(path):
    if path in ALLOW_PATHS or path.endswith(".example") or ".example." in path.rsplit("/", 1)[-1]:
        return None
    return "NG" if BAD_PATH.search(path) else None


def git(*args):
    return subprocess.run(["git", "-c", "core.quotePath=false", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def scan_text(p, data, commit=""):
    """findings of one file's content: (level, kind, value, path, line no, commit, line)."""
    if p in ALLOW_PATHS or b"\0" in data[:8192]:
        return []
    return [(lv, k, v, p, n, commit, line) for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1)
            for lv, k, v in scan_line(line)]


def scan_tree():
    findings = []
    for p in git("ls-files", "-z", "-co", "--exclude-standard").decode("utf-8").split("\0"):
        if not p:
            continue
        if path_level(p):
            findings.append(("NG", "path", p, p, 0, "", ""))
        if (ROOT / p).is_file():
            findings += scan_text(p, (ROOT / p).read_bytes())
    return findings


def scan_staged():
    """The index (what `git commit` records), not the working tree: the pre-commit hook."""
    findings = []
    for p in filter(None, git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR").decode("utf-8").split("\0")):
        if path_level(p):
            findings.append(("NG", "path", p, p, 0, "", ""))
        findings += scan_text(p, git("show", f":{p}"))
    return findings


def scan_history():
    findings = []
    commit = ""
    for line in git("log", "--all", "-m", "--name-only", "--format=@@COMMIT %h").decode("utf-8", "replace").splitlines():
        if line.startswith("@@COMMIT "):
            commit = line[9:]
        elif line and path_level(line):
            findings.append(("NG", "path", line, line, 0, commit, ""))
    path, n = "(message)", 0
    log = git("log", "--all", "-m", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=@@COMMIT %h%n%B")
    for line in log.decode("utf-8", "replace").splitlines():
        if line.startswith("@@COMMIT "):
            commit, path, n = line[9:], "(message)", 0
            continue
        if line.startswith("diff --git "):
            path = "?"
            continue
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else path
            continue
        if line.startswith("@@ ") and path != "(message)":
            m = re.match(r"@@ -\S+ \+(\d+)", line)
            n = int(m.group(1)) if m else 0
            continue
        if path == "(message)":
            text = line
        elif line.startswith("+"):
            text = line[1:]
        else:
            continue
        if path not in ALLOW_PATHS:
            findings += [(lv, k, v, path, n, commit, text) for lv, k, v in scan_line(text)]
        if path != "(message)":
            n += 1
    return findings


def report(title, findings, allow=frozenset()):
    seen, rows = set(), []
    for lv, kind, v, path, n, commit, text in findings:
        key = (lv, kind, v, path)
        if key in seen or (path, text.strip()) in allow:
            continue
        seen.add(key)
        rows.append(f"{lv:4} {kind:6} {mask(kind, v) if kind != 'path' else '':24} {path}{':' + str(n) if n else ''}"
                    + (f"  (commit {commit})" if commit else ""))
    ng = sum(r.startswith("NG") for r in rows)
    print(f"== {title}: {ng} NG, {len(rows) - ng} WARN")
    for r in sorted(rows):
        print("  " + r)
    return ng


def selftest():
    lv = lambda s: [(a, b) for a, b, _ in scan_line(s)]
    assert lv("syslog host 192.0.2.10 and 198.51.100.7:443, 203.0.113.9.50211") == []
    assert lv("127.0.0.1 0.0.0.0 255.255.255.0 224.0.0.251 172.31.253.2 OBS_GRAFANA_NET=172.31.253.0/29") == []
    assert lv("OID 1.3.6.1.2.1.31.1.1.1.6 v1.2.3.4 192.168.100.x 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16") == []
    assert lv("snmp host 192.168.100.10") == [("WARN", "ipv4")]
    assert lv("my LAN 10.20.30.40") == [("NG", "ipv4")] and lv("10.1.2.3:8080") == [("NG", "ipv4")]  # leak-scan: allow (selftest vector)
    assert lv("TCP 172.16.7.23.50211 > x") == [("NG", "ipv4")] and lv("8.8.8.8") == [("NG", "ipv4")]  # leak-scan: allow (selftest vector)
    assert lv("net 172.16.5.0/24") == [("NG", "ipv4")]  # leak-scan: allow (selftest vector)
    assert lv("2001:db8::1 ::1 fe80::1 ff02::1 ::ffff:192.0.2.1 14:04:20 std::string 64:ff9b::c000:201") == []
    assert lv("2400:4050:1:2::5") == [("NG", "ipv6")] and lv("fd12:3456::1") == [("WARN", "ipv6")]  # leak-scan: allow (selftest vector)
    assert lv("00:00:5e:00:53:01 02:00:5e:10:00:17 01:00:5e:00:00:fb ff:ff:ff:ff:ff:ff 0200.5e10.0017") == []
    assert lv("00:a0:de:12:34:56") == [("NG", "mac")] and lv("aa:bb:cc:dd:ee:ff") == [("WARN", "mac")]  # leak-scan: allow (selftest vector)
    assert lv("cisco 00a0.de12.3456 here") == [("NG", "mac")] and lv("v 1234.5678.9012 x")  # leak-scan: allow (selftest vector)
    assert lv("-----BEGIN OPENSSH PRIVATE KEY-----") == [("NG", "secret")] and lv("-----BEGIN CERTIFICATE-----") == [("NG", "secret")]  # leak-scan: allow (selftest vector)
    assert lv("SNMP_V3_AUTH_PASS=hunter2hunter2") == [("NG", "secret")] and lv("SMTP_PASSWORD: 'S3cr3t-value'") == [("NG", "secret")]  # leak-scan: allow (selftest vector)
    for single in ("PASSWORD=hunter2hunter2", "TOKEN=abcdef123456", "SECRET=s3cr3tvalue", "WEBHOOK_URL=https://hook.test/abc",  # leak-scan: allow (selftest vector)
                   "export PASS=hunter2hunter2", "password: hunter2hunter2", '"token": "abcdef123456"', "priv_password: s3cr3tvalue"):  # leak-scan: allow (selftest vector)
        assert lv(single) == [("NG", "secret")], single
    assert lv("BYPASS=whatever1 password: ${SNMP_V3_AUTH_PASS} token: <token> secret_name: x") == []
    assert lv("SNMP_V3_AUTH_PASS=testbed-auth-dummy GF_ADMIN_PASSWORD=change-me OBS_AUTH_PROXY_KEY=${OBS_AUTH_PROXY_KEY:-}") == []
    assert lv('-e GF_ADMIN_PASSWORD="$GF" SNMP_COMMUNITY= OBS_AUTH_STORAGE_KEY=$(rand 48) WEBHOOK_URL=<url>') == []
    assert lv("url https://hooks.slack.com/services/T0123/B0456/abcdefXYZ") == [("NG", "secret")]  # leak-scan: allow (selftest vector)
    assert lv("hash $argon2id$v=19$m=65536,t=3,p=4$abcdefgh$abcdefghijklmnop0123") == [("NG", "secret")] and lv("$argon2id$v=19$m=1,t=3,p=4$") == []  # leak-scan: allow (selftest vector)
    assert lv("10.9.8.7  # leak-scan: allow (test value)") == []
    assert path_level(".env") == path_level("x/prod.env") == path_level(".env.bak-1") == "NG"
    assert path_level(".env.example") is None and path_level("config.example/inventory/devices.example.yaml") is None
    assert path_level("testbed/testbed.env") is None and path_level("demo/demo-home.pcap") is None
    assert path_level("cap/x.pcapng") == path_level("db.sqlite3") == path_level("inventory/devices.yaml") == "NG"
    assert path_level("backups/obs-backup-1.tar.gz") == path_level("certs/root.crt") == "NG"
    assert path_level("testbed/devices.yaml") is None and path_level("tools/capture.py") is None
    assert mask("ipv4", "10.20.30.40") == "10.20.x.x" and mask("mac", "00:a0:de:12:34:56") == "00:a0:de:xx:xx:xx"  # leak-scan: allow (selftest vector)
    # the allow-list is per line: an allowed value elsewhere in the same file is still found
    f = [("NG", "ipv4", "10.0.0.1", "a.py", 1, "", "x = '10.0.0.1'"), ("NG", "ipv4", "10.0.0.1", "a.py", 9, "", "y = 10.0.0.1")]  # leak-scan: allow (selftest vector)
    assert report("selftest", f, {("a.py", "x = '10.0.0.1'")}) == 1  # leak-scan: allow (selftest vector)
    print("leak_scan selftest OK")


def main(argv):
    if "--selftest" in argv:
        selftest()
        return 0
    modes = ["--tree", "--history"] if "--all" in argv else [a for a in argv if a in ("--tree", "--history", "--staged")] or ["--tree"]
    ng, allow = 0, load_allow()
    try:
        if "--tree" in modes:
            ng += report("working tree (tracked + untracked, not ignored)", scan_tree(), allow)
        if "--staged" in modes:
            ng += report("staged (the index: what the next commit records)", scan_staged(), allow)
        if "--history" in modes:
            ng += report("history (git log -p --all: added lines, messages, paths)", scan_history(), allow)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"leak-scan: git failed: {e}", file=sys.stderr)
        return 2
    print("leak-scan: " + ("NG (values masked; fix or rewrite before publishing)" if ng else "OK"))
    return 1 if ng else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
