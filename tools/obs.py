"""GeoFront-NW setup / operations tool. Runs in the `tools` container: docker compose run --rm tools <command>.

  init         .env と機器台帳 (inventory/devices.yaml) を対話または引数で作り、検証する
  check        設定の検証・各機器への SNMP 疎通・syslog の受信待ち・各サービスの health を表で出す
  targets      台帳から Prometheus の scrape 対象・Alloy の送信元対応表・snmp_exporter の auth を生成する
  backup       設定と Prometheus スナップショット・Loki・抑止・利用者・認証局を 1 つのアーカイブにまとめる
  restore      backup のアーカイブを戻す (prometheus / loki / alertmanager / authelia / proxy は止めてから)
  notify-test  各通知先にテスト通知を送り (Alertmanager 経由)、応答 (HTTP / SMTP) を表で出す
  test-syslog  fixtures を Alloy に送り、Loki に正しく解析されて入ったかを確かめる (回帰テスト)
  capture      パケット取込の状態 (status) / リングとアップロードの一覧 (list) / 保存期間を過ぎたものの削除 (prune)
  geoip        DB-IP Lite (City + ASN) のダウンロード・更新 (update) / 版と鮮度 (status)
  user         ログインの利用者 (Authelia): add / passwd / role / remove / list、秘密値の生成 (secrets)
  doctor       導入前の自己診断 (Docker・CPU・メモリ・ディスク・時刻・ポート・.env・利用者・証明書。scripts/doctor.sh から)
  migrate-config  従来の配置 (リポジトリ内の .env・台帳・通知先・backups) を OBS_CONFIG_DIR へ写す / プロジェクト名を固定する

Read-only towards devices: SNMP goes through snmp_exporter (GET/WALK only); nothing here changes a device.
Paths: the repository is mounted at /work, the site configuration (OBS_CONFIG_DIR on the host; unset = the repository,
the legacy layout) at /config, the generated volume at /generated, data volumes under /vol. Configuration comes from the
environment compose passes in (from the config's .env or --env-file); `init` writes .env. Device specifics: drivers/.
"""
import argparse
import getpass
import functools
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sqlite3
import sys
import tarfile
import tempfile
import time
import types
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from notify import (DEMO_PLAN, NOTIFY_ENV, RECEIVER_TYPES, RELAY, RELAY_UID, SMTP_PORTS, TEST_ALERT, URL_SECRETS,
                    alertmanager_config, check_receivers, notify_summary, relay_config, render_receivers)
import notify  # the notification model (tools/notify.py, next to this file)
import capture as cap  # packet capture / GeoIP housekeeping (tools/capture.py)
import auth as au  # authentication: Authelia's config, users and secrets (tools/auth.py)
import doctor as dr  # preflight assessments (tools/doctor.py)

WORK = Path(os.environ.get("OBS_WORK", "/work"))
CONFIG = Path(os.environ.get("OBS_CONFIG", "/config"))  # .env, inventory, receivers, backups (OBS_CONFIG_DIR)
GEN = Path(os.environ.get("OBS_GENERATED", "/generated"))
VOL = Path(os.environ.get("OBS_VOLUMES", "/vol"))
AUTH_TEMPLATE = WORK / "snmp/auths.yml"
DRIVERS_DIR = WORK / "drivers"  # one directory per device driver (docs/drivers.md)
ENV_FILE = CONFIG / ".env"
ENV_EXAMPLE = WORK / "config.example/.env.example"
# the compose project name before R1 (compose.yaml keeps it as its default so that existing volumes stay in use);
# `tools init` pins the name it runs under into .env, new installs through ./geofront get geofront-nw
LEGACY_PROJECT = "yamaha-observatory-trial"
# secrets the ./geofront wrapper read from <NAME>_FILE (OBS_SECRET_FILES): never copied into .env
SECRETS_FROM_FILES = frozenset(os.environ.get("OBS_SECRET_FILES", "").split())
AUTH_PROTOS = ("SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5")  # what snmp_exporter accepts
PRIV_PROTOS = ("AES", "AES192", "AES256", "AES192C", "AES256C", "DES")
TEMPLATE_VARS = ("SNMP_V3_AUTH_PROTO", "SNMP_V3_PRIV_PROTO")  # filled in by us; everything else stays ${...}
# snmp_exporter's --config.expand-environment-variables covers username / password / priv_password only, not
# community: that one is written into the generated auths.yml (generated volume only, mode 0600, never printed).
LITERAL_SECRETS = ("SNMP_COMMUNITY",)
# data volume -> owner the service runs as (a fresh volume first mounted here would otherwise be root-owned)
VOLUMES = {"prometheus": (65534, 65534), "loki": (10001, 10001), "alertmanager": (65534, 65534),
           "capture": (0, 0), "uploads": (65534, 65534),  # these two only with backup --include-captures
           "authelia": (au.AUTHELIA_UID, au.AUTHELIA_UID),
           "caddy": (0, 0)}  # the proxy's own CA (its key) and certificates: the LAN devices trust that root
IFNAME_RE = re.compile(r"[A-Za-z0-9_/:-]{1,64}")  # no dots: mask-api rejects digit.digit in query literals
RESERVED_NAMES = ("unknown",)  # host label of syslog senders that are not in the inventory (alloy/config.alloy)
PUBLIC_URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?")  # host name, IPv4 or [IPv6]
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
SAFE_ENV = re.compile(r"[A-Za-z0-9_./:,@+-]*")
HTTP_TIMEOUT = 5
SNMP_TIMEOUT = 40


class Fail(Exception):
    """A user-facing error (Japanese message); exit code 2."""


def rel(path):
    """Path as shown and stored: relative to the config directory (or the repository) when inside it."""
    for base in (CONFIG, WORK):
        try:
            return str(Path(path).relative_to(base))
        except ValueError:
            pass
    return str(path)


def env(key, default=""):
    return os.environ.get(key, default)


def env_map():
    return dict(os.environ)


# ---- device drivers (drivers/<vendor-model>/: driver.yaml, demo.json, syslog.jsonl; docs/drivers.md) -------------

@functools.cache
def drivers():
    """{inventory kind: driver} from drivers/*/driver.yaml (+ its demo.json devices); the generic driver last."""
    out = {}
    for f in sorted(DRIVERS_DIR.glob("*/driver.yaml"), key=lambda q: (q.parent.name == "generic", q.parent.name)):
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        demo_f = f.with_name("demo.json")
        d["demo"] = json.loads(demo_f.read_text(encoding="utf-8"))["devices"] if demo_f.exists() else {}
        for k in d.get("kinds", []):
            out.setdefault(k, d)
    return out


def kinds():
    return tuple(drivers())


def driver(kind):
    return drivers().get(kind) or {}


def snmp_modules(kind):
    return ",".join(driver(kind).get("snmp_modules") or ["if_mib", "system"])


@functools.cache
def demo_devices():
    """{name: (kind, its demo.json record)} of every driver's demo devices, in driver order (demo-gen serves them)."""
    out = {}
    for d in {id(x): x for x in drivers().values()}.values():
        for name, rec in d["demo"].items():
            out[name] = (d["kinds"][0], rec)
    return out


def demo_names():
    return tuple(demo_devices())


def demo_hosts():
    """The demo pcap's router (its other hosts are named by DHCP)."""
    return {rec["pcap_address"]: n for n, (_, rec) in demo_devices().items() if rec.get("pcap_address")}


def demo_links():
    return [{"device": n, **rec["link"]} for n, (_, rec) in demo_devices().items() if rec.get("link")]


def demo_wan():
    for n, (_, rec) in demo_devices().items():
        if "wan_if" in rec:
            return {"device": n, "ifName": next(i[1] for i in rec["interfaces"] if i[0] == rec["wan_if"])}
    return None


# ---- inventory ----------------------------------------------------------------------------------

def inventory_path():
    return CONFIG / env("OBS_INVENTORY", "inventory/devices.yaml")


def split_address(address):
    """'192.168.100.1' / 'rtx.lan' / 'host:1161' -> (host, port or None)."""
    host, sep, port = str(address).rpartition(":")
    return (host, port) if sep and port.isdigit() else (str(address), None)


def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def check_devices(devices, known_auths):
    """-> list of Japanese error messages for an inventory's device list."""
    errs, names, addrs, wans = [], set(), set(), []
    if not isinstance(devices, list) or not devices:
        return ["機器台帳に devices: の一覧がありません (1 台以上必要です)"]
    for i, d in enumerate(devices, 1):
        where = f"台帳の {i} 台目"
        if not isinstance(d, dict):
            errs.append(f"{where}: name / kind / address / snmp_auth を持つ項目にしてください")
            continue
        name, kind, addr, auth = (str(d.get(k, "")).strip() for k in ("name", "kind", "address", "snmp_auth"))
        where = f"{where} ({name or '名前なし'})"
        unknown = set(d) - {"name", "kind", "address", "snmp_auth", "syslog", "wan_interface", *TOPO_KEYS}
        if unknown:
            errs.append(f"{where}: 不明な項目 {', '.join(sorted(map(str, unknown)))}")
        if name in RESERVED_NAMES:
            errs.append(f"{where}: name '{name}' は予約語です (台帳に無い syslog 送信元の host に使うため)。別の名前にしてください")
        elif not NAME_RE.fullmatch(name):
            errs.append(f"{where}: name は英小文字・数字・- _ の 1〜32 文字にしてください (例 rtx1300)")
        elif name in names:
            errs.append(f"{where}: name が重複しています")
        names.add(name)
        if kind not in kinds():
            errs.append(f"{where}: kind は {' / '.join(kinds())} のどれかにしてください (drivers/ のドライバ)")
        host, port = split_address(addr)
        looks_ip = re.fullmatch(r"[\d.]+", host) is not None
        if not addr or not (is_ipv4(host) if looks_ip else HOST_RE.fullmatch(host)) or (port and not 0 < int(port) < 65536):
            errs.append(f"{where}: address は管理 IP (IPv4) か DNS 名にしてください (ポート指定は host:1161 の形)")
        elif addr in addrs:
            errs.append(f"{where}: address が他の機器と重複しています")
        addrs.add(addr)
        if auth not in known_auths:
            avail = " / ".join(sorted(known_auths)) or "なし (.env の SNMP 資格情報が空です)"
            errs.append(f"{where}: snmp_auth '{auth}' は使えません。使える auth: {avail}")
        if "syslog" in d and not isinstance(d["syslog"], bool):
            errs.append(f"{where}: syslog は true / false にしてください")
        if "wan_interface" in d:
            wans.append(name)
            if not IFNAME_RE.fullmatch(str(d["wan_interface"] or "")):
                errs.append(f"{where}: wan_interface は ifName (英数字と _ / : - 、例 lan2) にしてください")
        for k in ("parent_if", "uplink_if"):
            if k in d and not IFNAME_RE.fullmatch(str(d[k] or "")):
                errs.append(f"{where}: {k} は ifName (英数字と _ / : - 、例 lan1) にしてください")
        if "parent_if" in d and "parent" not in d:
            errs.append(f"{where}: parent_if は parent (親機器の name) と一緒に書いてください")
    if len(wans) > 1:
        errs.append(f"wan_interface は 1 台だけに書いてください (今は {', '.join(wans)})")
    errs += check_parents(devices, names)
    return errs


TOPO_KEYS = ("parent", "parent_if", "uplink_if")  # optional: where a device is connected (network map)


def check_parents(devices, names):
    """parent: another inventory device; no loops (the network map is drawn as a tree from the WAN router)."""
    errs, parent = [], {}
    for d in devices:
        if isinstance(d, dict) and "parent" in d:
            n, p = str(d.get("name", "")).strip(), str(d["parent"] or "").strip()
            if p == n or p not in names:
                errs.append(f"機器 {n}: parent '{p}' は台帳にある別の機器の name にしてください")
            else:
                parent[n] = p
    for n in parent:
        seen, cur = {n}, parent.get(n)
        while cur in parent:
            if cur in seen:
                errs.append(f"機器 {n}: parent をたどると元に戻ります (ループ)。親子関係を見直してください")
                break
            seen.add(cur)
            cur = parent[cur]
    return errs


def load_inventory(path=None):
    path = path or inventory_path()
    if not path.exists():
        raise Fail(f"機器台帳 {rel(path)} がありません。`docker compose run --rm tools init` で作成してください")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise Fail(f"機器台帳 {rel(path)} の YAML が読めません: {e}") from None
    if not isinstance(doc, dict):
        raise Fail(f"機器台帳 {rel(path)} は devices: から始まる形にしてください")
    return doc.get("devices")


def device_rows(devices):
    return [{"name": str(d["name"]).strip(), "kind": str(d["kind"]).strip(), "address": str(d["address"]).strip(),
             "snmp_auth": str(d["snmp_auth"]).strip(), "syslog": d.get("syslog", True),
             **({"wan_interface": str(d["wan_interface"]).strip()} if d.get("wan_interface") else {}),
             **{k: str(d[k]).strip() for k in TOPO_KEYS if d.get(k)}} for d in devices]


def topology_links(rows, demo):
    """Inventory links for the network map (parent / parent_if / uplink_if): names only, no addresses."""
    if demo:
        return demo_links()
    return [{"device": d["name"], **{k: d[k] for k in TOPO_KEYS if d.get(k)}} for d in rows if d.get("parent")]


def wan_of(rows, demo):
    """-> {"device", "ifName"} of the WAN interface, or None (prod without wan_interface)."""
    if demo:
        return demo_wan()
    return next(({"device": d["name"], "ifName": d["wan_interface"]} for d in rows if d.get("wan_interface")), None)


def wan_rules(wan):
    """Prometheus rule file for the configured WAN interface (empty when there is none): the alert for download
    utilization above 80 %."""
    if not wan:
        return {"groups": []}
    sel = 'job="snmp",instance="%s",ifName="%s"' % (wan["device"], wan["ifName"])
    where = f'{wan["device"]} {wan["ifName"]}'
    return {"groups": [{"name": "yamaha-wan", "rules": [
        {"alert": "WanHighUtilization",
         "expr": f"rate(ifHCInOctets{{{sel}}}[2m]) * 8\n  / (ifHighSpeed{{{sel}}} * 1e6) * 100 > 80\n",
         "for": "30s", "labels": {"severity": "warning"},
         "annotations": {"summary": f'WAN ({where}) download utilization {{{{ $value | printf "%.0f" }}}}%',
                         "summary_ja": f'WAN ({where}) の下り使用率が {{{{ $value | printf "%.0f" }}}}% です (80% 超)',
                         "value": '{{ $value | printf "%.0f" }}%'}}]}]}


# ---- .env validation ----------------------------------------------------------------------------

def render_auths(values):
    """snmp/auths.yml template -> (auths dict for snmp_exporter, names). Protocols are substituted; secret
    references stay ${...}; an auth with an empty referenced variable is dropped."""
    text = AUTH_TEMPLATE.read_text(encoding="utf-8")
    for k in TEMPLATE_VARS:
        text = text.replace("${%s}" % k, values.get(k, ""))
    auths = (yaml.safe_load(text) or {}).get("auths", {})
    keep = {}
    for name, a in auths.items():
        refs = re.findall(r"\$\{(\w+)\}", json.dumps(a))
        if all(values.get(r) for r in refs):
            keep[name] = {k: literal_secret(v, values) for k, v in a.items()}
    return keep


def literal_secret(v, values):
    """A whole-value ${VAR} reference to one of LITERAL_SECRETS -> its value; anything else unchanged."""
    m = re.fullmatch(r"\$\{(\w+)\}", v) if isinstance(v, str) else None
    return values[m.group(1)] if m and m.group(1) in LITERAL_SECRETS else v


def check_env(values, used_auths=()):
    """-> (errors, warnings) for compose's environment (from .env); Japanese messages."""
    errs, warns = [], []
    for key, v in values.items():
        if key.startswith(("OBS_", "SNMP_", "SYSLOG_", "SMTP_", "SLACK_", "DISCORD_", "LINE_", "WEBHOOK_")) and ("'" in v or "\n" in v):
            errs.append(f"{key}: ' (シングルクォート) と改行は使えません")
    for key in ("OBS_BIND", "SYSLOG_BIND"):
        v = values.get(key, "127.0.0.1")
        if not is_ipv4(v):
            errs.append(f"{key}={v}: IPv4 アドレスにしてください (127.0.0.1 / LAN 側の IP / 0.0.0.0)")
        elif not ipaddress.IPv4Address(v).is_loopback:
            if key == "SYSLOG_BIND":
                warns.append(f"{key}={v}: syslog 受信を LAN に公開します")
    pub = values.get("OBS_PUBLIC_URL", "")
    if pub and not PUBLIC_URL_RE.fullmatch(pub):
        errs.append(f"OBS_PUBLIC_URL={pub}: http(s)://ホスト名か IP[:ポート] の形にしてください (末尾の / やパスは付けない)")
    elif values.get("OBS_BIND") == "0.0.0.0" and (not pub or re.match(r"https?://(127\.|localhost|\[::1\])", pub)):
        # the proxy answers only the loopback names, OBS_PUBLIC_URL's host and a concrete bind address (DNS rebinding)
        errs.append("OBS_BIND=0.0.0.0 で OBS_PUBLIC_URL が空か 127.0.0.1 のままです: LAN からは 421 で開けません — "
                    "OBS_PUBLIC_URL にこのホストの LAN 名 / IP を設定してください (例 http://192.168.100.10:8080)")
    elif lan_bind(values) and (not pub or re.match(r"https?://(127\.|localhost)", pub)):
        warns.append("OBS_PUBLIC_URL が 127.0.0.1 のままです。LAN から開くと通知のリンクがこの PC を指します。"
                     "LAN から開くときの URL (例 http://192.168.100.10:8080) にしてください")
    for key, default in (("OBS_PORT", "8080"), ("SYSLOG_PORT", "514")):
        v = values.get(key, default)
        if not (v.isdigit() and 0 < int(v) < 65536):
            errs.append(f"{key}={v}: 1〜65535 のポート番号にしてください")
    a_errs, a_warns = au.check(values)
    errs += a_errs
    warns += a_warns
    versions = auth_versions()
    if any(versions.get(a) == 3 for a in used_auths):
        if not values.get("SNMP_V3_USER"):
            errs.append("SNMP_V3_USER が空です (SNMPv3 のユーザー名)")
        for key in ("SNMP_V3_AUTH_PASS", "SNMP_V3_PRIV_PASS"):
            if len(values.get(key, "")) < 8:
                errs.append(f"{key} は 8 文字以上にしてください (SNMPv3 の決まり)")
        if values.get("SNMP_V3_AUTH_PROTO", "") not in AUTH_PROTOS:
            errs.append(f"SNMP_V3_AUTH_PROTO は {' / '.join(AUTH_PROTOS)} のどれかにしてください")
        if values.get("SNMP_V3_PRIV_PROTO", "") not in PRIV_PROTOS:
            errs.append(f"SNMP_V3_PRIV_PROTO は {' / '.join(PRIV_PROTOS)} のどれかにしてください")
    if any(versions.get(a) == 2 for a in used_auths):
        if not values.get("SNMP_COMMUNITY"):
            errs.append("SNMP_COMMUNITY が空です (SNMPv2c のコミュニティ名)")
        elif values["SNMP_COMMUNITY"] in ("public", "private"):
            warns.append("SNMP_COMMUNITY が推測されやすい値です。SNMPv3 (yamaha_v3) を推奨します")
        warns.append("SNMPv2c は暗号化されません。可能なら SNMPv3 (yamaha_v3) を使ってください")
    errs += check_surge(values)
    return errs, warns


def validate(values, devices):
    """Full prod validation: (errors, warnings, device rows or None)."""
    dev_errs = check_devices(devices, _declared_auths())
    used = {str(d.get("snmp_auth", "")).strip() for d in devices if isinstance(d, dict)} if isinstance(devices, list) else set()
    errs, warns = check_env(values, used)
    if dev_errs:
        return dev_errs + errs, warns, None
    if not errs:  # an auth added to snmp/auths.yml by hand: its ${...} variables must be set too
        errs = [f"snmp_auth {a} の資格情報 (snmp/auths.yml が参照する変数) が .env で空です" for a in sorted(used - set(render_auths(values)))]
    return errs, warns, device_rows(devices)


def _declared_auths():
    return set(auth_versions())


def auth_versions():
    """{auth name: SNMP version} of snmp/auths.yml (the checks go by version, not by the auth's name)."""
    auths = (yaml.safe_load(AUTH_TEMPLATE.read_text(encoding="utf-8")) or {}).get("auths") or {}
    return {n: a.get("version") for n, a in auths.items()}


# ---- generated files (Prometheus file_sd, Alloy host map, snmp_exporter auths) --------------------

def capture_on(values=None):
    """prod: flows come from the capture profile (OBS_CAPTURE=1 in .env, with COMPOSE_PROFILES=prod,capture)."""
    return (values if values is not None else os.environ).get("OBS_CAPTURE", "0") == "1"


def demo_replay(values=None):
    """demo: flows from the synthetic pcap replayed by flowd-demo (default), or demo-gen's synthetic counters."""
    return (values if values is not None else os.environ).get("DEMO_PCAP_REPLAY", "1") != "0"


def flow_source(demo, values=None):
    if demo:
        return "pcap-replay" if demo_replay(values) else "demo-gen"
    return "capture" if capture_on(values) else None


FLOW_TARGETS = {"pcap-replay": [{"targets": ["flowd-demo:9100"], "labels": {"__metrics_path__": "/metrics"}}],
                "demo-gen": [{"targets": ["demo-gen:9116"]}],
                "capture": [{"targets": ["flowd:9100"], "labels": {"__metrics_path__": "/metrics"}}], None: []}


def file_sd(rows, demo, values=None):
    flows = FLOW_TARGETS[flow_source(demo, values)]
    if demo:
        snmp = [{"targets": [n], "labels": {"__device": n, "__exporter": "demo-gen:9116", "__param_module": "if_mib"}}
                for n in demo_names()]
        return snmp, flows
    snmp = [{"targets": [d["address"]], "labels": {"__device": d["name"], "__exporter": "snmp-exporter:9116",
                                                   "__param_module": snmp_modules(d["kind"]), "__param_auth": d["snmp_auth"]}}
            for d in rows]
    return snmp, flows


def lldp_sd(snmp, rows, demo):
    """The `lldp` job's targets: the snmp targets whose driver reads LLDP-MIB (driver.yaml lldp)."""
    kind = {n: k for n, (k, _) in demo_devices().items()} if demo else {d["name"]: d["kind"] for d in rows}
    return [t for t in snmp if driver(kind.get(t["labels"]["__device"])).get("lldp")]


def flow_hosts(rows, demo):
    """Inventory names for flowd's src_host (IPv4 management addresses only)."""
    if demo:
        return demo_hosts()
    return {split_address(d["address"])[0]: d["name"] for d in rows if is_ipv4(split_address(d["address"])[0])}


def alloy_string(s):
    return json.dumps(s)  # Alloy string literals use the same escapes


def relabel_rule(sources, rx, replacement):
    srcs = ", ".join(alloy_string(s) for s in sources)
    return (f"    rule {{\n      source_labels = [{srcs}]\n      regex         = {alloy_string(rx)}\n"
            f"      target_label  = \"inv_host\"\n      replacement   = {alloy_string(replacement)}\n    }}\n")


def hostmap(rows, demo=False):
    """Alloy module: syslog sender address -> inventory name (host label). An IP address matches the packet's
    source IP; a DNS name matches the sender's reverse-DNS name (first label or full name). Demo: demo-gen sends
    for all three devices from one address, so only that sender may name them in its header, and only those names."""
    rules = []
    if demo:
        rules.append(relabel_rule(["src_name", "hdr_host"], r"[^;]*demo-gen[^;]*;(" + "|".join(demo_names()) + ")", "$1"))
    for d in rows:
        host, _ = split_address(d["address"])
        if is_ipv4(host):
            rules.append(relabel_rule(["src_addr"], re.escape(host), d["name"]))
        else:
            rules.append(relabel_rule(["src_name"], re.escape(host) + r"(\..*)?", d["name"]))
    return ("// Generated by `tools targets` from the device inventory. Do not edit: changes are overwritten.\n"
            "declare \"hostmap\" {\n  argument \"forward_to\" { }\n\n"
            "  loki.relabel \"inventory\" {\n    forward_to = argument.forward_to.value\n"
            + "".join(rules) + "  }\n\n  export \"receiver\" {\n    value = loki.relabel.inventory.receiver\n  }\n}\n")


def write_atomic(path, text, mode=0o644, owner=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    if owner and os.geteuid() == 0:  # the service reading it runs as this uid (only root may chown)
        os.chown(tmp, *owner)
    os.replace(tmp, path)


def write_generated(rows, values, demo, plan=None):
    snmp, flows = file_sd(rows, demo, values)
    write_atomic(GEN / "flowd/hosts.json", json.dumps(flow_hosts(rows, demo), indent=2) + "\n")
    write_atomic(GEN / "prometheus/snmp.json", json.dumps(snmp, indent=2) + "\n")
    write_atomic(GEN / "prometheus/lldp.json", json.dumps(lldp_sd(snmp, rows, demo), indent=2) + "\n")
    write_atomic(GEN / "prometheus/flows.json", json.dumps(flows, indent=2) + "\n")
    write_atomic(GEN / "alloy/hostmap.alloy", hostmap([] if demo else rows, demo))
    auths = render_auths(values) if not demo else {}
    write_atomic(GEN / "snmp/auths.yml", "# Generated by `tools targets` from snmp/auths.yml. Do not edit.\n"
                 + yaml.safe_dump({"auths": auths}, sort_keys=False), mode=0o600)  # may hold the v2c community
    write_atomic(GEN / "mode", "demo\n" if demo else "prod\n")
    write_atomic(GEN / "ui/config.json", json.dumps(ui_config(rows, demo, values), indent=2) + "\n")
    write_atomic(GEN / "prometheus/wan-rules.yml", "# Generated by `tools targets`. Do not edit.\n"
                 + yaml.safe_dump(wan_rules(wan_of(rows, demo)), sort_keys=False, width=200))
    write_atomic(GEN / "prometheus/surge-rules.yml", "# Generated by `tools targets` from SURGE_* in .env. Do not edit.\n"
                 + yaml.safe_dump(surge_rules(surge_settings(values)), sort_keys=False, width=200))
    if au.required(values):  # Authelia's configuration (no secrets; it refuses to start without users or secrets)
        write_atomic(GEN / "authelia/configuration.yml", au.config_text(values))
    if plan is not None:
        write_alerting(plan, values)


def ui_config(rows, demo, values=None):
    """What the command-center needs to know about the deployment (served by the proxy as /obs/config.json):
    no addresses or credentials, only names. flow_source: pcap-replay | demo-gen | capture | null (no flows)."""
    devices = ([{"name": n, "kind": k} for n, (k, _) in demo_devices().items()] if demo
               else [{"name": d["name"], "kind": d["kind"]} for d in rows])
    devices = [{**d, "wireless": bool(driver(d["kind"]).get("wireless_clients"))} for d in devices]  # client column
    src = flow_source(demo, values)
    return {"profile": "demo" if demo else "prod", "flows_configured": src is not None, "flow_source": src, "devices": devices,
            "wan": wan_of(rows, demo), "bind": env("OBS_BIND", "127.0.0.1"), "links": topology_links(rows, demo),
            "surge": surge_settings(values if values is not None else env_map())}


# ---- traffic surges (P5): host x destination against its own baseline, Prometheus recording rules ---------------------
SURGE_DEFAULTS = {"SURGE_FACTOR": "3", "SURGE_MIN_KBPS": "200", "SURGE_BASELINE": "1h"}
SURGE_BASELINE_RE = re.compile(r"([1-9]\d?)([hd])")


def surge_settings(values):
    """-> {"factor", "min_kbps", "baseline"} from .env (defaults for unset / invalid values: check_env reports those)."""
    v = {k: str(values.get(k) or d) for k, d in SURGE_DEFAULTS.items()}
    try:
        factor = float(v["SURGE_FACTOR"])
        factor = factor if 1.5 <= factor <= 100 else 3.0
    except ValueError:
        factor = 3.0
    kbps = int(v["SURGE_MIN_KBPS"]) if v["SURGE_MIN_KBPS"].isdigit() and 0 < int(v["SURGE_MIN_KBPS"]) <= 10**7 else 200
    m = SURGE_BASELINE_RE.fullmatch(v["SURGE_BASELINE"])
    base = v["SURGE_BASELINE"] if m and 3600 <= int(m.group(1)) * (3600 if m.group(2) == "h" else 86400) <= 86400 else "1h"
    return {"factor": factor, "min_kbps": kbps, "baseline": base}


def check_surge(values):
    errs = []
    f = values.get("SURGE_FACTOR")
    if f:
        try:
            ok = 1.5 <= float(f) <= 100
        except ValueError:
            ok = False
        if not ok:
            errs.append(f"SURGE_FACTOR={f}: 1.5〜100 の数にしてください (平常の何倍で急増とみなすか)")
    k = values.get("SURGE_MIN_KBPS")
    if k and not (k.isdigit() and 0 < int(k) <= 10**7):
        errs.append(f"SURGE_MIN_KBPS={k}: 1 以上の整数 (kbps) にしてください")
    b = values.get("SURGE_BASELINE")
    if b and surge_settings({"SURGE_BASELINE": b})["baseline"] != b:
        errs.append(f"SURGE_BASELINE={b}: 1h〜24h (または 1d) の長さにしてください (例 1h, 6h, 1d)")
    return errs


SURGE_KEYS = "src_host, dst_country, asn"
SURGE_MIN_SAMPLES = 10  # recent-rate samples (30 s apart) a baseline needs: about 5 min of history


def surge_rules(s):
    """Recent rate (5 min) per host x destination country / ASN; its baseline (the median over SURGE_BASELINE, ending
    5 min ago: an occasional burst does not raise it; evaluated every 5 min so a 1 d baseline stays cheap); and the surges:
    recent >= min and > factor x baseline.
    Only the surging pairs have an obs_surge:flow_bps:ratio series (value = recent / baseline). A pair with fewer than
    SURGE_MIN_SAMPLES recent-rate samples in the baseline window (about 5 min of history: new pairs, the first minutes
    after start-up) has no baseline and is never a surge."""
    return {"groups": [
        {"name": "obs-surge-rate", "rules": [
            {"record": "obs_surge:flow_bps:rate5m", "expr": f"sum by ({SURGE_KEYS}) (rate(obs_flow_bytes_total[5m])) * 8"}]},
        {"name": "obs-surge-baseline", "interval": "5m", "rules": [
            {"record": "obs_surge:flow_bps:baseline",
             "expr": f"quantile_over_time(0.5, obs_surge:flow_bps:rate5m[{s['baseline']}] offset 5m)"
                     f" and count_over_time(obs_surge:flow_bps:rate5m[{s['baseline']}] offset 5m) >= {SURGE_MIN_SAMPLES}"}]},
        {"name": "obs-surge-detect", "rules": [
            {"record": "obs_surge:flow_bps:ratio",
             "expr": f"(obs_surge:flow_bps:rate5m >= {s['min_kbps'] * 1000}) / on ({SURGE_KEYS}) "
                     f"(last_over_time(obs_surge:flow_bps:baseline[10m]) > 0) > {s['factor']:g}"}]}]}


# ---- alert notifications: files and commands (the model is tools/notify.py) ---------------------------------------

ALERTMANAGER = "http://alertmanager:9093"


def receivers_path():
    return CONFIG / env("OBS_RECEIVERS", "alerting/receivers.yaml")


def load_receivers(path=None):
    """-> the parsed receivers file, or None when there is none (no notifications)."""
    path = path or receivers_path()
    if not path.exists():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise Fail(f"通知先 {rel(path)} の YAML が読めません: {e}") from None


def write_alerting(plan, values):
    write_atomic(GEN / "alertmanager/alertmanager.yml", "# Generated by `tools targets` from alerting/receivers.yaml. Do not edit. (no secrets)\n"
                 + yaml.safe_dump(alertmanager_config(plan), sort_keys=False, width=200))
    write_atomic(GEN / "notify/relay.json", json.dumps(relay_config(plan, public_url(values.get("OBS_BIND", "127.0.0.1"), values.get("OBS_PORT", "8080"), values.get("OBS_PUBLIC_URL", ""), au.required(values))), ensure_ascii=False, indent=2) + "\n", mode=0o600, owner=RELAY_UID)


def notify_plan(demo, values):
    """-> (errors, warnings, plan) for the profile: the demo always uses only the demo sink."""
    if demo:
        return [], [], DEMO_PLAN
    return check_receivers(load_receivers(), values, rel(receivers_path()))


def reload_services():
    """Apply regenerated files now (Prometheus file_sd needs nothing; Alloy's import.file would also notice within
    a minute). snmp-exporter re-reads auths.yml; notify-relay re-reads its config by itself; changed secrets in .env
    still need `docker compose up -d` (setup step regenerates)."""
    for url in ("http://alloy:12345/-/reload", "http://snmp-exporter:9116/-/reload", "http://prometheus:9090/-/reload",
                ALERTMANAGER + "/-/reload"):
        try:
            urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=HTTP_TIMEOUT)
        except urllib.error.HTTPError as e:  # e.g. Alertmanager refusing the new config: it keeps the old one
            print(f"[NG] {url.split('/')[2]} が新しい設定を読み込めませんでした (HTTP {e.code}): {e.read(300).decode('utf-8', 'replace').strip()}")
        except OSError:  # not running (first `up`, or demo): it reads the files when it starts
            pass


def cmd_targets(args):
    values = env_map()
    if args.demo:
        errs, warns = check_env(values)  # e.g. a LAN-exposed demo without OBS_PUBLIC_URL
        report(errs, warns)
        if errs:
            return 2
        write_generated([], values, demo=True, plan=DEMO_PLAN)
        print(f"デモ用の scrape 対象を書きました: {', '.join(demo_names())} (demo-gen 経由)")
    else:
        errs, warns, rows = validate(values, load_inventory())
        n_errs, n_warns, plan = notify_plan(False, values)
        report(errs + n_errs, warns + n_warns)
        if errs or n_errs:
            return 2
        write_generated(rows, values, demo=False, plan=plan)
        print(f"scrape 対象 {len(rows)} 台を書きました ({rel(inventory_path())}): "
              + ", ".join(f"{d['name']}={d['address']}" for d in rows))
    plan = DEMO_PLAN if args.demo else plan
    print("通知先: " + (", ".join(f"{n} ({t}: {s})" for n, t, s, _ in notify_summary(plan)) or "なし (どこにも通知しません)"))
    reload_services()
    return 0


def lan_bind(values):
    return on_lan(values)


def public_url(bind, port, given="", secure=False):
    """Where browsers open the screens (login and notification links): given, else derived from OBS_BIND
    (https with authentication), else None (0.0.0.0: every address of the host, so a name has to be chosen)."""
    if given:
        return given.rstrip("/")
    if bind == "0.0.0.0":
        return None
    return f"{'https' if secure else 'http'}://{'127.0.0.1' if bind in ('localhost', '') else bind}:{port}"


def on_lan(values):
    return not au.is_local_bind(values.get("OBS_BIND", "127.0.0.1"))


def cmd_setup_check(args):
    """Shared services need the files of a profile's setup step: fail clearly when no profile was chosen."""
    fix_capture_volumes()
    au.fix_volume(VOL / "authelia")
    if (GEN / "mode").exists():
        print(f"profile の設定: {mode()}")
        return 0
    print("[NG] profile の設定がありません。profile を指定していない (docker compose --profile demo up -d か、"
          ".env に COMPOSE_PROFILES=prod (tools init が書きます)) か、設定の生成に失敗しました "
          "(理由: docker compose logs demo-setup prod-setup)", file=sys.stderr)
    return 1


# ---- output helpers -----------------------------------------------------------------------------

def width(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def table(headers, rows):
    cols = [max(width(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    line = lambda r: " | ".join(str(c) + " " * (w - width(str(c))) for c, w in zip(r, cols)).rstrip()
    print(line(headers))
    print("-+-".join("-" * w for w in cols))
    for r in rows:
        print(line(r))


def report(errs, warns):
    for e in errs:
        print(f"[NG] {e}")
    for w in warns:
        print(f"[注意] {w}")


def fix_owner(*paths):
    """Files written into the mounted config directory belong to its owner, not to root."""
    st = CONFIG.stat()
    for p in paths:
        try:
            os.chown(p, st.st_uid, st.st_gid)
        except OSError:
            pass


def prepare_volumes():
    for comp, (uid, gid) in VOLUMES.items():
        p = VOL / comp
        if p.is_dir() and p.stat().st_uid == 0 and not any(p.iterdir()):
            os.chown(p, uid, gid)


# ---- HTTP ---------------------------------------------------------------------------------------

def http_get(url, timeout=HTTP_TIMEOUT):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def probe(url):
    """-> (ok, detail)"""
    if url.startswith("tcp://"):
        host, port = url[6:].split(":")
        try:
            socket.create_connection((host, int(port)), HTTP_TIMEOUT).close()
            return True, "接続可"
        except OSError as e:
            return False, f"接続できません ({type(e).__name__})"
    try:
        status, _ = http_get(url)
        return status < 400, f"HTTP {status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except OSError as e:
        return False, f"応答なし ({type(e).__name__})"


def prom_query(q):
    _, body = http_get("http://prometheus:9090/api/v1/query?" + urllib.parse.urlencode({"query": q}))
    return json.loads(body)["data"]["result"]


def loki_lines(query, start_ns, end_ns, limit=1000):
    url = "http://loki:3100/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": query, "start": start_ns, "end": end_ns, "limit": limit, "direction": "forward"})
    _, body = http_get(url, timeout=15)
    return [(s["stream"], line) for s in json.loads(body)["data"]["result"] for _, line in s["values"]]


# ---- check --------------------------------------------------------------------------------------

def mode():
    try:
        return (GEN / "mode").read_text().strip()
    except OSError:
        return "unknown"


def services(m):
    base = [("prometheus", "http://prometheus:9090/-/healthy"), ("loki", "http://loki:3100/ready"),
            ("alloy", "http://alloy:12345/-/ready"), ("mask-api", "tcp://mask-api:8000"), ("command-center", "http://command-center/"), ("proxy", "http://proxy/healthz"),
            ("alertmanager", ALERTMANAGER + "/-/healthy"), ("notify-relay", RELAY + "/health")]
    if au.required(env_map()):
        base.append(("authelia", "http://authelia:9091/auth/api/health"))
    extra = {"demo": [("demo-gen", "http://demo-gen:9116/fault/status")],
             "prod": [("snmp-exporter", "http://snmp-exporter:9116/")]}
    flows = {"pcap-replay": [("flowd-demo", "http://flowd-demo:9100/health")], "capture": [("flowd", "http://flowd:9100/health")]}
    # the analyzer has no network: its health is mask-api's /pcap/ answering a filter check through it
    return base + extra.get(m, []) + flows.get(flow_source(m == "demo"), []) + [("analyzer", "http://mask-api:8000/pcap/check?filter=dns")]


def snmp_probe(d, m):
    """One scrape through the exporter -> (ok, sysUpTime text, ifHC series count, detail)."""
    if m == "demo":
        url = "http://demo-gen:9116/snmp?" + urllib.parse.urlencode({"target": d["name"], "module": "if_mib"})
    else:
        url = "http://snmp-exporter:9116/snmp?" + urllib.parse.urlencode(
            {"target": d["address"], "module": snmp_modules(d["kind"]), "auth": d["snmp_auth"]})
    try:
        _, body = http_get(url, timeout=SNMP_TIMEOUT)
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", "replace")
        return False, "—", 0, snmp_error(msg) or f"HTTP {e.code}"
    except OSError as e:
        return False, "—", 0, f"exporter に接続できません ({type(e).__name__})"
    up = re.search(r"^sysUpTime (\S+)$", body, re.M)
    hc = len(re.findall(r"^ifHCInOctets\{", body, re.M))
    if not up or not hc:
        return False, "—", hc, snmp_error(body) or "sysUpTime / ifHCInOctets が取れません"
    days = float(up.group(1)) / 100 / 86400
    wan = d.get("wan_interface")
    if wan:
        names = sorted(set(re.findall(r'^ifHCInOctets\{[^}]*ifName="([^"]*)"', body, re.M)))
        if wan not in names:
            return False, f"{days:.1f} 日", hc, f"WAN の ifName {wan} がありません (ある ifName: {', '.join(names) or 'なし'})"
        return True, f"{days:.1f} 日", hc, f"OK (WAN {wan})"
    return True, f"{days:.1f} 日", hc, "OK"


def snmp_error(text):
    m = re.search(r"error walking target [^:]*: (.*)", text)
    if not m:
        return ""
    hint = {"timeout": "応答なし (IP・ポート・SNMP 有効化・ACL を確認)", "authentic": "認証エラー (ユーザー名・パスワード・方式を確認)",
            "unknown user": "SNMPv3 ユーザーが機器にありません", "decrypt": "暗号化エラー (priv パスワード・方式を確認)"}
    for k, v in hint.items():
        if k in m.group(1).lower():
            return v
    return m.group(1)[:80]


def wait_syslog(rows, seconds):
    """-> {name: first line seen or None} for lines that arrive in Loki during the wait."""
    t0 = time.time_ns() - 2 * 10**9
    seen = {d["name"]: None for d in rows}
    deadline = time.monotonic() + seconds
    print(f"syslog の受信を最大 {seconds} 秒待ちます ({', '.join(seen)}) ...", flush=True)
    while time.monotonic() < deadline and None in seen.values():
        for name in [n for n, v in seen.items() if v is None]:
            try:
                got = loki_lines('{job="syslog",host=%s}' % json.dumps(name), t0, time.time_ns(), limit=1)
            except (OSError, ValueError, KeyError):
                got = []
            if got:
                seen[name] = got[0][1]
        time.sleep(2)
    return seen


def cmd_check(args):
    m = mode()
    rc = 0
    print(f"モード: {m}  (生成済みの scrape 対象から判定。demo / prod)\n")
    if m == "prod":
        errs, warns, rows = validate(env_map(), safe_inventory())
    else:
        errs, warns = check_env(env_map())
        rows = [{"name": n, "address": n, "snmp_auth": "-", "syslog": True, "kind": "demo"} for n in demo_names()]
    print("■ 設定の検証")
    report(errs, warns)
    if not errs:
        print("[OK] .env と機器台帳に問題はありません" if m == "prod" else "[OK] .env に問題はありません")
    rc |= bool(errs)
    print("\n■ サービスの health")
    srows = []
    for name, url in services(m):
        ok, detail = probe(url)
        rc |= not ok
        srows.append((name, "OK" if ok else "NG", detail))
    table(("サービス", "状態", "詳細"), srows)
    rc |= check_users()
    rc |= check_notify(m)
    rc |= check_capture(m)
    if not rows:
        return 1
    print("\n■ 機器 (SNMP: exporter 経由で sysUpTime と ifHC カウンタを取得 / Prometheus の up)")
    try:
        up = {r["metric"].get("instance"): r["value"][1] for r in prom_query('up{job="snmp"}')}
        up_err = None
    except (OSError, ValueError, KeyError) as e:
        up, up_err = {}, f"Prometheus に問い合わせできません ({type(e).__name__})"
    drows = []
    for d in rows:
        ok, uptime, hc, detail = snmp_probe(d, m)
        state = up.get(d["name"])
        if up_err or state != "1":  # Prometheus is what the screens use: its target must exist and be up too
            ok = False
            why = up_err or ("Prometheus の scrape 対象にありません (tools targets を確認)" if state is None else "Prometheus の scrape が失敗中 (up=0)")
            detail = why if detail.startswith("OK") else f"{detail} / {why}"
        rc |= not ok
        drows.append((d["name"], d["address"], "OK" if ok else "NG", uptime, hc, state or "—", detail))
    table(("機器", "アドレス", "SNMP", "稼働時間", "ifHC 数", "up", "詳細"), drows)
    targets = [d for d in rows if d.get("syslog", True)]
    if args.syslog_wait > 0 and targets:
        print()
        seen = wait_syslog(targets, args.syslog_wait)
        lrows = []
        for name, line in seen.items():
            rc |= line is None
            lrows.append((name, "OK" if line else "NG", (line or "届きませんでした (機器の syslog host 設定・SYSLOG_BIND/PORT・FW を確認)")[:70]))
        table(("機器", "syslog", "最初に届いた行 / 対処"), lrows)
    print("\n結果:", "すべて OK" if not rc else "NG があります (上の表を確認してください)")
    return 1 if rc else 0


def check_users():
    """With authentication: at least one login user with a role (else Authelia does not start and nothing opens)."""
    if not au.required(env_map()):
        return False
    print("\n■ ログインの利用者 (Authelia)")
    try:
        users = au.load_users(AUTHELIA_USERS)
    except (au.AuthError, OSError, yaml.YAMLError) as e:
        print(f"[NG] 利用者のファイルを読めません: {e}")
        return True
    usable = [n for n, u in users.items() if not u.get("disabled") and au.role_of(u) != "-"]
    if not usable:
        print("[NG] 利用者がいません。docker compose run --rm tools user add <名前> --role admin で作ってください")
        return True
    print(f"[OK] {len(usable)} 人 (" + ", ".join(f"{n}={au.role_of(users[n])}" for n in usable) + ")")
    return False


def check_capture(m):
    """Packet capture (prod with OBS_CAPTURE=1) and the GeoIP databases. -> 1 on a problem."""
    print("\n■ パケット取込とフロー (flowd) / GeoIP")
    rc = 0
    src = flow_source(m == "demo")
    if src is None:
        print("キャプチャは無効です (OBS_CAPTURE=0。有効にするには docs/capture.md)")
    elif src == "capture":
        st = cap.capture_status(CAPTURE_VOL)
        if st["state"] == "running":
            print(f"[OK] キャプチャ中: {st.get('iface')} / フィルタ {st.get('filter') or '(なし)'} / snaplen {st.get('snaplen')} / "
                  f"リング {st.get('ring_files')} 本 {st.get('ring_bytes', 0) / 1e6:.0f} MB (上限 {st.get('ring_limit_bytes', 0) / 1e6:.0f} MB) / "
                  f"受信 {st.get('received')} / NIC の受信ドロップ {st.get('nic_rx_dropped')} / dumpcap の欠落 (終了したセッション分) {st.get('dumpcap_dropped')}")
            if st.get("nic_rx_dropped") or st.get("dumpcap_dropped"):
                print("[注意] パケットの取りこぼしがあります (NIC の受信ドロップ / dumpcap の欠落)。CAPTURE_BPF で絞るか CAPTURE_SNAPLEN を下げてください")
            print(RAW_NOTE)
        else:
            rc = 1
            why = st.get("error") or ("status.json がありません (capture サービスが動いていない: docker compose --profile capture up -d)" if st["state"] == "none"
                                      else f"{st['age_s']} 秒更新がありません")
            print(f"[NG] キャプチャが動いていません: {why}")
    else:
        print(f"デモ: フローは {'合成 pcap (demo/demo-home.pcap) を flowd-demo が繰り返し再生' if src == 'pcap-replay' else 'demo-gen の合成値'}")
    demo = subprocess.run([sys.executable, str(WORK / "demo/make_demo_pcap.py"), "--check"], capture_output=True, text=True)
    print(f"[{'OK' if demo.returncode == 0 else 'NG'}] デモ pcap: {(demo.stdout or demo.stderr).strip()[:120]}")
    rc |= demo.returncode != 0
    rows = cap.geoip_rows(GEOIP_VOL)
    table(("GeoIP", "版 (月)", "MiB", "経過日数", "状態"), [(a, b, c, "—" if d is None else d, e) for a, b, c, d, e in rows])
    print(f"  ({cap.ATTRIBUTION})")
    if src == "capture" and any(r[3] is None or r[3] > cap.GEOIP_STALE_DAYS for r in rows):
        print("[注意] GeoIP がないか古いと、通信先の国・都市は Unknown / 古い推定になります (docker compose run --rm tools geoip update)")
    return rc


def check_notify(m):
    """Receiver config, Alertmanager running the generated config, Prometheus sending to it. -> 1 on a problem."""
    print("\n■ 通知 (Alertmanager と通知先)")
    try:
        errs, warns, plan = notify_plan(m == "demo", env_map())
    except Fail as e:
        errs, warns, plan = [str(e)], [], None
    if m == "demo":
        print("デモ: 通知はデモ用の受信先 (demo-sink) に記録するだけで、外部へは送りません")
    report(errs, warns)
    rc = int(bool(errs))
    try:
        same, when = alertmanager_current()
        print(f"[OK] Alertmanager は生成された設定で動いています (読み込み {when})" if same else
              "[NG] Alertmanager が生成済みの設定を読み込んでいません (docker compose run --rm tools targets で再生成・再読込。"
              "直らなければ docker compose logs alertmanager)")
    except (OSError, ValueError, KeyError, AttributeError, yaml.YAMLError) as e:
        same = False
        print(f"[NG] Alertmanager の設定を確認できません ({type(e).__name__})")
    rc |= not same
    try:
        am = json.loads(http_get("http://prometheus:9090/api/v1/alertmanagers")[1])["data"]["activeAlertmanagers"]
        print("[OK] Prometheus はアラートを Alertmanager に送っています" if am else "[NG] Prometheus に Alertmanager の送り先がありません")
        rc |= not am
    except (OSError, ValueError, KeyError) as e:
        print(f"[NG] Prometheus に問い合わせできません ({type(e).__name__})")
        rc = 1
    if plan and plan["receivers"]:
        table(("通知先", "種別", "重大度", "宛先"), notify_summary(plan))
        print("  (実際に届くかは docker compose run --rm tools notify-test で確認)")
    return rc


def alertmanager_current():
    """-> (True when Alertmanager's last reload succeeded, after the generated file was written, with the same receivers;
    time of that reload). Its /api/v2/status shows the config with defaults filled in, so only the receivers compare."""
    path = GEN / "alertmanager/alertmanager.yml"
    metrics = http_get(ALERTMANAGER + "/metrics")[1]
    ok = re.search(r"^alertmanager_config_last_reload_successful 1$", metrics, re.M)
    t = float(re.search(r"^alertmanager_config_last_reload_success_timestamp_seconds (\S+)$", metrics, re.M).group(1))
    loaded = yaml.safe_load(json.loads(http_get(ALERTMANAGER + "/api/v2/status")[1])["config"]["original"])
    names = lambda c: sorted(r["name"] for r in c.get("receivers") or [])
    gen = yaml.safe_load(path.read_text(encoding="utf-8"))
    return bool(ok) and t + 2 >= path.stat().st_mtime and names(loaded) == names(gen), time.strftime("%m-%d %H:%M:%S", time.localtime(t))


def iso_utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def post_alerts(alerts):
    req = urllib.request.Request(ALERTMANAGER + "/api/v2/alerts", data=json.dumps(alerts).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=HTTP_TIMEOUT).close()


def cmd_notify_test(args):
    """A synthetic alert through Alertmanager to each receiver (or one); the relay's record of each answer -> table."""
    try:
        am = yaml.safe_load((GEN / "alertmanager/alertmanager.yml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        raise Fail("通知の設定が生成されていません。docker compose up -d の後に実行してください") from None
    names = [r["name"] for r in am.get("receivers", []) if r["name"] != "none"]
    if args.receiver and args.receiver not in names:
        raise Fail(f"通知先 {args.receiver} はありません (ある通知先: {', '.join(names) or 'なし'})")
    names = [args.receiver] if args.receiver else names
    if not names:
        raise Fail(f"通知先がありません。{rel(receivers_path())} を作って (例 config.example/alerting/receivers.example.yaml) "
                   "docker compose run --rm tools targets を実行してください")
    run, now = f"{int(time.time())}-{os.getpid()}", time.time()
    alert = lambda n, end: {"labels": {"alertname": TEST_ALERT, "severity": "info", "instance": "notify-test", "obs_test": run, "obs_test_receiver": n},
                            "annotations": {"summary": "notification test (tools notify-test)", "summary_ja": "通知のテストです (tools notify-test)。対応は不要です",
                                            "value": "—"}, "startsAt": iso_utc(now), "endsAt": iso_utc(end)}
    try:
        post_alerts([alert(n, now + 300) for n in names])
    except OSError as e:
        raise Fail(f"Alertmanager にテストのアラートを送れません ({type(e).__name__})。docker compose up -d の後に実行してください") from None
    print(f"テスト通知を {len(names)} 件の通知先に送りました (run {run})。結果を最大 {args.timeout} 秒待ちます ...", flush=True)
    got, deadline = {}, time.monotonic() + args.timeout
    while time.monotonic() < deadline and len(got) < len(names):
        time.sleep(2)
        try:
            for rec in json.loads(http_get(f"{RELAY}/results?test={run}")[1]):
                got[rec["receiver"]] = rec  # the last attempt (Alertmanager retries a failed one)
        except (OSError, ValueError) as e:
            print(f"notify-relay に問い合わせできません ({type(e).__name__})")
    try:
        post_alerts([alert(n, time.time()) for n in names])  # resolve the test (the relay does not send its resolution)
    except OSError:
        pass
    rows = [(n, got[n]["type"], "OK" if got[n]["result"] == "ok" else "NG", got[n]["detail"]) if n in got
            else (n, "—", "NG", "届きませんでした (docker compose logs alertmanager notify-relay を確認)") for n in names]
    table(("通知先", "種別", "結果", "応答"), rows)
    bad = sum(r[2] != "OK" for r in rows)
    print(f"\n{len(rows) - bad}/{len(rows)} OK")
    return 1 if bad else 0


def safe_inventory():
    try:
        return load_inventory()
    except Fail as e:
        print(f"[NG] {e}")
        return None


# ---- init ---------------------------------------------------------------------------------------

def env_line_value(v):
    return v if SAFE_ENV.fullmatch(v) else f"'{v}'"  # single quotes: compose takes the value literally (no $ expansion)


def render_env(values):
    """.env.example with the given values filled in (comments and order kept; unknown keys appended)."""
    out, done = [], set()
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"#?\s*([A-Z][A-Z0-9_]*)=", line)
        if m and m.group(1) in values:
            out.append(f"{m.group(1)}={env_line_value(values[m.group(1)])}")
            done.add(m.group(1))
        else:
            out.append(line)
    out += [f"{k}={env_line_value(v)}" for k, v in values.items() if k not in done]
    return "\n".join(out) + "\n"


def render_inventory(rows):
    head = ("# 機器台帳 (tools init が生成。手で編集してよい。変更後は `docker compose run --rm tools targets`)\n"
            f"#   name: 表示名 (Prometheus の instance / Loki の host)   kind: {' | '.join(kinds())} (drivers/ のドライバ)\n"
            "#   address: 管理 IP か DNS 名 (SNMP の宛先。syslog の送信元の照合にも使う)\n"
            "#   snmp_auth: snmp/auths.yml の auth 名 (yamaha_v3 / yamaha_v2c)   syslog: syslog を送ってくるか\n"
            "#   wan_interface: (任意、1 台だけ) WAN 側の ifName (例 lan2)。WAN 表示とアラート WanHighUtilization に使う\n"
            "# 秘密値 (SNMP のパスワード等) はここに書かず .env に置く。\n")
    return head + yaml.safe_dump({"devices": rows}, sort_keys=False, allow_unicode=True)


def parse_device(spec):
    parts = [p.strip() for p in spec.split(",")]
    if len(parts) not in (3, 4):
        raise Fail(f"--device '{spec}': 名前,種別,アドレス[,auth] の形にしてください (例 rtx1300,rtx,192.168.100.1)")
    return {"name": parts[0], "kind": parts[1], "address": parts[2],
            "snmp_auth": parts[3] if len(parts) == 4 else "yamaha_v3", "syslog": True}


def apply_wan(devices, spec):
    """--wan NAME:IFNAME -> wan_interface on that device."""
    if not spec:
        return
    name, _, ifname = spec.partition(":")
    for d in devices:
        if d["name"] == name:
            d["wan_interface"] = ifname
            return
    raise Fail(f"--wan {spec}: 機器 {name} が --device にありません")


def ask(prompt, default="", secret=False):
    shown = f" [{default}]" if default and not secret else (" [設定済み]" if default else "")
    v = (getpass.getpass if secret else input)(f"{prompt}{shown}: ").strip()
    return v or default


def interactive(values, devices):
    print("対話モード: Enter で [ ] 内の既定値を使います。パスワードは表示されません。\n")
    values["OBS_BIND"] = ask("画面を公開するアドレス (127.0.0.1 はこの PC のみ。LAN 公開は LAN 側 IP か 0.0.0.0、ログイン必須)", values["OBS_BIND"])
    values["OBS_PORT"] = ask("画面のポート", values["OBS_PORT"])
    values["SYSLOG_BIND"] = ask("syslog を受けるアドレス (機器から送るなら LAN 側 IP か 0.0.0.0)", values["SYSLOG_BIND"])
    values["SYSLOG_PORT"] = ask("syslog のポート (UDP/TCP)", values["SYSLOG_PORT"])
    values["SNMP_V3_USER"] = ask("SNMPv3 ユーザー名 (機器側に設定したもの)", values["SNMP_V3_USER"])
    values["SNMP_V3_AUTH_PROTO"] = ask(f"SNMPv3 認証方式 ({'/'.join(AUTH_PROTOS)})", values["SNMP_V3_AUTH_PROTO"])
    values["SNMP_V3_AUTH_PASS"] = ask("SNMPv3 認証パスワード (8 文字以上)", values["SNMP_V3_AUTH_PASS"], secret=True)
    values["SNMP_V3_PRIV_PROTO"] = ask(f"SNMPv3 暗号方式 ({'/'.join(PRIV_PROTOS)})", values["SNMP_V3_PRIV_PROTO"])
    values["SNMP_V3_PRIV_PASS"] = ask("SNMPv3 暗号パスワード (8 文字以上)", values["SNMP_V3_PRIV_PASS"], secret=True)
    values["SNMP_COMMUNITY"] = ask("SNMPv2c コミュニティ (使わないなら空のまま)", values["SNMP_COMMUNITY"], secret=True)
    if devices:
        print(f"機器 {len(devices)} 台は引数で指定済みです")
        return
    print("\n機器を登録します (名前を空にすると終了)")
    while True:
        name = ask("  機器名 (例 rtx1300)")
        if not name:
            break
        kind = ask(f"  種別 ({'/'.join(kinds())})", next((k for k in kinds() if name.startswith(k)), kinds()[-1]))
        addr = ask("  管理 IP または DNS 名")
        auth = ask("  SNMP 認証 (yamaha_v3 / yamaha_v2c)", "yamaha_v3")
        dev = {"name": name, "kind": kind, "address": addr, "snmp_auth": auth, "syslog": True}
        if driver(kind).get("wan") and not any("wan_interface" in x for x in devices):
            wan = ask("  WAN 側インターフェースの ifName (例 lan2。WAN 表示とアラートに使う。空ならなし)")
            if wan:
                dev["wan_interface"] = wan
        devices.append(dev)


def ask_receiver(rtype, values):
    """Questions for one receiver: its non-secret part (-> receivers.yaml) and secrets (-> values, i.e. .env)."""
    r = {"name": ask("  名前 (英小文字・数字・- _)", rtype), "type": rtype}
    if rtype == "email":
        r["to"] = [x.strip() for x in ask("  宛先メールアドレス (複数はカンマ区切り)").split(",") if x.strip()]
        values["SMTP_HOST"] = ask("  SMTP サーバー (例 smtp.example.com)", values.get("SMTP_HOST", ""))
        values["SMTP_TLS"] = ask("  暗号化 (starttls / tls / none)", values.get("SMTP_TLS") or "starttls")
        values["SMTP_PORT"] = ask("  SMTP ポート", values.get("SMTP_PORT") or SMTP_PORTS.get(values["SMTP_TLS"], "587"))
        values["SMTP_FROM"] = ask("  送信元メールアドレス", values.get("SMTP_FROM", ""))
        values["SMTP_USER"] = ask("  SMTP ユーザー名 (認証なしなら空)", values.get("SMTP_USER", ""))
        if values["SMTP_USER"]:
            values["SMTP_PASSWORD"] = ask("  SMTP パスワード", values.get("SMTP_PASSWORD", ""), secret=True)
    elif rtype == "line":
        values["LINE_CHANNEL_ACCESS_TOKEN"] = ask("  LINE Messaging API のチャネルアクセストークン (長期)", values.get("LINE_CHANNEL_ACCESS_TOKEN", ""), secret=True)
        r["to"] = ask("  送り先のユーザー ID / グループ ID (U… / C…、LINE Developers で確認)")
    else:
        key = URL_SECRETS[rtype]
        what = {"slack": "Slack の Incoming Webhook URL", "discord": "Discord の Webhook URL", "webhook": "送り先の URL"}[rtype]
        values[key] = ask(f"  {what}", values.get(key, ""), secret=True)
        if rtype == "webhook":
            values["WEBHOOK_BEARER_TOKEN"] = ask("  Authorization: Bearer に付けるトークン (不要なら空)", values.get("WEBHOOK_BEARER_TOKEN", ""), secret=True)
    return r


def interactive_receivers(values):
    """init: optionally scaffold alerting/receivers.yaml (critical / warning to every receiver, info to none)."""
    path = receivers_path()
    if path.exists():
        print(f"\n通知先: 既存の {rel(path)} を使います (変更は手で編集し、tools targets)")
        return None
    if ask("\nアラートの通知先 (メール / Slack / Discord / LINE / Webhook) を設定しますか? (y/N)", "n").lower() != "y":
        print(f"通知先なし (アラートは画面にだけ出ます)。後から: config.example/alerting/receivers.example.yaml を {rel(path)} にコピーして編集")
        return None
    receivers = []
    while True:
        rtype = ask(f"  通知先の種類 ({' / '.join(RECEIVER_TYPES)}、空で終了)")
        if not rtype:
            break
        if rtype not in RECEIVER_TYPES or any(r["type"] == rtype for r in receivers):
            print("  使えない種類か、追加済みの種類です (秘密値は種類ごとに 1 組。メールの宛先は 1 件に複数書けます)")
            continue
        receivers.append(ask_receiver(rtype, values))
    if not receivers:
        return None
    names = [r["name"] for r in receivers]
    return {"receivers": receivers, "routes": {"critical": {"receivers": list(names), "repeat": "1h"},  # own lists: no YAML anchors
                                               "warning": {"receivers": list(names), "repeat": "4h"}, "info": {"receivers": [], "repeat": "24h"}}}


def cmd_init(args):
    fix_capture_volumes()
    inv = inventory_path()
    exists = [p for p in (ENV_FILE, inv) if p.exists()]
    if exists and not args.force:
        raise Fail("既にあります: " + ", ".join(rel(p) for p in exists)
                   + "。作り直すなら --force (元のファイルは .bak に残します)")
    values = {"COMPOSE_PROFILES": "prod", **pinned_settings(), "OBS_BIND": args.bind, "OBS_PORT": args.port, "SYSLOG_BIND": args.syslog_bind,
              "SYSLOG_PORT": args.syslog_port,
              "SNMP_V3_USER": args.snmp_user or env("SNMP_V3_USER"), "SNMP_V3_AUTH_PROTO": args.snmp_auth_proto,
              "SNMP_V3_AUTH_PASS": env("SNMP_V3_AUTH_PASS"), "SNMP_V3_PRIV_PROTO": args.snmp_priv_proto,
              "SNMP_V3_PRIV_PASS": env("SNMP_V3_PRIV_PASS"), "SNMP_COMMUNITY": env("SNMP_COMMUNITY"),
              "OBS_INVENTORY": rel(inv), "OBS_PUBLIC_URL": args.public_url, "OBS_AUTH": "1" if args.auth else env("OBS_AUTH", "0"),
              **{k: env(k) for k in NOTIFY_ENV if env(k)},  # notification settings already in .env are kept
              **{k: env(k) for k in au.SECRETS if env(k)}}  # so are the authentication secrets (sessions, stored TOTP keys)
    values.update(au.missing_secrets(values))  # generated here, written only into .env
    devices = [parse_device(s) for s in args.device]
    apply_wan(devices, args.wan)
    receivers = None
    if not args.yes:
        if not sys.stdin.isatty():
            raise Fail("対話できません (TTY なし)。`docker compose run --rm tools init` で実行するか、--yes と引数で指定してください")
        interactive(values, devices)
        receivers = interactive_receivers(values)
    values["OBS_PUBLIC_URL"] = public_url(values["OBS_BIND"], values["OBS_PORT"], values["OBS_PUBLIC_URL"], au.required(values)) or ""
    if not values["OBS_PUBLIC_URL"] and not args.yes:
        values["OBS_PUBLIC_URL"] = ask("LAN から画面を開くときの URL (例 https://192.168.100.10:8080。ログイン・通知のリンクに使う)").rstrip("/")
    errs, warns, rows = validate(values, devices)
    if receivers is not None:
        n_errs, n_warns, _ = check_receivers(receivers, values, rel(receivers_path()))
        errs, warns = errs + n_errs, warns + n_warns
    if not values["OBS_PUBLIC_URL"] and not any("421" in e for e in errs):  # (check_env already says it for 0.0.0.0)
        errs.append("OBS_BIND=0.0.0.0 のときは --public-url で LAN から開く URL を指定してください (例 https://192.168.100.10:8080)")
    print("\n■ 設定の検証")
    report(errs, warns)
    if errs:
        print("\n書き込みませんでした。上の NG を直してもう一度実行してください")
        return 2
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for p in exists:
        shutil.copy2(p, p.with_name(f"{p.name}.bak-{stamp}"))
    write_atomic(ENV_FILE, render_env(env_file_values(values, read_env_file(ENV_FILE))), mode=0o600)
    write_atomic(inv, render_inventory(rows))
    fix_owner(ENV_FILE, inv, inv.parent)
    print(f"[OK] 書きました: .env (秘密値はここだけ、権限 600), {rel(inv)} ({len(rows)} 台)"
          + (f" — 設定ディレクトリ {env('OBS_CONFIG_DIR')}" if env("OBS_CONFIG_DIR") else
             " — リポジトリ内 (従来の配置、git 管理外)。外に置くなら OBS_CONFIG_DIR (docs/configuration.md)")
          + (f"。{', '.join(sorted(SECRETS_FROM_FILES))} は *_FILE から (.env には書きません)" if SECRETS_FROM_FILES else ""))
    if receivers is not None:
        write_atomic(receivers_path(), render_receivers(receivers))
        fix_owner(receivers_path())
        print(f"[OK] 書きました: {rel(receivers_path())} (通知先 {len(receivers['receivers'])} 件)。起動後に docker compose run --rm tools notify-test")
    if au.required(values):
        print("[OK] ログインの秘密値 (OBS_AUTH_*) を .env に作りました。画面はログイン必須 (HTTPS) です。\n"
              "次: 利用者を作る: docker compose run --rm tools user add <名前> --role admin   (operator / viewer も)")
    print(f"次: docker compose up -d   (COMPOSE_PROFILES={values['COMPOSE_PROFILES']} を .env に書いたので profile 指定は不要)\n"
          "    docker compose run --rm tools check   (SNMP 疎通・syslog 受信・health の確認)")
    return 0


def pinned_settings():
    """What `tools init` / `migrate-config` pin into .env: the compose project it runs under (existing volumes keep
    their names whatever compose.yaml's default becomes) and the config directory (compose mounts it at /config)."""
    return {"COMPOSE_PROJECT_NAME": env("COMPOSE_PROJECT_NAME") or LEGACY_PROJECT,
            **({"OBS_CONFIG_DIR": env("OBS_CONFIG_DIR")} if env("OBS_CONFIG_DIR") else {})}


def env_file_values(values, old_file, from_files=SECRETS_FROM_FILES):
    """What init writes into .env: secrets ./geofront read from <NAME>_FILE stay out (their <NAME>_FILE line of the old
    .env is kept, so `init --force` does not lose where they come from)."""
    out = {k: v for k, v in values.items() if k not in from_files}
    out.update({f"{k}_FILE": old_file[f"{k}_FILE"] for k in sorted(from_files) if f"{k}_FILE" in old_file})
    return out


def pin_env(path, settings):
    """Append KEY=VALUE for the keys .env does not set yet (existing lines are never touched). -> keys added."""
    have = read_env_file(path)
    new = {k: v for k, v in settings.items() if k not in have}
    if new:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        write_atomic(path, text + ("" if not text or text.endswith("\n") else "\n")
                     + "".join(f"{k}={env_line_value(v)}\n" for k, v in new.items()), mode=0o600)
    return list(new)


def migration_plan(legacy_env, src, dst):
    """-> [(source, destination)] of the legacy layout's files that exist: .env, the inventory and the receivers it
    names (paths kept relative), backups/*."""
    rels = [".env", legacy_env.get("OBS_INVENTORY") or "inventory/devices.yaml",
            legacy_env.get("OBS_RECEIVERS") or "alerting/receivers.yaml"]
    out = [(src / r, dst / r) for r in rels if not Path(r).is_absolute() and ".." not in Path(r).parts and (src / r).is_file()]
    if (src / "backups").is_dir():
        out += [(f, dst / "backups" / f.name) for f in sorted((src / "backups").iterdir()) if f.is_file()]
    return out


def cmd_migrate_config(args):
    """Legacy layout (config inside the repository) -> OBS_CONFIG_DIR, or (without OBS_CONFIG_DIR) only pin the project
    name into the repository's .env. Copies, never moves: the old files stay until the operator removes them."""
    target = env("OBS_CONFIG_DIR")
    if not target:
        if not ENV_FILE.exists():
            raise Fail("リポジトリ内に .env がありません (移すものがありません)。新しく作るなら tools init")
        added = pin_env(ENV_FILE, pinned_settings())
        fix_owner(ENV_FILE)
        print(f"[OK] .env に {', '.join(added)} を固定しました (今のボリュームをそのまま使います)" if added
              else "[OK] .env にプロジェクト名は固定済みです (変えません)")
        print("設定をリポジトリの外へ移すには: OBS_CONFIG_DIR=<dir> ./geofront run --rm tools migrate-config")
        return 0
    legacy = read_env_file(WORK / ".env")
    plan = migration_plan(legacy, WORK, CONFIG)
    if not plan:
        raise Fail("リポジトリ内に移す設定 (.env・台帳・通知先・backups) がありません")
    clash = [d for _, d in plan if d.exists()]
    if clash and not args.force:
        raise Fail("移す先に既にあります: " + ", ".join(rel(d) for d in clash) + "。上書きするなら --force (元は .bak に残します)")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for src, dst in plan:
        if dst.exists():
            shutil.copy2(dst, dst.with_name(f"{dst.name}.bak-{stamp}"))
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        if dst.name == ".env" or dst.parent.name == "backups":
            os.chmod(dst, 0o600)
        fix_owner(dst, dst.parent)
    pin_env(ENV_FILE, {"COMPOSE_PROJECT_NAME": legacy.get("COMPOSE_PROJECT_NAME") or pinned_settings()["COMPOSE_PROJECT_NAME"],
                       "OBS_CONFIG_DIR": target})
    fix_owner(ENV_FILE)
    old = [str(s.relative_to(WORK)) for s, _ in plan]
    print(f"[OK] {len(plan)} 件を {target} に写しました: {', '.join(rel(d) for _, d in plan)}")
    print(f"     .env に COMPOSE_PROJECT_NAME={read_env_file(ENV_FILE)['COMPOSE_PROJECT_NAME']} (今のボリュームのまま) と OBS_CONFIG_DIR を固定")
    print("次: export OBS_CONFIG_DIR=" + target + " して ./geofront up -d (または docker compose --env-file " + target + "/.env ...)、"
          "./geofront run --rm tools check で確認してから、リポジトリ内の旧ファイルを消してください: " + " ".join(old))
    return 0


def doctor_config_rows():
    rows = []
    if env("OBS_CONFIG_DIR"):
        rows.append(("設定の場所", dr.OK, f"OBS_CONFIG_DIR ({env('OBS_CONFIG_DIR')})", ""))
        if (WORK / ".env").exists():
            rows.append(("旧配置の .env", dr.WARN, "リポジトリ内にも .env があります (使われません)", "移行を確かめてからリポジトリの .env を消す"))
    else:
        rows.append(("設定の場所", dr.WARN, "リポジトリ内 (従来の配置。git 管理外)",
                     "外へ: OBS_CONFIG_DIR=<dir> ./geofront run --rm tools migrate-config (docs/configuration.md)"))
    leak = env("OBS_DOCTOR_LEAK")  # scripts/doctor.sh runs scripts/leak-scan.sh on the host (git is not in this image)
    if leak:
        rows.append(("コミットしてはいけないデータ", dr.OK if leak == "OK" else dr.WARN, leak,
                     "" if leak == "OK" or leak.startswith("省略") else "scripts/leak-scan.sh で場所を確認 (.gitignore / config の外出し)"))
    return rows


# ---- doctor (H1): preflight before `up` / `check`, no device traffic ---------------------------------

CADDY_VOL = VOL / "caddy"


def env_file_value(v):
    """One .env value as compose reads it: 'single' literal, "double" with \\n \\" \\\\ escapes (text after the closing
    quote ignored), unquoted up to an inline ` #` comment."""
    v = v.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1) if v[0] == "'" else next((i for i in range(1, len(v)) if v[i] == '"' and v[i - 1] != "\\"), -1)
        if end > 0:
            inner = v[1:end]
            return inner if v[0] == "'" else re.sub(r"\\(.)", lambda m: "\n" if m.group(1) == "n" else m.group(1), inner)
    return re.split(r"\s+#", v, maxsplit=1)[0].rstrip()


def read_env_file(path=None):
    """KEY=VALUE lines of .env ({} without one), also `export KEY=...`, values as compose reads them."""
    path = path or ENV_FILE
    out = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            k, sep, v = line.partition("=")
            if sep and re.fullmatch(r"[A-Z][A-Z0-9_]*", k.strip()):
                out[k.strip()] = env_file_value(v)
    return out


def published_ports(values, demo):
    v = lambda k, d: values.get(k) or d
    want = [("tcp", v("OBS_BIND", "127.0.0.1"), v("OBS_PORT", "8080")), ("tcp", "127.0.0.1", v("PROM_LOCAL_PORT", "9090")),
            ("tcp", v("SYSLOG_BIND", "127.0.0.1"), v("SYSLOG_PORT", "514")), ("udp", v("SYSLOG_BIND", "127.0.0.1"), v("SYSLOG_PORT", "514"))]
    if demo:
        want.append(("tcp", "127.0.0.1", "9116"))
    return [(p, a, int(n)) for p, a, n in want if str(n).isdigit()]


def profiles_of(file_env):
    return {p.strip() for p in (env("COMPOSE_PROFILES") or file_env.get("COMPOSE_PROFILES", "")).split(",") if p.strip()}


def doctor_host_rows(values, file_env):
    rows = []
    add = lambda item, res: rows.append((item, *res))
    add("Docker Engine", dr.engine(env("OBS_DOCTOR_ENGINE")))
    add("docker compose", dr.compose(env("OBS_DOCTOR_COMPOSE")))
    add("CPU", dr.arch(env("OBS_DOCTOR_ARCH") or os.uname().machine))
    try:
        mem = int(re.search(r"^MemTotal:\s+(\d+) kB", Path("/proc/meminfo").read_text(), re.M).group(1)) * 1024
        add("メモリ", dr.memory(mem))
    except (OSError, AttributeError):
        add("メモリ", (dr.WARN, "不明 (/proc/meminfo)", ""))
    need, seen = dr.disk_need(values), set()
    for label, p in (("ディスク (リポジトリ)", WORK), ("ディスク (Docker のボリューム)", VOL / "prometheus")):
        if p.exists() and p.stat().st_dev not in seen:
            seen.add(p.stat().st_dev)
            add(label, dr.disk(str(p), shutil.disk_usage(p).free, need))
    ref = max((q.stat().st_mtime for q in (WORK / "compose.yaml", WORK / "README.md") if q.exists()), default=None)
    add("時刻", dr.clock(time.time(), ref, env("OBS_DOCTOR_NTP")))
    add("ポート", dr.ports(published_ports(values, "demo" in profiles_of(file_env)), dr.listeners(env("OBS_DOCTOR_LISTEN")),
                          "OBS_DOCTOR_LISTEN" in os.environ, dr.listeners(env("OBS_DOCTOR_OWN"))))
    return rows


def doctor_env_rows(values, file_env):
    if not ENV_FILE.exists():
        return [(".env", dr.NG, "ありません", "docker compose run --rm tools init (デモだけなら不要: --profile demo)")]
    rows = []
    bits = ENV_FILE.stat().st_mode & 0o777
    rows.append((".env の権限", dr.WARN if bits & 0o077 else dr.OK, oct(bits), "chmod 600 .env (秘密値が入っています)" if bits & 0o077 else ""))
    profiles = profiles_of(file_env)
    if not profiles & {"prod", "demo"}:
        rows.append(("COMPOSE_PROFILES", dr.NG, f"{','.join(sorted(profiles)) or '空'} (prod か demo が必要)", ".env に COMPOSE_PROFILES=prod (tools init が書きます)"))
        return rows
    rows.append(("COMPOSE_PROFILES", dr.OK, ",".join(sorted(profiles)), ""))
    if "prod" in profiles:
        try:
            errs, warns, _ = validate(values, load_inventory())
        except Fail as e:
            errs, warns = [str(e)], []
    else:
        errs, warns = check_env(values)
    rows += [(".env / 台帳", dr.NG, e, "") for e in errs] + [(".env / 台帳", dr.WARN, w, "") for w in warns]
    if not errs and not warns:
        rows.append((".env / 台帳", dr.OK, "必須値と形式に問題はありません", ""))
    return rows


def doctor_access_rows(values):
    if not au.required(values):
        return [("ログイン / 証明書", dr.OK, "ログインなし (127.0.0.1 のみ、http)", "")]
    rows = []
    try:
        users = au.load_users(AUTHELIA_USERS)
        usable = [n for n, u in users.items() if not u.get("disabled") and au.role_of(u) != "-"]
        if usable:
            admins = sum(au.role_of(users[n]) == "admin" for n in usable)
            rows.append(("ログインの利用者", dr.OK, f"{len(usable)} 人 (admin {admins} 人)", ""))
        else:
            rows.append(("ログインの利用者", dr.NG, "0 人 (ログイン必須なので画面は開きません)", "docker compose run --rm tools user add <名前> --role admin"))
    except (au.AuthError, OSError, yaml.YAMLError) as e:
        rows.append(("ログインの利用者", dr.NG, f"利用者のファイルを読めません: {e}", ""))
    pki = CADDY_VOL / "caddy"
    root = dr.decode_cert(pki / "pki/authorities/local/root.crt")
    leaves = [c for c in map(dr.decode_cert, sorted((pki / "certificates").glob("*/*/*.crt"))) if c]
    rows.append(("証明書 (HTTPS)", *dr.certificate(root, leaves, [h.strip("[]") for h, _ in au.hosts(values)], time.time())))
    return rows


def cmd_doctor(args):
    file_env = read_env_file()
    values = {**file_env, **env_map()}
    rows = (doctor_host_rows(values, file_env) + doctor_config_rows() + doctor_env_rows(values, file_env) + doctor_access_rows(values)
)
    print("■ 導入前の自己診断 (機器には接続しません)\n")
    table(("項目", "状態", "詳細", "直し方"), rows)
    ng = sum(r[1] == dr.NG for r in rows)
    print(f"\n結果: NG {ng} / WARN {sum(r[1] == dr.WARN for r in rows)} / OK {sum(r[1] == dr.OK for r in rows)}"
          + ("  — NG を直してから docker compose up -d" if ng else "  — 起動できます (起動後: docker compose run --rm tools check)"))
    return 1 if ng else 0


# ---- backup / restore ---------------------------------------------------------------------------

def snapshot_prometheus():
    req = urllib.request.Request("http://prometheus:9090/api/v1/admin/tsdb/snapshot", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            name = json.loads(r.read())["data"]["name"]
    except urllib.error.HTTPError as e:
        raise Fail(f"Prometheus のスナップショットに失敗しました (HTTP {e.code}。admin API が無効?)") from None
    except OSError:
        raise Fail("Prometheus に接続できません。起動してから backup してください (docker compose up -d)") from None
    return VOL / "prometheus/snapshots" / name


def sqlite_copy(tmp, src, name):
    """Consistent copy of a SQLite database while its service keeps running (sqlite backup API, source opened read-only;
    Authelia's db.sqlite3). -> path of the copy, or None when there is no database."""
    src = Path(src)
    if not src.exists():
        return None
    dst = Path(tmp) / name
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    d = sqlite3.connect(dst)
    try:
        s.backup(d)
    finally:
        s.close()
        d.close()
    return dst


def write_archive(path, manifest, sources, tmp):
    """Write the backup to <path>.partial and move it into place only when everything was added. sources:
    [(part or None, arcname, source path, tar filter)]. The manifest (last member) records files / bytes per part,
    so restore can tell a complete archive from a cut one; on any error the partial file is removed."""
    partial = path.with_name(path.name + ".partial")
    counts = {}

    def counting(part, flt):
        def f(ti):
            ti = flt(ti) if flt else ti
            if ti is not None and part and ti.isfile():
                c = counts.setdefault(part, {"files": 0, "bytes": 0})
                c["files"] += 1
                c["bytes"] += ti.size
            return ti
        return f
    try:
        with tarfile.open(partial, "w:gz") as tar:
            for part, arcname, src, flt in sources:
                tar.add(src, arcname, filter=counting(part, flt))
            manifest = {**manifest, "parts": sorted(counts), "contents": counts}
            mf = Path(tmp) / "manifest.json"
            mf.write_text(json.dumps(manifest, indent=2))
            tar.add(mf, "manifest.json")
        os.replace(partial, path)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return manifest


def cmd_backup(args):
    prepare_volumes()
    out = CONFIG / args.out
    out.mkdir(parents=True, exist_ok=True)
    fix_owner(out)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = out / f"obs-backup-{stamp}.tar.gz"
    inv = inventory_path()
    manifest = {"created": stamp, "format": 2, "mode": mode(), "include_env": bool(args.include_env and ENV_FILE.exists()),
                "inventory": rel(inv) if inv.exists() else None, "receivers": rel(receivers_path()) if receivers_path().exists() else None}
    snap = snapshot_prometheus()
    if args.include_captures:
        print("[注意] キャプチャのリングとアップロードした pcap を含めます (通信内容そのもの。取り扱い注意)")
    umask = os.umask(0o077)  # the archive (and the copies in tmp) are owner-only from the first byte
    staged = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sources = [("prometheus", "prometheus", snap, None), ("loki", "loki", VOL / "loki", None),
                       ("alertmanager", "alertmanager", VOL / "alertmanager", None)]
            adb = sqlite_copy(tmp, VOL / "authelia/db.sqlite3", "authelia.sqlite3")
            if (VOL / "authelia/users_database.yml").exists():  # login users (argon2id hashes) + bans / TOTP keys
                skip_adb = lambda ti: None if re.search(r"(^|/)db\.sqlite3(-wal|-shm|-journal)?$", ti.name) else ti
                sources.append(("authelia", "authelia", VOL / "authelia", skip_adb))
                if adb:
                    sources.append(("authelia", "authelia/db.sqlite3", adb, None))
            sources.append(("caddy", "caddy", VOL / "caddy", None))  # same CA after a restore: no new root on the devices
            if args.include_captures:  # never by default: full packets, bounded by their own retention instead
                # closed files only, staged first: the ring rotates and prunes under a running capture
                stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=out))
                staged.append(stage)
                cap.stage_closed(CAPTURE_VOL, stage / "capture", capture_volume=True)
                cap.stage_closed(UPLOADS_VOL, stage / "uploads")
                sources += [("capture", "capture", stage / "capture", None), ("uploads", "uploads", stage / "uploads", None)]
            if inv.exists():
                sources.append((None, "config/" + manifest["inventory"].lstrip("/"), inv, None))
            if manifest["receivers"]:
                sources.append((None, "config/" + manifest["receivers"].lstrip("/"), receivers_path(), None))
            if manifest["include_env"]:
                sources.append((None, "config/.env", ENV_FILE, None))
            manifest = write_archive(path, manifest, [s for s in sources if Path(s[2]).exists()], tmp)
    finally:
        os.umask(umask)
        shutil.rmtree(snap, ignore_errors=True)
        for stage in staged:
            shutil.rmtree(stage, ignore_errors=True)
    os.chmod(path, 0o600)
    fix_owner(path)
    size = path.stat().st_size / 2**20
    print(f"[OK] {rel(path)} ({size:.1f} MiB): {', '.join(manifest['parts'])}"
          + (", 機器台帳" if manifest["inventory"] else "") + (", 通知先" if manifest["receivers"] else "") + (", .env (秘密値を含む。取り扱い注意)" if manifest["include_env"] else ", .env は含めていません"))
    return 0


def running_services():
    return [n for n, port in (("prometheus", 9090), ("loki", 3100), ("alertmanager", 9093), ("authelia", 9091),
                              ("proxy", 80))
            if probe(f"tcp://{n}:{port}")[0]]


def extract_part(tar, members, prefix, dest):
    for m in members:
        if m.name == prefix or not m.name.startswith(prefix + "/"):
            continue
        m.name = m.name[len(prefix) + 1:]
        tar.extract(m, dest, filter="data")


def chown_tree(root, uid, gid):
    os.chown(root, uid, gid)
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            each(os.chown, os.path.join(dirpath, n), uid, gid, follow_symlinks=False)


def each(fn, *args, **kw):
    """Per entry of a live tree (ring rotation, uploads, prune): an entry that vanished or changed meanwhile is skipped."""
    try:
        fn(*args, **kw)
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        pass


def reader_modes(root):
    """Capture / upload trees: directories 0755, files 0644 (flowd, the analyzer and mask-api read them as other users)."""
    each(os.chmod, root, 0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames:
            each(os.chmod, os.path.join(dirpath, n), 0o755, follow_symlinks=False)
        for n in filenames:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                each(os.chmod, p, 0o644)


def fix_capture_volumes():
    """Every start (setup-check) and tools init: a volume first mounted by a tools container is root-owned, so mask-api
    (nobody) could not write uploads; restored / staged trees may carry owner-only modes the readers cannot traverse.
    Never fails the start: entries that vanish meanwhile are skipped, any other error is reported and ignored."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        if UPLOADS_VOL.is_dir():
            chown_tree(UPLOADS_VOL, *VOLUMES["uploads"])
            reader_modes(UPLOADS_VOL)
        if CAPTURE_VOL.is_dir():
            reader_modes(CAPTURE_VOL)
    except OSError as e:
        print(f"[注意] キャプチャ / アップロードのボリュームの所有者・権限を直せませんでした: {e}", file=sys.stderr)


def clear_dir(p):
    for child in p.iterdir():
        shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()


def check_manifest(manifest, members, with_config):
    """Reject an archive whose manifest points outside what restore may write. -> [(name, destination)] for config."""
    parts = manifest.get("parts")
    if not isinstance(parts, list) or not set(parts) <= set(VOLUMES):
        raise Fail(f"manifest の parts が不正です: {parts!r}")
    names = {m.name for m in members}
    for part in parts:  # the archive must be complete before any volume is cleared
        files = [m for m in members if m.isfile() and m.name.startswith(part + "/")]
        want = (manifest.get("contents") or {}).get(part)
        if not files:
            raise Fail(f"アーカイブの {part} が空です。途中で切れたバックアップかもしれません (何も消していません)")
        if want is not None and (len(files), sum(m.size for m in files)) != (want.get("files"), want.get("bytes")):
            raise Fail(f"アーカイブの {part} が manifest と合いません ({len(files)} ファイル / {sum(m.size for m in files)} バイト、"
                       f"記録は {want.get('files')} / {want.get('bytes')})。途中で切れたか壊れています (何も消していません)")
    out = []
    for key, what, dirs in (("inventory", "機器台帳", ("inventory", "testbed")), ("receivers", "通知先", ("alerting", "testbed"))):
        given = manifest.get(key)
        if given is None:
            continue
        rp = Path(str(given))
        dst = (CONFIG / rp).resolve()
        if (rp.is_absolute() or ".." in rp.parts or rp.suffix not in (".yaml", ".yml")
                or not any(dst.is_relative_to((CONFIG / d).resolve()) for d in dirs)):
            raise Fail(f"manifest の{what}のパスが不正です ({' か '.join(d + '/' for d in dirs)} の .yaml のみ): {given!r}")
        out.append((str(rp), dst))
    if manifest.get("include_env"):
        out.append((".env", ENV_FILE))
    for name, _ in out:
        if "config/" + name not in names:
            raise Fail(f"アーカイブに config/{name} がありません")
    return out if with_config else []


def cmd_restore(args):
    path = (CONFIG / args.archive) if not Path(args.archive).is_absolute() else Path(args.archive)
    if not path.exists():
        raise Fail(f"アーカイブがありません: {args.archive}")
    busy = running_services()
    if busy:
        raise Fail(f"{', '.join(busy)} が動いています。先に止めてください: docker compose stop prometheus loki alertmanager authelia proxy")
    with tarfile.open(path, "r:gz") as tar:
        members = tar.getmembers()
        try:
            manifest = json.load(tar.extractfile("manifest.json"))
        except KeyError:
            raise Fail("manifest.json がありません。tools backup で作ったアーカイブではありません") from None
        config = check_manifest(manifest, members, args.with_config)
        if {"capture", "uploads"} & set(manifest["parts"]):  # their writers / readers must be stopped too
            using = [n for n, port in (("mask-api", 8000), ("flowd", 9100), ("flowd-demo", 9100)) if probe(f"tcp://{n}:{port}")[0]]
            if cap.capture_status(CAPTURE_VOL)["state"] == "running":
                using.append("capture")
            if using:
                raise Fail(f"キャプチャ / アップロードを戻すには {', '.join(using)} も止めてください: "
                           "docker compose stop capture flowd flowd-demo mask-api (何も消していません)")
        if not args.yes:
            if not sys.stdin.isatty():
                raise Fail("確認できません (TTY なし)。--yes を付けてください")
            if input(f"{', '.join(manifest['parts'])} の現在のデータを消して {path.name} の内容に置き換えます。続けますか? [y/N]: ").lower() != "y":
                print("中止しました")
                return 1
        for comp in manifest["parts"]:
            dest = VOL / comp
            uid, gid = VOLUMES[comp]
            clear_dir(dest)
            extract_part(tar, members, comp, dest)
            chown_tree(dest, uid, gid)
            if comp in ("capture", "uploads"):
                reader_modes(dest)
            print(f"[OK] {comp} を戻しました")
        if args.with_config:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            for name, dst in config:
                bak = dst.with_name(f"{dst.name}.bak-{stamp}")
                if dst.exists():
                    shutil.copy2(dst, bak)
                    fix_owner(bak)
                dst.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile("config/" + name) as f:
                    write_atomic(dst, f.read().decode("utf-8"), mode=0o600 if name == ".env" else 0o644)
                fix_owner(dst, dst.parent)  # a directory created here (inventory/ on a new host) too, not root's
                print(f"[OK] {name} を戻しました (元のファイルは .bak-{stamp})")
    print("次: docker compose up -d   (台帳・通知先を戻したなら docker compose run --rm tools targets も)")
    return 0


# ---- login users (Authelia) -------------------------------------------------------------------------------

AUTHELIA_USERS = VOL / "authelia/users_database.yml"


def append_env(new):
    """Add secrets to .env (created from .env.example when there is none); existing lines are never touched."""
    if ENV_FILE.exists():
        text = ENV_FILE.read_text(encoding="utf-8")
        write_atomic(ENV_FILE, text + ("" if text.endswith("\n") else "\n") + "".join(f"{k}={v}\n" for k, v in new.items()), mode=0o600)
    else:
        write_atomic(ENV_FILE, render_env(new), mode=0o600)
    fix_owner(ENV_FILE)


def cmd_user(args):
    if args.action == "secrets":
        current = {k: env(k) for k in au.SECRETS}
        if ENV_FILE.exists():  # what .env says counts, not only what this container was started with
            for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
                k, sep, v = line.partition("=")
                if sep and k.strip() in au.SECRETS:
                    current[k.strip()] = v.strip().strip("'")
        new = au.missing_secrets(current)
        if not new:
            print("[OK] ログインの秘密値は .env に揃っています (変えません)")
            return 0
        append_env(new)
        print(f"[OK] .env に書きました: {', '.join(new)} (権限 600。値は表示しません)。反映: docker compose up -d")
        return 0
    users = au.load_users(AUTHELIA_USERS)
    if args.action == "list":
        if not users:
            print("利用者はいません (docker compose run --rm tools user add <名前> --role admin)")
            return 0
        table(("利用者", "表示名", "役割", "状態"), [(n, u.get("displayname", ""), au.role_of(u), "無効" if u.get("disabled") else "有効")
                                                for n, u in sorted(users.items())])
        return 0
    if not args.name:
        raise Fail(f"tools user {args.action} <名前> のように利用者名を指定してください")
    if args.action == "add":
        users = au.add(users, args.name, args.role or "viewer", au.read_password(env("OBS_USER_PASSWORD"), args.name), args.display, args.email)
    elif args.action == "passwd":
        users = au.passwd(users, args.name, au.read_password(env("OBS_USER_PASSWORD"), args.name))
    elif args.action == "role":
        if not args.role:
            raise Fail("--role viewer / operator / admin を指定してください")
        users = au.passwd(users, args.name, None, role=args.role)
    elif args.action == "remove":
        users = au.remove(users, args.name)
    au.save_users(AUTHELIA_USERS, users)
    print(f"[OK] {args.action} {args.name}" + (f" (役割 {au.role_of(users[args.name])})" if args.name in users else "")
          + "。Authelia は変更をすぐ読み込みます (削除・役割の変更は次の操作から効きます)")
    return 0


# ---- packet capture / GeoIP ------------------------------------------------------------------------

CAPTURE_VOL = VOL / "capture"
# the operator's own console shows interface / filter / errors raw (enx<MAC> names, BPF addresses); the screens never do
RAW_NOTE = "[注意] インターフェース名・フィルタ・エラーは生の値です (MAC / IP を含むことがあります。共有するときは伏せてください。画面では伏せ字)"
UPLOADS_VOL = VOL / "uploads"
GEOIP_VOL = VOL / "geoip"


def cmd_capture_setup(args):
    """capture profile, at `up`: the profile and .env must agree (OBS_CAPTURE=1 makes the setup step scrape flowd and
    tell the screens that flows are configured), and an interface must be named."""
    if not capture_on():
        print("[NG] capture profile が有効ですが .env に OBS_CAPTURE=1 がありません。両方を設定してください "
              "(COMPOSE_PROFILES=prod,capture と OBS_CAPTURE=1、CAPTURE_IFACE=<LAN 側のインターフェース>)", file=sys.stderr)
        return 1
    if mode() != "prod":
        print("[NG] capture profile は prod と一緒に使います (COMPOSE_PROFILES=prod,capture)", file=sys.stderr)
        return 1
    if not env("CAPTURE_IFACE"):
        print("[NG] CAPTURE_IFACE (キャプチャするインターフェース名) を .env に設定してください", file=sys.stderr)
        return 1
    print(f"キャプチャ: {env('CAPTURE_IFACE')} (フィルタ {env('CAPTURE_BPF') or 'なし'})。flowd を scrape します")
    return 0


def cmd_capture(args):
    now = time.time()
    keep_h = float(env("CAPTURE_KEEP_HOURS", "24"))
    up_keep_h = float(env("PCAP_KEEP_HOURS", "24"))
    up_max = int(env("PCAP_UPLOADS_TOTAL_MB", "200")) * 2**20
    st = cap.capture_status(CAPTURE_VOL, now)
    ring = cap.capture_files(CAPTURE_VOL / "ring")
    ups = cap.capture_files(UPLOADS_VOL)
    current = st.get("current") if st["state"] == "running" else None
    if args.action == "status":
        print(f"キャプチャ: {dict(running='動作中', stopped='停止', none='未起動')[st['state']]}"
              + (f" ({st['age_s']} 秒前に更新)" if st["state"] != "none" else ""))
        if st["state"] != "none":
            table(("項目", "値"), [("インターフェース", st.get("iface") or "—"), ("BPF フィルタ", st.get("filter") or "(なし)"),
                                  ("snaplen", st.get("snaplen") or "—"), ("リング", f"{len(ring)} 本 / {sum(f[1] for f in ring) / 1e6:.1f} MB (上限 {(st.get('ring_limit_bytes') or 0) / 1e6:.0f} MB)"),
                                  ("受信", st.get("received", "—")), ("NIC の受信ドロップ (取込開始から)", st.get("nic_rx_dropped", "—")),
                                  ("dumpcap の欠落 (終了したセッションの合計)", st.get("dumpcap_dropped", "—")), ("エラー", st.get("error") or "なし")])
            print(RAW_NOTE)
        print(f"アップロード: {len(ups)} 件 / {sum(f[1] for f in ups) / 2**20:.1f} MiB (上限 {up_max / 2**20:.0f} MiB、{up_keep_h:g} 時間で削除)")
        return 0 if st["state"] != "stopped" or not capture_on() else 1
    if args.action == "list":
        rows = [("ring", n + (" (記録中)" if n == current else ""), f"{b / 1e6:.1f}", time.strftime("%m-%d %H:%M:%S", time.localtime(t))) for n, b, t in ring]
        rows += [("upload", n, f"{b / 1e6:.1f}", time.strftime("%m-%d %H:%M:%S", time.localtime(t))) for n, b, t in ups]
        table(("種類", "ファイル", "MB", "更新"), rows or [("—", "なし", "", "")])
        return 0
    keep = (args.keep_hours if args.keep_hours is not None else keep_h) * 3600
    gone_r = cap.prune_plan(ring, now, keep, current=current)
    gone_u = cap.prune_plan(ups, now, (args.keep_hours if args.keep_hours is not None else up_keep_h) * 3600, up_max)
    if args.dry_run:
        print("削除対象 (--dry-run):", ", ".join(gone_r + gone_u) or "なし")
        return 0
    print(f"[OK] リング {cap.prune(CAPTURE_VOL / 'ring', gone_r)} 本、アップロード {cap.prune(UPLOADS_VOL, gone_u)} 件を削除しました")
    return 0


def cmd_geoip(args):
    if args.action == "update":
        print(f"DB-IP Lite (City + ASN) を取得します ({cap.ATTRIBUTION}) ...", flush=True)
        ok, _ = cap.geoip_update(GEOIP_VOL, force=args.force)
        print("flowd は 1 分以内に新しい版を読み込みます" if ok else "一部取得できませんでした (ネットワーク / 月初めはまだ公開前のことがあります)")
        return 0 if ok else 1
    rows = cap.geoip_rows(GEOIP_VOL)
    table(("GeoIP", "版 (月)", "MiB", "経過日数", "状態"), [(a, b, c, "—" if d is None else d, e) for a, b, c, d, e in rows])
    print(f"({cap.ATTRIBUTION})")
    return 0 if all(r[3] is not None and r[3] <= cap.GEOIP_STALE_DAYS for r in rows) else 1


# ---- syslog regression test ---------------------------------------------------------------------

def load_fixtures():
    return [json.loads(l) for f in sorted(DRIVERS_DIR.glob("*/syslog.jsonl"))
            for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]


def send_tcp(host, port, msgs):
    with socket.create_connection((host, port), HTTP_TIMEOUT) as s:
        for m in msgs:
            b = m.encode()
            s.sendall(b"%d %s" % (len(b), b))  # RFC 6587 octet counting


def expected_line(f):
    """Message as stored for a sender outside the inventory: a header hostname ("host" in the fixture, "$sender" =
    none) is not the device's name, so it stays in front of the message."""
    return f["line"] if f["host"] == "$sender" else f"{f['host']} {f['line']}"


def cmd_test_syslog(args):
    fixtures = load_fixtures()
    run = f"{int(time.time())}-{os.getpid()}"
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.connect((args.host, args.port))
    me = udp.getsockname()[0]
    t0 = time.time_ns() - 5 * 10**9
    want = {}
    tcp_msgs = []
    for i, f in enumerate(fixtures):
        for proto in ("udp", "tcp"):
            tag = f" [obs-test {run}-{proto}-{i}]"
            want[tag.strip()] = (f, proto)
            if proto == "udp":
                udp.send((f["raw"] + tag).encode())
            else:
                tcp_msgs.append(f["raw"] + tag)
    send_tcp(args.host, args.port, tcp_msgs)
    got = {}
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline and len(got) < len(want):
        time.sleep(2)
        try:
            for stream, line in loki_lines('{job="syslog"} |= %s' % json.dumps(f"[obs-test {run}-"), t0, time.time_ns() + 10**9):
                m = re.search(r" (\[obs-test \S+\])$", line)
                if m:
                    got[m.group(1)] = (stream, line[:m.start()])
        except (OSError, ValueError, KeyError) as e:
            print(f"Loki 照会失敗: {e}")
    rows, rc = [], 0
    for tag, (f, proto) in want.items():
        exp_line = expected_line(f)
        if tag not in got:
            rows.append((f["id"], f["form"], proto, "NG", "Loki に届いていません"))
            rc = 1
            continue
        stream, line = got[tag]
        # the test sender is not in the inventory: host must be "unknown" whatever the header claims (no spoofing)
        diffs = [f"{k}={stream.get(k)!r} (期待 {v!r})" for k, v in (("host", "unknown"), ("src_ip", me), ("severity", f["severity"]),
                                                                    ("facility", f["facility"])) if stream.get(k) != v]
        if line != exp_line:
            diffs.append(f"line={line!r} (期待 {exp_line!r})")
        leaked = set(stream) & {"src_addr", "src_name", "hdr_host", "inv_host"}  # pipeline-internal labels
        if leaked:  # (Loki itself adds service_name / detected_level; those are not ours)
            diffs.append(f"内部ラベルが残っています {sorted(leaked)}")
        rc |= bool(diffs)
        rows.append((f["id"], f["form"], proto, "NG" if diffs else "OK", "; ".join(diffs) or exp_line[:48]))
    table(("fixture", "形式", "経路", "結果", "詳細"), rows)
    print(f"\n{sum(r[3] == 'OK' for r in rows)}/{len(rows)} OK (送信元 {me} → {args.host}:{args.port}, run {run})")
    return rc


# ---- self-test (image build) --------------------------------------------------------------------

def selftest():
    """Pure checks of validation and generation (reads snmp/auths.yml and .env.example from the repository):
    docker compose run --rm tools --selftest"""
    good = {"SNMP_V3_USER": "obs", "SNMP_V3_AUTH_PASS": "a" * 8, "SNMP_V3_PRIV_PASS": "p" * 8, "SNMP_V3_AUTH_PROTO": "SHA",
            "SNMP_V3_PRIV_PROTO": "AES", "OBS_BIND": "127.0.0.1", "SYSLOG_BIND": "127.0.0.1"}
    dev = [{"name": "rtx1300", "kind": "rtx", "address": "192.168.100.1", "snmp_auth": "yamaha_v3"},
           {"name": "wlx413", "kind": "wlx", "address": "testbed-wlx:1161", "snmp_auth": "yamaha_v3", "syslog": False}]
    errs, warns, rows = validate(good, dev)
    assert not errs and not warns and rows[1]["syslog"] is False, (errs, warns)
    a = render_auths(good)
    assert set(a) == {"yamaha_v3"} and a["yamaha_v3"]["auth_protocol"] == "SHA" and a["yamaha_v3"]["password"] == "${SNMP_V3_AUTH_PASS}"
    assert set(render_auths({**good, "SNMP_COMMUNITY": "c0mm"})) == {"yamaha_v3", "yamaha_v2c"}
    two = render_auths({**good, "SNMP_COMMUNITY": "c0mm: #x'"})  # snmp_exporter does not expand community: literal value
    assert two["yamaha_v2c"]["community"] == "c0mm: #x'" and two["yamaha_v3"]["password"] == "${SNMP_V3_AUTH_PASS}"
    dumped = yaml.safe_dump({"auths": two})
    assert yaml.safe_load(dumped)["auths"]["yamaha_v2c"]["community"] == "c0mm: #x'"  # survives YAML quoting
    assert "a" * 8 not in dumped and "p" * 8 not in dumped, "v3 secrets stay references"
    bad = [{"name": "RTX!", "kind": "router", "address": "999.1.1.1:99999", "snmp_auth": "nope", "colour": 1}, dev[0], dev[0]]
    errs = check_devices(bad, {"yamaha_v3"})
    assert len(errs) >= 6 and any("重複" in e for e in errs) and any("address" in e for e in errs[:5]), errs
    errs, warns, rows_bad = validate({**good, "OBS_BIND": "0.0.0.0", "SYSLOG_BIND": "0.0.0.0", "SYSLOG_PORT": "70000"}, bad)  # device and env problems together
    assert rows_bad is None and any("ポート" in e for e in errs) and any("name" in e for e in errs) and warns, (errs, warns)
    errs, warns, _ = validate({**good, "SNMP_V3_AUTH_PASS": "short", "OBS_BIND": "0.0.0.0", "OBS_PORT": "0"}, dev)
    assert any("8 文字" in e for e in errs) and any("ポート" in e for e in errs), errs
    assert check_env({**good, "SYSLOG_BIND": "0.0.0.0"})[1] and check_env({**good, "OBS_BIND": "lan"})[0]
    sec = au.missing_secrets({})  # P7: a LAN exposure needs the login secrets (tools init / tools user secrets)
    assert any("tools user secrets" in e for e in check_env({**good, "OBS_BIND": "192.168.100.10"})[0])
    # 0.0.0.0 needs a LAN name in OBS_PUBLIC_URL: the proxy answers no other LAN host (421)
    assert any("421" in e for e in check_env({**good, "OBS_BIND": "0.0.0.0"})[0])
    assert any("421" in e for e in check_env({**good, "OBS_BIND": "0.0.0.0", "OBS_PUBLIC_URL": "http://127.0.0.1:8080"})[0])
    assert not check_env({**good, **sec, "OBS_BIND": "0.0.0.0", "OBS_PUBLIC_URL": "https://obs.lan:8080"})[0]
    assert any("cookie" in e for e in check_env({**good, **sec, "OBS_BIND": "0.0.0.0", "OBS_PUBLIC_URL": "https://[fd00::10]:8080"})[0])  # no login cookie on an IPv6 literal
    assert not check_env({**good, "OBS_PUBLIC_URL": "http://[fd00::10]:8080"})[0]  # (accepted without authentication)
    assert check_env({**good, "OBS_PUBLIC_URL": "http://[fd00::10/x"})[0]
    assert check_env({**good, "SNMP_V3_PRIV_PASS": "it's"})[0]
    lan = {**good, **sec, "OBS_BIND": "192.168.100.10", "OBS_PUBLIC_URL": "https://192.168.100.10:8080"}
    assert check_env(lan) == ([], []), check_env(lan)
    assert any("https" in w for w in check_env({**lan, "OBS_PUBLIC_URL": "http://192.168.100.10:8080"})[1])
    errs, _, _ = validate({**good, "SNMP_V3_USER": ""}, dev)  # v3 auth dropped -> reported as missing credentials
    assert errs, errs
    snmp, flows = file_sd(rows, demo=False, values={})
    assert snmp[0] == {"targets": ["192.168.100.1"], "labels": {"__device": "rtx1300", "__exporter": "snmp-exporter:9116",
                                                                "__param_module": "if_mib,system", "__param_auth": "yamaha_v3"}} and flows == []
    assert file_sd(rows, demo=False, values={"OBS_CAPTURE": "1"})[1] == [{"targets": ["flowd:9100"], "labels": {"__metrics_path__": "/metrics"}}]
    assert file_sd([], demo=True, values={})[1][0]["targets"] == ["flowd-demo:9100"]
    assert file_sd([], demo=True, values={"DEMO_PCAP_REPLAY": "0"})[1] == [{"targets": ["demo-gen:9116"]}]
    assert flow_hosts(rows, demo=False) == {"192.168.100.1": "rtx1300"} and flow_hosts([], demo=True) == {"192.168.100.1": "rtx1300"}
    assert [t["targets"] for t in file_sd([], demo=True)[0]] == [["rtx1300"], ["wlx413"], ["wlx222"]]
    hm = hostmap(rows)
    assert '"192\\\\.168\\\\.100\\\\.1"' in hm and '"testbed\\\\-wlx(\\\\..*)?"' in hm and hm.count("rule {") == 2, hm
    assert hostmap([]).count("rule {") == 0 and '"[^;]*demo-gen[^;]*;(rtx1300|wlx413|wlx222)"' in hostmap([], demo=True)
    assert ui_config(rows, demo=False, values={}) == {"profile": "prod", "flows_configured": False, "flow_source": None, "wan": None,
                                                      "bind": env("OBS_BIND", "127.0.0.1"), "links": [],
                                                      "surge": {"factor": 3.0, "min_kbps": 200, "baseline": "1h"},
                                                      "devices": [{"name": "rtx1300", "kind": "rtx", "wireless": False},
                                                                  {"name": "wlx413", "kind": "wlx", "wireless": True}]}
    # P5 network map: optional parent / parent_if / uplink_if; parents must exist, no loops
    trows = validate(good, [{**dev[0], "wan_interface": "lan2"}, {**dev[1], "parent": "rtx1300", "parent_if": "lan1", "uplink_if": "lan1"}])[2]
    assert topology_links(trows, demo=False) == [{"device": "wlx413", "parent": "rtx1300", "parent_if": "lan1", "uplink_if": "lan1"}]
    assert ui_config(trows, demo=False, values={})["links"][0]["parent"] == "rtx1300" and ui_config([], demo=True)["links"] == [
        {"device": "wlx413", "parent": "rtx1300", "parent_if": "lan1", "uplink_if": "lan1"},
        {"device": "wlx222", "parent": "rtx1300", "parent_if": "lan1", "uplink_if": "lan1"}]
    terrs = check_devices([{**dev[0], "parent": "wlx413"}, {**dev[1], "parent": "rtx1300"}], {"yamaha_v3"})
    assert any("ループ" in e for e in terrs), terrs
    terrs = check_devices([{**dev[0], "parent": "rtx1300", "parent_if": "ge0.1"}, {**dev[1], "parent_if": "lan1"}], {"yamaha_v3"})
    assert any("別の機器" in e for e in terrs) and any("ifName" in e for e in terrs) and any("一緒に" in e for e in terrs), terrs
    # P5 surges: thresholds from .env into the recording rules; invalid values refused by check_env
    s = surge_settings({"SURGE_FACTOR": "4", "SURGE_MIN_KBPS": "50", "SURGE_BASELINE": "1d"})
    assert s == {"factor": 4.0, "min_kbps": 50, "baseline": "1d"} and surge_settings({"SURGE_BASELINE": "30m"})["baseline"] == "1h"
    srec = {r["record"]: r["expr"] for g in surge_rules(s)["groups"] for r in g["rules"]}
    assert srec["obs_surge:flow_bps:baseline"] == ("quantile_over_time(0.5, obs_surge:flow_bps:rate5m[1d] offset 5m)"
                                                   " and count_over_time(obs_surge:flow_bps:rate5m[1d] offset 5m) >= 10"), srec
    assert srec["obs_surge:flow_bps:ratio"].startswith("(obs_surge:flow_bps:rate5m >= 50000) / on (src_host, dst_country, asn)") and srec["obs_surge:flow_bps:ratio"].endswith("> 4"), srec
    assert surge_rules(s)["groups"][1]["interval"] == "5m"
    for bad_s in ({"SURGE_FACTOR": "1"}, {"SURGE_FACTOR": "x"}, {"SURGE_MIN_KBPS": "0"}, {"SURGE_BASELINE": "2d"}, {"SURGE_BASELINE": "90m"}):
        assert check_env({**good, **bad_s})[0], bad_s
    assert not check_env({**good, "SURGE_FACTOR": "2.5", "SURGE_MIN_KBPS": "100", "SURGE_BASELINE": "6h"})[0]
    # the LLDP module (snmp/lldp.yml) is a valid snmp_exporter module of the read-only LLDP-MIB tables
    lldp = yaml.safe_load((WORK / "snmp/lldp.yml").read_text(encoding="utf-8"))["modules"]["lldp"]
    assert all(w.startswith("1.0.8802.1.1.2.1.") for w in lldp["walk"]) and [m["name"] for m in lldp["metrics"]] == ["lldpRemSysName"]
    assert ui_config(rows, demo=False, values={"OBS_CAPTURE": "1"})["flows_configured"] is True
    assert ui_config([], demo=True, values={})["flow_source"] == "pcap-replay"
    assert ui_config([], demo=True)["wan"] == {"device": "rtx1300", "ifName": "lan2"} and wan_rules(None) == {"groups": []}
    wrows = validate(good, [{**dev[0], "wan_interface": "lan2"}, dev[1]])[2]
    assert wan_of(wrows, demo=False) == {"device": "rtx1300", "ifName": "lan2"}
    wrules = wan_rules(wan_of(wrows, demo=False))["groups"][0]["rules"]
    rule = next(r for r in wrules if r.get("alert") == "WanHighUtilization")
    assert 'ifHighSpeed{job="snmp",instance="rtx1300",ifName="lan2"}' in rule["expr"] and rule["annotations"]["summary"].startswith("WAN (rtx1300 lan2)")
    assert rule["annotations"]["summary_ja"].startswith("WAN (rtx1300 lan2) の下り使用率") and rule["annotations"]["value"]
    assert not [r for r in wrules if "record" in r]
    notify.selftest(good)
    cap.selftest()
    au.selftest()
    each(os.chmod, "/nonexistent/obs-selftest", 0o644)  # a vanished entry never fails setup-check
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "ring").mkdir(mode=0o700)
        Path(tmp, "ring", "a.pcapng").write_bytes(b"x")
        os.chmod(Path(tmp, "ring", "a.pcapng"), 0o600)
        reader_modes(tmp)
        assert Path(tmp, "ring").stat().st_mode & 0o777 == 0o755 and Path(tmp, "ring", "a.pcapng").stat().st_mode & 0o777 == 0o644
    assert check_env({**good, "SLACK_WEBHOOK_URL": "https://x/'"})[0]  # quoting rules cover the notification secrets too
    werrs = check_devices([{**dev[0], "wan_interface": "ge0.1"}, {**dev[1], "wan_interface": "lan1"}], {"yamaha_v3"})
    assert any("ifName" in e for e in werrs) and any("1 台だけ" in e for e in werrs), werrs
    assert ui_config([], demo=True)["devices"][2] == {"name": "wlx222", "kind": "wlx", "wireless": True} and ui_config([], demo=True)["flows_configured"]
    e = render_env({"OBS_BIND": "0.0.0.0", "SNMP_V3_AUTH_PASS": "pa$$ word", "COMPOSE_PROFILES": "prod", "NEW_KEY": "1"})
    assert "OBS_BIND=0.0.0.0\n" in e and "SNMP_V3_AUTH_PASS='pa$$ word'\n" in e and "COMPOSE_PROFILES=prod\n" in e and e.endswith("NEW_KEY=1\n")
    assert width("機器a") == 5 and split_address("h:1161") == ("h", "1161") and split_address("10.0.0.1") == ("10.0.0.1", None)
    assert snmp_error("error walking target x: request timeout (after 3 retries)").startswith("応答なし")
    assert any("予約語" in e for e in check_devices([{**dev[0], "name": "unknown"}], {"yamaha_v3"}))
    assert public_url("127.0.0.1", "8080") == "http://127.0.0.1:8080" and public_url("192.168.100.10", "8080") == "http://192.168.100.10:8080"
    assert public_url("0.0.0.0", "8080") is None and public_url("0.0.0.0", "80", "http://obs.lan/") == "http://obs.lan"
    assert public_url("192.168.100.10", "8080", secure=True) == "https://192.168.100.10:8080"
    assert check_env({**good, "OBS_PUBLIC_URL": "http://x/path"})[0] and not check_env({**good, "OBS_PUBLIC_URL": "https://obs.lan:8443"})[0]
    assert any("OBS_PUBLIC_URL" in w for w in check_env({**good, "OBS_BIND": "192.168.100.10", "OBS_PUBLIC_URL": "http://127.0.0.1:8080"})[1])
    assert on_lan({"OBS_BIND": "0.0.0.0"}) and not on_lan({"OBS_BIND": "127.0.0.1"}) and not on_lan({})
    # restore: the manifest may only name volumes and an inventory under inventory/ or testbed/
    mem = lambda *names: [types.SimpleNamespace(name=n, size=1, isfile=lambda: True) for n in names + ("loki/chunk",)]
    good_m = {"parts": ["loki"], "inventory": "inventory/devices.yaml", "include_env": True}
    assert check_manifest(good_m, mem("config/inventory/devices.yaml", "config/.env"), True) == [
        ("inventory/devices.yaml", (CONFIG / "inventory/devices.yaml").resolve()), (".env", ENV_FILE)]
    for bad_inv in ("../generated/alloy/hostmap.alloy", "/generated/alloy/hostmap.alloy", "inventory/../compose.yaml",
                    "snmp/auths.yml", "inventory/x.alloy"):
        try:
            check_manifest({**good_m, "inventory": bad_inv}, mem("config/" + bad_inv.lstrip("/"), "config/.env"), True)
            raise AssertionError(bad_inv)
        except Fail:
            pass
    for bad in ({**good_m, "parts": ["etc"]}, {**good_m, "parts": "loki"}):
        try:
            check_manifest(bad, mem("config/inventory/devices.yaml", "config/.env"), True)
            raise AssertionError(bad)
        except Fail:
            pass
    assert check_manifest(good_m, mem("config/inventory/devices.yaml", "config/.env"), False) == []
    assert check_manifest({"parts": ["capture", "uploads"], "contents": {}}, mem("capture/ring/a.pcapng", "uploads/u.pcap"), False) == []
    # backup: written to .partial, moved into place only when complete; restore checks completeness first
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp, "loki")
        (src / "chunks").mkdir(parents=True)
        for i in range(3):
            (src / "chunks" / f"c{i}").write_bytes(b"x" * (10 + i))
        out = Path(tmp, "obs-backup-test.tar.gz")
        m = write_archive(out, {"format": 2}, [("loki", "loki", src, None)], tmp)
        assert out.exists() and not Path(f"{out}.partial").exists() and m["contents"] == {"loki": {"files": 3, "bytes": 33}}
        with tarfile.open(out) as tar:
            members = tar.getmembers()
            mf = json.load(tar.extractfile("manifest.json"))
        assert members[-1].name == "manifest.json" and mf["parts"] == ["loki"] and check_manifest(mf, members, False) == []
        cut = [x for x in members if not x.name.endswith("c2")]  # a member missing: refused before anything is cleared
        try:
            check_manifest(mf, cut, False)
            raise AssertionError("cut archive accepted")
        except Fail:
            pass
        try:
            check_manifest({**mf, "contents": {}}, [x for x in members if not x.name.startswith("loki/")], False)
            raise AssertionError("empty part accepted")
        except Fail:
            pass

        def vanish(ti):  # a source file disappearing mid-copy
            if ti.name.endswith("c1"):
                raise FileNotFoundError(ti.name)
            return ti
        failed = Path(tmp, "obs-backup-fail.tar.gz")
        try:
            write_archive(failed, {"format": 2}, [("loki", "loki", src, vanish)], tmp)
            raise AssertionError("failure not raised")
        except FileNotFoundError:
            pass
        assert not failed.exists() and not Path(f"{failed}.partial").exists(), "no archive (and no partial) after a failure"
    # syslog: a header hostname that is not the device's name stays in the message
    assert expected_line({"host": "nas01", "line": "sshd: x"}) == "nas01 sshd: x" and expected_line({"host": "$sender", "line": "a"}) == "a"
    # docs: the README's non-interactive init example passes every value init requires (review S2)
    readme = (WORK / "README.md").read_text(encoding="utf-8")
    example = readme[readme.index("tools init --yes") - 200:readme.index("tools init --yes") + 300]
    for var in ("SNMP_V3_AUTH_PASS", "SNMP_V3_PRIV_PASS"):
        assert f"-e {var}=" in example, var
    # doctor (H1): assessments, .env parsing, the ports this stack publishes
    dr.selftest()
    with tempfile.TemporaryDirectory() as tmp:
        ef = Path(tmp) / ".env"
        ef.write_text("# c\nOBS_PORT=8443 # https\nSMTP_PASSWORD='a b#c' # pw\nlower=x\nSYSLOG_PORT=\n"
                      "export PROM_LOCAL_PORT=19090\n  export   PROM_MEM = 512m\nOBS_PUBLIC_URL=https://h#x\n"
                      'SMTP_FROM="a \\"b\\" # c" # d\n', encoding="utf-8")
        want = {"OBS_PORT": "8443", "SMTP_PASSWORD": "a b#c", "SYSLOG_PORT": "", "PROM_LOCAL_PORT": "19090",
                "PROM_MEM": "512m", "OBS_PUBLIC_URL": "https://h#x", "SMTP_FROM": 'a "b" # c'}
        assert read_env_file(ef) == want, read_env_file(ef)
    # R1 drivers: the inventory kind picks the driver (drivers/*/driver.yaml); the demo devices are the drivers' demo.json
    assert {"rtx", "wlx", "other"} <= set(kinds()) and kinds()[-1] == "other" and snmp_modules("rtx") == snmp_modules("other") == "if_mib,system", kinds()
    assert demo_names() == ("rtx1300", "wlx413", "wlx222") and demo_wan() == {"device": "rtx1300", "ifName": "lan2"}
    assert [t["labels"]["__device"] for t in lldp_sd(snmp, rows, demo=False)] == ["rtx1300", "wlx413"]
    assert len(lldp_sd(file_sd([], demo=True)[0], [], demo=True)) == 3 and auth_versions() == {"yamaha_v3": 3, "yamaha_v2c": 2}
    fx = load_fixtures()
    assert len(fx) == 17 and len({f["id"] for f in fx}) == 17 and {f["model"] for f in fx} == {"rtx", "wlx", "other"}
    # R1 config layout: what migrate-config copies (relative paths kept), pinning never rewrites a line
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp, "repo"), Path(tmp, "cfg")
        for rp in (".env", "inventory/devices.yaml", "backups/obs-backup-1.tar.gz", "testbed/devices.yaml"):
            Path(src, rp).parent.mkdir(parents=True, exist_ok=True)
            Path(src, rp).write_text("x\n", encoding="utf-8")
        plan = migration_plan({"OBS_INVENTORY": "inventory/devices.yaml", "OBS_RECEIVERS": "../x.yaml"}, src, dst)
        assert [(str(a.relative_to(src)), str(b.relative_to(dst))) for a, b in plan] == [
            (".env", ".env"), (str(Path("inventory/devices.yaml")),) * 2, (str(Path("backups/obs-backup-1.tar.gz")),) * 2], plan
        ef = Path(src, ".env")
        ef.write_text("COMPOSE_PROJECT_NAME=old\nA=1", encoding="utf-8")
        assert pin_env(ef, {"COMPOSE_PROJECT_NAME": "new", "OBS_CONFIG_DIR": "/etc/geofront"}) == ["OBS_CONFIG_DIR"]
        assert ef.read_text(encoding="utf-8") == "COMPOSE_PROJECT_NAME=old\nA=1\nOBS_CONFIG_DIR=/etc/geofront\n"
    assert env_file_values({"SMTP_PASSWORD": "s3cret", "OBS_PORT": "8080"}, {"SMTP_PASSWORD_FILE": "/run/pw"},
                           frozenset({"SMTP_PASSWORD"})) == {"OBS_PORT": "8080", "SMTP_PASSWORD_FILE": "/run/pw"}
    pp = published_ports({"OBS_BIND": "192.0.2.10", "OBS_PORT": "443", "SYSLOG_BIND": "0.0.0.0"}, demo=False)
    assert ("tcp", "192.0.2.10", 443) in pp and ("udp", "0.0.0.0", 514) in pp and ("tcp", "127.0.0.1", 9116) not in pp, pp
    print("selftest ok")


# ---- CLI ----------------------------------------------------------------------------------------

def parser():
    p = argparse.ArgumentParser(prog="tools", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    i = sub.add_parser("init", help=".env と機器台帳を作る (対話 / --yes で引数のみ)")
    i.add_argument("--yes", action="store_true", help="対話せず引数・環境変数と既定値で作る")
    i.add_argument("--force", action="store_true", help="既存の .env / 台帳を作り直す (.bak に退避)")
    i.add_argument("--device", action="append", default=[], metavar="名前,種別,アドレス[,auth]", help="機器 (複数回可)")
    i.add_argument("--bind", default="127.0.0.1", help="画面の公開アドレス (既定 127.0.0.1)")
    i.add_argument("--port", default="8080")
    i.add_argument("--public-url", default="", help="LAN から開く URL (既定: --bind と --port から。0.0.0.0 のときは必須)")
    i.add_argument("--syslog-bind", default="127.0.0.1", help="syslog 受信アドレス (機器から受けるなら LAN 側 IP)")
    i.add_argument("--syslog-port", default="514")
    i.add_argument("--snmp-user", default="")
    i.add_argument("--snmp-auth-proto", default="SHA", choices=AUTH_PROTOS)
    i.add_argument("--snmp-priv-proto", default="AES", choices=PRIV_PROTOS)
    i.add_argument("--wan", default="", metavar="機器名:ifName", help="WAN 側インターフェース (例 rtx1300:lan2)")
    i.add_argument("--auth", action="store_true", help="127.0.0.1 公開でもログインを必須にする (OBS_AUTH=1。LAN 公開では常に必須)")
    i.epilog = "SNMP のパスワードは引数にせず -e SNMP_V3_AUTH_PASS=... -e SNMP_V3_PRIV_PASS=... (または対話) で渡します"
    c = sub.add_parser("check", help="検証・SNMP 疎通・syslog 受信・health")
    c.add_argument("--syslog-wait", type=int, default=60, metavar="秒", help="syslog の受信を待つ秒数 (0 で省略、既定 60)")
    t = sub.add_parser("targets", help="台帳から scrape 対象などを生成")
    t.add_argument("--demo", action="store_true", help="デモ用 (demo-gen) の対象を書く")
    b = sub.add_parser("backup", help="設定とデータを 1 つのアーカイブに")
    b.add_argument("--include-env", action="store_true", help=".env (秘密値) も含める")
    b.add_argument("--out", default="backups", help="出力先 (設定ディレクトリ OBS_CONFIG_DIR からの相対、既定 backups)")
    b.add_argument("--include-captures", action="store_true", help="キャプチャのリングとアップロードした pcap も含める (既定は含めない)")
    r = sub.add_parser("restore", help="アーカイブを戻す (prometheus / loki / alertmanager / authelia / proxy、キャプチャを含むなら capture / flowd / mask-api も停止しておく)")
    r.add_argument("archive")
    r.add_argument("--with-config", action="store_true", help="機器台帳・通知先 (と含まれていれば .env) も戻す")
    r.add_argument("--yes", action="store_true", help="確認せずに実行")
    sub.add_parser("setup-check", help="(起動時に自動) profile の設定が済んでいるか")
    n = sub.add_parser("notify-test", help="各通知先にテスト通知 (Alertmanager 経由) を送り、応答を表で出す")
    n.add_argument("--receiver", default="", metavar="名前", help="この通知先だけ (既定: すべて)")
    n.add_argument("--timeout", type=int, default=40, metavar="秒", help="結果を待つ秒数 (既定 40)")
    s = sub.add_parser("test-syslog", help="syslog 解析の回帰テスト (fixtures → Alloy → Loki)")
    s.add_argument("--host", default="alloy")
    s.add_argument("--port", type=int, default=514)
    s.add_argument("--timeout", type=int, default=30)
    cp = sub.add_parser("capture", help="パケット取込: status / list / prune (保存期間・合計容量を超えたものを削除)")
    cp.add_argument("action", choices=("status", "list", "prune"))
    cp.add_argument("--keep-hours", type=float, default=None, metavar="時間", help="prune: この時間より古いものを削除 (既定 CAPTURE_KEEP_HOURS / PCAP_KEEP_HOURS)")
    cp.add_argument("--dry-run", action="store_true", help="prune: 削除せずに対象だけ表示")
    gp = sub.add_parser("geoip", help="GeoIP (DB-IP Lite City + ASN, CC BY 4.0): update / status")
    gp.add_argument("action", choices=("update", "status"))
    gp.add_argument("--force", action="store_true", help="update: 最新でも取り直す")
    sub.add_parser("capture-setup", help="(capture profile の起動時に自動) .env と profile の整合確認")
    u = sub.add_parser("user", help="ログインの利用者 (Authelia): add / passwd / role / remove / list、秘密値: secrets")
    u.add_argument("action", choices=("add", "passwd", "role", "remove", "list", "secrets"))
    u.add_argument("name", nargs="?", default="")
    u.add_argument("--role", choices=au.ROLES, default=None, help="add (既定 viewer) / role: viewer・operator・admin")
    u.add_argument("--display", default="", help="add: 表示名 (既定は利用者名)")
    u.add_argument("--email", default="", help="add: メールアドレス (TOTP の登録に必要。送信はしない。既定は <名前>@users.obs.invalid)")
    u.epilog = "パスワードは対話で 2 回入力 (TTY なしなら -e OBS_USER_PASSWORD=...)。保存は argon2id のハッシュだけです"
    mc = sub.add_parser("migrate-config", help="従来の配置 (リポジトリ内) の設定を OBS_CONFIG_DIR へ写す (なければプロジェクト名を .env に固定)")
    mc.add_argument("--force", action="store_true", help="移す先にあるファイルを上書き (元は .bak に残す)")
    sub.add_parser("doctor", help="導入前の自己診断 (Docker・CPU・メモリ・ディスク・時刻・ポート・.env・利用者・証明書。ホストの項目は scripts/doctor.sh から)")
    sub.add_parser("help", help="この説明")
    return p


def main(argv):
    if "--selftest" in argv:
        selftest()
        return 0
    p = parser()
    args = p.parse_args(argv)
    cmds = {"init": cmd_init, "check": cmd_check, "targets": cmd_targets, "backup": cmd_backup,
            "setup-check": cmd_setup_check,
            "restore": cmd_restore, "test-syslog": cmd_test_syslog, "notify-test": cmd_notify_test,
            "capture": cmd_capture, "geoip": cmd_geoip, "capture-setup": cmd_capture_setup, "user": cmd_user, "doctor": cmd_doctor,
            "migrate-config": cmd_migrate_config}
    if args.cmd not in cmds:
        p.print_help()
        return 0
    try:
        return cmds[args.cmd](args)
    except (Fail, au.AuthError) as e:
        print(f"[NG] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n中止しました", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
