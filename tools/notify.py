"""Alert notification model of the tools: alerting/receivers.yaml + .env values -> a checked plan -> the Alertmanager
config (no secrets) and the notify-relay config (destinations with their secrets). Pure: no file, network or prompt
here; obs.py reads / writes the files and runs the commands (targets, check, notify-test, init).

Alertmanager routes by severity, repeats and silences; every receiver of it is a webhook to notify-relay, which sends
the Japanese, masked message to the real destination and records the answer.
"""
import json
import re
import urllib.parse

import yaml

RECEIVER_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")  # also the relay's /notify/<name> path rule
SMTP_HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
RECEIVER_TYPES = ("email", "slack", "discord", "line", "webhook")
SEVERITIES = ("critical", "warning", "info")
DEFAULT_REPEAT = {"critical": "1h", "warning": "4h", "info": "24h"}
DEFAULT_TIMING = {"group_wait": "30s", "group_interval": "5m"}
RESERVED_RECEIVERS = ("none", "demo-sink")
# .env variables of the notification secrets / SMTP server (one set per type; several e-mail / LINE receivers share it)
NOTIFY_ENV = ("SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "SMTP_USER", "SMTP_PASSWORD", "SMTP_TLS", "SMTP_TLS_VERIFY", "SLACK_WEBHOOK_URL",
              "DISCORD_WEBHOOK_URL", "LINE_CHANNEL_ACCESS_TOKEN", "LINE_API_URL", "WEBHOOK_URL", "WEBHOOK_BEARER_TOKEN")
URL_SECRETS = {"slack": "SLACK_WEBHOOK_URL", "discord": "DISCORD_WEBHOOK_URL", "webhook": "WEBHOOK_URL"}
LINE_API = "https://api.line.me/v2/bot/message/push"
LINE_TO_RE = re.compile(r"[UCR][0-9a-f]{32}")  # user / group / room ID
EMAIL_RE = re.compile(r"[^@\s,<>'\"]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*")
URL_RE = re.compile(r"https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^\s'\"<>]*)?")
DUR_RE = re.compile(r"(\d{1,6})([smhd])")
DUR_S = {"s": 1, "m": 60, "h": 3600, "d": 86400}
SMTP_PORTS = {"starttls": "587", "tls": "465", "none": "25"}
RELAY = "http://notify-relay:9095"
TEST_ALERT = "ObsNotifyTest"  # `tools notify-test` (notify-relay knows the name too)
RELAY_UID = (10095, 10095)  # notify-relay's own user (notify-relay/Dockerfile): only it can read relay.json
DEMO_PLAN = {"receivers": {"demo-sink": {"type": "sink"}}, "group_wait_s": 10, "group_interval_s": 60,
             "routes": {"critical": {"receivers": ["demo-sink"], "repeat_s": 600}, "warning": {"receivers": ["demo-sink"], "repeat_s": 1800},
                        "info": {"receivers": [], "repeat_s": 86400}}}


def duration_s(v):
    m = DUR_RE.fullmatch(str(v).strip())
    return int(m.group(1)) * DUR_S[m.group(2)] if m else None


def secret_url(values, key, where, errs, warns):
    v = values.get(key, "")
    if not v:
        errs.append(f"{where}: .env の {key} が空欄です")
    elif not URL_RE.fullmatch(v):
        errs.append(f"{where}: .env の {key} は http(s):// で開始する URL を指定してください")
    elif v.startswith("http://"):
        warns.append(f"{where}: {key} が http:// です (非暗号化通信。通常は https://)")
    return v


def smtp_settings(values, where, errs, warns):
    tls = values.get("SMTP_TLS") or "starttls"
    if tls not in SMTP_PORTS:
        errs.append(f"{where}: SMTP_TLS は starttls / tls / none のいずれかを指定してください")
        tls = "starttls"
    port = values.get("SMTP_PORT") or SMTP_PORTS[tls]
    host, frm, user, pw = (values.get(k, "") for k in ("SMTP_HOST", "SMTP_FROM", "SMTP_USER", "SMTP_PASSWORD"))
    if not SMTP_HOST_RE.fullmatch(host):
        errs.append(f"{where}: .env の SMTP_HOST (SMTP サーバーのホスト名) を設定してください")
    if not (port.isdigit() and 0 < int(port) < 65536):
        errs.append(f"{where}: SMTP_PORT={port}: 1〜65535 のポート番号を指定してください")
    if not EMAIL_RE.fullmatch(frm):
        errs.append(f"{where}: .env の SMTP_FROM (送信元メールアドレス) を設定してください")
    if bool(user) != bool(pw):
        errs.append(f"{where}: SMTP_USER と SMTP_PASSWORD は双方を設定、または双方を空欄にしてください")
    if tls == "none":
        warns.append(f"{where}: SMTP_TLS=none: メールは暗号化されずに送信されます" + (" (パスワードも同様)" if user else ""))
    verify = values.get("SMTP_TLS_VERIFY", "1") != "0"
    if not verify:
        warns.append(f"{where}: SMTP_TLS_VERIFY=0: SMTP サーバーの証明書を検証しません (testbed のモック用。本番環境では不使用)")
    return {"host": host, "port": int(port) if port.isdigit() else 0, "from": frm, "user": user, "password": pw, "tls": tls, "verify": verify}


def receiver_entry(r, values, errs, warns):
    """One receiver of receivers.yaml -> the relay's entry for it (with its secrets from .env)."""
    name, rtype = r["name"], r["type"]
    where = f"通知先 {name} ({rtype})"
    unknown = set(r) - {"name", "type"} - ({"to"} if rtype in ("email", "line") else set())
    if unknown:
        errs.append(f"{where}: 不明な項目 {', '.join(sorted(map(str, unknown)))}")
    if rtype == "email":
        to = [r["to"]] if isinstance(r.get("to"), str) else r.get("to")
        if not (isinstance(to, list) and 0 < len(to) <= 10 and all(isinstance(x, str) and EMAIL_RE.fullmatch(x) for x in to)):
            errs.append(f"{where}: to は送信先メールアドレス (1〜10 件) を指定してください")
        return {"type": "email", "to": to if isinstance(to, list) else [], "smtp": smtp_settings(values, where, errs, warns)}
    if rtype == "line":
        token, to = values.get("LINE_CHANNEL_ACCESS_TOKEN", ""), str(r.get("to", ""))
        if not token:
            errs.append(f"{where}: .env の LINE_CHANNEL_ACCESS_TOKEN (Messaging API のチャネルアクセストークン) が空欄です")
        if not LINE_TO_RE.fullmatch(to):
            errs.append(f"{where}: to は送信先のユーザー ID / グループ ID (U / C / R + 英数字 32 文字) を指定してください")
        api = values.get("LINE_API_URL") or LINE_API
        if not URL_RE.fullmatch(api):
            errs.append(f"{where}: LINE_API_URL は URL を指定してください (通常は空欄)")
        return {"type": "line", "to": to, "token": token, "api": api}
    entry = {"type": rtype, "url": secret_url(values, URL_SECRETS[rtype], where, errs, warns)}
    if rtype == "webhook" and values.get("WEBHOOK_BEARER_TOKEN"):
        entry["token"] = values["WEBHOOK_BEARER_TOKEN"]
    return entry


def check_timing(doc, errs):
    timing = doc.get("timing") or {}
    if not isinstance(timing, dict) or set(timing) - set(DEFAULT_TIMING):
        errs.append("timing: group_wait / group_interval のみを記述してください")
        timing = {}
    gw, gi = (duration_s(timing.get(k, DEFAULT_TIMING[k])) for k in ("group_wait", "group_interval"))
    if gw is None or gw > 600:
        errs.append("timing.group_wait は 0s〜10m (例 30s) で指定してください")
    if gi is None or not 10 <= gi <= 3600:
        errs.append("timing.group_interval は 10s〜1h (例 5m) で指定してください")
    return gw or 0, gi or 300


def check_routes(doc, names, gi, errs):
    routes_doc = doc.get("routes") or {}
    if not isinstance(routes_doc, dict) or set(routes_doc) - set(SEVERITIES):
        errs.append(f"routes: 重大度 ({' / '.join(SEVERITIES)}) 単位で記述してください")
        routes_doc = {}
    routes = {}
    for sev in SEVERITIES:
        rd = routes_doc.get(sev)
        if rd is None:  # default: critical / warning to every receiver, info to none
            rd = {"receivers": [] if sev == "info" else list(names)}
        if not isinstance(rd, dict) or set(rd) - {"receivers", "repeat"} or not isinstance(rd.get("receivers", []), list):
            errs.append(f"routes.{sev}: receivers: [名前, ...] と repeat: (再通知の間隔) のみを記述してください")
            rd = {}
        to = [str(n) for n in rd.get("receivers") or []]
        for n in sorted(set(to) - set(names)):
            errs.append(f"routes.{sev}: 通知先 {n} は receivers に未定義です")
        rs = duration_s(rd.get("repeat", DEFAULT_REPEAT[sev]))
        if rs is None or not 60 <= rs <= 7 * 86400:
            errs.append(f"routes.{sev}.repeat は 1m〜7d (例 1h) で指定してください")
        elif rs < gi:
            errs.append(f"routes.{sev}.repeat ({rd.get('repeat')}) は timing.group_interval 以上を指定してください")
        routes[sev] = {"receivers": list(dict.fromkeys(to)), "repeat_s": rs or 3600}
    return routes


def check_receivers(doc, values, where="alerting/receivers.yaml"):
    """receivers.yaml (parsed) + .env values -> (errors, warnings, plan or None). plan: receivers (relay entries),
    routes per severity (receiver names, repeat seconds), group_wait_s / group_interval_s."""
    errs, warns = [], []
    if doc is None:
        warns.append(f"通知先がありません ({where})。アラートは画面表示のみで、外部通知は未実施です"
                     " (例: config.example/alerting/receivers.example.yaml をコピーして編集)")
        doc = {}
    if not isinstance(doc, dict) or set(doc) - {"receivers", "routes", "timing"}:
        return ["通知先の設定は receivers: / routes: / timing: のみの構成にしてください"], warns, None
    receivers = {}
    rlist = doc.get("receivers") or []
    if not isinstance(rlist, list):
        return ["receivers: は一覧形式にしてください"], warns, None
    for i, r in enumerate(rlist, 1):
        name = str(r.get("name", "")).strip() if isinstance(r, dict) else ""
        where = f"通知先の {i} 件目 ({name or '名称なし'})"
        if not isinstance(r, dict) or r.get("type") not in RECEIVER_TYPES:
            errs.append(f"{where}: type は {' / '.join(RECEIVER_TYPES)} のいずれかを指定してください")
        elif not RECEIVER_NAME_RE.fullmatch(name) or name in RESERVED_RECEIVERS:
            errs.append(f"{where}: name は英小文字・数字・- _ による 1〜32 文字で指定してください ({' / '.join(RESERVED_RECEIVERS)} は予約語)")
        elif name in receivers:
            errs.append(f"{where}: name が重複しています")
        else:
            receivers[name] = receiver_entry({**r, "name": name}, values, errs, warns)
    gw, gi = check_timing(doc, errs)
    routes = check_routes(doc, list(receivers), gi, errs)
    used = {n for r in routes.values() for n in r["receivers"]}
    if receivers and not used:
        warns.append("全重大度で通知先が未割当です (routes)")
    for n in sorted(set(receivers) - used):
        warns.append(f"通知先 {n} は全重大度で未使用です (notify-test での送信は可能)")
    errs, warns = list(dict.fromkeys(errs)), list(dict.fromkeys(warns))
    return errs, warns, None if errs else {"receivers": receivers, "routes": routes, "group_wait_s": gw, "group_interval_s": gi}


def alertmanager_config(plan):
    """Alertmanager config (no secrets): a route per severity fanning out to its receivers, each receiver a webhook to
    notify-relay. Test alerts of `tools notify-test` go to the one receiver they name, straight away."""
    names = list(plan["receivers"])
    routes = [{"matchers": [f'obs_test_receiver="{n}"'], "receiver": n, "group_by": ["obs_test"], "group_wait": "0s",
               "group_interval": "10s", "repeat_interval": "7d"} for n in names]
    routes.append({"matchers": [f'alertname="{TEST_ALERT}"'], "receiver": "none"})  # a test naming no receiver of ours
    for sev in SEVERITIES:
        r = plan["routes"][sev]
        if r["receivers"]:
            routes.append({"matchers": [f'severity="{sev}"'], "receiver": "none", "repeat_interval": f"{r['repeat_s']}s",
                           "routes": [{"receiver": n, "continue": True} for n in r["receivers"]]})
    hook = lambda n: {"name": n, "webhook_configs": [{"url": f"{RELAY}/notify/{n}", "send_resolved": True, "max_alerts": 20}]}
    return {"route": {"receiver": "none", "group_by": ["alertname", "instance", "ifName"], "group_wait": f"{plan['group_wait_s']}s",
                      "group_interval": f"{plan['group_interval_s']}s", "repeat_interval": "24h", "routes": routes},
            "receivers": [{"name": "none"}] + [hook(n) for n in names]}


def relay_config(plan, public):
    """public: where the screens are opened (OBS_PUBLIC_URL), for the link in every message."""
    return {"public_url": public or "", "group_interval_s": plan["group_interval_s"],
            "receivers": plan["receivers"], "repeat": {s: plan["routes"][s]["repeat_s"] for s in SEVERITIES}}


def receiver_where(r):
    """Where a receiver sends, without secrets (for tables)."""
    if r["type"] == "email":
        return f"{len(r['to'])} 送信先 / {r['smtp']['host']}:{r['smtp']['port']} {r['smtp']['tls']}"
    if r["type"] == "line":
        return f"to {r['to'][:5]}…"
    if r["type"] == "sink":
        return "Loki に記録のみ (外部送信なし)"
    return urllib.parse.urlsplit(r.get("url", "")).netloc or "—"


def notify_summary(plan):
    route = lambda n: "/".join(s for s in SEVERITIES if n in plan["routes"][s]["receivers"]) or "(なし)"
    return [(n, r["type"], route(n), receiver_where(r)) for n, r in plan["receivers"].items()]


def render_receivers(doc):
    return ("# 通知先 (tools init が生成。手動編集も可。変更後は `docker compose run --rm tools targets`)\n"
            "# 秘密値 (Webhook URL・トークン・SMTP パスワード) は本ファイルに記述せず .env に配置。書式: config.example/alerting/receivers.example.yaml\n"
            + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))


def selftest(good):
    """receivers.yaml + .env -> Alertmanager / relay configs (pure)."""
    sec = {**good, "SMTP_HOST": "smtp.example.com", "SMTP_FROM": "obs@example.com", "SMTP_USER": "u", "SMTP_PASSWORD": "pw-secret",
           "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/slack-secret", "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/discord-secret",
           "LINE_CHANNEL_ACCESS_TOKEN": "line-secret", "WEBHOOK_URL": "https://hook.example.com/x?k=hook-secret", "WEBHOOK_BEARER_TOKEN": "bearer-secret",
           "OBS_PUBLIC_URL": "http://192.168.100.10:8080"}
    line_to = "U" + "0123456789abcdef" * 2
    doc = {"receivers": [{"name": "mail", "type": "email", "to": ["a@example.com", "b@example.com"]}, {"name": "slack", "type": "slack"},
                         {"name": "discord", "type": "discord"}, {"name": "line", "type": "line", "to": line_to}, {"name": "hook", "type": "webhook"}],
           "routes": {"critical": {"receivers": ["mail", "line", "hook"], "repeat": "30m"}, "warning": {"receivers": ["slack", "discord"]}},
           "timing": {"group_wait": "15s", "group_interval": "2m"}}
    errs, warns, plan = check_receivers(doc, sec)
    assert not errs and not warns, (errs, warns)
    assert plan["routes"]["critical"] == {"receivers": ["mail", "line", "hook"], "repeat_s": 1800}
    assert plan["routes"]["warning"]["repeat_s"] == 14400 and plan["routes"]["info"] == {"receivers": [], "repeat_s": 86400}  # info: none by default
    assert plan["receivers"]["mail"]["smtp"] == {"host": "smtp.example.com", "port": 587, "from": "obs@example.com", "user": "u",
                                                 "password": "pw-secret", "tls": "starttls", "verify": True}
    assert plan["receivers"]["line"] == {"type": "line", "to": line_to, "token": "line-secret", "api": LINE_API}
    assert plan["receivers"]["hook"]["token"] == "bearer-secret"
    am = alertmanager_config(plan)
    dumped = yaml.safe_dump(am)
    assert not any(x in dumped for x in ("secret", "hooks.slack.com", "discord.com")), "no secret in the Alertmanager config"
    by = {tuple(r["matchers"]): r for r in am["route"]["routes"]}
    crit = by[('severity="critical"',)]
    assert [c["receiver"] for c in crit["routes"]] == ["mail", "line", "hook"] and all(c["continue"] for c in crit["routes"])
    assert crit["repeat_interval"] == "1800s" and ('severity="info"',) not in by and by[('obs_test_receiver="slack"',)]["receiver"] == "slack"
    assert list(by)[-3:] == [('alertname="ObsNotifyTest"',), ('severity="critical"',), ('severity="warning"',)]  # tests first
    assert am["route"]["group_wait"] == "15s" and am["receivers"][0] == {"name": "none"}
    assert am["receivers"][1]["webhook_configs"] == [{"url": "http://notify-relay:9095/notify/mail", "send_resolved": True, "max_alerts": 20}]
    rc = relay_config(plan, "http://192.168.100.10:8080")
    assert rc["public_url"] == "http://192.168.100.10:8080" and rc["group_interval_s"] == 120 and rc["repeat"] == {"critical": 1800, "warning": 14400, "info": 86400}
    assert rc["receivers"]["slack"]["url"].endswith("slack-secret")
    assert [r[2] for r in notify_summary(plan)] == ["critical", "warning", "warning", "critical", "critical"]
    assert "secret" not in json.dumps(notify_summary(plan)), "tables never show secrets"
    # no receivers file: valid, nothing is sent (warned)
    errs, warns, empty = check_receivers(None, good)
    assert not errs and warns and empty["receivers"] == {} and not [r for r in alertmanager_config(empty)["route"]["routes"] if "severity" in str(r)]
    # each problem is reported, nothing is generated
    bad_doc = {"receivers": [{"name": "mail", "type": "email", "to": "not-an-address"}, {"name": "mail", "type": "slack"},
                             {"name": "none", "type": "discord"}, {"name": "x", "type": "pager"}, {"name": "line", "type": "line", "to": "someone"},
                             {"name": "s2", "type": "slack", "channel": "#x"}],
               "routes": {"critical": {"receivers": ["ghost"], "repeat": "10s"}, "urgent": {}}, "timing": {"group_interval": "1s"}}
    errs, _, plan = check_receivers(bad_doc, {**good, "SMTP_TLS": "ssl"})
    want = ["to は送信先メールアドレス", "name が重複", "予約語", "type は", "ユーザー ID", "不明な項目 channel", "routes: 重大度",
            "SMTP_HOST", "SMTP_FROM", "SMTP_TLS は", "LINE_CHANNEL_ACCESS_TOKEN", "SLACK_WEBHOOK_URL が空", "group_interval は"]
    assert plan is None and all(any(w in e for e in errs) for w in want), [w for w in want if not any(w in e for e in errs)]
    errs, _, _ = check_receivers({"receivers": [], "routes": {"critical": {"receivers": ["ghost"], "repeat": "10s"}}}, good)
    assert any("ghost" in e for e in errs) and any("repeat は 1m" in e for e in errs), errs
    errs, warns, _ = check_receivers({"receivers": [{"name": "m", "type": "email", "to": "a@example.com"}]},
                                     {**sec, "SMTP_TLS": "none", "SMTP_TLS_VERIFY": "0", "SMTP_PASSWORD": ""})
    assert any("SMTP_USER と SMTP_PASSWORD" in e for e in errs) and any("暗号化されず" in w for w in warns) and any("証明書" in w for w in warns)
    errs, warns, _ = check_receivers({"receivers": [{"name": "s", "type": "slack"}], "routes": {"warning": {"receivers": ["s"], "repeat": "1m"}}},
                                     {**sec, "SLACK_WEBHOOK_URL": "http://notifymock:8080/slack"})
    assert any("group_interval 以上" in e for e in errs) and any("http://" in w for w in warns), (errs, warns)
    assert duration_s("90s") == 90 and duration_s("7d") == 604800 and duration_s("1h30m") is None
    demo = alertmanager_config(DEMO_PLAN)
    assert demo["receivers"][1]["name"] == "demo-sink" and relay_config(DEMO_PLAN, "")["receivers"] == {"demo-sink": {"type": "sink"}}
