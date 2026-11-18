"""Notification relay: Alertmanager webhook -> e-mail / Slack / Discord / LINE / generic webhook (or the demo sink).

Alertmanager does the grouping, the routing by severity, the repeats, resolved notifications and silences; each of its
receivers posts to /notify/<receiver name> here. The relay turns a notification into one Japanese message (IPv4 / MAC
masked with the same rules as mask-api), sends it to that receiver's destination and records every attempt in Loki
({job="notify"}): that record is how the command-center shows 通知完了 and the next repeat time, and how
`tools notify-test` reads each destination's answer (HTTP status / SMTP reply).

Why not Alertmanager's own integrations: it has none for the LINE Messaging API, and its results (the HTTP / SMTP answer
per destination) are only in its log, which `tools` cannot read. Here one masking function covers every channel.

Address tokens (P6): a label value of a record (instance / ifName) that is exactly one IPv4 address is recorded as
mask-api shows it, a.b.c.x~<token>, with mask-api's own HMAC and key, so the screens and 原因候補 can match the record to
the same device. The key is mask-api's per-process key, shared through the memory-only token-key volume (mask-api writes
it, this relay only reads it); no key (not there yet, unreadable) -> a.b.c.x as before (fail closed). The messages sent
to the destinations are not affected (masked as before, no tokens).

Secrets: only in the generated config (/etc/obs-generated/notify/relay.json, mode 0600, written by `tools targets`
from .env). Nothing secret is logged: log lines name the receiver and the answer, never a URL or a token.

ACK reaper: an ACK from the command-center is an Alertmanager silence (createdBy command-center, comment "ACK...");
once none of the alerts it matches is active any more, the relay expires it, so an ACK lasts "until resolved" (and at
most until its end time).

Run: python relay.py            (listens on :9095, internal network only)
     python relay.py --selftest
"""
import contextlib
import email.policy
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import smtplib
import ssl
import sys
import threading
import time
import types
import urllib.error
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG = Path(os.environ.get("RELAY_CONFIG", "/etc/obs-generated/notify/relay.json"))
LOKI = os.environ.get("LOKI_URL", "http://loki:3100")
ALERTMANAGER = os.environ.get("ALERTMANAGER_URL", "http://alertmanager:9093")
PORT = 9095
SEND_TIMEOUT = 10
MAX_BODY = 1 << 20
JST = timezone(timedelta(hours=9), "JST")  # Japan has no daylight saving time
TEXT_LIMIT = {"slack": 3500, "discord": 2000, "line": 5000}  # per-message limits of the services (characters)
TEST_ALERT = "ObsNotifyTest"  # `tools notify-test`
LINK_PREFIX = "\n\n画面: "  # the last line of every message: the link to the screens
ACK_BY = "command-center"
REAP_INTERVAL = 60
REAP_GRACE_S = 120  # a fresh ACK is never reaped before Prometheus / Alertmanager have caught up with it
# After an Alertmanager (re)start its alert list is empty until Prometheus re-sends (every 1 m) and pending alerts pass
# their `for:` again (longest 30 s): no ACK is judged before 2 x 60 s + 30 s of uptime, and only after it has matched
# no alert on REAP_PASSES consecutive passes.
REAP_MIN_UPTIME_S = int(os.environ.get("RELAY_REAP_MIN_UPTIME_S", "150"))
REAP_PASSES = 3
RETRY_AFTER_MAX_S = 10  # a 429 / 503 asking for at most this long is retried here once; longer: Alertmanager retries
RETRY_KEY_WINDOW_S = 300  # LINE X-Line-Retry-Key window cap; the window is min(this, group_interval) (see line_retry_key)
ACK_RE = re.compile(r"^ACK\b")  # an ACK silence's comment (the same rule in mask-api and the command-center)
TOKEN_KEY = Path(os.environ.get("RELAY_TOKEN_KEY", "/run/obs-key/token.key"))  # mask-api's key (compose: token-key volume)
TOKEN_LEN = 12  # mask_api.TOKEN_LEN
EXACT_V4 = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}")  # mask_api.IPV4 as mask_value uses it: fullmatch

# Same rules as mask-api (mask_text): IPv4 -> a.b.c.x, MAC -> aa:bb:cc:xx:xx:xx.
IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")
MAC = re.compile(r"\b([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\b")

SEV_JA = {"critical": "重大", "warning": "警告", "info": "情報"}
NAME_JA = {"DeviceDown": "機器応答なし", "WanHighUtilization": "WAN 使用率超過", "InterfaceErrors": "インターフェースのエラーが増加",
           "DeviceRebooted": "機器再起動", TEST_ALERT: "通知テスト"}

RESULTS = deque(maxlen=1000)  # recent attempts, for GET /results?test=<id>
_cfg_lock = threading.Lock()
_log_lock = threading.Lock()


def log(line, err=False):
    """One whole line per call (request threads must not interleave their output)."""
    with _log_lock:
        out = sys.stderr if err else sys.stdout
        out.write(line + "\n")
        out.flush()
_cfg = {"mtime": None, "data": None}


def mask(s):
    return MAC.sub(r"\1\2xx\2xx\2xx", IPV4.sub(r"\1.x", str(s)))


_key = {"stamp": None, "key": None}
_key_lock = threading.Lock()


def token_key():
    """mask-api's address-token key (32 bytes), re-read when mask-api has replaced it, or None."""
    with _key_lock:
        try:
            st = TOKEN_KEY.stat()
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
            if stamp != _key["stamp"]:
                k = TOKEN_KEY.read_bytes()
                _key.update(stamp=stamp, key=k if len(k) == 32 else None)
        except OSError:
            _key.update(stamp=None, key=None)
        return _key["key"]


def label_value(s, key):
    """A record's label value as mask-api's mask_value shows it: exactly one IPv4 -> a.b.c.x~<token> (same HMAC-SHA256
    of the whole value, same key), without the key a.b.c.x; exactly one IPv6 -> x (its /64 is not recorded); anything
    else as free text (mask)."""
    s = str(s)
    m = EXACT_V4.fullmatch(s)
    if m:
        return f"{m.group(1)}.x~{hmac.new(key, s.encode(), hashlib.sha256).hexdigest()[:TOKEN_LEN]}" if key else f"{m.group(1)}.x"
    if ":" in s and len(s) <= 45:
        try:
            ipaddress.IPv6Address(s)
            return "x"
        except ValueError:
            pass
    return mask(s)


def config():
    """The generated config, re-read when `tools targets` has rewritten it (no restart needed)."""
    with _cfg_lock:
        try:
            mtime = CONFIG.stat().st_mtime_ns
        except FileNotFoundError:
            return {"receivers": {}, "repeat": {}, "public_url": ""}
        if mtime != _cfg["mtime"]:
            _cfg["data"], _cfg["mtime"] = json.loads(CONFIG.read_text(encoding="utf-8")), mtime
        return _cfg["data"]


# ---- message ------------------------------------------------------------------------------------

def parse_time(iso):
    """Alertmanager's RFC 3339 times (nanoseconds, Z) -> aware datetime, or None (zero / missing)."""
    if not iso or iso.startswith("0001-"):
        return None
    try:
        return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", iso).replace("Z", "+00:00"))
    except ValueError:
        return None


def jst(iso):
    t = parse_time(iso)
    return t.astimezone(JST).strftime("%Y-%m-%d %H:%M:%S JST") if t else "—"


def alert_block(a):
    labels, ann = a.get("labels") or {}, a.get("annotations") or {}
    name, sev = labels.get("alertname", "?"), labels.get("severity", "")
    resolved = a.get("status") == "resolved"
    lines = [f"{'【復旧】' if resolved else '【' + SEV_JA.get(sev, sev or '情報') + '】'} {NAME_JA.get(name, name)} ({name})",
             f"機器: {labels.get('instance') or '—'}"]
    if labels.get("ifName"):
        lines.append(f"対象: {labels['ifName']}")
    if ann.get("value"):
        lines.append(f"数値: {ann['value']}")
    lines.append(f"開始: {jst(a.get('startsAt'))}")
    if resolved:
        lines.append(f"復旧: {jst(a.get('endsAt'))}")
    text = ann.get("summary_ja") or ann.get("summary")
    if text:
        lines.append(f"内容: {text}")
    return "\n".join(lines)


def message(payload, public_url):
    """-> (subject, body), both masked. One message per Alertmanager notification (a group of alerts)."""
    alerts = payload.get("alerts") or []
    firing = [a for a in alerts if a.get("status") != "resolved"]
    resolved = len(alerts) - len(firing)
    if firing:
        head = f"障害 {len(firing)} 件" + (f" / 復旧 {resolved} 件" if resolved else "")
    else:
        head = f"復旧 {resolved} 件"
    names = sorted({NAME_JA.get(n, n) for n in ((a.get("labels") or {}).get("alertname", "?") for a in (firing or alerts))})
    where = sorted({(a.get("labels") or {}).get("instance", "") for a in alerts} - {""})
    subject = f"[宅内網監視] {head}: {' / '.join(names)}" + (f" ({', '.join(where)})" if where else "")
    body = [f"[宅内網監視] {head}", *(alert_block(a) for a in alerts)]
    if payload.get("truncatedAlerts"):
        body.append(f"(他 {payload['truncatedAlerts']} 件は省略)")
    text = mask("\n\n".join(body))
    if public_url:  # the screens' own address (OBS_PUBLIC_URL, set by the operator): not masked, or the link breaks
        text += f"{LINK_PREFIX}{public_url.rstrip('/')}/?open=alerts"
    return mask(subject), text


def clip(text, limit):
    tail = "\n…(以下省略)"
    return text if len(text) <= limit else text[:limit - len(tail)] + tail


# ---- senders: each returns (ok, code, detail); detail is the destination's answer, never a secret ---------

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A destination that redirects is refused (3xx error): the POST and its Authorization never go elsewhere."""

    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def retry_after(value):
    """Retry-After in seconds (the HTTP-date form is left to Alertmanager's own retries) or None."""
    return int(value) if value and value.strip().isdigit() else None


def http_post(url, body, headers=None, sleep=time.sleep):
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "obs-notify-relay", **(headers or {})})
    for attempt in (1, 2):
        try:
            with OPENER.open(req, timeout=SEND_TIMEOUT) as r:
                return True, r.status, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            wait = retry_after(e.headers.get("Retry-After")) if e.code in (429, 503) else None
            if attempt == 1 and wait is not None and wait <= RETRY_AFTER_MAX_S:
                sleep(wait)
                continue
            answer = mask(e.read(300).decode("utf-8", "replace")).strip().replace("\n", " ")[:120]
            return False, e.code, f"HTTP {e.code}" + (f" {answer}" if answer else "")
        except (OSError, ValueError) as e:  # timeouts included; no URL in the text: it may carry a token
            return False, None, f"接続不可 ({type(e).__name__})"


def send_slack(r, subject, text, payload):
    return http_post(r["url"], {"text": clip(text, TEXT_LIMIT["slack"])})


def send_discord(r, subject, text, payload):
    return http_post(r["url"], {"content": clip(text, TEXT_LIMIT["discord"]), "allowed_mentions": {"parse": []}})


LINE_KEY_TTL_S = 86400  # LINE keeps a retry key for 24 h
_line_keys = {}  # retry key -> (receiver, to, first sent): pushes this relay itself made (409 is trusted only for those)
_line_lock = threading.Lock()


def line_retry_key(payload, now, window=RETRY_KEY_WINDOW_S, receiver="", to=""):
    """Same notification (group, status, alerts) retried within one time bucket -> same key, so LINE pushes it once.
    The bucket is at most group_interval long: Alertmanager's retries of one flush stay inside it, while its next
    flush or a repeat (>= group_interval later) falls into a later bucket and is pushed again.
    ponytail: a retry straddling a bucket boundary gets a new key (one duplicate at most)."""
    fps = ",".join(sorted(a.get("fingerprint", "") for a in payload.get("alerts") or []))
    # receiver and destination are part of the key: two routes sharing a token must never dedupe each other
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{receiver}|{to}|{payload.get('groupKey')}|{payload.get('status')}|{fps}|{int(now // max(1, window))}"))


def remember_line_key(key, receiver, to, now):
    """-> True when this relay already pushed with this key for the same receiver and destination (a retry)."""
    with _line_lock:
        for k in [k for k, v in _line_keys.items() if now - v[2] > LINE_KEY_TTL_S]:
            del _line_keys[k]
        seen = _line_keys.get(key)
        if seen is None:
            _line_keys[key] = (receiver, to, now)
        return seen is not None and seen[:2] == (receiver, to)


def send_line(r, subject, text, payload, now=None):
    now = now or time.time()
    window = min(RETRY_KEY_WINDOW_S, r.get("group_interval_s") or RETRY_KEY_WINDOW_S)
    key = line_retry_key(payload, now, window, r.get("name", ""), r["to"])
    retry = remember_line_key(key, r.get("name", ""), r["to"], now)
    ok, code, detail = http_post(r["api"], {"to": r["to"], "messages": [{"type": "text", "text": clip(text, TEXT_LIMIT["line"])}]},
                                 {"Authorization": f"Bearer {r['token']}", "X-Line-Retry-Key": key})
    if code == 409:  # LINE already accepted this key: delivered only if it was our own earlier attempt of this very push
        return (True, code, "HTTP 409 (送信完了: 再送重複を LINE 側で除外)") if retry else (False, code, "HTTP 409 (再送キーの衝突: 未送信の可能性)")
    return ok, code, detail


def send_webhook(r, subject, text, payload):
    keep = ("status", "labels", "annotations", "startsAt", "endsAt", "fingerprint")
    alerts = [{k: a.get(k) for k in keep} for a in payload.get("alerts") or []]
    body = {"version": "obs-1", "status": payload.get("status"), "receiver": payload.get("receiver"), "title": subject, "text": text,
            "alerts": json.loads(mask(json.dumps(alerts, ensure_ascii=False)))}
    return http_post(r["url"], body, {"Authorization": f"Bearer {r['token']}"} if r.get("token") else None)


def send_email(r, subject, text, payload):
    s = r["smtp"]
    ctx = ssl.create_default_context()
    if not s.get("verify", True):  # testbed's mock server only (tools check warns when it is off)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, s["from"], ", ".join(r["to"])
    msg["Date"], msg["Message-ID"] = formatdate(), make_msgid(domain="obs.local")
    msg.set_content(text)
    try:
        smtp = smtplib.SMTP_SSL(s["host"], s["port"], timeout=SEND_TIMEOUT, context=ctx) if s["tls"] == "tls" \
            else smtplib.SMTP(s["host"], s["port"], timeout=SEND_TIMEOUT)
        with smtp:
            smtp.ehlo()
            if s["tls"] == "starttls":
                smtp.starttls(context=ctx)
                smtp.ehlo()
            if s.get("user"):
                smtp.login(s["user"], s["password"])
            code, answer = smtp.mail(s["from"])
            if code != 250:
                return False, code, f"SMTP {code} {answer.decode('utf-8', 'replace')[:80]} (送信元 {s['from']})"
            refused = []
            for to in r["to"]:  # every recipient is tried; the accepted ones get the message
                code, answer = smtp.rcpt(to)
                if code not in (250, 251):
                    refused.append((to, code, answer.decode("utf-8", "replace")[:60]))
            if len(refused) == len(r["to"]):
                to, code, why = refused[0]
                return False, code, f"SMTP {code} {why} (送信先 {', '.join(t for t, _, _ in refused)} を全件拒否)"
            code, answer = smtp.data(msg.as_bytes(policy=email.policy.SMTP))  # CRLF line ends (RFC 5321)
            detail = f"SMTP {code} {answer.decode('utf-8', 'replace')[:80]}"
            if code == 250 and refused:  # sent, but not to everyone: a failure to report, not to retry (no duplicates)
                return True, code, detail + " / 拒否: " + ", ".join(f"{t} ({c})" for t, c, _ in refused), True
            return code == 250, code, detail
    except smtplib.SMTPException as e:
        code = getattr(e, "smtp_code", None)
        return False, code, f"SMTP エラー ({type(e).__name__}{f' {code}' if code else ''})"
    except (OSError, ValueError) as e:
        return False, None, f"接続不可 ({type(e).__name__})"


def send_sink(r, subject, text, payload):
    return True, 200, "記録のみ (デモ用受信先。外部送信なし)"


SENDERS = {"email": send_email, "slack": send_slack, "discord": send_discord, "line": send_line, "webhook": send_webhook, "sink": send_sink}


# ---- records (Loki + memory) --------------------------------------------------------------------

def records(name, rtype, payload, result, detail, repeat, now, text=None, key=None):
    """One record per alert of the notification (what the command-center matches by fingerprint). text: the rendered,
    masked message (kept for the demo sink, so the demo shows what would have been sent). key: the token key or None."""
    out = []
    for a in payload.get("alerts") or []:
        labels = a.get("labels") or {}
        sev = labels.get("severity", "")
        out.append({"t": now, "receiver": name, "type": rtype, "status": a.get("status"), "result": result, "starts": a.get("startsAt", ""),
                    "detail": detail, "fingerprint": a.get("fingerprint", ""), "alertname": labels.get("alertname", ""),
                    "instance": label_value(labels.get("instance", ""), key), "ifName": label_value(labels.get("ifName", ""), key), "severity": sev,
                    "repeat_s": repeat.get(sev), "test": labels.get("obs_test", ""), **({"message": text} if text else {})})
    return out


def push_loki(recs):
    streams = {}
    for rec in recs:
        key = (rec["receiver"], rec["severity"], rec["status"], rec["result"])
        streams.setdefault(key, []).append([str(int(rec["t"] * 1e9)), json.dumps(rec, ensure_ascii=False)])
    body = {"streams": [{"stream": {"job": "notify", "receiver": k[0], "severity": k[1] or "none", "status": k[2] or "unknown", "result": k[3]},
                         "values": v} for k, v in streams.items()]}
    req = urllib.request.Request(LOKI + "/loki/api/v1/push", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except (OSError, ValueError) as e:
        log(f"loki push failed: {type(e).__name__}", err=True)


def is_test_resolved(payload):
    alerts = payload.get("alerts") or []
    return bool(alerts) and all((a.get("labels") or {}).get("alertname") == TEST_ALERT and a.get("status") == "resolved" for a in alerts)


def notify(name, payload, cfg, now=None, send=None, push=push_loki, key=token_key):
    """-> HTTP status for Alertmanager: 200 sent; 400 the destination refused (no retry helps); 502 retry later."""
    r = cfg.get("receivers", {}).get(name)
    if r is None:
        log(f"notify {name}: unknown receiver (config not regenerated?)", err=True)
        return 404
    if is_test_resolved(payload):  # a test is one message; its automatic resolution is not sent
        return 200
    subject, text = message(payload, cfg.get("public_url", ""))
    res = (send or SENDERS[r["type"]])({**r, "name": name, "group_interval_s": cfg.get("group_interval_s")}, subject, text, payload)
    ok, code, detail = res[:3]
    partial = len(res) > 3 and res[3]  # sent, but some recipients refused it
    result = "partial" if ok and partial else "ok" if ok else "failed"
    detail = mask(detail)  # an SMTP / HTTP answer may quote an address
    # the sink keeps the message without the link line (every read masks IPs, which would break the screens' own URL)
    kept = text.split(LINK_PREFIX)[0].rstrip() if r["type"] == "sink" else None
    recs = records(name, r["type"], payload, result, detail, cfg.get("repeat", {}), now or time.time(), kept, key())
    RESULTS.extend(recs)
    push(recs)
    log(f"notify {name} ({r['type']}) {payload.get('status')} {len(recs)} alert(s): { {'ok': 'OK', 'partial': 'PARTIAL', 'failed': 'NG'}[result] } {detail}")
    if ok:
        return 200
    return 400 if permanent_failure(r["type"], code) else 502


def permanent_failure(rtype, code):
    """SMTP 5xx, HTTP 3xx (redirect refused) / 4xx except 429: retrying will not help. Everything else (429, 5xx,
    timeouts, no connection) is answered 502 so that Alertmanager retries."""
    if not isinstance(code, int):
        return False
    if rtype == "email":
        return 500 <= code < 600
    return 300 <= code < 500 and code != 429


# ---- ACK reaper ---------------------------------------------------------------------------------

def am_json(path, method="GET"):
    req = urllib.request.Request(ALERTMANAGER + path, method=method)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or b"null")


def matches(matchers, labels):
    return all((labels.get(m["name"], "") == m["value"]) == m.get("isEqual", True) for m in matchers if not m.get("isRegex"))


def is_ack(s):
    by = str(s.get("createdBy", "")) if isinstance(s, dict) else ""
    return (by == ACK_BY or by.startswith(ACK_BY + " (")) and bool(ACK_RE.match(str(s.get("comment", ""))))


def stale_acks(silences, alerts, now):
    """ACK silences (active, older than the grace period) that no active alert matches any more -> their ids."""
    out = []
    for s in silences:
        if not isinstance(s, dict):
            continue
        started = parse_time(s.get("startsAt"))
        if (s.get("status") or {}).get("state") != "active" or not is_ack(s) or not started or now - started.timestamp() < REAP_GRACE_S:
            continue
        if not any(matches(s.get("matchers") or [], a.get("labels") or {}) for a in alerts):
            out.append(s["id"])
    return out


ACK_USER_RE = re.compile(re.escape(ACK_BY) + r" \(([A-Za-z0-9._@-]{1,64})\)")  # mask-api: "command-center (<user>)"


def ack_record(s, now, key):
    """The notification record of an ACK this relay expired (Loki {job="notify"}, receiver "ack"): who acknowledged it
    (the logged-in user mask-api wrote into createdBy; "local" on the 127.0.0.1 screen) and what it covered. No
    fingerprint: the screens' per-alert notification state does not count it."""
    m = ACK_USER_RE.fullmatch(str(s.get("createdBy", "")))
    by = m.group(1) if m else "local"
    labels = {x.get("name"): str(x.get("value", "")) for x in s.get("matchers") or [] if isinstance(x, dict) and not x.get("isRegex")}
    return {"t": now, "receiver": "ack", "type": "ack", "status": "resolved", "result": "expired", "starts": s.get("startsAt", ""),
            "detail": f"ACK by {by}: alert resolved, ACK expired", "fingerprint": "", "alertname": labels.get("alertname", ""),
            "instance": label_value(labels.get("instance", ""), key), "ifName": label_value(labels.get("ifName", ""), key),
            "severity": labels.get("severity", ""), "repeat_s": None, "test": "", "by": by}


def reap_pass(silences, alerts, am_up_s, now, counts):
    """-> ACK ids to expire now. counts: silence id -> consecutive passes without a matching alert (updated)."""
    if am_up_s < REAP_MIN_UPTIME_S:  # Alertmanager just (re)started: its alert list is not complete yet
        counts.clear()
        return []
    stale = set(stale_acks(silences, alerts, now))
    for sid in list(counts):
        if sid not in stale:
            del counts[sid]
    for sid in stale:
        counts[sid] = counts.get(sid, 0) + 1
    return sorted(sid for sid in stale if counts[sid] >= REAP_PASSES)


def reap_loop():
    counts = {}
    while True:
        time.sleep(REAP_INTERVAL)
        try:
            now = time.time()
            started = parse_time((am_json("/api/v2/status") or {}).get("uptime"))
            alerts = am_json("/api/v2/alerts?active=true&silenced=true&inhibited=true&unprocessed=true")
            silences = am_json("/api/v2/silences")
            if not (started and isinstance(alerts, list) and isinstance(silences, list)):
                continue
            by_id = {s.get("id"): s for s in silences if isinstance(s, dict)}
            for sid in reap_pass(silences, alerts, now - started.timestamp(), now, counts):
                am_json(f"/api/v2/silence/{sid}", "DELETE")
                counts.pop(sid, None)
                rec = ack_record(by_id.get(sid, {}), now, token_key())
                push_loki([rec])
                log(f"ACK {sid} by {rec['by']}: no matching alert on {REAP_PASSES} passes (resolved), silence expired")
        except (OSError, ValueError) as e:
            log(f"ack reaper: Alertmanager unavailable ({type(e).__name__})", err=True)
        except Exception as e:  # noqa: BLE001 - one bad pass must never stop the reaper thread
            log(f"ack reaper: pass failed ({type(e).__name__}: {mask(str(e))[:120]})", err=True)


# ---- HTTP ---------------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/health":
            return self.reply(200, {"ok": True})
        if path == "/results":
            test = dict(p.partition("=")[::2] for p in query.split("&") if p).get("test", "")
            return self.reply(200, [r for r in list(RESULTS) if test and r["test"] == test])
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        m = re.fullmatch(r"/notify/([a-z0-9][a-z0-9_-]{0,31})", self.path)
        length = self.headers.get("Content-Length") or "0"
        length = int(length) if length.isdigit() else -1
        if not m or not 0 < length <= MAX_BODY:
            return self.reply(404 if not m else 400, {"error": "bad request"})
        try:
            payload = json.loads(self.rfile.read(length))
        except ValueError:
            return self.reply(400, {"error": "bad json"})
        if not isinstance(payload, dict):
            return self.reply(400, {"error": "not an Alertmanager notification"})
        try:
            status = notify(m.group(1), payload, config())
        except (OSError, ValueError, KeyError) as e:  # broken config: retry after `tools targets`
            log(f"notify {m.group(1)}: {type(e).__name__}", err=True)
            status = 500
        self.reply(status, {"status": status})

    def log_message(self, *a):
        pass


# ---- self-test ----------------------------------------------------------------------------------

def selftest():
    assert mask("TCP 192.168.100.7:5555 02-00-5e-20-00-01 1.3.6") == "TCP 192.168.100.x:5555 02-00-5e-xx-xx-xx 1.3.6"
    assert jst("2026-10-26T05:03:04.123456789Z") == "2026-10-26 14:03:04 JST" and jst("0001-01-01T00:00:00Z") == "—"
    fire = {"status": "firing", "labels": {"alertname": "DeviceDown", "severity": "critical", "instance": "192.0.2.10"},
            "annotations": {"summary_ja": "rtx1300 (aa:bb:cc:dd:ee:ff) から SNMP の応答がありません", "value": "0"},
            "startsAt": "2026-10-26T05:03:04Z", "endsAt": "0001-01-01T00:00:00Z", "fingerprint": "0123456789abcdef"}
    res = {**fire, "status": "resolved", "labels": {**fire["labels"], "alertname": "WanHighUtilization", "ifName": "lan2", "severity": "warning"},
           "endsAt": "2026-10-26T05:13:04Z", "fingerprint": "fedcba9876543210"}
    subj, body = message({"alerts": [fire, res], "truncatedAlerts": 2}, "http://192.168.100.10:8080")
    assert "192.0.2.10" not in subj + body and "192.0.2.x" in body and "aa:bb:cc:xx:xx:xx" in body, body
    assert subj == "[宅内網監視] 障害 1 件 / 復旧 1 件: 機器応答なし (192.0.2.x)", subj
    for part in ("【重大】 機器応答なし (DeviceDown)", "開始: 2026-10-26 14:03:04 JST", "数値: 0", "【復旧】", "対象: lan2",
                 "復旧: 2026-10-26 14:13:04 JST", "(他 2 件は省略)", "画面: http://192.168.100.10:8080/?open=alerts"):
        assert part in body, (part, body)
    assert message({"alerts": [res]}, "")[0].startswith("[宅内網監視] 復旧 1 件: WAN 使用率超過")
    assert len(clip("x" * 3000, 2000)) == 2000 and clip("abc", 10) == "abc"
    # notify: result per alert, recorded with the repeat interval of its severity; status code for Alertmanager's retry
    cfg = {"receivers": {"s": {"type": "slack", "url": "http://x"}, "m": {"type": "email"}, "d": {"type": "sink"}},
           "repeat": {"critical": 3600}, "public_url": ""}
    pushed = []
    sent = lambda ok, code: (lambda r, s, t, p: (ok, code, f"HTTP {code}"))
    assert notify("s", {"status": "firing", "alerts": [fire]}, cfg, 100.0, sent(True, 200), pushed.extend, key=lambda: None) == 200
    assert pushed[-1]["result"] == "ok" and pushed[-1]["repeat_s"] == 3600 and pushed[-1]["fingerprint"] == "0123456789abcdef"
    assert pushed[-1]["instance"] == "192.0.2.x" and pushed[-1]["t"] == 100.0  # no key: fail closed, no token
    # address tokens: the same as mask-api's for the same address and key (golden vector, asserted in mask-api too)
    gold = bytes(range(32))
    assert label_value("192.0.2.10", gold) == "192.0.2.x~141e10c52e03" and label_value("192.0.2.11", gold) == "192.0.2.x~65ccf18bfbf0"
    assert label_value("192.0.2.10", None) == "192.0.2.x" and label_value("2001:db8::1", gold) == "x" == label_value("2001:db8::1", None)
    assert label_value("rtx1300", gold) == "rtx1300" and label_value("aa:bb:cc:dd:ee:ff", gold) == "aa:bb:cc:xx:xx:xx"
    assert label_value("192.0.2.10:161", gold) == "192.0.2.x:161"  # not exactly one address: free text, no token
    out = []
    assert notify("s", {"alerts": [fire]}, cfg, 1, lambda r, s_, t, p: out.append(s_ + t) or (True, 200, "HTTP 200"), pushed.extend, key=lambda: gold) == 200
    assert pushed[-1]["instance"] == "192.0.2.x~141e10c52e03", pushed[-1]
    assert "~" not in out[-1] and "192.0.2.x" in out[-1] and "192.0.2.10" not in out[-1]  # the message sent out: unchanged, no token
    assert notify("s", {"alerts": [fire]}, cfg, 1, sent(True, 200), pushed.extend, key=lambda: None) == 200
    assert pushed[-1]["instance"] == "192.0.2.x"  # no key: fail closed
    # the key file: missing / wrong length -> None (fail closed); replaced -> re-read
    global TOKEN_KEY
    real_key, tmp = TOKEN_KEY, Path(os.environ.get("TMPDIR") or os.environ.get("TEMP") or "/tmp") / f"relay-key-{os.getpid()}"
    try:
        TOKEN_KEY = tmp
        assert token_key() is None
        tmp.write_bytes(b"short")
        assert token_key() is None
        tmp.write_bytes(gold)
        os.utime(tmp, ns=(1, 2))
        assert token_key() == gold
    finally:
        TOKEN_KEY = real_key
        tmp.unlink(missing_ok=True)
    assert notify("s", {"alerts": [fire]}, cfg, 1, sent(False, 404), pushed.extend) == 400  # refused: no retry
    assert notify("s", {"alerts": [fire]}, cfg, 1, sent(False, 503), pushed.extend) == 502  # retried by Alertmanager
    assert notify("m", {"alerts": [fire]}, cfg, 1, sent(False, 550), pushed.extend) == 400
    assert notify("m", {"alerts": [fire]}, cfg, 1, sent(False, 451), pushed.extend) == 502
    assert notify("d", {"alerts": [fire]}, cfg, 1, None, pushed.extend) == 200 and pushed[-1]["type"] == "sink"
    assert notify("nope", {"alerts": [fire]}, cfg) == 404
    n = len(pushed)
    test_done = {**fire, "status": "resolved", "labels": {"alertname": TEST_ALERT, "obs_test": "t1"}}
    assert notify("s", {"alerts": [test_done]}, cfg, 1, sent(True, 200), pushed.extend) == 200 and len(pushed) == n  # not sent
    # webhook payload: masked, no secrets
    seen = {}
    def fake_post(url, body, headers=None):
        seen.update(url=url, body=body, headers=headers)
        return True, 204, "HTTP 204"
    global http_post
    real, http_post = http_post, fake_post
    try:
        send_webhook({"url": "http://hook", "token": "tok"}, "s", "t", {"alerts": [fire], "status": "firing"})
        assert seen["headers"] == {"Authorization": "Bearer tok"} and "192.0.2.10" not in json.dumps(seen["body"])
        send_discord({"url": "http://d"}, "s", "x" * 2500, {})
        assert len(seen["body"]["content"]) == 2000 and seen["body"]["allowed_mentions"] == {"parse": []}
        send_line({"api": "http://line", "to": "U" + "0" * 32, "token": "T"}, "s", "本文", {})
        assert seen["body"] == {"to": "U" + "0" * 32, "messages": [{"type": "text", "text": "本文"}]} and seen["headers"]["Authorization"] == "Bearer T"
    finally:
        http_post = real
    # ACK reaper: only command-center ACKs, only past the grace period, only when no alert matches
    now = parse_time("2026-10-26T06:00:00Z").timestamp()
    ack = {"id": "a1", "createdBy": "command-center", "comment": "ACK by operator", "startsAt": "2026-10-26T05:50:00Z", "status": {"state": "active"},
           "matchers": [{"name": "alertname", "value": "DeviceDown", "isRegex": False, "isEqual": True}, {"name": "instance", "value": "wlx222", "isRegex": False}]}
    live = [{"labels": {"alertname": "DeviceDown", "instance": "wlx222", "severity": "critical"}}]
    assert stale_acks([ack], live, now) == [] and stale_acks([ack], [], now) == ["a1"]
    assert stale_acks([{**ack, "comment": "maintenance"}], [], now) == []  # a plain silence stays until its end
    assert stale_acks([{**ack, "createdBy": "amtool"}], [], now) == []
    assert stale_acks([{**ack, "startsAt": "2026-10-26T05:59:30Z"}], [], now) == []  # grace period
    assert stale_acks([{**ack, "status": {"state": "expired"}}], [], now) == []
    assert stale_acks([{**ack, "createdBy": "command-center (alice)"}], [], now) == ["a1"] and stale_acks(["junk", None], [], now) == []
    # P7: the record of an expired ACK names the logged-in user who made it (mask-api's createdBy), tokens as elsewhere
    rec = ack_record({**ack, "createdBy": "command-center (alice)", "matchers": ack["matchers"] + [{"name": "ifName", "value": "192.0.2.10"}]}, now, bytes(range(32)))
    assert rec["by"] == "alice" and rec["detail"].startswith("ACK by alice") and rec["alertname"] == "DeviceDown" and rec["fingerprint"] == ""
    assert rec["instance"] == "wlx222" and rec["ifName"] == "192.0.2.x~141e10c52e03" and rec["receiver"] == "ack", rec
    assert ack_record(ack, now, None)["by"] == "local" and ack_record({**ack, "createdBy": "command-center (a b)"}, now, None)["by"] == "local"
    assert ack_record({}, now, None)["by"] == "local"
    # restart safety: nothing while Alertmanager is young, then only after REAP_PASSES unmatched passes in a row
    counts = {}
    assert reap_pass([ack], [], REAP_MIN_UPTIME_S - 1, now, counts) == [] and counts == {}
    assert [reap_pass([ack], [], 9999, now, counts) for _ in range(REAP_PASSES)] == [[]] * (REAP_PASSES - 1) + [["a1"]]
    counts = {}
    reap_pass([ack], [], 9999, now, counts)
    reap_pass([ack], live, 9999, now, counts)  # matched again: the count starts over
    assert counts == {} and reap_pass([ack], [], 9999, now, counts) == []
    # retry policy for Alertmanager: 429 / 5xx / no answer -> 502 (retry); 3xx / other 4xx -> 400; SMTP 5xx -> 400
    for rtype, code, want in (("slack", 429, False), ("slack", 503, False), ("slack", None, False), ("slack", 302, True), ("slack", 404, True),
                              ("email", 550, True), ("email", 421, False)):
        assert permanent_failure(rtype, code) is want, (rtype, code)
    assert notify("s", {"alerts": [fire]}, cfg, 1, sent(False, 429), pushed.extend) == 502
    # Retry-After within bounds: retried once here; the HTTP answer of the destination is masked in the record
    calls = []

    class Fake:
        def __init__(self, codes):
            self.codes = codes

        def open(self, req, timeout):
            calls.append(req.get_header("X-line-retry-key"))
            code, retry = self.codes.pop(0)
            if code >= 400:
                raise urllib.error.HTTPError(req.full_url, code, "x", {"Retry-After": retry} if retry else {}, io.BytesIO(b"busy 192.0.2.10"))
            return contextlib.nullcontext(types.SimpleNamespace(status=code))
    global OPENER
    real_opener = OPENER
    try:
        slept = []
        OPENER = Fake([(429, "2"), (200, None)])
        assert http_post("http://x", {}, sleep=slept.append)[:2] == (True, 200) and slept == [2]
        OPENER = Fake([(429, "3600")])
        ok_, code_, detail_ = http_post("http://x", {}, sleep=slept.append)
        assert (ok_, code_) == (False, 429) and slept == [2] and "192.0.2.10" not in detail_  # long wait: left to Alertmanager
        _line_keys.clear()
        pl = {"groupKey": "g", "alerts": [fire]}
        line = lambda name, to: {"api": "http://line", "to": to, "token": "T", "name": name}
        OPENER = Fake([(409, None)])  # 409 on a first push (someone else's key): not delivered
        assert send_line(line("l1", "U1"), "s", "t", pl, now=1000)[0] is False
        OPENER = Fake([(500, None), (409, None)])  # our own push timed out / failed, the retry gets 409: delivered
        assert send_line(line("l2", "U2"), "s", "t", pl, now=1000)[0] is False
        assert send_line(line("l2", "U2"), "s", "t", pl, now=1100)[0] is True
        assert calls[-1] == calls[-2], "the same notification keeps its retry key"
        OPENER = Fake([(200, None), (200, None)])  # two routes sharing a token: different keys, both pushed
        send_line(line("ops", "Ua"), "s", "t", pl, now=1000)
        send_line(line("family", "Ub"), "s", "t", pl, now=1000)
        assert calls[-1] != calls[-2]
        assert len({line_retry_key(pl, 1000, 300, n, t) for n, t in (("a", "U1"), ("b", "U1"), ("a", "U2"))}) == 3
        assert line_retry_key({"groupKey": "g", "alerts": [fire]}, 1000) != line_retry_key({"groupKey": "g", "alerts": [fire]}, 1000 + RETRY_KEY_WINDOW_S)
    finally:
        OPENER = real_opener
    assert isinstance(OPENER.handlers[0], NoRedirect) or any(isinstance(h, NoRedirect) for h in OPENER.handlers)
    # SMTP: the message goes out with CRLF line ends only
    m = EmailMessage()
    m["Subject"] = "件名"
    m.set_content("一行目\n二行目\n")
    raw = m.as_bytes(policy=email.policy.SMTP)
    assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")
    # demo sink: the masked Japanese message is kept with the record; SMTP / HTTP answers are masked
    pushed.clear()
    notify("d", {"status": "firing", "alerts": [fire]}, {**cfg, "public_url": "http://192.168.100.10:8080"}, 1, None, pushed.extend)
    assert "【重大】" in pushed[-1]["message"] and "192.0.2.10" not in pushed[-1]["message"] and "画面:" not in pushed[-1]["message"]
    notify("s", {"alerts": [fire]}, cfg, 1, lambda *a: (False, 550, "SMTP 550 no such user 192.0.2.10"), pushed.extend)
    assert "192.0.2.x" in pushed[-1]["detail"] and "message" not in pushed[-1]
    # per-recipient SMTP results: MAIL FROM refused -> failed; some RCPT refused -> sent to the rest, recorded "partial"
    class FakeSMTP:
        def __init__(self, *a, **k):
            self.sent = None
        __enter__ = lambda self: self
        __exit__ = lambda self, *a: False
        ehlo = starttls = login = lambda self, *a, **k: None
        mail = lambda self, frm: (550, b"sender refused") if frm.startswith("bad") else (250, b"ok")
        rcpt = lambda self, to: (550, b"no such user") if "reject" in to else (250, b"ok")
        def data(self, raw):
            assert b"\n" not in raw.replace(b"\r\n", b""), "CRLF only"
            return 250, b"queued"
    real_smtp, smtplib.SMTP = smtplib.SMTP, FakeSMTP
    try:
        mk = lambda frm, to: {"type": "email", "to": to, "smtp": {"host": "h", "port": 25, "from": frm, "tls": "none", "verify": True}}
        assert send_email(mk("bad@x", ["a@x"]), "s", "t", {})[:2] == (False, 550)
        assert send_email(mk("obs@x", ["reject@x"]), "s", "t", {})[0] is False
        res = send_email(mk("obs@x", ["a@x", "reject@x"]), "s", "t", {})
        assert res[0] is True and res[3] is True and "reject@x" in res[2], res
        assert send_email(mk("obs@x", ["a@x"]), "s", "t", {}) == (True, 250, "SMTP 250 queued")
    finally:
        smtplib.SMTP = real_smtp
    pushed.clear()
    assert notify("m", {"alerts": [fire]}, cfg, 1, lambda *a: (True, 250, "SMTP 250 / 拒否: x", True), pushed.extend) == 200  # no retry: no duplicates
    assert pushed[-1]["result"] == "partial" and pushed[-1]["starts"] == fire["startsAt"]  # the activation it belongs to
    # one ACK rule everywhere: "ACK" as a word at the start
    assert is_ack({**ack, "comment": "ACK by local"}) and is_ack({**ack, "comment": "ACK"}) and not is_ack({**ack, "comment": "ACKNOWLEDGED"})
    # LINE retry key: bucket = min(300 s, group_interval): a re-notification one group_interval later gets a new key
    k = lambda t, w: line_retry_key({"groupKey": "g", "alerts": [fire]}, t, w)
    assert k(1000, 30) == k(1010, 30) and k(1000, 30) != k(1030, 30)
    seen_keys = []
    def capture(url, body, headers=None):
        seen_keys.append(headers["X-Line-Retry-Key"])
        return True, 200, "HTTP 200"
    real_post = http_post
    globals()["http_post"] = capture
    try:
        send_line({"api": "a", "to": "U", "token": "T", "group_interval_s": 30}, "s", "t", {"groupKey": "g", "alerts": [fire]}, now=1000)
        send_line({"api": "a", "to": "U", "token": "T", "group_interval_s": 30}, "s", "t", {"groupKey": "g", "alerts": [fire]}, now=1030)
    finally:
        globals()["http_post"] = real_post
    assert seen_keys[0] != seen_keys[1]
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        threading.Thread(target=reap_loop, daemon=True).start()
        ThreadingHTTPServer.daemon_threads = True
        log(f"notify-relay on :{PORT} (config {CONFIG})")
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
