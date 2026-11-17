"""HTTP checks of the screens from the host, as a browser would reach them (stdlib only; python3 on the Pi).

  probe.py screens --url http://127.0.0.1:8080                      open mode: screens, APIs, Host check
  probe.py screens --url https://192.0.2.10:8080 --ca root.crt  login: HTTPS with the proxy's CA, roles
  probe.py status  --url ... [--ca ...] PATH...                     one line per PATH: its HTTP status (logged in as admin)
Secrets from the environment only: E2E_ADMIN / E2E_VIEWER ("user:password").
Prints one line per check (OK / NG); exit 1 when any is NG."""
import argparse
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

RESULTS = []
TREND_WAIT = int(os.environ.get("E2E_TREND_WAIT", "300"))  # s: the first points of the rate series (see trend_and_search)
# the devices modal's "Last seen" (F2, command-center/js/main.js Q.lastOk): accepted by mask-api's /prom/ path
UP_TS = 'timestamp(up{job="snmp"}) and up{job="snmp"} == 1'
LAST_OK = f"time() - max by (instance) ({UP_TS} or max_over_time(({UP_TS})[900s:30s]))"


class Client:
    def __init__(self, url, ca):
        u = urllib.parse.urlsplit(url)
        self.base, self.host, self.port, self.tls = url.rstrip("/"), u.hostname, u.port or (443 if u.scheme == "https" else 80), u.scheme == "https"
        self.ctx = ssl.create_default_context(cafile=ca) if self.tls else None
        self.cookie, self.ca, self.set_cookie = None, ca, ""

    def req(self, method, path, headers=None, body=None, tls=None, host=None):
        tls = self.tls if tls is None else tls
        h = {"Accept": "application/json", **(headers or {})}
        if self.cookie:
            h["Cookie"] = self.cookie
        if host:
            h["Host"] = host
        conn = (http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=60) if tls
                else http.client.HTTPConnection(self.host, self.port, timeout=60))
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        except OSError as e:
            return 0, {}, str(e).encode()
        finally:
            conn.close()

    def login(self, cred):
        user, _, pw = cred.partition(":")
        body = json.dumps({"username": user, "password": pw, "keepMeLoggedIn": False, "targetURL": self.base + "/"})
        st, hd, _ = self.req("POST", "/auth/api/firstfactor", {"Content-Type": "application/json", "Origin": self.base}, body)
        sc = self.set_cookie = hd.get("set-cookie", "")
        self.cookie = sc.split(";")[0] if "obs_session=" in sc else None
        return st, self.cookie is not None


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"[{'OK' if ok else 'NG'}] {name}" + (f"  ({detail})" if detail != "" else ""), flush=True)


def js(body):
    try:
        return json.loads(body)
    except ValueError:
        return None


def common(c):
    st, _, b = c.req("GET", "/")
    check("command-center GET /", st == 200 and b"<title" in b, st)
    st, _, b = c.req("GET", "/obs/config.json")
    cfg = js(b) or {}
    check("config.json (setup が生成)", st == 200 and cfg, f"{st} {str(cfg)[:100]}")
    st, _, b = c.req("GET", "/prom/api/v1/query?query=" + urllib.parse.quote('up{job="snmp"}'))
    res = (js(b) or {}).get("data", {}).get("result", [])
    check("Prometheus (mask-api 経由): snmp の対象が up", st == 200 and res and all(r["value"][1] == "1" for r in res), f"{st} {len(res)} 件")
    q = urllib.parse.urlencode({"query": '{job="syslog"}', "limit": 5, "start": int((time.time() - 900) * 1e9), "end": int(time.time() * 1e9)})
    st, _, b = c.req("GET", "/loki/loki/api/v1/query_range?" + q)
    check("Loki (mask-api 経由): syslog の行", st == 200 and (js(b) or {}).get("data", {}).get("result"), st)
    st, _, b = c.req("GET", "/prom/api/v1/query?query=" + urllib.parse.quote(LAST_OK))
    res = (js(b) or {}).get("data", {}).get("result", [])
    check("機器ごとの Last seen (mask-api 経由)", st == 200 and res and all(0 <= float(r["value"][1]) <= 900 for r in res),
          f"{st} {[(r['metric'].get('instance'), round(float(r['value'][1]))) for r in res]}")
    trend_and_search(c)
    st, _, _ = c.req("GET", "/", host="evil.example:%d" % c.port)
    check("知らない Host -> 421", st == 421, st)


def unknown_path(c, who):
    st, _, _ = c.req("GET", "/no-such-page/")
    check(f"{who}: 知らないパス -> 404", st == 404, st)


def trend_and_search(c):
    """F1: 推移 / ログ検索 through mask-api (templates only, masked), with refused injections."""
    now = time.time()
    win = {"from": f"{now - 3600:.0f}", "to": f"{now:.0f}"}
    st, _, b = c.req("GET", "/trend/families")
    fams = [f["family"] for f in ((js(b) or {}).get("data") or {}).get("families", [])]
    check("推移: 種類の一覧", st == 200 and "if_bps" in fams and "flow_country" in fams, f"{st} {len(fams)} 種類")
    for fam, scope, want in (("if_bps", {"instance": "rtx1300", "ifName": "lan2"}, True), ("dev_up", {}, True),
                             ("wan_util", {"instance": "rtx1300", "ifName": "lan2"}, True), ("if_drops", {"instance": "rtx1300"}, None),
                             ("flow_country", {}, None), ("capture_ring", {}, None)):
        # a rate over 2 min needs a few scrapes (30 s): right after `up` (fast host) the series may not have 2 points yet
        t_end = time.time() + (TREND_WAIT if want else 0)
        while True:
            st, _, b = c.req("GET", "/trend/series?" + urllib.parse.urlencode({"family": fam, **scope, **win}))
            d = (js(b) or {}).get("data") or {}
            ser = d.get("series", [])
            pts = max((len(x["points"]) for x in ser), default=0)
            ok = st == 200 and d.get("step") and pts <= 600 and (want is None or (ser and pts > 1))
            if ok or time.time() >= t_end:
                break
            time.sleep(10)
            now = time.time()
            win = {"from": f"{now - 3600:.0f}", "to": f"{now:.0f}"}
        check(f"推移: {fam} {scope or ''}".rstrip(), ok, f"{st} {len(ser)} 系列 {pts} 点 step {d.get('step')}")
    for bad in ({"family": "if_bps", "instance": 'rtx1300"} or vector(1) #', **win}, {"family": "if_bps", "instance": "192.0.2.10", **win},
                {"family": "up", **win}, {"family": "dev_up", "query": "up", **win}):
        st, _, b = c.req("GET", "/trend/series?" + urllib.parse.urlencode(bad))
        check(f"推移: 拒否 {str(bad)[:60]}", st == 400, st)
    st, _, _ = c.req("POST", "/trend/series", {"Content-Type": "application/json"}, "{}")
    check("推移: POST は 405", st == 405, st)
    st, _, b = c.req("GET", "/logsearch/facets")
    check("ログ検索: facet", st == 200 and "severities" in ((js(b) or {}).get("data") or {}), st)
    st, _, b = c.req("GET", "/logsearch/lines?" + urllib.parse.urlencode({"limit": 20, **win}))
    d = (js(b) or {}).get("data") or {}
    ents = d.get("entries", [])
    check("ログ検索: 新しい順の行", st == 200 and ents and all(int(ents[i]["ts"]) >= int(ents[i + 1]["ts"]) for i in range(len(ents) - 1)),
          f"{st} {len(ents)} 行")
    word = next((w for e in ents for t, _ in e["parts"] for w in t.split() if len(w) >= 4 and w.isalpha()), "LAN")
    st, _, b = c.req("GET", "/logsearch/lines?" + urllib.parse.urlencode({"q": word.lower(), "limit": 20, **win}))
    d = (js(b) or {}).get("data") or {}
    hit = [e for e in d.get("entries", []) if any(h for _, h in e["parts"])]
    check(f"ログ検索: 語句 {word.lower()} (大小文字を区別しない、印付き)", st == 200 and hit and len(hit) == len(d["entries"]), f"{st} {len(hit)} 行")
    st, _, b = c.req("GET", "/logsearch/hist?" + urllib.parse.urlencode({"q": word, **win}))
    h = (js(b) or {}).get("data") or {}
    check("ログ検索: 件数の棒グラフ", st == 200 and len(h.get("counts", [])) == 60 and sum(h["counts"]) > 0, f"{st} {sum(h.get('counts', []))} 件")
    st, _, b = c.req("GET", "/logsearch/hist?" + urllib.parse.urlencode({"from": f"{now - 930.5:.1f}", "to": f"{now:.0f}"}))
    h = (js(b) or {}).get("data") or {}
    check("ログ検索: 棒グラフ (端数の最後の棒も数える)", st == 200 and len(h.get("counts", [])) == 16 and sum(h["counts"]) > 0, f"{st} {h.get('counts', [])[-3:]}")
    for bad in ({"q": "(a+)+$", "regex": "1"}, {"q": "192.0.2.10"}, {"host": 'rtx1300"} |= "x'}, {"q": "a", "regex": "1", "query": "x"}):
        st, _, b = c.req("GET", "/logsearch/lines?" + urllib.parse.urlencode({**bad, **win}))
        check(f"ログ検索: 拒否 {str(bad)[:50]}", st == 400, st)


def screens_open(c):
    st, _, b = c.req("GET", "/obs/exposure.json")
    check("exposure: open", st == 200 and (js(b) or {}).get("access") == "open", b[:80])
    common(c)
    unknown_path(c, "open")
    st, _, b = c.req("GET", "/am/ops")
    check("書き込み可 (127.0.0.1、ログインなし)", st == 200 and (js(b) or {}).get("writable") is True, b[:100])


def screens_auth(c):
    st, hd, _ = c.req("GET", "/am/ops", tls=False)
    check("HTTP -> HTTPS", st in (301, 302, 307, 308) and hd.get("location", "").startswith("https://"), f"{st} {hd.get('location')}")
    st, hd, _ = c.req("GET", "/")
    check("ログインなしでは開かない", st in (302, 303, 401) and st != 200, f"{st} {hd.get('location', '')}")
    st, _, b = c.req("GET", "/obs/exposure.json")
    check("exposure: auth (ログイン前に読めない)", st != 200, st)
    st, ok = c.login(os.environ.get("E2E_ADMIN", ""))
    check("admin ログイン (Authelia)", ok, st)
    if not ok:
        return
    sc = c.cookie
    flags = c.set_cookie.lower()
    check("cookie: Secure / HttpOnly / SameSite=Strict", all(f in flags for f in ("secure", "httponly", "samesite=strict")), c.set_cookie.split(";", 1)[-1])
    common(c)
    st, _, b = c.req("GET", "/am/ops")
    o = js(b) or {}
    check("admin: 役割と書き込み", st == 200 and o.get("role") == "admin" and o.get("writable") is True and o.get("auth") is True, b[:120])
    unknown_path(c, "admin")
    if os.environ.get("E2E_VIEWER"):
        v = Client(c.base, c.ca)
        st, ok = v.login(os.environ["E2E_VIEWER"])
        check("viewer ログイン", ok, st)
        st, _, b = v.req("GET", "/am/ops")
        o = js(b) or {}
        check("viewer: 読み取りだけ", st == 200 and o.get("role") == "viewer" and o.get("writable") is False, b[:120])
        unknown_path(v, "viewer")
    c.cookie = sc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("screens", "status"))
    ap.add_argument("--url", required=True)
    ap.add_argument("--ca", default=None)
    ap.add_argument("paths", nargs="*")
    # intermixed: `status --url U --ca C PATH...` (Python <= 3.12 leaves PATH unparsed with parse_args: what + paths
    # are matched together before the options, paths empty)
    a = ap.parse_intermixed_args()
    c = Client(a.url, a.ca)
    if a.what == "status":
        if c.tls:
            st, ok = c.login(os.environ.get("E2E_ADMIN", ""))
            print(f"login {st}")
        for p in a.paths:
            print(f"{p} {c.req('GET', p)[0]}")
        return 0
    (screens_auth if c.tls else screens_open)(c)
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
