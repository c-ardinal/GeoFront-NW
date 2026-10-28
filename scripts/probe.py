"""HTTP checks of the screens from the host, as a browser would reach them (stdlib only; python3 on the Pi).

  probe.py screens --url http://127.0.0.1:8080                      open mode: screens, APIs, Grafana admin, Host check
  probe.py screens --url https://192.0.2.10:8080 --ca root.crt  login: HTTPS with the proxy's CA, roles, Grafana admin
  probe.py status  --url ... [--ca ...] PATH...                     one line per PATH: its HTTP status (logged in as admin)
Secrets from the environment only: E2E_GF_PW (Grafana admin, open mode), E2E_ADMIN / E2E_VIEWER ("user:password").
Prints one line per check (OK / NG); exit 1 when any is NG."""
import argparse
import base64
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

RESULTS = []


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
    st, _, b = c.req("GET", "/grafana/api/health")
    check("Grafana health", st == 200, st)
    st, _, _ = c.req("GET", "/", host="evil.example:%d" % c.port)
    check("知らない Host -> 421", st == 421, st)


def screens_open(c):
    st, _, b = c.req("GET", "/obs/exposure.json")
    check("exposure: open", st == 200 and (js(b) or {}).get("access") == "open", b[:80])
    common(c)
    token = base64.b64encode(f"admin:{os.environ.get('E2E_GF_PW', '')}".encode()).decode()
    st, _, b = c.req("GET", "/grafana/api/user", {"Authorization": "Basic " + token})
    check("Grafana admin (GF_ADMIN_PASSWORD)", st == 200 and (js(b) or {}).get("isGrafanaAdmin") is True, st)
    st, _, b = c.req("GET", "/grafana/api/dashboards/uid/yamaha-wallboard")
    check("Grafana wallboard (匿名 Viewer)", st == 200, st)
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
    st, _, b = c.req("GET", "/grafana/api/user")
    u = js(b) or {}
    check("Grafana: admin として入れる (auth proxy)", st == 200 and u.get("login") == os.environ.get("E2E_ADMIN", "").split(":")[0], f"{st} {u.get('login')}")
    st, _, b = c.req("GET", "/grafana/api/dashboards/uid/yamaha-wallboard")
    check("Grafana wallboard (admin)", st == 200, st)
    if os.environ.get("E2E_VIEWER"):
        v = Client(c.base, c.ca)
        st, ok = v.login(os.environ["E2E_VIEWER"])
        check("viewer ログイン", ok, st)
        st, _, b = v.req("GET", "/am/ops")
        o = js(b) or {}
        check("viewer: 読み取りだけ", st == 200 and o.get("role") == "viewer" and o.get("writable") is False, b[:120])
        st, _, _ = v.req("GET", "/grafana/")
        check("viewer: Grafana は 403", st == 403, st)
    c.cookie = sc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("screens", "status"))
    ap.add_argument("--url", required=True)
    ap.add_argument("--ca", default=None)
    ap.add_argument("paths", nargs="*")
    a = ap.parse_args()
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
