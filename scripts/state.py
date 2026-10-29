"""State of the stored data at one time, as JSON, for comparing two projects (backup -> restore, old -> new version).
Runs in the tools container (internal network + the data volumes under /vol), stdlib only:
  docker compose run --rm -T --entrypoint python tools /work/scripts/state.py --at <unix seconds> [--make-silence <comment>]
Prints hashes of secrets (CA key, users file), never their values."""
import argparse
import hashlib
import json
import sqlite3
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

VOL = Path("/vol")


def get(url, timeout=20):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def prom(q, at):
    try:
        res = get("http://prometheus:9090/api/v1/query?" + urllib.parse.urlencode({"query": q, "time": at}))["data"]["result"]
        return res[0]["value"][1] if res else None
    except OSError as e:
        return f"error {type(e).__name__}"


def loki(q, at):
    try:
        res = get("http://loki:3100/loki/api/v1/query?" + urllib.parse.urlencode({"query": q, "time": int(at * 1e9)}))["data"]["result"]
        return res[0]["value"][1] if res else None
    except OSError as e:
        return f"error {type(e).__name__}"


def silences():
    try:
        return sorted((s["id"], s["comment"]) for s in get("http://alertmanager:9093/api/v2/silences") if s["status"]["state"] == "active")
    except OSError as e:
        return f"error {type(e).__name__}"


def make_silence(comment):
    end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))
    body = json.dumps({"matchers": [{"name": "alertname", "value": "H1StateCheck", "isRegex": False, "isEqual": True}],
                       "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "endsAt": end,
                       "createdBy": "scripts/state.py", "comment": comment}).encode()
    req = urllib.request.Request("http://alertmanager:9093/api/v2/silences", body, {"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())["silenceID"]


def sqlite_rows(path, query):
    if not path.exists():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        dst = sqlite3.connect(Path(tmp) / "c.db")
        try:
            src.backup(dst)
            return [list(r) for r in dst.execute(query)]
        except sqlite3.Error as e:
            return f"error {e}"
        finally:
            src.close()
            dst.close()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16] if path.exists() else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--at", type=float, default=time.time())
    ap.add_argument("--make-silence", default="")
    a = ap.parse_args()
    if a.make_silence:
        print(json.dumps({"silence": make_silence(a.make_silence)}))
        return
    pki = VOL / "caddy/caddy/pki/authorities/local"
    out = {
        "prom_up_samples_10m": prom("sum(count_over_time(up[10m]))", a.at),
        "prom_ifHCInOctets": prom("sum(ifHCInOctets)", a.at),
        "loki_syslog_lines_10m": loki('sum(count_over_time({job="syslog"}[10m]))', a.at),
        "silences": silences(),
        "authelia_users_sha": sha(VOL / "authelia/users_database.yml"),
        "authelia_auth_logs": sqlite_rows(VOL / "authelia/db.sqlite3", "SELECT count(*) FROM authentication_logs"),
        "ca_root_sha": sha(pki / "root.crt"),
        "ca_key_sha": sha(pki / "root.key"),
    }
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
