"""Authentication (P7): Authelia behind the proxy's forward_auth, for the LAN.

  access mode   auth = a LAN exposure (OBS_BIND not 127.x / localhost) or OBS_AUTH=1; else open (127.0.0.1, no login).
                The same rule is in the proxy's and Authelia's entrypoints (compose.yaml) and in mask-api (auth_required).
  secrets       OBS_AUTH_SESSION_SECRET / OBS_AUTH_STORAGE_KEY (Authelia's session and storage encryption) and
                OBS_AUTH_PROXY_KEY (the proxy -> mask-api identity key): generated into .env by `tools init` / `tools
                user secrets`, nowhere else (Authelia gets them as environment variables).
  config        generated/authelia/configuration.yml, written by the setup step (`tools targets`) from .env: file users
                (argon2id), access only for the groups viewer / operator / admin, brute-force regulation, session
                cookie per screen host (Secure, HttpOnly, SameSite=Strict), optional TOTP (OBS_AUTH_TOTP=1).
  users         the authelia-data volume's users_database.yml, managed with `tools user add / passwd / remove / list`.
                Passwords are hashed here (argon2id, Authelia's own default parameters); no plain password is stored.
"""
import getpass
import ipaddress
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

import yaml
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

ROLES = ("viewer", "operator", "admin")  # Authelia groups; the proxy maps the highest one to X-Obs-Role
AUTHELIA_UID = 10091  # Authelia runs as this uid (compose.yaml); its data volume and users file belong to it
USER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")  # within mask-api's operator name rule ([A-Za-z0-9._@-]{1,64})
RESERVED_USERS = ("admin", "root", "local")  # admin: Grafana's own server admin (its auth proxy would log in as it); local: mask-api's "no login"
PASSWORD_MIN = 12
# Authelia's identity verification (TOTP registration) needs an e-mail address per user even with the filesystem notifier;
# nothing is ever sent (the code goes to notification.txt): a placeholder in the reserved .invalid domain by default
EMAIL_DOMAIN = "users.obs.invalid"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
# argon2id: 32 MiB, 3 passes, 4 lanes (above OWASP's minimum of 19 MiB / 2 passes; half of Authelia's 64 MiB default so that
# a few logins at once stay within a Raspberry Pi's small Authelia limit: 4 parallel logins at 64 MiB reached 256 MiB measured).
# Authelia verifies any argon2id hash with the parameters stored in it.
ARGON2 = {"time_cost": 3, "memory_cost": 32768, "parallelism": 4, "hash_len": 32, "salt_len": 16}
SECRETS = {"OBS_AUTH_SESSION_SECRET": 64, "OBS_AUTH_STORAGE_KEY": 64, "OBS_AUTH_PROXY_KEY": 43}  # name -> minimum length
DURATION_RE = re.compile(r"[1-9][0-9]{0,3}[smhd]")
DEFAULTS = {"OBS_AUTH_INACTIVITY": "30m", "OBS_AUTH_EXPIRATION": "12h", "OBS_AUTH_REMEMBER_ME": "0",
            "OBS_AUTH_MAX_RETRIES": "5", "OBS_AUTH_FIND_TIME": "10m", "OBS_AUTH_BAN_TIME": "15m", "OBS_AUTH_TOTP": "0"}


class AuthError(Exception):
    """A user-facing error (Japanese)."""


def setting(values, key):
    return values.get(key) or DEFAULTS[key]


def is_local_bind(bind):
    """localhost or a loopback IPv4 address (strict: the same rule as compose.yaml's entrypoints and mask-api); anything
    else, also a malformed value, is a LAN exposure."""
    if (bind or "127.0.0.1") == "localhost":
        return True
    try:
        return ipaddress.IPv4Address(bind or "127.0.0.1").is_loopback
    except ValueError:
        return False


def required(values):
    """Authentication is on: always on a LAN exposure, on 127.0.0.1 with OBS_AUTH=1."""
    return values.get("OBS_AUTH") == "1" or not is_local_bind(values.get("OBS_BIND", "127.0.0.1"))


def url_host_port(url):
    m = re.fullmatch(r"(https?)://([^/:\[\]]+|\[[0-9A-Fa-f:.]+\])(?::([0-9]{1,5}))?/?", url or "")
    return (m.group(1), m.group(2).lower(), m.group(3)) if m else (None, None, None)


def hosts(values):
    """-> [(host, port)] the screens answer for with authentication: OBS_PUBLIC_URL's host, then the bind address (both as
    the browser opens them). Same list as the proxy's entrypoint."""
    port = values.get("OBS_PORT", "8080")
    out = []
    _, h, p = url_host_port(values.get("OBS_PUBLIC_URL", ""))
    if h:
        out.append((h, p or "443"))
    bind = values.get("OBS_BIND", "127.0.0.1")
    if bind == "localhost":
        bind = "127.0.0.1"
    if bind not in ("", "0.0.0.0") and bind not in (x for x, _ in out):
        out.append((bind, port))
    return out


def cookie_host_ok(h):
    """Authelia's cookie domain rule: an IPv4 address or a name with at least one dot (not localhost / single labels)."""
    try:
        return ipaddress.ip_address(h).version == 4
    except ValueError:
        return "." in h and not h.endswith(".localhost") and re.fullmatch(r"[a-z0-9.-]+", h) is not None


def check(values):
    """-> (errors, warnings) of the authentication settings (only when authentication is on)."""
    if not required(values):
        return [], []
    errs, warns = [], []
    for key, n in SECRETS.items():
        v = values.get(key, "")
        if len(v) < n or not re.fullmatch(r"[A-Za-z0-9_-]+", v):
            errs.append(f"{key} がありません (または短すぎます)。docker compose run --rm tools user secrets で .env に作ってください")
    hs = hosts(values)
    if not hs:
        errs.append("認証を使うには OBS_PUBLIC_URL (例 https://192.168.100.10:8080) が必要です")
    for h, _ in hs:
        if not cookie_host_ok(h):
            errs.append(f"{h}: ログインの cookie を置けない名前です。IPv4 アドレスか、ドットを含む名前 (例 obs.home.arpa) で開いてください")
    scheme, _, _ = url_host_port(values.get("OBS_PUBLIC_URL", ""))
    if scheme == "http":
        warns.append("OBS_PUBLIC_URL が http:// です。認証ありの画面は https:// です (http は https に転送します)。https:// にしてください")
    for key in ("OBS_AUTH_INACTIVITY", "OBS_AUTH_EXPIRATION", "OBS_AUTH_FIND_TIME", "OBS_AUTH_BAN_TIME"):
        if not DURATION_RE.fullmatch(setting(values, key)):
            errs.append(f"{key}={values.get(key)}: 30m / 12h / 7d のような期間にしてください")
    rm = setting(values, "OBS_AUTH_REMEMBER_ME")
    if rm != "0" and not DURATION_RE.fullmatch(rm):
        errs.append(f"OBS_AUTH_REMEMBER_ME={rm}: 0 (使わない) か 7d のような期間にしてください")
    mr = setting(values, "OBS_AUTH_MAX_RETRIES")
    if not (mr.isdigit() and 1 <= int(mr) <= 20):
        errs.append(f"OBS_AUTH_MAX_RETRIES={mr}: 1〜20 にしてください (0 = 締め出しなし は使えません)")
    if setting(values, "OBS_AUTH_TOTP") not in ("0", "1"):
        errs.append("OBS_AUTH_TOTP は 0 か 1 にしてください")
    return errs, warns


def authelia_config(values):
    """The generated configuration.yml (no secrets: Authelia reads them from its environment)."""
    two = setting(values, "OBS_AUTH_TOTP") == "1"
    hs = hosts(values)
    url = lambda h, p, path: f"https://{h}{'' if p == '443' else ':' + p}{path}"
    rm = setting(values, "OBS_AUTH_REMEMBER_ME")
    return {
        "theme": "auto",
        "server": {"address": "tcp://:9091/auth", "endpoints": {"authz": {"forward-auth": {"implementation": "ForwardAuth"}}}},
        "log": {"level": "info"},
        "ntp": {"disable_startup_check": True},  # no outbound NTP query from the LAN box
        "authentication_backend": {
            "password_reset": {"disable": True},
            "refresh_interval": "always",  # a removed user or a changed role applies at the next request
            "file": {"path": "/config/users_database.yml", "watch": True,
                     "password": {"algorithm": "argon2", "argon2": {"variant": "argon2id", "iterations": ARGON2["time_cost"],
                                                                   "memory": ARGON2["memory_cost"], "parallelism": ARGON2["parallelism"],
                                                                   "key_length": ARGON2["hash_len"], "salt_length": ARGON2["salt_len"]}}}},
        "access_control": {"default_policy": "deny",
                           "rules": [{"domain": [h for h, _ in hs], "subject": [[f"group:{r}"] for r in ROLES],
                                      "policy": "two_factor" if two else "one_factor"}]},
        "session": {"name": "obs_session", "same_site": "strict", "inactivity": setting(values, "OBS_AUTH_INACTIVITY"),
                    "expiration": setting(values, "OBS_AUTH_EXPIRATION"), "remember_me": -1 if rm == "0" else rm,
                    "cookies": [{"domain": h, "authelia_url": url(h, p, "/auth"), "default_redirection_url": url(h, p, "/")} for h, p in hs]},
        "regulation": {"modes": ["user", "ip"], "max_retries": int(setting(values, "OBS_AUTH_MAX_RETRIES")),
                       "find_time": setting(values, "OBS_AUTH_FIND_TIME"), "ban_time": setting(values, "OBS_AUTH_BAN_TIME")},
        "storage": {"local": {"path": "/config/db.sqlite3"}},
        # TOTP registration codes: written to this file in the volume (README: how to read it)
        "notifier": {"filesystem": {"filename": "/config/notification.txt"}},
        "totp": {"disable": not two, "issuer": "NETWORK OBSERVATORY"},
        "webauthn": {"disable": True},
    }


def config_text(values):
    return ("# Generated by `tools targets` (tools/auth.py) from .env. Do not edit. Secrets: Authelia's environment only.\n"
            + yaml.safe_dump(authelia_config(values), sort_keys=False, allow_unicode=True))


def missing_secrets(values):
    """-> {name: new value} for every secret that is not there yet (existing ones are never replaced)."""
    return {k: secrets.token_urlsafe(n) for k, n in SECRETS.items() if len(values.get(k, "")) < n}


# ---- users file (authelia-data volume) ------------------------------------------------------------------

def hasher():
    return PasswordHasher(type=Type.ID, **ARGON2)


def hash_password(pw):
    return hasher().hash(pw)


def verify(stored, pw):
    try:
        return hasher().verify(stored, pw)
    except VerifyMismatchError:
        return False


def check_password(pw, name=""):
    if len(pw) < PASSWORD_MIN:
        raise AuthError(f"パスワードは {PASSWORD_MIN} 文字以上にしてください")
    if name and name.lower() in pw.lower():
        raise AuthError("パスワードに利用者名を含めないでください")
    if any(ord(c) < 32 for c in pw):
        raise AuthError("パスワードに制御文字は使えません")


def check_name(name):
    if not USER_RE.fullmatch(name or ""):
        raise AuthError(f"利用者名 {name!r}: 英小文字・数字で始まる 1〜32 文字 (英小文字・数字・. _ -) にしてください")
    if name in RESERVED_USERS:
        raise AuthError(f"利用者名 {name} は予約語です (Grafana の管理者 / ログインなしの表示名と重なるため)。別の名前にしてください")


def load_users(path):
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    users = data.get("users") or {}
    if not isinstance(users, dict):
        raise AuthError(f"{path.name} の形式が違います (users: の下に利用者)")
    return users


def fix_volume(path):
    """Authelia's data volume belongs to its uid (a volume first created by a tools run is root's). Every start (setup-check)."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0 and path.is_dir()):
        return
    for p in (path, *path.iterdir()):
        try:
            os.chown(p, AUTHELIA_UID, AUTHELIA_UID, follow_symlinks=False)
        except OSError:
            pass


def save_users(path, users):
    """Atomic, owner-only (Authelia's uid when run as root); Authelia notices the change (watch) and reloads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = ("# Authelia users (tools user add / passwd / remove). Passwords: argon2id hashes only.\n"
            + yaml.safe_dump({"users": users}, sort_keys=True, allow_unicode=True))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".users-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())  # on disk before it replaces the old file (power loss on a Pi)
    os.chmod(tmp, 0o600)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(tmp, AUTHELIA_UID, AUTHELIA_UID)
    os.replace(tmp, path)
    fix_volume(path.parent)


def role_of(user):
    groups = user.get("groups") or []
    return next((r for r in reversed(ROLES) if r in groups), "-")


def email_of(name, email=""):
    email = email or f"{name}@{EMAIL_DOMAIN}"
    if not EMAIL_RE.fullmatch(email):
        raise AuthError(f"メールアドレス {email!r} の形が違います")
    return email


def add(users, name, role, pw, display="", email=""):
    check_name(name)
    if name in users:
        raise AuthError(f"利用者 {name} は既にいます (パスワードの変更は tools user passwd {name})")
    if role not in ROLES:
        raise AuthError(f"役割は {' / '.join(ROLES)} のどれかです")
    check_password(pw, name)
    return {**users, name: {"displayname": display or name, "password": hash_password(pw), "email": email_of(name, email),
                            "groups": [role], "disabled": False}}


def passwd(users, name, pw, role=None):
    if name not in users:
        raise AuthError(f"利用者 {name} はいません")
    u = {"email": email_of(name), **users[name]}  # (users made before the e-mail was recorded get the placeholder)
    if pw is not None:
        check_password(pw, name)
        u["password"] = hash_password(pw)
    if role is not None:
        if role not in ROLES:
            raise AuthError(f"役割は {' / '.join(ROLES)} のどれかです")
        u["groups"] = [role]
    return {**users, name: u}


def remove(users, name):
    if name not in users:
        raise AuthError(f"利用者 {name} はいません")
    return {k: v for k, v in users.items() if k != name}


def read_password(env_value, name):
    """The new password: OBS_USER_PASSWORD (non-interactive: docker compose run -e OBS_USER_PASSWORD=...), else asked twice."""
    if env_value:
        return env_value
    if not sys.stdin.isatty():
        raise AuthError("パスワードを入力できません (TTY なし)。-e OBS_USER_PASSWORD=... で渡してください")
    pw = getpass.getpass(f"{name} の新しいパスワード ({PASSWORD_MIN} 文字以上): ")
    if getpass.getpass("もう一度: ") != pw:
        raise AuthError("2 回の入力が一致しません")
    return pw


# ---- self-test ------------------------------------------------------------------------------------------

# made by Authelia itself: `authelia crypto hash generate argon2 --variant argon2id --iterations 3 --memory 65536
# --parallelism 4 --password 'p7-selftest-Pw!'` (authelia/authelia:4.39.28): the two implementations agree
AUTHELIA_VECTOR = ("p7-selftest-Pw!", "$argon2id$v=19$m=65536,t=3,p=4$CRDeXlNmpWRzbfBCDg7hCw$K0RpbyWWpU/PkWwHjjnfvQfQ6jEgFvcTrD6WC0tQTS4")


def selftest():
    pw, vec = AUTHELIA_VECTOR
    assert verify(vec, pw) and not verify(vec, pw + "x")  # Authelia's hash verifies here
    h = hash_password("correct horse battery")
    assert h.startswith("$argon2id$v=19$m=32768,t=3,p=4$") and verify(h, "correct horse battery") and not verify(h, "wrong horse battery")
    assert hash_password("correct horse battery") != h  # salted
    users = add({}, "alice", "operator", "Wonder-pass-123", "Alice")
    assert users["alice"]["groups"] == ["operator"] and users["alice"]["displayname"] == "Alice" and "Wonder-pass-123" not in str(users)
    assert users["alice"]["email"] == "alice@users.obs.invalid"  # TOTP registration needs an address (nothing is sent)
    assert add({}, "carol", "viewer", "Quiet-pass-123", email="c@home.example")["carol"]["email"] == "c@home.example"
    old = {"dave": {k: v for k, v in add({}, "dave", "viewer", "Quiet-pass-123")["dave"].items() if k != "email"}}
    assert passwd(old, "dave", None, role="operator")["dave"]["email"] == "dave@users.obs.invalid"
    try:
        add({}, "erin", "viewer", "Quiet-pass-123", email="not-an-address")
        raise AssertionError("bad e-mail accepted")
    except AuthError:
        pass
    assert verify(users["alice"]["password"], "Wonder-pass-123") and role_of(users["alice"]) == "operator"
    for bad in (("Bob", "viewer", "x" * 12), ("admin", "admin", "x" * 12), ("local", "viewer", "x" * 12), ("a b", "viewer", "x" * 12),
                ("bob", "root", "x" * 12), ("bob", "viewer", "short"), ("bob", "viewer", "my-bob-password"), ("alice", "viewer", "x" * 12),
                ("bob", "viewer", "tab\there-12345"), ("", "viewer", "x" * 12)):
        try:
            add(users, *bad)
            raise AssertionError(bad)
        except AuthError:
            pass
    users = add(users, "bob", "viewer", "Blue-pass-12345")
    users2 = passwd(users, "bob", "Green-pass-678", role="admin")
    assert verify(users2["bob"]["password"], "Green-pass-678") and role_of(users2["bob"]) == "admin" and users["bob"]["groups"] == ["viewer"]
    assert role_of(passwd(users, "bob", None, role="operator")["bob"]) == "operator"
    assert set(remove(users2, "bob")) == {"alice"}
    for fn in (lambda: passwd(users, "nobody", "x" * 12), lambda: remove(users, "nobody"), lambda: passwd(users, "bob", "x" * 12, role="root")):
        try:
            fn()
            raise AssertionError("accepted")
        except AuthError:
            pass
    assert role_of({"groups": ["viewer", "admin"]}) == "admin" and role_of({"groups": ["dev"]}) == "-"
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp, "users_database.yml")
        assert load_users(p) == {}
        save_users(p, users)
        assert load_users(p) == users and p.stat().st_mode & 0o777 == 0o600 and "Blue-pass-12345" not in p.read_text()
        p.write_text("users: [1]\n")
        try:
            load_users(p)
            raise AssertionError("bad users file accepted")
        except AuthError:
            pass
    # access mode, hosts and the generated Authelia configuration
    lan = {"OBS_BIND": "192.168.100.10", "OBS_PORT": "8080", "OBS_PUBLIC_URL": "https://192.168.100.10:8080", **missing_secrets({})}
    assert required(lan) and required({"OBS_AUTH": "1"}) and not required({}) and not required({"OBS_BIND": "127.0.0.1", "OBS_AUTH": "0"})
    assert all(required({"OBS_BIND": b}) for b in ("127.evil", "127.0.0.01", "127.0.0.256", "0.0.0.0", "192.168.1.2"))
    assert not required({"OBS_BIND": "127.1.2.3"}) and not required({"OBS_BIND": "localhost"})
    assert hosts(lan) == [("192.168.100.10", "8080")] and check(lan) == ([], [])
    assert hosts({**lan, "OBS_BIND": "0.0.0.0", "OBS_PUBLIC_URL": "https://obs.home.arpa"}) == [("obs.home.arpa", "443")]
    assert hosts({"OBS_AUTH": "1", "OBS_BIND": "127.0.0.1", "OBS_PORT": "8080"}) == [("127.0.0.1", "8080")]
    cfg = authelia_config(lan)
    assert cfg["access_control"]["default_policy"] == "deny" and cfg["access_control"]["rules"][0]["subject"] == [["group:viewer"], ["group:operator"], ["group:admin"]]
    assert cfg["session"]["cookies"] == [{"domain": "192.168.100.10", "authelia_url": "https://192.168.100.10:8080/auth", "default_redirection_url": "https://192.168.100.10:8080/"}]
    assert cfg["session"]["same_site"] == "strict" and cfg["session"]["remember_me"] == -1 and cfg["regulation"]["max_retries"] == 5
    assert cfg["totp"]["disable"] and cfg["access_control"]["rules"][0]["policy"] == "one_factor"
    two = authelia_config({**lan, "OBS_AUTH_TOTP": "1", "OBS_AUTH_REMEMBER_ME": "7d"})
    assert not two["totp"]["disable"] and two["access_control"]["rules"][0]["policy"] == "two_factor" and two["session"]["remember_me"] == "7d"
    text = config_text(lan)
    assert all(lan[k] not in text for k in SECRETS) and yaml.safe_load(text) == cfg  # no secret in the generated file
    assert any("OBS_AUTH_PROXY_KEY" in e for e in check({**lan, "OBS_AUTH_PROXY_KEY": "short"})[0])
    assert check({**lan, "OBS_PUBLIC_URL": "https://raspberrypi:8080", "OBS_BIND": "0.0.0.0"})[0]  # no dot: no cookie
    assert check({**lan, "OBS_BIND": "0.0.0.0", "OBS_PUBLIC_URL": ""})[0]
    assert check({**lan, "OBS_PUBLIC_URL": "http://192.168.100.10:8080"})[1]
    for k, v in (("OBS_AUTH_MAX_RETRIES", "0"), ("OBS_AUTH_BAN_TIME", "forever"), ("OBS_AUTH_TOTP", "yes"), ("OBS_AUTH_REMEMBER_ME", "-1")):
        assert check({**lan, k: v})[0], (k, v)
    s = missing_secrets({"OBS_AUTH_PROXY_KEY": "k" * 50})
    assert set(s) == {"OBS_AUTH_SESSION_SECRET", "OBS_AUTH_STORAGE_KEY"} and all(len(v) >= SECRETS[k] for k, v in s.items())
    assert cookie_host_ok("192.168.1.2") and cookie_host_ok("obs.home.arpa") and not cookie_host_ok("localhost") and not cookie_host_ok("[fd00::1]")
    print("auth selftest ok")
