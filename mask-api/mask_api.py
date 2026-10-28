"""Masking read-only proxy between the command-center (nginx) and Prometheus/Loki.

The browser never talks to Prometheus/Loki directly: every /prom/ and /loki/ request goes
through here. Only GET on an allowlisted path is forwarded; every JSON string in the response
(label names/values, log lines, rule expressions) is masked (NFR-09). A value that is exactly one address keeps a
structured mask with an opaque token, so the UI can still tell addresses apart and drill down: a.b.c.x~<token>,
<first 64 bits>::x~<token>, aa:bb:cc:xx:xx:xx. Free text is masked by shape only (see "text masking" below): a standalone
IPv4 keeps a.b.c.x (+ its port), a 6-pair MAC aa:bb:cc:xx:xx:xx, anything else address-like becomes "x".

Queries cannot test hidden digits:
- Loki: only the shapes the UI sends are accepted (stream selector on known labels with equality,
  optional |= / != line filters, or the two severity count aggregations). Only the selector goes to
  Loki; line filters are applied here to the already-masked lines, so a filter can only ever match
  text the user can already see.
- Prometheus: string literals are only allowed as = / != label-matcher values and must not contain a
  full or partial address (tokens are resolved here); regex matchers and the functions that read or
  copy label text are rejected.

Alertmanager (/am/, from the proxy): the alert and silence lists are read the same way (masked); the one write path
is the silence allowlist (create / extend / expire, for ACK and 抑止), see the "Alertmanager" section.

Packet analysis (/pcap/, from the proxy): pcap_api.py, sharing this module's tokens, masking and write guards.

Evidence export (/evidence/, from the proxy): evidence.py builds a zip from this module's own read paths (GET); the one
POST adds the browser's screen snapshot (PNG) to it, under the same write rules as the silences.

notify-relay's records ({job="notify"}): the relay writes an address label value as a.b.c.x~<token> with this module's
key (shared through the token-key volume, see shared_key); such a token is kept only when it checks out with the current
key (mask_line), so the screens match the record to the same device.

原因候補 (/correlate/, from the proxy, GET only): correlate.py lists what happened around a moment, read the same way.

Run: python mask_api.py            (listens on :8000)
     python mask_api.py --selftest
"""
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import secrets
import select
import socket
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import OrderedDict
from typing import NamedTuple

import correlate
import evidence
import pcap_api

PROM = os.environ.get("PROM_URL", "http://prometheus:9090")
LOKI = os.environ.get("LOKI_URL", "http://loki:3100")
TIMEOUT_S = 12  # below nginx proxy_read_timeout (15 s) so the client gets our error, not nginx's
MAX_BYTES = 32 * 1024 * 1024
LOKI_MAX_LINES = 5000  # Loki's default max_entries_limit_per_query
SCAN_MAX_LINES = 100000  # filtered logs/counts: raw lines read from Loki per request at most (demo 6 h window ~ 67k lines)
SCAN_DEADLINE_S = 9  # total budget for all Loki pages of one filtered request (each page's timeout is cut to what is left), beats nginx's 15 s
COUNT_AGG_GRACE_S = 2  # counting may run this long past the paging budget (9 + 2 s still beats nginx)
PAGE_OVERLAP_NS = 10**9  # filtered scans: each next Loki page re-reads this far back over the last page's edge
MAX_EVALS = 11000  # evaluation points per filtered count query (Loki's own limit)

PROM_QUERY = {"/prom/api/v1/query": PROM + "/api/v1/query", "/prom/api/v1/query_range": PROM + "/api/v1/query_range"}
PROM_PLAIN = {"/prom/api/v1/alerts": PROM + "/api/v1/alerts", "/prom/api/v1/rules": PROM + "/api/v1/rules"}
LOKI_RANGE = "/loki/loki/api/v1/query_range"

# Exact values (one IPv4 / MAC label value; pcap_api) and the literal checks. Free text is masked by mask_text.
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?!\d)")
MAC = re.compile(r"(?<!\d)(?<![0-9A-Fa-f][:-])([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}(?!\d)(?![:-][0-9A-Fa-f])")
# ---- text masking: shape only, fail closed --------------------------------------------------------------------------
# Free text (log lines, annotations, any string that is not exactly one address) is cut into runs over
# [0-9A-Fa-f:.-] after normalising for classification: invisible / combining / variation characters are dropped,
# full-width and other Unicode digits / letters / dot and colon look-alikes (。 ｡ ． ﹒ ： ﹕ ∶ ...) count as ASCII,
# Unicode spaces as a space. A run is classified by its shape only - nothing in this path parses an address, so nothing
# can raise. Kept partial forms (all standalone: no letter, digit or "._:-" right next to them):
#   - a dotted quad a.b.c.d (octets 0-255) -> a.b.c.x, also with ":port" (a.b.c.x:443), a trailing ":" / ".", and
#     YAMAHA's ".port" when that reading is the only one (exactly 5 groups and the last > 255: no octet)
#   - a MAC of exactly 6 pairs with one separator (":" or "-") -> aa:bb:cc:xx:xx:xx
# Kept as is: clock times / time ranges, dates, host:port (one ":", decimal port), runs with at most one hex group
# (std::string, ".443", "::"), silence ids (UUID), a quoted 16-hex Alertmanager fingerprint, already masked forms,
# a string that is only a number (JSON values, timestamps, counters - also one of 12 digits: values are never masked).
# Everything else that looks like an address -> "x": 2+ ":" with 2+ groups, 3+ hex groups joined by ":" / "-", any
# other dotted digits of 4+ groups (overlong octets too), Cisco aaaa.bbbb.cccc, 8+ hex characters with a digit, and
# inside text a bounded run of exactly 12 digits (a MAC written as digits).
# Structured masks (IPv6 /64 + token) exist only for label values that ARE one address (mask_value).
# Any exception while masking masks the whole string as "x" (fail closed; a response is never lost to it).
FREE_RUN = re.compile(r"[0-9A-Fa-f:.\-]{3,}")  # shorter runs hold nothing address-like
SEPS = re.compile(r"[:.\-]")
QUAD_FORM = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?([:.])?")
QUAD_DOTPORT = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,5})")
MAC_FORM = re.compile(r"([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}([:.])?")
MASKED_MAC_PREFIX = re.compile(r"[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1")
ANY_DOTTED = re.compile(r"\d+\.\d+\.\d+\.\d+")
CISCO = re.compile(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}")
_T = r"(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?"  # a real clock time (00:00-23:59:59.f): not 33:44:55
TIME_RUN = re.compile(_T)
TIME_RANGE = re.compile(_T + "-" + _T)  # ponytail: a MAC with mixed separators that reads as two clock times stays
DATE_RUN = re.compile(r"\d{4}-\d{2}-\d{2}")
HOST_PORT = re.compile(r"[0-9A-Fa-f]*:\d{1,5}")
FINGERPRINT = re.compile(r"[0-9a-f]{16}")
UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")  # silence ids
MASKED_V4_RUN = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.")  # a.b.c. before the "x"
NUMBER = re.compile(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
STANDALONE_EDGE = re.compile(r"[0-9A-Za-z.:_\-]")
# masked forms the screens are given (exact label values; also cut out before checking a query literal for raw parts)
MASKED_ANY = re.compile(r"(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,3})?::x|(?:::ffff:|64:ff9b::)?\d{1,3}\.\d{1,3}\.\d{1,3}\.x"
                        r"|[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1xx\1xx\1xx)(?:~[0-9a-f]{12})?")
# characters that render as nothing (or only modify the previous one): dropped before classifying
_INVISIBLE_CATS = {"Cf", "Mn", "Me", "Cc", "Cn"}  # Cn: unassigned (U+2065, U+FFF0-FFF8, U+E0000...)
_INVISIBLE = {"\u3164", "⠀", "ᅟ", "ᅠ", "ﾠ", "᠎"} | {chr(c) for c in range(0xFE00, 0xFE10)}
# look-alikes NFKC leaves alone
_LOOKALIKE = {"。": ".", "\u00b7": ".", "\u2022": ".", "\u30fb": ".", "\uff65": ".", "\u2026": ".", "\u2025": ".", "\u066b": ".", "\u066c": ".", "\u06d4": ".", "\u2e31": ".", "\u0387": ".", "\u2219": ".", "｡": ".", "․": ".", "‧": ".", "܁": ".", "܂": ".", "ꓸ": ".",
              "∶": ":", "꞉": ":", "ː": ":", "׃": ":", "܃": ":", "܄": ":", "፡": ":", "︰": ":",
              "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-", "﹣": "-", "－": "-"}
TOKEN_LEN = 12
# Masked IPv4 as sent to the browser: a.b.c.x, or a.b.c.x~<token> for a value that was exactly one address.
MASKED_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.x(?:~([0-9a-f]{%d}))?\b" % TOKEN_LEN)
MASKED_MAC = re.compile(r"\b([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2xx\2xx\2xx\b")
TOKEN_REF = re.compile(r"[.:]x~(\w*)")
# masked IPv6 as flowd labels it (and as text masking writes it): <up to 64 bits>::x, ::ffff:/64:ff9b:: + masked IPv4
MASKED_V6 = re.compile(r"(?<![0-9A-Fa-f:.])(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,3})?::x|(?:::ffff:|64:ff9b::)\d{1,3}\.\d{1,3}\.\d{1,3}\.x)"
                       r"(?:~([0-9a-f]{%d}))?(?![0-9A-Za-z_:])" % TOKEN_LEN)
# hex groups with colons that could narrow a hidden IPv6 part: "::" with a hex digit, or a group mixing a-f and digits
HEXCOLON = re.compile(r"(?<![0-9A-Za-z_])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4})+(?![0-9A-Za-z_])")
# What is left of a literal once masked forms are removed must not narrow a hidden part:
# no digit.digit (a partial IPv4 such as "113.50") and no 4+ hex pairs (a partial MAC).
FRAGMENT = re.compile(r"\d\.\d|\b[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){2}\b")

STRING = r'''"(?:[^"\\]|\\.)*"|`[^`]*`|'(?:[^'\\]|\\.)*\''''
# PromQL: regex matchers, and functions that read, copy, sort or hash label text (some experimental).
PROM_FORBIDDEN = re.compile(r"=~|!~|\b(?:label_replace|label_join|sort_by_label|sort_by_label_desc|info|limitk|limit_ratio|count_values)\b")
PROM_MATCHER_LHS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*!?=\s*$")
PROM_LITERAL = re.compile(r"(!=|=)(\s*)(" + STRING + ")")
PROM_TIME = re.compile(r"\d+(?:\.\d+)?[smhdwy]?")

# LogQL: the exact shapes the UI sends.
LOKI_STR = r'"(?:[^"\\]|\\.)*"|`[^`]*`'
LOKI_MATCHER = r"\s*(job|host|severity|facility)\s*=\s*(" + LOKI_STR + r")\s*"
LOKI_MATCHER_NC = r"\s*(?:job|host|severity|facility)\s*=\s*(?:" + LOKI_STR + r")\s*"
LOKI_SEL = r"\{" + LOKI_MATCHER_NC + r"(?:," + LOKI_MATCHER_NC + r")*\}"
LOKI_FILTER = r"\s*(\|=|!=)\s*(" + LOKI_STR + ")"
LOKI_LOG = re.compile(r"\s*(" + LOKI_SEL + r")((?:\s*(?:\|=|!=)\s*(?:" + LOKI_STR + r"))*)\s*")
LOKI_METRIC = re.compile(r"\s*sum\s+by\s*\(\s*(severity|host\s*,\s*severity)\s*\)\s*\(\s*count_over_time\s*\(\s*(" + LOKI_SEL +
                         r")((?:\s*(?:\|=|!=)\s*(?:" + LOKI_STR + r"))*)\s*\[\s*(\d{1,6}[smh])\s*\]\s*\)\s*\)\s*")
LOKI_PARAMS = {"query", "start", "end", "limit", "direction", "step"}

REJECT_MSG = "full or partial IP/MAC addresses, regex matchers and other query forms are not searchable; filter by the masked form (e.g. 192.0.2.x)"
TOKEN_MSG = "unknown or expired address token; reload the page"

# Opaque per-address tokens keep distinct addresses distinct in the UI (rows, keys, drill-downs)
# without revealing them. The key is random per process, so tokens expire on restart (shared_key: shared with
# notify-relay through a memory-only volume, and kept while that volume stays mounted).
KEY = secrets.token_bytes(32)
KEY_FILE = os.environ.get("OBS_TOKEN_KEY_FILE", "")  # compose: /run/obs-key/token.key (tmpfs volume token-key)
MAX_TOKENS = 65536


def shared_key(path, key):
    """-> the token key of this process. A valid key already in path (written by an earlier mask-api process while the
    memory-only volume stayed mounted) is reused, so tokens and notify-relay's records stay comparable across a restart of
    mask-api alone; else key is written there for notify-relay (readable by it, the only other container mounting the
    volume, read-only). No path / not writable: key stays private (notify-relay then records a.b.c.x)."""
    if not path:
        return key
    try:
        with open(path, "rb") as f:
            old = f.read(64)
        if len(old) == 32:
            return old
    except OSError:
        pass
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        os.replace(tmp, path)
    except OSError as e:
        print(f"token key not shared ({type(e).__name__}): notify-relay records addresses without tokens", file=sys.stderr)
    return key


class TokenStore(OrderedDict):
    """token -> address, most recently used kept: past MAX_TOKENS the oldest token is forgotten, so a flood of new
    addresses (a large pcap) cannot use up the table. A forgotten token only means an old screen's drill-down or
    silence asks to reload ("unknown or expired address token")."""

    lock = threading.Lock()  # request threads share the table: check + move / evict as one step
    pins = threading.local()  # .d: {token: address} collector of this thread (pcap_api.with_tokens), or None

    def __setitem__(self, k, v):
        got = getattr(self.pins, "d", None)
        if got is not None:
            got[k] = v
        with self.lock:
            if k in self:
                self.move_to_end(k)
            super().__setitem__(k, v)
            while len(self) > MAX_TOKENS:
                self.popitem(last=False)

    def get(self, k, default=None):
        with self.lock:
            if k in self:
                self.move_to_end(k)
                return super().__getitem__(k)
            return default


TOKENS = TokenStore()  # written only by the masking (mask_json / pcap_api), from addresses the services returned


class Rejected(ValueError):
    pass


def v6_base(ip):
    """pcap_api.v6_base without building network objects per call (label values): IPv4-mapped / NAT64 keep the masked
    IPv4, 6to4 / Teredo hide everything, else the /64 + "::x" (compressed like ipaddress)."""
    n = int(ip)
    v4 = n & 0xFFFFFFFF
    q = f"{v4 >> 24}.{(v4 >> 16) & 255}.{(v4 >> 8) & 255}.x"
    if n >> 32 == 0xFFFF:
        return "::ffff:" + q
    if n >> 32 == 0x64FF9B << 64:
        return "64:ff9b::" + q
    if n >> 112 == 0x2002:
        return "2002::x"
    if n >> 96 == 0x20010000:
        return "2001::x"
    g = [(n >> (112 - 16 * i)) & 0xFFFF for i in range(4)]
    while g and not g[-1]:
        g.pop()
    return ":".join(f"{x:x}" for x in g) + "::x"


_CHAR = {}  # non-ASCII char -> its ASCII stand-in for classification (one char -> one char)


def _ascii_char(c):
    m = _CHAR.get(c)
    if m is None:
        k = unicodedata.normalize("NFKC", c)
        if c in _LOOKALIKE:
            m = _LOOKALIKE[c]
        elif len(k) == 1 and k.isascii() and (k.isalnum() or k in ":.-"):
            m = k
        elif unicodedata.decimal(c, None) is not None:
            m = str(unicodedata.decimal(c))
        elif unicodedata.category(c) == "Zs":
            m = " "
        else:
            m = c
        if len(_CHAR) < 4096:
            _CHAR[c] = m
    return m


def _invisible(c):
    return c in _INVISIBLE or unicodedata.category(c) in _INVISIBLE_CATS


def _edge(c):
    return bool(c) and bool(STANDALONE_EDGE.match(c))


def _long_hex(g, quoted=False):
    """8+ hex mixing a digit in (IPv4 / MAC / IPv6 written as one word: c0000201, 0011aabbccdd), or 12 digits (a MAC of
    digits only). Not: shorter numbers, a quoted 16-hex Alertmanager fingerprint (ponytail: an IPv6 half written that
    way, in quotes, would pass)."""
    if len(g) < 8 or len(g) == 16 and quoted:
        return False
    if g.isdigit():
        return len(g) == 12
    return any(ch.isdigit() for ch in g)


def _keep_quad(q, before, after):
    return not _edge(before) and not _edge(after) and all(int(x) <= 255 for x in q[:4])


def _free_run(r, s, start, end):
    """One run of the normalised text s at [start, end) -> its masked form."""
    before, after = s[start - 1:start], s[end:end + 1]
    if TIME_RUN.fullmatch(r) or DATE_RUN.fullmatch(r):  # the commonest runs in a log line
        return r
    # the kept partial forms: standalone IPv4 (+ :port, + a trailing ":" / "."), YAMAHA's a.b.c.d.port, a 6-pair MAC
    q = QUAD_FORM.fullmatch(r)
    if q:
        a, b, c, d, port, punct = q.groups()
        return f"{a}.{b}.{c}.x" + (f":{port}" if port else "") + (punct or "") if _keep_quad((a, b, c, d), before, after) else "x"
    q = QUAD_DOTPORT.fullmatch(r)
    if q:
        a, b, c, d, port = q.groups()
        sure = int(port) > 255  # a port that cannot be an octet: 1.192.0.2.1 must not read as 1.192.0.x + .1
        return f"{a}.{b}.{c}.x.{port}" if sure and _keep_quad((a, b, c, d), before, after) else "x"
    mac = MAC_FORM.fullmatch(r)
    if mac:
        return f"{mac.group(1)}{mac.group(2)}xx{mac.group(2)}xx{mac.group(2)}xx" + (mac.group(3) or "") if not _edge(before) and not _edge(after) else "x"
    if after == "x" and not _edge(before):  # the visible part of a form written by this masking (the "x" follows)
        if MASKED_V4_RUN.fullmatch(r):
            return r
        if MASKED_MAC_PREFIX.fullmatch(r) and s[end:end + 8] == "xx{0}xx{0}xx".format(r[2]):
            return r
    nc = r.count(":")
    if nc < 2 and r.count(".") < 3 and nc + r.count("-") < 2:  # no quad, no 3 groups: only a long hex word can matter
        quoted = before == '"' and after == '"'
        return "x" if any(_long_hex(g, quoted) for g in SEPS.split(r)) or CISCO.search(r) else r
    core = r.strip(".-:")
    if not core:
        return r
    i = r.find(core)
    lead, tail = r[:i], r[i + len(core):]
    if UUID.fullmatch(core):  # silence ids
        return r
    groups = [g for g in SEPS.split(core) if g]
    if any(_long_hex(g) for g in groups):  # before the keep-forms below: c0000201:443 is no host:port
        return lead + "x" + tail
    if TIME_RUN.fullmatch(core) or TIME_RANGE.fullmatch(core) or HOST_PORT.fullmatch(core) or UUID.fullmatch(core):
        return r
    if len(groups) <= 1:
        return r
    if r.count(":") >= 2 or ANY_DOTTED.search(core) or CISCO.search(core) or any(
            not (TIME_RUN.fullmatch(g.group(0)) or TIME_RANGE.fullmatch(g.group(0)) or DATE_RUN.fullmatch(g.group(0)) or UUID.fullmatch(g.group(0)))
            for g in HEX_GROUPS3.finditer(core)):
        return lead + "x" + tail
    return r


HEX_GROUPS3 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]+(?:[:\-][0-9A-Fa-f]+){2,}")  # 3+ hex groups joined by : / -


CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # tab / newline / carriage return stay (whitespace)


def _normalise(s):
    """-> (s without invisible / control characters, the same text with ASCII stand-ins; same length)."""
    if s.isascii():
        s = CONTROL.sub("", s) if CONTROL.search(s) else s
        return s, s
    s = "".join(c for c in s if (c.isascii() and not CONTROL.match(c)) or not c.isascii() and not _invisible(c))
    return s, "".join(c if c.isascii() else _ascii_char(c) for c in s)


def _mask_text(s):
    s, t = _normalise(s)
    out, pos = [], 0
    for m in FREE_RUN.finditer(t):
        r = m.group(0)
        rep = _free_run(r, t, m.start(), m.end())
        if rep != r:
            out += (s[pos:m.start()], rep)
            pos = m.end()
    if not out:
        return s
    out.append(s[pos:])
    return "".join(out)


def mask_text(s):
    """Free text -> masked (see above). A string that is only a number (JSON values, timestamps) is returned as is."""
    if len(s) < 3 or NUMBER.fullmatch(s):
        return s
    try:
        return _mask_text(s)
    except Exception:  # fail closed: never pass text that could not be masked, never fail the response
        return "x"


def raw_runs(s):
    """The parts of s that free-text masking changes (debugging / reviews; the export check uses leak_detector)."""
    s, t = _normalise(s)
    return [m.group(0) for m in FREE_RUN.finditer(t) if _free_run(m.group(0), t, m.start(), m.end()) != m.group(0)]


def has_raw_address(s):
    """Does s hold any part of an address that free-text masking would hide (masked forms the screens use are fine)?"""
    rest = MASKED_ANY.sub(" ", s)
    return mask_text(rest) != rest


def v6_fragment(s):
    for m in HEXCOLON.finditer(s):
        t = m.group(0)
        if "::" in t and re.search(r"[0-9A-Fa-f]", t) or re.search(r"[A-Fa-f]", t) and re.search(r"\d", t):
            return True
    return False


def mask_value(s):
    """One string from a service. A value that is exactly one address keeps a structured mask (+ a token: the screens
    still tell addresses apart and drill down); a value that is already masked stays; anything else is free text."""
    if MASKED_ANY.fullmatch(s) or FINGERPRINT.fullmatch(s):  # masked already / an Alertmanager fingerprint
        return s
    m = IPV4.fullmatch(s)
    if m:
        tok = hmac.new(KEY, s.encode(), hashlib.sha256).hexdigest()[:TOKEN_LEN]
        TOKENS[tok] = s
        return f"{m.group(1)}.x~{tok}"
    if ":" in s and len(s) <= 45:
        try:
            ip = ipaddress.IPv6Address(s)
        except ValueError:
            ip = None
        if ip is not None:
            return f"{v6_base(ip)}~{pcap_api.token(str(ip))}"
    mac = MAC.fullmatch(s)
    if mac:
        return MAC.sub(r"\1\2xx\2xx\2xx", s)
    return mask_text(s)


RELAY_TOKEN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.x~([0-9a-f]{%d})" % TOKEN_LEN)
_relay_bad = set()  # (prefix, token) pairs that did not check out (an older key): not tried again
RELAY_BAD_MAX = 4096


def relay_value(v):
    """One value of a notify-relay record. a.b.c.x~<token> (the relay's form of an IPv4 label value) is kept, and its
    token registered, only when one address a.b.c.0-255 gives that token under this process's key; else (made with an
    older key, forged) -> a.b.c.x. Everything else is masked like any other JSON value."""
    m = RELAY_TOKEN.fullmatch(v) if isinstance(v, str) else None
    if not m:
        return mask_json(v)
    prefix, tok = m.groups()
    known = TOKENS.get(tok)
    if known is not None and known.rpartition(".")[0] == prefix:
        return v
    if (prefix, tok) not in _relay_bad:
        for d in range(256):
            ip = f"{prefix}.{d}"
            if hmac.new(KEY, ip.encode(), hashlib.sha256).hexdigest()[:TOKEN_LEN] == tok:
                TOKENS[tok] = ip
                return v
        if len(_relay_bad) >= RELAY_BAD_MAX:  # ponytail: dropped all at once, a few repeated searches after that
            _relay_bad.clear()
        _relay_bad.add((prefix, tok))
    return f"{prefix}.x"


def mask_line(stream, line):
    """One Loki line. notify-relay's records ({job="notify"}, one JSON object per line) are masked value by value
    (relay_value), so a checked address token survives; every other line (and a notify line that is not such an object)
    as free text, like before."""
    if isinstance(stream, dict) and stream.get("job") == "notify" and isinstance(line, str) and line.startswith("{"):
        try:
            rec = json.loads(line)
        except ValueError:
            rec = None
        if isinstance(rec, dict):
            return json.dumps({mask_text(str(k)): relay_value(x) for k, x in rec.items()}, ensure_ascii=False)
    return mask_text(line) if isinstance(line, str) else mask_json(line)


def mask_json(v):
    if isinstance(v, str):
        return mask_value(v)
    if isinstance(v, list):
        return [mask_json(x) for x in v]
    if isinstance(v, dict):
        st = v.get("stream")
        if isinstance(st, dict) and st.get("job") == "notify" and isinstance(v.get("values"), list):  # a Loki stream of records
            return {mask_text(k): [[mask_json(e[0]), mask_line(st, e[1]), *mask_json(e[2:])] if isinstance(e, list) and len(e) >= 2 else mask_json(e)
                                   for e in x] if k == "values" else mask_json(x) for k, x in v.items()}
        out = {mask_text(k): pcap_api.mask_free(x) if k in FREE_LABELS and isinstance(x, str) else mask_json(x) for k, x in v.items()}
        labels, notes = v.get("labels"), v.get("annotations")
        if isinstance(labels, dict) and isinstance(notes, dict):  # an alert: its text may quote those label values
            raw = sorted((x for k, x in labels.items() if k in FREE_LABELS and isinstance(x, str) and x), key=len, reverse=True)
            for x in raw:  # replaced in the raw text first (as the label shows it), then the text is masked
                notes = {k: n.replace(x, pcap_api.mask_free(x)) if isinstance(n, str) else n for k, n in notes.items()}
            out["annotations"] = mask_json(notes)
        return out
    return v


# labels whose values are free text from the capture side (interface names like enx<MAC>, error reasons): flowd masks
# them already; masked here too so older series in the TSDB never show them raw
FREE_LABELS = {"iface", "reason"}


# ---- literal checks and masked-form rewriting (shared) ------------------------------------------

def literal_body(lit):
    if lit[0] == "`":
        return lit[1:-1]
    if lit[0] == "'":
        if "\\" in lit:
            raise Rejected("escapes in single-quoted strings are not accepted")
        return lit[1:-1]
    try:
        return json.loads(lit)
    except ValueError:  # Go-only escapes (\x2e, \056) could hide a dot from the checks
        raise Rejected("unsupported string escape") from None


def check_literal(body):
    if has_raw_address(body):
        raise Rejected(REJECT_MSG)
    rest = MASKED_MAC.sub(" ", MASKED_IPV4.sub(" ", MASKED_V6.sub(" ", body)))
    if FRAGMENT.search(rest) or v6_fragment(rest):
        raise Rejected(REJECT_MSG)
    for t in TOKEN_REF.finditer(body):
        if t.group(1) not in TOKENS:
            raise Rejected(TOKEN_MSG)


def _ip_span(m, as_regex):
    a, b, c, tok = m.groups()
    if tok:
        ip = TOKENS.get(tok)
        if not ip or not ip.startswith(f"{a}.{b}.{c}."):
            raise Rejected(TOKEN_MSG)
        return re.escape(ip) if as_regex else ip
    return f"{a}[.]{b}[.]{c}[.][0-9]{{1,3}}"


def _v6_span(m, as_regex):
    """A masked IPv6: with its token -> the exact address (checked against the visible part); without -> as written
    (flowd labels IPv6 destinations in this masked form)."""
    tok = m.group(1)
    if not tok:
        return re.escape(m.group(0)) if as_regex else m.group(0)
    ip = TOKENS.get(tok)
    try:
        ok = ip is not None and v6_base(ipaddress.IPv6Address(ip)) == m.group(0).split("~")[0]
    except ValueError:
        ok = False
    if not ok:
        raise Rejected(TOKEN_MSG)
    return re.escape(ip) if as_regex else ip


def _rewrite(text, as_regex):
    """Replace masked forms: tokens -> exact address; plain masks -> prefix regex (regex mode only)."""
    v6 = [(m.start(), m.end(), _v6_span(m, as_regex)) for m in MASKED_V6.finditer(text)]
    inside = lambda m: any(a <= m.start() < b for a, b, _ in v6)  # 64:ff9b::192.0.2.x~t: the IPv4 inside belongs to the IPv6
    spans = sorted(v6 + [(m.start(), m.end(), _ip_span(m, as_regex)) for m in MASKED_IPV4.finditer(text) if not inside(m)]
                   + [(m.start(), m.end(), "{1}{2}{3}{2}{4}(?:{2}[0-9A-Fa-f]{{2}}){{3}}".format(None, *m.groups()))
                      for m in MASKED_MAC.finditer(text)])
    out, pos = [], 0
    for start, end, rep in spans:
        out.append((re.escape(text[pos:start]) if as_regex else text[pos:start]) + rep)
        pos = end
    out.append(re.escape(text[pos:]) if as_regex else text[pos:])
    return "".join(out)


def matcher(label, op, body):
    """Label matcher upstream: token -> exact address; plain masked form -> prefix regex."""
    rest = MASKED_V6.sub(" ", body)
    has_plain = any(not x.group(4) for x in MASKED_IPV4.finditer(rest)) or MASKED_MAC.search(rest)
    if has_plain:
        return f"{label}{ {'=': '=~', '!=': '!~'}[op] }{json.dumps(_rewrite(body, as_regex=True))}"
    return f"{label}{op}{json.dumps(_rewrite(body, as_regex=False))}"


# ---- Prometheus -------------------------------------------------------------------------------

def prom_query(q):
    if has_raw_address(q) or PROM_FORBIDDEN.search(q):
        raise Rejected(REJECT_MSG)
    for m in re.finditer(STRING, q):
        if not PROM_MATCHER_LHS.search(q[:m.start()]):
            raise Rejected("string literals are only accepted as label matcher values")
        check_literal(literal_body(m.group(0)))

    def sub(m):  # every literal is a matcher value (checked above); the label name stays in place
        op, _, lit = m.groups()
        body = literal_body(lit)
        v6 = MASKED_V6.fullmatch(body)
        if v6 and not v6.group(1) or not (MASKED_IPV4.search(body) or MASKED_MAC.search(body) or MASKED_V6.search(body)):
            return m.group(0)  # nothing to rewrite (a masked IPv6 without a token is matched as flowd labels it)
        return matcher("", op, body)
    return PROM_LITERAL.sub(sub, q)


def prom_plan(path, params):
    if path in PROM_PLAIN:
        if params:
            raise Rejected("no parameters accepted here")
        return PROM_PLAIN[path], None
    out = []
    for k, v in params:
        if k == "query":
            out.append((k, prom_query(v)))
        elif k in ("time", "start", "end", "step") and PROM_TIME.fullmatch(v):
            out.append((k, v))
        else:
            raise Rejected(f"parameter not accepted: {k[:20]}")
    if not any(k == "query" for k, _ in out):
        raise Rejected("query is required")
    return PROM_QUERY[path] + "?" + urllib.parse.urlencode(out), None


# ---- Loki -------------------------------------------------------------------------------------

def loki_selector(sel):
    parts = []
    for label, lit in re.findall(LOKI_MATCHER, sel[1:-1]):
        body = literal_body(lit)
        check_literal(body)
        parts.append(matcher(label, "=", body))
    return "{" + ",".join(parts) + "}"


def line_filters(rest):
    filters = []
    for op, lit in re.findall(LOKI_FILTER, rest):
        body = literal_body(lit)
        check_literal(body)
        filters.append((op, body))
    return filters


class CountSpec(NamedTuple):
    """sum by (<by>) (count_over_time(<selector> <filters> [range])) evaluated here on masked lines."""
    by: tuple
    selector: str
    filters: list
    first_ns: int
    step_ns: int
    range_ns: int
    evals: int


NS = {"s": 10**9, "m": 60 * 10**9, "h": 3600 * 10**9}


def to_ns(v):  # Loki accepts unix seconds or nanoseconds
    return int(v) * 10**9 if int(v) < 10**12 else int(v)


def count_spec(p, by, selector, filters, rng):
    if not {"start", "end", "step"} <= set(p):
        raise Rejected("start, end and step are required")
    step = re.fullmatch(r"(\d+)([smh]?)", p["step"])
    step_ns = int(step.group(1)) * NS[step.group(2) or "s"]
    range_ns = int(rng[:-1]) * NS[rng[-1]]
    first, last = to_ns(p["start"]), to_ns(p["end"])
    if step_ns <= 0 or last < first or range_ns > 1440 * step_ns:
        raise Rejected("unsupported start/end/step")
    evals = (last - first) // step_ns + 1
    if evals > MAX_EVALS:
        raise Rejected("too many evaluation steps")
    return CountSpec(tuple(x.strip() for x in by.split(",")), selector, filters, first, step_ns, range_ns, evals)


def loki_plan(params):
    p = dict(params)
    if len(p) != len(params) or not set(p) <= LOKI_PARAMS or "query" not in p:
        raise Rejected("unsupported parameters")
    for k in ("start", "end", "limit"):
        if k in p and not p[k].isdigit():
            raise Rejected(f"{k} must be an integer")
    if p.get("direction", "backward") not in ("backward", "forward") or not re.fullmatch(r"\d{1,6}[smh]?", p.get("step", "60")):
        raise Rejected("unsupported direction/step")
    q = p["query"]
    metric = LOKI_METRIC.fullmatch(q)
    if metric:
        by, sel, rest, rng = metric.groups()
        filters = line_filters(rest)
        if filters:
            return None, count_spec(p, by, loki_selector(sel), filters, rng)
        p["query"] = f"sum by ({by}) (count_over_time({loki_selector(sel)}[{rng}]))"
        return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(p), None
    log = LOKI_LOG.fullmatch(q)
    if not log:
        raise Rejected(REJECT_MSG)
    sel, rest = log.groups()
    filters = line_filters(rest)
    limit = min(int(p.get("limit", "100")), LOKI_MAX_LINES)
    direction = p.get("direction", "backward")
    if filters:  # scanned and filtered here on masked text; Loki only ever sees the selector
        end = to_ns(p["end"]) if "end" in p else time.time_ns()
        start = to_ns(p["start"]) if "start" in p else end - 3600 * 10**9
        return None, LogSpec(loki_selector(sel), filters, limit, direction, start, end)
    p["query"] = loki_selector(sel)
    p["limit"] = str(limit)
    return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(p), ([], limit, direction)


def apply_line_filters(obj, filters, limit, direction):
    """Line filters on the masked lines, then the caller's limit in the caller's direction."""
    data = obj.get("data") if isinstance(obj, dict) else None
    if not data or data.get("resultType") != "streams":
        return obj
    keep = [(int(ts), i, ts, line) for i, s in enumerate(data["result"]) for ts, line in s["values"]
            if all((b in line) == (op == "|=") for op, b in filters)]
    keep.sort(key=lambda e: e[0], reverse=direction == "backward")
    values = {}
    for _, i, ts, line in keep[:limit]:
        values.setdefault(i, []).append([ts, line])
    result = [{"stream": data["result"][i]["stream"], "values": v} for i, v in values.items()]
    return {"status": obj.get("status"), "data": {"resultType": "streams", "result": result}}  # stats dropped: they describe the unfiltered fetch


def count_buckets(spec, entries, deadline=None):
    """Loki matrix for sum by (...) (count_over_time(... [range])) at first + k*step, counting
    (labels, ts_ns, masked_line) entries that pass the line filters; window is (t - range, t].
    -> (result, complete). Each line covers a run of evaluation indexes [k_lo, k_hi]; a difference
    array (+1 at k_lo, -1 after k_hi) plus one sweep keeps this O(lines + points) however much
    the windows overlap. Entries come newest first, so stopping at the deadline keeps recent buckets."""
    diffs, complete = {}, True
    for n, (labels, ts, line) in enumerate(entries):
        if deadline is not None and n % 4096 == 0 and time.monotonic() > deadline:
            complete = False
            break
        if not all((b in line) == (op == "|=") for op, b in spec.filters):
            continue
        d = ts - spec.first_ns
        k_lo = max(0, -(-d // spec.step_ns))
        k_hi = min(spec.evals - 1, -(-(d + spec.range_ns) // spec.step_ns) - 1)
        if k_lo > k_hi:
            continue
        diff = diffs.setdefault(tuple(labels.get(b) for b in spec.by), {})
        diff[k_lo] = diff.get(k_lo, 0) + 1
        diff[k_hi + 1] = diff.get(k_hi + 1, 0) - 1
    t = lambda k: (spec.first_ns + k * spec.step_ns) / 10**9
    result = []
    for key, diff in diffs.items():
        values, running, marks = [], 0, sorted(diff)
        for i, k in enumerate(marks[:-1]):
            running += diff[k]
            if running:
                values += [[int(t(j)) if t(j).is_integer() else t(j), str(running)] for j in range(k, marks[i + 1])]
        if values:
            result.append({"metric": {b: v for b, v in zip(spec.by, key) if v is not None}, "values": values})
    return result, complete


def loki_page(selector, start, end, limit, timeout, direction="backward"):
    """One page of raw Loki entries in [start, end) -> [(stream, ts_ns, line)] (unmasked)."""
    url = LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": selector, "start": start, "end": end, "limit": limit, "direction": direction})
    with urllib.request.urlopen(url, timeout=timeout) as r:
        raw = read_capped(r)
    return [(s["stream"], int(ts), line) for s in json.loads(raw)["data"]["result"] for ts, line in s["values"]]


class Scan:
    """Pages a selector's raw lines from Loki in one direction; iterate for lists of new entries.

    A limited Loki page is not strictly the first N lines in its direction (measured: lines < 1 ms
    past a backward page's oldest entry were missing from it), so each next page reaches back
    overlap_ns over the previous page's edge; entries already returned are skipped by their raw
    (stream, ts, line) key, so overlaps and instants split across pages are neither lost nor
    repeated (Loki itself drops exact duplicates). After iteration: done (window exhausted),
    partial (reasons the scan stopped early or may have skipped lines), edge (ts of the last
    scanned edge, for continuing), scanned (raw lines read)."""

    def __init__(self, selector, start, end, direction, get_page, page_size, deadline, overlap_ns):
        self.args = (selector, get_page, page_size, deadline, overlap_ns)
        self.start, self.end, self.backward = start, end, direction == "backward"
        self.lo, self.hi = start, end  # the caller's window [lo, hi): no page request or entry leaves it
        self.done, self.partial, self.edge, self.scanned, self.full = False, [], None, 0, False

    def __iter__(self):
        selector, get_page, page_size, deadline, overlap = self.args
        seen, prev, tight = set(), None, False  # seen is bounded by the callers' line caps
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.partial.append("time budget used up")
                return
            try:
                page = get_page(selector, max(self.start, self.lo), min(self.end, self.hi), page_size,
                                min(TIMEOUT_S, remaining), "backward" if self.backward else "forward")
            except TimeoutError:
                if not self.scanned:
                    raise
                self.partial.append("time budget used up")
                return
            self.scanned += len(page)
            new = []
            for e in page:
                if not self.lo <= e[1] < self.hi:  # defense in depth: Loki should never return these
                    continue
                k = (tuple(sorted(e[0].items())), e[1], e[2])
                if k not in seen:
                    seen.add(k)
                    new.append(e)
            if page:  # set before yielding: a caller that stops here continues after this page, not the last
                edge = min(e[1] for e in page) if self.backward else max(e[1] for e in page)
                self.edge = edge
            self.full = len(page) >= page_size
            yield new
            if len(page) < page_size:
                self.done = True
                return
            if prev is None or (edge < prev if self.backward else edge > prev):  # progress: overlap back
                prev, tight = edge, False
                if self.backward:
                    self.end = edge + 1 + overlap
                else:
                    self.start = edge - overlap
            elif overlap and not tight:  # the overlap alone filled a page: retry without it
                tight = True
                if self.backward:
                    self.end = prev + 1
                else:
                    self.start = prev
            else:  # a full page of one instant: cannot tell whether more lines share it
                self.partial.append("some lines sharing one timestamp may be skipped")
                tight = False
                if self.backward:
                    self.end = prev
                else:
                    self.start = prev + 1


def passes(line, filters):
    return all((b in line) == (op == "|=") for op, b in filters)


def _json(obj):
    return 200, json.dumps(obj, separators=(",", ":")).encode(), "application/json"


def run_count(spec, get_page=loki_page, page_size=LOKI_MAX_LINES, budget_s=SCAN_DEADLINE_S, overlap_ns=PAGE_OVERLAP_NS):
    """Page the selector's lines newest first (so a partial count keeps the recent buckets complete),
    mask them, count here. -> (status, body, ctype)."""
    deadline = time.monotonic() + budget_s
    scan = Scan(spec.selector, spec.first_ns - spec.range_ns + 1, spec.first_ns + (spec.evals - 1) * spec.step_ns + 1,
                "backward", get_page, page_size, deadline, overlap_ns)  # Loki's end is exclusive
    entries = []
    try:
        for new in scan:
            entries += [(mask_json(st), ts, mask_line(st, line)) for st, ts, line in new]
            if scan.scanned >= SCAN_MAX_LINES:  # raw lines read (overlapping pages re-read some), not deduped
                scan.partial.append("line cap reached")
                break
    except urllib.error.HTTPError as e:
        return (e.code, *masked_body(read_capped(e), e.headers.get("Content-Type")))
    result, complete = count_buckets(spec, entries, deadline + COUNT_AGG_GRACE_S)
    if not complete:
        scan.partial.append("time budget used up")
    data = {"resultType": "matrix", "result": result}
    if scan.partial:
        data["warnings"] = [f"partial count ({', '.join(dict.fromkeys(scan.partial))}): {len(entries)} newest lines of the window counted; older buckets may be low"]
    return _json({"status": "success", "data": data})


class LogSpec(NamedTuple):
    """{selector} |= ... != ... log query, filtered here on masked lines."""
    selector: str
    filters: list
    limit: int
    direction: str
    start_ns: int
    end_ns: int


def settled(hits, spec, scan, overlap_ns):
    """True once the first `limit` hits (in the scan direction) can no longer change: Loki may omit
    lines just inside a full page's edge, and only the next, overlapping page recovers them, so the
    cutoff (the limit-th hit) must lie more than overlap_ns inside the last consumed page's edge."""
    if not scan.full:
        return True
    back = spec.direction == "backward"
    cutoff = sorted((h[0] for h in hits), reverse=back)[spec.limit - 1]
    return scan.edge + overlap_ns < cutoff if back else scan.edge - overlap_ns > cutoff


def run_log(spec, get_page=loki_page, page_size=LOKI_MAX_LINES, budget_s=SCAN_DEADLINE_S, overlap_ns=PAGE_OVERLAP_NS):
    """Scan the selector's lines in the requested direction until `limit` lines pass the filters on
    the masked text, the window ends, or the scan budget/cap runs out. In the last case the reply is
    partial: data.warnings says so and data.scanned_until is the ns timestamp the scan reached
    (continue with end=scanned_until when backward, start=scanned_until+1 when forward). It is the
    outer edge of the last page actually consumed, so a continuation never repeats returned lines;
    ponytail: other lines sharing exactly that ns, not in the page, are not revisited."""
    scan = Scan(spec.selector, spec.start_ns, spec.end_ns, spec.direction, get_page, page_size,
                time.monotonic() + budget_s, overlap_ns)
    hits = []  # (ts, stream, masked line)
    try:
        for new in scan:
            for st, ts, line in new:
                masked = mask_line(st, line)
                if passes(masked, spec.filters):
                    hits.append((ts, mask_json(st), masked))
            if len(hits) >= spec.limit and settled(hits, spec, scan, overlap_ns):
                break
            if scan.scanned >= SCAN_MAX_LINES:
                scan.partial.append("line cap reached")
                break
    except urllib.error.HTTPError as e:
        return (e.code, *masked_body(read_capped(e), e.headers.get("Content-Type")))
    hits.sort(key=lambda h: h[0], reverse=spec.direction == "backward")
    streams = {}
    for ts, st, line in hits[:spec.limit]:
        streams.setdefault(json.dumps(st, sort_keys=True), {"stream": st, "values": []})["values"].append([str(ts), line])
    data = {"resultType": "streams", "result": list(streams.values())}
    if len(hits) < spec.limit and not scan.done:
        data["warnings"] = [f"partial result ({', '.join(dict.fromkeys(scan.partial)) or 'stopped early'}): scanned {scan.scanned} lines "
                            f"; continue from data.scanned_until"]
        data["scanned_until"] = str(scan.edge if scan.edge is not None else (spec.end_ns if spec.direction == "backward" else spec.start_ns))
    elif scan.partial:  # also when limit was reached: lines skipped earlier in the scan may belong in this page
        data["warnings"] = [f"possible gaps ({', '.join(dict.fromkeys(scan.partial))})"]
    return _json({"status": "success", "data": data})


# ---- routing / HTTP ---------------------------------------------------------------------------

def route(method, raw_path):
    """-> (upstream_url, post_filter, None) or (None, None, (status, message))."""
    if method != "GET":
        return None, None, (405, "method not allowed")
    parts = urllib.parse.urlsplit(raw_path)
    if parts.path not in PROM_QUERY and parts.path not in PROM_PLAIN and parts.path != LOKI_RANGE:
        return None, None, (403, "forbidden")
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    try:
        if any(has_raw_address(v) for _, v in params):
            raise Rejected(REJECT_MSG)
        url, post = loki_plan(params) if parts.path == LOKI_RANGE else prom_plan(parts.path, params)
    except Rejected as e:
        return None, None, (400, str(e))
    return url, post, None


def read_capped(resp):
    body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("upstream response too large")
    return body


def masked_body(raw, content_type, post=None):
    if "json" in (content_type or ""):
        obj = mask_json(json.loads(raw))
        if post:
            obj = apply_line_filters(obj, *post)
        return json.dumps(obj, separators=(",", ":")).encode(), "application/json"
    return mask_text(raw.decode("utf-8", "replace")).encode(), "text/plain; charset=utf-8"


def fetch(url, post=None, timeout=TIMEOUT_S):
    """-> (status, body bytes, content type), masked (and line-filtered for Loki)."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
            status, raw, ctype = r.status, read_capped(r), r.headers.get("Content-Type")
    except urllib.error.HTTPError as e:
        status, raw, ctype = e.code, read_capped(e), e.headers.get("Content-Type")
    return (status, *masked_body(raw, ctype, post if status == 200 else None))


def error_body(status, msg):
    return json.dumps({"status": "error", "errorType": "masked_query" if status == 400 else "proxy", "error": msg}).encode()


# ---- identity (P7): who is asking, as the front proxy says after Authelia -----------------------------------------------
# The proxy (caddy/Caddyfile) strips every client copy of X-Obs-User / X-Obs-Role / X-Obs-Auth, asks Authelia, and sets
# the verified user and role (viewer / operator / admin from the Authelia groups). It adds X-Obs-Auth: OBS_AUTH_PROXY_KEY
# (a secret from .env) on the requests it sends here, so the identity is believed only from the proxy, never from another
# container on the internal network or from a client: no key configured, a wrong key, a header given twice, an unknown role
# or a malformed name -> no identity at all (viewer, no writes). Masking and query restrictions never depend on the role.
ROLE_HEADER = "X-Obs-Role"
USER_HEADER = "X-Obs-User"
AUTH_KEY_HEADER = "X-Obs-Auth"
ROLES = ("viewer", "operator", "admin")
OPS_ROLES = ("operator", "admin")
AUTH_KEY_MIN = 32
OPERATOR_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")


class Identity(NamedTuple):
    user: str
    role: str


def one_header(headers, name):
    """The header's value when it is there exactly once, else None (a duplicate is never resolved in anyone's favour)."""
    if hasattr(headers, "get_all"):
        vals = headers.get_all(name) or []
        return vals[0] if len(vals) == 1 else None
    return headers.get(name)


def identity(headers):
    """-> Identity from the proxy, or None."""
    key = os.environ.get("OBS_AUTH_PROXY_KEY", "")
    got = one_header(headers, AUTH_KEY_HEADER)
    if len(key) < AUTH_KEY_MIN or got is None or not hmac.compare_digest(got.encode(), key.encode()):
        return None
    user, role = one_header(headers, USER_HEADER), one_header(headers, ROLE_HEADER)
    if user is None or role is None or not OPERATOR_RE.fullmatch(user) or role not in ROLES:
        return None
    return Identity(user, role)


def request_role(headers):
    """Role for a request: the proxy's verified role, else viewer. It only decides writes (writable()): every role sees
    the same masked data (伏せ字の解除は無い)."""
    ident = identity(headers)
    return ident.role if ident else "viewer"


# ---- Alertmanager (/am/): masked reads, and the only writes: silences (ACK) --------------------------------------------
# Reads: the alert and silence lists, masked like every other response (exact IPv4 values become tokens, so the screens
# can match them to Prometheus' alerts). Writes: create / extend / expire a silence, nothing else. A write must come from
# the command-center itself (same origin + the X-Obs-Csrf header, which a cross-site form cannot send and a cross-site
# script cannot send without a CORS preflight that is never granted), by a verified operator / admin (identity()), or
# without authentication only while the screens are on 127.0.0.1 (the demo default). Matchers: equality on
# alertname / instance / ifName / severity only (no regex: a silence must name what it mutes), addresses only as tokens
# the screen was given; duration at most 7 days (also counted from an extended silence's start); comment bounded;
# createdBy is always "command-center (<operator>)" and an ACK comment always "ACK by <operator>[: note]". The operator
# is the verified user (X-Obs-User from the proxy, identity()), else "local".
# Origins: only the names the proxy answers for (loopback, OBS_PUBLIC_URL's host, the bind address): with the proxy's
# Host allowlist this keeps a DNS-rebinding page (evil.example -> 127.0.0.1) out, even if the proxy rule were removed.

ALERTMANAGER = os.environ.get("ALERTMANAGER_URL", "http://alertmanager:9093")
AM_READ = {"/am/api/v2/alerts": "/api/v2/alerts?active=true&silenced=true&inhibited=true&unprocessed=true",
           "/am/api/v2/silences": "/api/v2/silences"}
AM_OPS = "/am/ops"
AM_SILENCES = "/am/api/v2/silences"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
AM_SILENCE_ID = re.compile(r"/am/api/v2/silence/(" + UUID_RE.pattern + ")")
SILENCE_LABELS = ("alertname", "instance", "ifName", "severity")
SILENCE_MAX_S = 7 * 86400
CLOCK_SLACK_S = 300  # browser vs server clock
COMMENT_MAX = 200
WRITE_MAX_BODY = 8192
CREATED_BY = "command-center"
CSRF_HEADER = "X-Obs-Csrf"
WRITES_PER_MIN = 30
_writes = []  # monotonic times of recent writes (rate limit)


def bind_is_local():
    """localhost or a loopback IPv4 address (the same strict rule as compose.yaml's entrypoints and tools/auth.py);
    anything else, also a malformed value, is a LAN exposure (login required)."""
    b = os.environ.get("OBS_BIND") or "127.0.0.1"
    if b == "localhost":
        return True
    try:
        return ipaddress.IPv4Address(b).is_loopback
    except ValueError:
        return False


def auth_required():
    """The screens need a login: always on a LAN exposure, on 127.0.0.1 when .env says OBS_AUTH=1 (same rule as the
    proxy's entrypoint in compose.yaml)."""
    return os.environ.get("OBS_AUTH") == "1" or not bind_is_local()


def operator(headers):
    """Who writes: the verified user, else "local" (the 127.0.0.1 screen without authentication)."""
    ident = identity(headers)
    return ident.user if ident else "local"


def is_ours(s):
    by = str(s.get("createdBy", "")) if isinstance(s, dict) else ""
    return by == CREATED_BY or by.startswith(CREATED_BY + " (")


def ack_comment(c, op):
    """An ACK comment names who acknowledged, whatever the client wrote after "ACK"."""
    m = re.match(r"ACK\b[\s:]*(.*)", c)  # the ACK rule is ^ACK\b everywhere (notify-relay ACK_RE, command-center ACK_RE)
    if not m:
        return c
    return (f"ACK by {op}" + (f": {m.group(1)}" if m.group(1) else ""))[:COMMENT_MAX]


def allowed_hosts():
    hosts = {"127.0.0.1", "localhost", "::1"}
    pub = urllib.parse.urlsplit(os.environ.get("OBS_PUBLIC_URL", "")).hostname
    bind = os.environ.get("OBS_BIND", "127.0.0.1")
    if pub:
        hosts.add(pub.lower())
    if bind not in ("", "0.0.0.0"):
        hosts.add(bind.lower())
    return hosts


def writable(headers):
    """-> (allowed, reason). Fail closed: with authentication required, only a verified operator / admin writes."""
    ident = identity(headers)
    if ident and ident.role in OPS_ROLES:
        return True, f"role {ident.role}: silences / ACK allowed"
    if not auth_required():
        return True, "127.0.0.1 only: silences / ACK allowed"
    if ident:
        return False, f"役割 {ident.role} では抑止・確認の操作はできません (operator 以上が必要です)"
    return False, "利用者を確認できないため抑止・確認の操作はできません (ログインが必要です)"


def same_origin(headers):
    origin, host = headers.get("Origin") or "", headers.get("X-Forwarded-Host") or headers.get("Host") or ""
    o = urllib.parse.urlsplit(origin)
    if o.scheme not in ("http", "https") or not host or headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
        return False
    return (o.hostname or "") in allowed_hosts() and o.netloc.lower() == host.split(",")[0].strip().lower()


def am_time(v, what):
    try:
        d = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", str(v)).replace("Z", "+00:00"))
    except ValueError:
        raise Rejected(f"{what} must be an RFC 3339 time") from None
    if d.tzinfo is None:
        raise Rejected(f"{what} needs a time zone")
    return d.timestamp()


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def silence_matchers(ms):
    if not isinstance(ms, list) or not 1 <= len(ms) <= len(SILENCE_LABELS):
        raise Rejected("matchers: 1 to 4 equality matchers")
    out, names = [], set()
    for m in ms:
        if not isinstance(m, dict) or set(m) - {"name", "value", "isRegex", "isEqual"}:
            raise Rejected("matcher fields: name, value, isRegex, isEqual")
        if m.get("isRegex", False) is not False or m.get("isEqual", True) is not True:
            raise Rejected("only equality matchers (isRegex false, isEqual true) are accepted")
        name, value = m.get("name"), m.get("value")
        if name not in SILENCE_LABELS or name in names:
            raise Rejected(f"matcher names: {', '.join(SILENCE_LABELS)} (each once)")
        if not isinstance(value, str) or not 0 < len(value) <= 128:
            raise Rejected("matcher value: 1 to 128 characters")
        check_literal(value)
        if any(not x.group(4) for x in MASKED_IPV4.finditer(value)) or MASKED_MAC.search(value):
            raise Rejected("a masked address without its token cannot be matched exactly")
        names.add(name)
        out.append({"name": name, "value": _rewrite(value, as_regex=False), "isRegex": False, "isEqual": True})
    if not names & {"alertname", "instance"}:
        raise Rejected("a silence must name the alert (alertname) or the device (instance)")
    return out


def check_comment(c):
    c = c.strip() if isinstance(c, str) else ""
    if not 0 < len(c) <= COMMENT_MAX or any(ord(ch) < 32 for ch in c):
        raise Rejected(f"comment: 1 to {COMMENT_MAX} characters, one line")
    return c


def check_end(v, start, now, began=None):
    """began: an extended silence's start; the 7 days count from there too (no endless extension)."""
    end = am_time(v, "endsAt")
    if not now < end <= now + SILENCE_MAX_S + CLOCK_SLACK_S or end <= start:
        raise Rejected("endsAt: in the future, at most 7 days from now")
    if began is not None and end > began + SILENCE_MAX_S + CLOCK_SLACK_S:
        raise Rejected("endsAt: a silence lasts at most 7 days from its start (make a new one)")
    return end


def silence_body(body, now, existing=None, op="local"):
    """Client body -> the Alertmanager silence to post. New: matchers + endsAt + comment. Extend (id given): endsAt and
    optionally comment; matchers and start stay those of the existing command-center silence."""
    if not isinstance(body, dict) or set(body) - {"id", "matchers", "endsAt", "comment", "createdBy"}:
        raise Rejected("fields: matchers, endsAt, comment (id to extend)")
    if "createdBy" in body:
        raise Rejected("createdBy is set by the server")
    if "id" in body:
        if existing is None:
            raise Rejected("unknown silence")
        if "matchers" in body:
            raise Rejected("an extension keeps the silence's matchers")
        start = am_time(existing["startsAt"], "startsAt")
        comment = ack_comment(check_comment(body["comment"]), op) if "comment" in body else existing.get("comment")
        return {"id": existing["id"], "matchers": existing["matchers"], "startsAt": existing["startsAt"],
                "endsAt": iso(check_end(body.get("endsAt"), max(start, now - CLOCK_SLACK_S), now, began=start)),
                "createdBy": existing.get("createdBy"), "comment": comment}
    return {"matchers": silence_matchers(body.get("matchers")), "startsAt": iso(now), "endsAt": iso(check_end(body.get("endsAt"), now, now)),
            "createdBy": f"{CREATED_BY} ({op})", "comment": ack_comment(check_comment(body.get("comment")), op)}


def am_request(path, method="GET", body=None):
    """-> (status, raw body) from Alertmanager (errors included)."""
    req = urllib.request.Request(ALERTMANAGER + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return r.status, read_capped(r)
    except urllib.error.HTTPError as e:
        return e.code, read_capped(e)


def own_silence(sid):
    """The silence if it exists and was made by the command-center (only those may be extended / expired here)."""
    status, raw = am_request(f"/api/v2/silence/{sid}")
    try:
        s = json.loads(raw) if status == 200 else None
    except ValueError:
        s = None
    if not is_ours(s):
        raise Rejected("unknown silence, or not created by the command-center")
    if (s.get("status") or {}).get("state") == "expired":
        raise Rejected("the silence has already expired")
    return s


def rate_limited(now):
    _writes[:] = [t for t in _writes if now - t < 60]
    if len(_writes) >= WRITES_PER_MIN:
        return True
    _writes.append(now)
    return False


def am_json(status, obj):
    return status, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(), "application/json"


def am_handle(method, raw_path, headers, read_body):
    """/am/... -> (status, body, content type)."""
    parts = urllib.parse.urlsplit(raw_path)
    path = parts.path
    if method in ("GET", "HEAD"):
        if parts.query:
            return am_json(400, {"status": "error", "error": "no parameters accepted here"})
        if path == AM_OPS:
            ok, reason = writable(headers)
            ident = identity(headers)  # for the settings menu: who the screens are logged in as (the proxy's word)
            return am_json(200, {"writable": ok, "reason": reason, "max_s": SILENCE_MAX_S, "labels": SILENCE_LABELS,
                                 "auth": auth_required(), "user": ident.user if ident else None, "role": request_role(headers)})
        if path not in AM_READ:
            return am_json(403, {"status": "error", "error": "forbidden"})
        status, raw = am_request(AM_READ[path])
        return (status, *masked_body(raw, "application/json"))
    is_new = method == "POST" and path == AM_SILENCES
    sid = AM_SILENCE_ID.fullmatch(path) if method == "DELETE" else None
    if not is_new and not sid:
        return am_json(403 if method in ("POST", "DELETE") else 405, {"status": "error", "error": "only silences can be written"})
    ok, reason = writable(headers)
    if not ok:
        return am_json(403, {"status": "error", "errorType": "forbidden", "error": reason})
    if headers.get(CSRF_HEADER) != "1" or not same_origin(headers):
        return am_json(403, {"status": "error", "errorType": "csrf", "error": "cross-site or scripted request refused (same origin + X-Obs-Csrf required)"})
    if rate_limited(time.monotonic()):
        return am_json(429, {"status": "error", "error": "too many changes; wait a minute"})
    try:
        if sid:
            own_silence(sid.group(1))
            status, raw = am_request(f"/api/v2/silence/{sid.group(1)}", "DELETE")
            return am_json(status, {"status": "success" if status == 200 else "error"})
        if "json" not in (headers.get("Content-Type") or ""):
            raise Rejected("Content-Type: application/json required")
        length = headers.get("Content-Length") or "0"
        length = int(length) if length.isdigit() else -1
        if not 0 < length <= WRITE_MAX_BODY:
            raise Rejected("body too large or empty")
        try:
            body = json.loads(read_body(length))
        except ValueError:
            raise Rejected("body is not JSON") from None
        existing = None
        if isinstance(body, dict) and "id" in body:
            if not (isinstance(body["id"], str) and UUID_RE.fullmatch(body["id"])):
                raise Rejected("id: a silence id")
            existing = own_silence(body["id"])
        status, raw = am_request("/api/v2/silences", "POST", silence_body(body, time.time(), existing, operator(headers)))
        return (status, *masked_body(raw, "application/json"))
    except Rejected as e:
        return am_json(400, {"status": "error", "errorType": "rejected", "error": str(e)})


def respond(method, raw_path, headers, read_body, gone=None):
    """-> (status, body, content type[, extra headers]) for one request. gone(): the client has disconnected."""
    try:
        if raw_path.startswith("/am/"):
            return am_handle(method, raw_path, headers, read_body)
        if raw_path.startswith("/pcap/"):
            return pcap_api.handle(method, raw_path, headers, read_body)
        if raw_path.startswith("/evidence/"):
            return evidence.handle(method, raw_path, headers, gone, read_body)
        if raw_path.startswith("/correlate/"):
            return correlate.handle(method, raw_path)
        url, post, err = route(method, raw_path)
        if err:
            return err[0], error_body(*err), "application/json"
        if isinstance(post, CountSpec):
            return run_count(post)
        if isinstance(post, LogSpec):
            return run_log(post)
        return fetch(url, post)
    except TimeoutError:
        return 504, error_body(504, "upstream timeout"), "application/json"
    except (OSError, ValueError) as e:  # URLError, connection reset, bad/oversize JSON
        print(f"upstream error: {type(e).__name__}", file=sys.stderr)
        return 502, error_body(502, "upstream unavailable"), "application/json"


BODY_IDLE_S = 15  # longest pause between two pieces of a request body


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        t0 = time.monotonic()
        got = [0]

        def read_body(n, deadline=None):
            """n bytes (fewer at the end of the body). With a deadline (monotonic): at most one read from the socket, waiting
            no longer than the time left, so the caller can enforce a total time limit on a trickling upload."""
            idle = BODY_IDLE_S if deadline is None else max(0.05, min(BODY_IDLE_S, deadline - time.monotonic()))
            self.connection.settimeout(idle)  # a client that stops sending mid-body does not hold the thread
            try:
                data = self.rfile.read(n) if deadline is None else self.rfile.read1(n)
            finally:
                self.connection.settimeout(None)
            got[0] += len(data)
            return data
        status, body, ctype, *extra = respond(self.command, self.path, self.headers, read_body, self._gone)
        self.send_response(status)
        for k, v in (extra[0] if extra else {}).items():  # e.g. the evidence zip's Content-Disposition
            self.send_header(k, v)
        length = self.headers.get("Content-Length") or "0"
        if not length.isdigit() or int(length) > got[0] or self.headers.get("Transfer-Encoding"):  # body left unread (early reject): never parse it as a request
            self.close_connection = True
            self.send_header("Connection", "close")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        note = ""
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                note = " client-gone"
        path = urllib.parse.urlsplit(self.path).path  # never log the query string
        sys.stdout.write(f"{self.command} {path} {status} {int((time.monotonic() - t0) * 1000)}ms{note}\n")
        sys.stdout.flush()

    def _gone(self):
        """The client closed its connection (a readable socket with nothing to read), e.g. the proxy gave up."""
        try:
            if not select.select([self.connection], [], [], 0)[0]:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle

    def log_message(self, *args):  # replaced by the single line in _handle
        pass


def relay_selftest():
    """notify-relay's tokens: same as mask_value's for the same key and address (golden vector, also in relay.py), kept
    in its records only when they check out with the current key; the shared key file."""
    global KEY
    real = KEY
    try:
        KEY = bytes(range(32))
        assert mask_value("192.0.2.10") == "192.0.2.x~141e10c52e03" and mask_value("192.0.2.11") == "192.0.2.x~65ccf18bfbf0"
        TOKENS.pop("141e10c52e03", None)
        rec = {"receiver": "demo-sink", "instance": "192.0.2.x~141e10c52e03", "ifName": "lan2", "detail": "HTTP 550 192.0.2.10 aa:bb:cc:dd:ee:ff",
               "message": "【重大】 機器が応答しません (192.0.2.x)", "fingerprint": "0123456789abcdef", "t": 1.5}
        forged = {**rec, "instance": "192.0.2.x~000000000000"}
        page = {"status": "success", "data": {"resultType": "streams", "result": [
            {"stream": {"job": "notify", "receiver": "demo-sink"}, "values": [["1", json.dumps(rec, ensure_ascii=False)], ["2", json.dumps(forged)], ["3", "not json 192.0.2.10"]]},
            {"stream": {"job": "syslog"}, "values": [["4", json.dumps(rec)]]}]}}
        out = mask_json(page)["data"]["result"]
        got = json.loads(out[0]["values"][0][1])
        assert got["instance"] == "192.0.2.x~141e10c52e03" and TOKENS.get("141e10c52e03") == "192.0.2.10"  # checked, registered (drill-down)
        assert got["detail"] == "HTTP 550 192.0.2.x aa:bb:cc:xx:xx:xx" and got["t"] == 1.5 and got["message"] == rec["message"], got
        assert json.loads(out[0]["values"][1][1])["instance"] == "192.0.2.x"  # unknown / older key: no token
        assert out[0]["values"][2][1] == "not json 192.0.2.x" and "~141e10c52e03" not in out[1]["values"][0][1]  # other lines: free text
        assert mask_line({"job": "notify"}, json.dumps(rec)) == json.dumps(got, ensure_ascii=False)  # the scanned paths: the same
        assert mask_line({"job": "syslog"}, "192.0.2.10 up") == "192.0.2.x up"
        KEY = secrets.token_bytes(32)  # mask-api restarted with a new key (and an empty token table): an old record keeps no token
        TOKENS.pop("65ccf18bfbf0", None)
        assert json.loads(mask_line({"job": "notify"}, json.dumps({**rec, "instance": "192.0.2.x~65ccf18bfbf0"})))["instance"] == "192.0.2.x"
    finally:
        KEY = real
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "token.key")
        k1 = shared_key(path, b"1" * 32)
        assert k1 == b"1" * 32 and open(path, "rb").read() == k1
        assert shared_key(path, b"2" * 32) == k1  # still in the volume: reused
        open(path, "wb").write(b"bad")
        assert shared_key(path, b"3" * 32) == b"3" * 32 == open(path, "rb").read()
        assert shared_key(os.path.join(d, "missing", "token.key"), b"4" * 32) == b"4" * 32 and shared_key("", b"5" * 32) == b"5" * 32


# Adversarial probes (also replayed live by the evidence script). Every one must be rejected (400).
LOKI_PROBES = [
    '{job="syslog"} |> "<_>192.<_>168.<_>100.<_>7:<_>"',  # pattern filter (Codex P1)
    '{job="syslog"} !> "<_>.7:<_>"',
    r'{job="syslog"} |~ "192\\.0\\.2\\.1[0-9]"',
    r'{job="syslog"} | regexp "(?P<o>\\d+)"',
    '{job="syslog"} | line_format "{{.x}}"',
    '{job="syslog"} | logfmt',
    '{job="syslog"} | json | dst="x"',
    '{job="syslog",host=~"rtx.*"}',
    '{job="syslog",host!="rtx1300"}',
    '{job="syslog",dst="x"}',
    '{job="syslog"} |= "192.0.2.10"',
    '{job="syslog"} |= `02:00:5e:20:00:01`',
    '{job="syslog"} |= "113.50"',
    r'{job="syslog"} |= "113.50"',
    r'{job="syslog"} |= "113\x2e50"',
    '{job="syslog"} |= \'113.50\'',
    'count_over_time({job="syslog"} |= "x" [5m])',
    'sum by (host) (count_over_time({job="syslog"}[5m]))',
    'sum by (severity) (count_over_time({job="syslog"} |= "113.50" [60s]))',  # filtered counts: same literal rules
    'sum by (severity) (count_over_time({job="syslog"} |= "192.0.2.10" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |= "5e:20:00:01" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |~ "Rej.*" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |> "<_>.7<_>" [60s]))',
    'sum by (severity) (count_over_time({job="syslog"} |= "x" | logfmt [60s]))',
    r'sum by (severity) (count_over_time({job="syslog"} |= "113.50" [60s]))',
    'sum by (dst) (count_over_time({job="syslog"} |= "x" [60s]))',
    '{job="syslog"} |= "a" or {job="syslog"}',
    # IPv6 (P4 review probe4): full addresses and fragments that could narrow a hidden host part
    '{job="syslog"} |= "2001:db8:10:1:211"',
    '{job="syslog"} |= "fe33:4455"',
    '{job="syslog"} |= "2001:db8::1"',
    '{job="syslog"} |= "::ffff:192.0.2.1"',
    '{job="syslog"} |= "機器192.0.2.1"',
    '{job="syslog"} |= "MAC00:11:22:33:44:55"',
]
PROM_PROBES = [
    'demo_flow_bytes_total{dst_ip=~"203.*"}',
    'demo_flow_bytes_total{dst_ip!~"203.0.113.5.*"}',
    '{__name__=~"demo.*"}',
    'label_replace(demo_flow_bytes_total, "o", "$1", "dst_ip", ".*[.](.*)")',
    'label_join(demo_flow_bytes_total, "o", "", "dst_ip")',
    'sort_by_label(demo_flow_bytes_total, "dst_ip")',
    'count_values("v", demo_flow_bytes_total)',
    'demo_flow_bytes_total{dst_ip="203.0.113.50"}',
    'demo_flow_bytes_total{dst_ip=`203.0.113.50`}',
    r'demo_flow_bytes_total{dst_ip="203.0.113.50"}',
    r'demo_flow_bytes_total{dst_ip="203\x2e0.113.50"}',
    'demo_flow_bytes_total{dst_ip="203.0.113.5"}',
    'demo_flow_bytes_total{dst_ip="203.0.113.x~000000000000"}',
    'absent(nope{dst_ip="203.0.113.50"})',
    'demo_flow_bytes_total{dst_ip="203.0.113.x"} > on() group_left() vector(1) == bool 1 or "113.50"',
    'info(up)',
    "demo_flow_bytes_total{dst_ip='1.2'}",
    'up{instance="[2001:db8::5]:9100"}',
    'obs_flow_bytes_total{dst_ip="2001:db8:1:2:a:b:c:d"}',
    'obs_flow_bytes_total{dst_ip="2001:db8:1:2::x:abcd"}',
    'up{instance="host_192.0.2.1"}',
]


def am_selftest(tok):
    """/am/: masked reads, the write allowlist and its guards, against a fake Alertmanager."""
    global am_request
    calls, store = [], {}
    sid = "0b9cbd2e-8d2c-4a39-9e0f-4b0c6e6c1a11"

    def fake(path, method="GET", body=None):
        calls.append((method, path, body))
        if path.startswith("/api/v2/alerts"):
            return 200, json.dumps([{"labels": {"alertname": "DeviceDown", "instance": "203.0.113.50"}, "fingerprint": "0123456789abcdef"}]).encode()
        if path == "/api/v2/silences" and method == "POST":
            return 200, json.dumps({"silenceID": sid}).encode()
        if path == f"/api/v2/silence/{sid}":
            return (200, json.dumps(store.get(sid) or {}).encode()) if method == "GET" else (200, b"")
        return 404, b"{}"
    real, am_request = am_request, fake
    env_was = {k: os.environ.get(k) for k in ("OBS_BIND", "OBS_AUTH", "OBS_AUTH_PROXY_KEY", "OBS_PUBLIC_URL")}
    try:
        os.environ["OBS_BIND"], os.environ["OBS_AUTH"], os.environ["OBS_PUBLIC_URL"] = "127.0.0.1", "0", "http://127.0.0.1:8080"
        os.environ.pop("OBS_AUTH_PROXY_KEY", None)
        hdr = {"Origin": "http://127.0.0.1:8080", "X-Forwarded-Host": "127.0.0.1:8080", "X-Obs-Csrf": "1", "Content-Type": "application/json",
               "Sec-Fetch-Site": "same-origin"}
        now = time.time()
        good = {"matchers": [{"name": "alertname", "value": "DeviceDown", "isRegex": False, "isEqual": True},
                             {"name": "instance", "value": tok}], "endsAt": iso(now + 3600), "comment": "ACK: looking into it"}

        def post(body, headers=hdr, path=AM_SILENCES, method="POST"):
            raw = json.dumps(body).encode()
            st, out, _ = am_handle(method, path, {**headers, "Content-Length": str(len(raw))}, lambda n: raw[:n])
            return st, json.loads(out or b"null")
        st, out = am_handle("GET", "/am/api/v2/alerts", {}, None)[:2]
        assert st == 200 and b"203.0.113.50" not in out and tok.encode() in out  # masked; same token as Prometheus' alerts
        assert am_handle("GET", "/am/api/v2/alerts?filter=x", {}, None)[0] == 400 and am_handle("GET", "/am/api/v2/status", {}, None)[0] == 403
        assert json.loads(am_handle("GET", AM_OPS, {}, None)[1])["writable"] is True
        st, out = post(good)
        assert st == 200 and out == {"silenceID": sid}, (st, out)
        sent = calls[-1][2]
        assert sent["createdBy"] == "command-center (local)" and sent["matchers"][1] == {"name": "instance", "value": "203.0.113.50", "isRegex": False, "isEqual": True}
        assert abs(am_time(sent["startsAt"], "") - now) < 5 and sent["comment"] == "ACK by local: looking into it", sent
        post({**good, "comment": "ACK by mallory"})
        assert calls[-1][2]["comment"] == "ACK by local: by mallory"  # the operator is never taken from the comment
        post({**good, "comment": "maintenance"})
        assert calls[-1][2]["comment"] == "maintenance"
        # DNS rebinding (reviewer probe): a page on evil.example resolved to 127.0.0.1 - Host and Origin both the attacker's
        for h in ({**hdr, "Origin": "http://evil.example:8080", "X-Forwarded-Host": "evil.example:8080"},
                  {**hdr, "Origin": "http://evil.example:8080", "Host": "evil.example:8080", "X-Forwarded-Host": "evil.example:8080"}):
            assert post(good, h)[0] == 403, h
        assert post(good, {**hdr, "Origin": "http://localhost:8080", "X-Forwarded-Host": "localhost:8080"})[0] == 200
        raw = b"{}"
        for bad_len in ("abc", "-5", "99999999"):
            assert am_handle("POST", AM_SILENCES, {**hdr, "Content-Length": bad_len}, lambda n: raw)[0] == 400, bad_len
        rejected = [
            {**good, "matchers": [{"name": "alertname", "value": "Device.*", "isRegex": True}]},                    # regex matcher
            {**good, "matchers": [{"name": "alertname", "value": "X", "isEqual": False}]},                          # negative matcher
            {**good, "matchers": [{"name": "job", "value": "snmp"}]},                                               # label not allowed
            {**good, "matchers": [{"name": "severity", "value": "critical"}]},                                      # mutes everything critical
            {**good, "matchers": [{"name": "instance", "value": "203.0.113.50"}]},                                  # raw address
            {**good, "matchers": [{"name": "instance", "value": "203.0.113.x"}]},                                   # masked without token
            {**good, "matchers": [{"name": "instance", "value": "203.0.113.x~000000000000"}]},                      # forged token
            {**good, "matchers": []}, {**good, "matchers": [good["matchers"][0]] * 2},
            {**good, "endsAt": iso(now + 8 * 86400)}, {**good, "endsAt": iso(now - 10)}, {**good, "endsAt": "tomorrow"},  # duration
            {**good, "comment": ""}, {**good, "comment": "x" * 201}, {**good, "comment": "a\nb"},
            {**good, "createdBy": "admin"}, {**good, "createdBy": "command-center"}, {**good, "startsAt": iso(now)}, [good],
        ]
        for i, bad in enumerate(rejected):
            st, out = post(bad)
            assert st == 400 and out["errorType"] == "rejected", (i, st, out)
        for h in ({k: v for k, v in hdr.items() if k != "X-Obs-Csrf"}, {**hdr, "Origin": "http://evil.example"},
                  {k: v for k, v in hdr.items() if k != "Origin"}, {**hdr, "Sec-Fetch-Site": "cross-site"}):
            assert post(good, h)[0] == 403 and post(good, h)[1]["errorType"] == "csrf", h
        assert post(good, {**hdr, "Content-Type": "text/plain"})[0] == 400
        assert post(good, path="/am/api/v2/alerts")[0] == 403 and post(good, method="PUT")[0] == 405
        # extend / expire: only the command-center's own, not yet expired silences; matchers are kept
        store[sid] = {"id": sid, "createdBy": "command-center (local)", "comment": "maintenance", "startsAt": iso(now - 600), "endsAt": iso(now + 60),
                      "status": {"state": "active"}, "matchers": [{"name": "instance", "value": "wlx222", "isRegex": False, "isEqual": True}]}
        st, _ = post({"id": sid, "endsAt": iso(now + 7200)})
        assert st == 200 and calls[-1][2]["matchers"] == store[sid]["matchers"] and calls[-1][2]["id"] == sid and calls[-1][2]["startsAt"] == store[sid]["startsAt"]
        assert calls[-1][2]["createdBy"] == "command-center (local)" and calls[-1][2]["comment"] == "maintenance"
        assert post({"id": sid, "endsAt": iso(now + 7200), "matchers": good["matchers"]})[0] == 400
        _writes.clear()  # (the rate limit is tested below)
        store[sid] = {**store[sid], "startsAt": iso(now - 6 * 86400)}  # extensions stop at 7 days from the start
        assert post({"id": sid, "endsAt": iso(now + 2 * 86400)})[0] == 400 and post({"id": sid, "endsAt": iso(now + 86400 - 600)})[0] == 200
        store[sid] = {**store[sid], "startsAt": iso(now - 600)}
        assert am_handle("DELETE", f"/am/api/v2/silence/{sid}", {**hdr, "Origin": "http://evil.example:8080", "X-Forwarded-Host": "evil.example:8080"}, None)[0] == 403
        assert post({"id": "nope", "endsAt": iso(now + 7200)})[0] == 400
        assert am_handle("DELETE", f"/am/api/v2/silence/{sid}", hdr, None)[0] == 200 and calls[-1][:2] == ("DELETE", f"/api/v2/silence/{sid}")
        store[sid] = {**store[sid], "createdBy": "amtool"}
        assert am_handle("DELETE", f"/am/api/v2/silence/{sid}", hdr, None)[0] == 400  # not ours
        assert am_handle("DELETE", "/am/api/v2/silences", hdr, None)[0] == 403
        # P7 LAN exposure: authentication required. A role / user is believed only with the proxy's key (X-Obs-Auth):
        # client-made or forged headers give no identity (no writes); viewer reads only; operator / admin write as themselves
        os.environ["OBS_BIND"] = "192.168.100.10"
        key = "K" * 43
        os.environ["OBS_AUTH_PROXY_KEY"] = key
        lan = {**hdr, "Origin": "https://192.168.100.10:8080", "X-Forwarded-Host": "192.168.100.10:8080"}
        spoofed = [{**lan, "X-Obs-Role": "admin", "X-Obs-User": "mallory"},                                  # no key: a client's own headers
                   {**lan, "X-Obs-Role": "admin", "X-Obs-User": "mallory", "X-Obs-Auth": "K" * 42},          # wrong key
                   {**lan, "X-Obs-Role": "admin", "X-Obs-User": "mallory", "X-Obs-Auth": ""}]
        for h in spoofed:
            st, out = post(good, h)
            ops = json.loads(am_handle("GET", AM_OPS, h, None)[1])
            assert st == 403 and out["errorType"] == "forbidden" and ops["writable"] is False and ops["auth"] is True, (h, out)
            assert ops["user"] is None and ops["role"] == "viewer" and request_role(h) == "viewer", ops
        ok = {**lan, "X-Obs-Auth": key, "X-Obs-User": "alice"}
        assert post(good, {**ok, "X-Obs-Role": "viewer"})[0] == 403 and "viewer" in post(good, {**ok, "X-Obs-Role": "viewer"})[1]["error"]
        assert json.loads(am_handle("GET", AM_OPS, {**ok, "X-Obs-Role": "viewer"}, None)[1])["user"] == "alice"
        for bad_role in ("Admin", " admin", "root", "operator,admin", ""):  # only the exact names the proxy sets
            assert post(good, {**ok, "X-Obs-Role": bad_role})[0] == 403, bad_role
        assert post(good, {**ok, "X-Obs-Role": "operator"})[0] == 200
        assert calls[-1][2]["createdBy"] == "command-center (alice)" and calls[-1][2]["comment"].startswith("ACK by alice")
        assert post(good, {**ok, "X-Obs-Role": "admin", "X-Obs-User": "bob"})[0] == 200 and calls[-1][2]["createdBy"] == "command-center (bob)"
        assert post(good, {**ok, "X-Obs-Role": "admin", "X-Obs-User": "bad user;"})[0] == 403  # malformed name: no identity
        ops = json.loads(am_handle("GET", AM_OPS, {**ok, "X-Obs-Role": "operator"}, None)[1])
        assert ops == {**ops, "writable": True, "user": "alice", "role": "operator", "auth": True}, ops
        os.environ["OBS_AUTH_PROXY_KEY"] = "short"  # a key too short to be the generated one is never accepted
        assert post(good, {**ok, "X-Obs-Auth": "short", "X-Obs-Role": "admin"})[0] == 403
        os.environ["OBS_AUTH_PROXY_KEY"] = ""  # no key configured: nobody is verified (fail closed)
        assert post(good, {**ok, "X-Obs-Auth": "", "X-Obs-Role": "admin"})[0] == 403
        os.environ["OBS_AUTH_PROXY_KEY"] = key
        from email.message import Message  # a header given twice (http.server's headers) is never resolved
        twice = Message()
        for k, v in {**ok, "X-Obs-Role": "operator"}.items():
            twice[k] = v
        twice["X-Obs-Role"] = "admin"
        assert identity(twice) is None
        twice.replace_header("X-Obs-Role", "operator")  # (replaces the first; the second stays: still twice)
        assert identity(twice) is None
        for bad_bind in ("127.evil", "127.0.0.01", "127.0.0.256", "0.0.0.0", ""):  # strict loopback rule: else LAN
            os.environ["OBS_BIND"] = bad_bind
            assert (bind_is_local() is (bad_bind == "")) and auth_required() is (bad_bind != ""), bad_bind
        os.environ["OBS_BIND"] = "127.1.2.3"
        assert bind_is_local()
        # 127.0.0.1 with OBS_AUTH=1: same rules as the LAN; without it, the demo default (no login, writes as "local")
        os.environ["OBS_BIND"], os.environ["OBS_AUTH"] = "127.0.0.1", "1"
        assert post(good, {**hdr, "X-Obs-Role": "admin"})[0] == 403 and post(good, {**hdr, "X-Obs-Auth": key, "X-Obs-User": "carol", "X-Obs-Role": "operator"})[0] == 200
        os.environ["OBS_AUTH"] = "0"
        assert post(good, hdr)[0] == 200 and calls[-1][2]["createdBy"] == "command-center (local)"
        os.environ["OBS_BIND"] = "192.168.100.10"
        lan = {**ok, "X-Obs-Role": "operator"}
        _writes[:] = [time.monotonic()] * WRITES_PER_MIN
        assert post(good, lan)[0] == 429  # rate limit
        _writes.clear()
    finally:
        am_request = real
        for k, v in env_was.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ---- leak detector: independent of the masking (its own normalisation and patterns), deliberately broader: when it
# flags what masking keeps, the masking is adjusted, never the detector loosened --------------------------------------
_DET_DROP = {"Cf", "Mn", "Me", "Cc", "Cn"}
_DET_EXTRA = {"\u3164", "⠀", "ᅟ", "ᅠ", "ﾠ", "᠎", "\u034f"} | {chr(c) for c in range(0xFE00, 0xFE10)}
_DET_MAP = str.maketrans({"。": ".", "\u00b7": ".", "\u2022": ".", "\u30fb": ".", "\uff65": ".", "\u2026": ".", "\u2025": ".", "\u066b": ".", "\u066c": ".", "\u06d4": ".", "\u2e31": ".", "\u0387": ".", "\u2219": ".", "｡": ".", "․": ".", "‧": ".", "܁": ".", "܂": ".", "ꓸ": ".",
                          "∶": ":", "꞉": ":", "ː": ":", "׃": ":", "܃": ":", "܄": ":", "፡": ":",
                          "︰": ":", "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-"})
DET_QUAD = re.compile(r"(?<!\d)\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}(?!\d)")  # overlong octets (0192.0.2.1) are findings
DET_GROUPS = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]+(?:[:\-]{1,2}[0-9A-Fa-f]+){2,}")
DET_V6 = re.compile(r"[0-9A-Fa-f]::[0-9A-Fa-f]")  # fe80::1, 2001:db8::a
DET_CISCO = re.compile(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}")
DET_LONG = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8,}(?![0-9A-Fa-f])")
DET_OK_CONTEXT = re.compile(r'"(?:fingerprint|sha256|observatory)":\s*"[0-9a-f]{7,64}"')  # fingerprints, digests, the build revision
DET_KEEP = [re.compile(r"(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:-(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?)?"),
            re.compile(r"\d{4}-\d{2}-\d{2}"), re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")]


def _det_normalise(text):
    text = unicodedata.normalize("NFKC", text.translate(_DET_MAP))  # look-alikes first: NFKC turns … into ...
    text = "".join(" " if unicodedata.category(c) == "Zs" else c for c in text
                   if c not in _DET_EXTRA and unicodedata.category(c) not in _DET_DROP or c in "\n\t\r")
    return text.translate(_DET_MAP)


def leak_detector(text):
    """Raw address parts in text: any 4 dotted digit groups; 3+ hex groups joined by ':' / '-' (clock times, dates,
    silence ids excepted); compressed IPv6 (a::b); Cisco aaaa.bbbb.cccc; 8+ hex mixing letters and digits, or 12
    digits. Masked forms the screens use and quoted fingerprints / digests are not findings."""
    t = _det_normalise(text)
    t = DET_OK_CONTEXT.sub(" ", MASKED_ANY.sub(" ", t))
    out = DET_QUAD.findall(t) + DET_V6.findall(t) + DET_CISCO.findall(t)
    for m in DET_GROUPS.finditer(t):
        g = m.group(0).strip(":-")
        if not any(k.fullmatch(g) for k in DET_KEEP):
            out.append(m.group(0))
    for m in DET_LONG.finditer(t):
        g = m.group(0)
        if re.search(r"[A-Fa-f]", g) and re.search(r"\d", g) or len(g) == 12 and g.isdigit():
            out.append(g)
    return out


def masker_selftest(perf_strict=False):
    """Free-text masking (P4 re-review r3): property tests (glue incl. "-" and hex letters, every IPv6 shape, 6-8 pair
    MACs with mixed separators, IPv4 incl. mapped, full-width text), the reviewer's DoS inputs, idempotence,
    readability, the independent leak detector, and time (absolute bounds only with OBS_SELFTEST_PERF=1)."""
    rnd = random.Random(7)
    glue = ["", " ", "x", "ip=", "addr:", "[", "(", "dst:", "IP", "機器", "ｱ", "\"", "'", "<", "@", "#", "/", ",", "_", "src ", "a.", "-", "--",
            ".", ":", "=", "g", "host-", "dead", "a", "ff:", "1.", "ver 3."]
    tails = ["", " ", "]", ")", ".443", ":443", "]:443", "%eth0", "%25lan1", "/64", ",", "が", "x", "g", ".", ":", "-", "::", "\"", "_", "#53",
             ".51000", ":51000", "z1", "-ab", "ab"]
    full = str.maketrans("0123456789abcdefABCDEF:.", "０１２３４５６７８９ａｂｃｄｅｆＡＢＣＤＥＦ：．")
    n = 0
    for _ in range(4000):
        groups = [rnd.randrange(0x10000) for _ in range(4)] + [rnd.randrange(0x1000, 0x10000) for _ in range(4)]
        if rnd.random() < .3:
            groups[rnd.randrange(1, 4)] = 0
        ip = ipaddress.IPv6Address(sum(g << (112 - 16 * k) for k, g in enumerate(groups)))
        form = rnd.choice([str(ip), ip.exploded, str(ip).upper(), ip.exploded.upper()])
        if rnd.random() < .1:
            form = form.translate(full)
        text = rnd.choice(glue) + form + rnd.choice(tails)
        out = mask_text(text)
        low = [f"{g:x}" for g in groups[4:]] + [f"{g:04x}" for g in groups[4:]]
        assert not any(x in out.lower() for x in low), (text, out)
        assert mask_text(out) == out and not leak_detector(out), (text, out, leak_detector(out))
        q = [rnd.randrange(1, 256), rnd.randrange(256), rnd.randrange(256), rnd.randrange(100, 256)]
        form = ".".join(map(str, q))
        text = rnd.choice(glue) + form + rnd.choice(tails)
        out = mask_text(text)
        assert form not in out and f"{q[2]}.{q[3]}" not in out and mask_text(out) == out and not leak_detector(out), (text, out)
        mac = [f"{rnd.randrange(256):02x}" for _ in range(rnd.choice([6, 7, 8]))]
        if rnd.random() < .5:
            mac = [m.upper() for m in mac]
        seps = [rnd.choice(":-")] * (len(mac) - 1) if rnd.random() < .7 else [rnd.choice(":-") for _ in mac[1:]]
        form = mac[0] + "".join(sp + m for sp, m in zip(seps, mac[1:]))
        text = rnd.choice(glue) + form + rnd.choice(tails)
        out = mask_text(text)
        assert not any(f"{mac[i - 1]}{seps[i - 1]}{mac[i]}" in out for i in range(3, len(mac))), (text, out)
        assert mask_text(out) == out and not leak_detector(out), (text, out, leak_detector(out))
        v4 = ipaddress.IPv4Address(rnd.getrandbits(32) | 100)
        for f2 in [str(ipaddress.IPv6Address(0xFFFF << 32 | int(v4))), "::ffff:%x:%x" % (int(v4) >> 16, int(v4) & 0xffff)]:
            out = mask_text(rnd.choice(glue) + f2 + rnd.choice(tails))
            assert str(v4) not in out and ("%x" % (int(v4) & 0xffff)) not in out.split("::ffff:")[-1][:5] and not leak_detector(out), (f2, out)
        n += 5
    # the raw forms are seen by the detector (it is not blind to what the masking hides)
    for raw in ["2001:db8::1", "fe80::1%eth0", "00:11:22:33:44:55", "host-00-11-22-33-44-55", "192.0.2.1", "c0000201", "001122334455", "a:b:c",
                "0011.2233.4455", "0192.0.2.1", "192\u034f.0.2.1", "192\ufe0f.0.2.1", "１９２。１６８。１。１", "192\u3164.0.2.1", "2001:db8\u200b::1",
                "192\x00.0.2.1", "192\u2065.0.2.1", "192\U000e0001.0.2.1", "192・168・1・1", "192·0·2·1", "192٫0٫2٫1", "192…0…2…1"]:
        assert leak_detector(raw), raw
    # the reviewer's DoS inputs: masked, never an exception (r3 a3 / a4)
    for c in ["a.::ffff:192.0.2.100", "a.::ffff:c000:264", "a.::1.2.3.4", "1.::1.2.3.4", "b.::ffff:1.2.3.4 x", "a.:1.2.3.4", "e.:2001:db8::1.2.3.4",
              "a.2001:db8::1.2.3.4", "ab.cd::1.2.3.4", "fe80::a.1.2.3.4", "Login failed user=ed.:2001:db8::192.0.2.1", "seen e.:1.2.3.4::1.2.3.4",
              "192\u200b.0.2.1", "192.0.2\xad.1", "١٩٢.٠.٢.١", "192.0.2.𝟏", "192﹒0﹒2﹒1", "2001﹕db8﹕﹕1", "00︓11︓22︓33︓44︓55"]:
        out = mask_text(c)
        assert not leak_detector(out) and mask_text(out) == out, (c, out)
    # readable text stays as it is
    for keep in ["14:04:20", "13:52:00.123", "2026-10-26T13:52:00+09:00", "rtx1300:9100", "10:443", "std::string", "foo::bar", "LAN2:", "PP[01]",
                 "LAN2[in]", "v3.6.0", "ab:cd", "ff:ff", "192.0.2.x", "192.0.2.x.443", "a - b", "-----", "...", "::", "::1", "12:00:00-13:00:00",
                 '"fingerprint": "0123456789abcdef"', "8f3e2a1c-1b2d-4c5e-9f00-123456789abc", "1792990353919000000", "1.5", "NaN", "Rejected at IN(1020) filter",
                 "[WLAN] STA associated: x SSID=home-main band=5GHz", "2026-10-26T05:03:04.123456789Z", "45.5 %"]:
        assert mask_text(keep) == keep, (keep, mask_text(keep))
    for c, want in [
            ("[INSPECT] PP[01][out][101098] TCP 192.168.100.23:50211 > 192.0.2.10:443 (2026/10/24 12:00:00)",
             "[INSPECT] PP[01][out][101098] TCP 192.168.100.x:50211 > 192.0.2.x:443 (2026/10/24 12:00:00)"),
            ("PP[01] Rejected at IN(1020) filter: TCP 198.51.100.7:51515 > 192.168.100.1:23", "PP[01] Rejected at IN(1020) filter: TCP 198.51.100.x:51515 > 192.168.100.x:23"),
            ("<190>Oct 25 12:00:00 rtx1300 PP[01] Rejected at IN(1020) filter: UDP 203.0.113.9:5353 > 192.168.100.1:161",
             "<190>Oct 25 12:00:00 rtx1300 PP[01] Rejected at IN(1020) filter: UDP 203.0.113.x:5353 > 192.168.100.x:161"),
            ("[DHCPD] LAN1(1) Allocates 192.168.100.23: 02:00:5e:10:00:17", "[DHCPD] LAN1(1) Allocates 192.168.100.x: 02:00:5e:xx:xx:xx"),
            ("[WLAN] STA associated: 02:00:5e:20:00:2a SSID=home-main band=5GHz", "[WLAN] STA associated: 02:00:5e:xx:xx:xx SSID=home-main band=5GHz"),
            ("[WLAN] STA disassociated: 02-00-5e-20-00-2a reason=8", "[WLAN] STA disassociated: 02-00-5e-xx-xx-xx reason=8"),
            ("TCP 192.168.100.23.50211 > 192.0.2.10.443 rejected", "TCP 192.168.100.x.50211 > 192.0.2.x.443 rejected"),  # YAMAHA addr.port
            ("192.0.2.1.80 ", "x "), ("1.192.0.2.1 ", "x "), ("192.0.2.1.8080 ", "192.0.2.x.8080 "), ("192.0.2.1.80x", "xx"), ("1.192.0.2.1;", "x;"),
            ("c0000201:443", "x"), ("001122334455:1", "x"), ("0011.2233.4455", "x"), ("0011-2233-4455", "x"), ("0192.0.2.1", "x"), ("192.0.2.1234", "x"),
            ("192\u034f.0.2.1", "192.0.2.x"), ("192\ufe0f.0.2.1", "192.0.2.x"), ("１９２。１６８。１。１", "192.168.1.x"), ("192｡168｡1｡1", "192.168.1.x"),
            ("00:11:22:33:44:55:66", "x"), ("00:11:22-33:44:55", "x"), ("MAC 00:11:22:33:44:55.", "MAC 00:11:22:xx:xx:xx."),
            ("192\x00.0.2.1", "192.0.2.x"), ("192\ufff0.0.2.1", "192.0.2.x"), ("192・168・1・1", "192.168.1.x"), ("192…0…2…1", "192.0.2.x"),
            ("a\tb\n192.0.2.1\r", "a\tb\n192.0.2.x\r"), ("日本・東京", "日本・東京"),
            ("192.0.2.1", "192.0.2.x"), ("IP 192.0.2.1.", "IP 192.0.2.x."), ("機器192.0.2.1が", "機器192.0.2.xが"), ("192.0.2.1:443", "192.0.2.x:443"),
                    ("2001:db8::1", "x"), ("[2001:db8::5]:443", "[x]:443"), ("fe80::1%eth0", "x%eth0"), ("host-00-11-22-33-44-55", "host-x"),
                    ("client-id 01:00:a0:de:12:34:56", "client-id x"), ("2001:db8:1:2:1234::gateway", "x::gateway"), ("enx001122334455", "enxx"),
                    ("dst:2001:db8:10:1:211:22ff:fe33:4455.51000", "dst:x")]:
        assert mask_text(c) == want, (c, mask_text(c), want)

    def took(f):
        t = time.perf_counter()
        f()
        return time.perf_counter() - t
    evil = ["a:" * 32768, "1:" * 32768, "fe:" * 21845, "1." * 32768, "a-" * 32768, ("ab:cd " * 11000)[:65536], ("::" + "1:" * 4) * 6000,
            "a.::1.2.3.4 " * 5000, ("2001:db8::1 " * 6000)[:65536]]
    worst = max(took(lambda e=e: mask_text(e)) for e in evil)
    lines = [f"2026-10-26T13:52:{i % 60:02d}+09:00 rtx1300 [INSPECT] LAN2[in] TCP 2001:db8:10:1:{rnd.getrandbits(16):x}:{rnd.getrandbits(16):x}:fe33:4455.51000"
             f" > 192.0.{i % 250}.{i % 199} 00:11:22:33:{i % 90:02d}:55 12:00:00" for i in range(5000)]
    page = took(lambda: [mask_text(x) for x in lines])
    small, big = ("2001:db8::1 " * 1400)[:16384], ("2001:db8::1 " * 5600)[:65536]
    t_small, t_big = took(lambda: mask_text(small)), took(lambda: mask_text(big))
    print(f"masker: {n} property cases; 64 KB adversarial max {worst * 1000:.1f} ms; 5000-line page {page * 1000:.0f} ms")
    assert t_big / max(t_small, 1e-3) < 8, (t_big, t_small)  # linear, never quadratic
    if perf_strict:
        assert worst < 0.05 and page < 0.2, (worst, page)


def selftest():
    q = urllib.parse.quote
    masker_selftest(os.environ.get("OBS_SELFTEST_PERF") == "1")
    assert mask_json({"metric": {"__name__": "obs_capture_up", "iface": "enx02005e100017"}})["metric"]["iface"] == "enx"
    al = mask_json({"labels": {"alertname": "CaptureDown", "iface": "enx02005e100017"},
                    "annotations": {"summary_ja": "enx02005e100017 でキャプチャが止まりました (5 分)"}})
    assert al["labels"]["iface"] == "enx" and al["annotations"]["summary_ja"] == "enx でキャプチャが止まりました (5 分)", al
    nested ={"status": "success", "data": {"result": [
        {"metric": {"dst_ip": "203.0.113.50", "mac": "02:00:5E:10:00:0A"}, "value": [1, "42"]},
        {"stream": {"host": "rtx1300"}, "values": [["1", "TCP 192.168.100.7:5555 > 192.0.2.10:443 02-00-5e-20-00-01"]]},
    ], "rules": [{"expr": 'x{dst_ip="198.51.100.20"}'}], "v6": "2001:db8::1", "oid": "1.3.6.1.2.1.1.3"}}
    out = json.dumps(mask_json(nested))
    assert not IPV4.search(out) and not MAC.search(out), out
    m = mask_json(nested)["data"]
    tok = m["result"][0]["metric"]["dst_ip"]
    assert re.fullmatch(r"203\.0\.113\.x~[0-9a-f]{12}", tok) and m["result"][0]["metric"]["mac"] == "02:00:5E:xx:xx:xx"
    assert mask_value("203.0.113.50") == tok and mask_value("203.0.113.60") != tok  # stable, and distinct per address
    assert m["result"][1]["values"][0][1] == "TCP 192.168.100.x:5555 > 192.0.2.x:443 02-00-5e-xx-xx-xx"  # free text keep-forms, no tokens
    assert m["result"][0]["value"] == [1, "42"] and re.fullmatch(r"2001:db8::x~[0-9a-f]{12}", m["v6"]), m["v6"]  # one IPv6 value: /64 + token
    assert m["oid"] == "x"  # free text: dotted digits that are not one standalone quad
    assert mask_json({"10.0.0.1": 1}) == {"10.0.0.x": 1}
    assert mask_value("2001:db8:1:2::x") == "2001:db8:1:2::x" and mask_value("192.0.2.x") == "192.0.2.x"  # masked values stay
    assert mask_value("02:00:5e:10:00:0a") == "02:00:5e:xx:xx:xx" and mask_value("rtx1300") == "rtx1300"
    # free text: the standalone keep-forms (IPv4 [+port], 6-pair MAC), everything else address-like -> "x"
    for raw, want in [("192.0.2.1が応答なし", "192.0.2.xが応答なし"), ("機器192.0.2.1", "機器192.0.2.x"), ("host_192.0.2.1", "host_x"),
                      ("x192.0.2.1y", "xxy"), ("MAC00:11:22:33:44:55", "Mx"), ("経由00:11:22:33:44:55です", "経由00:11:22:xx:xx:xxです"),
                      ("192.0.2.1:443", "192.0.2.x:443"), ("192.0.2.1.443", "192.0.2.x.443"), ("2001:db8::1", "x"), ("fe80::1%eth0", "x%eth0"),
                      ("[2001:db8::5]:443", "[x]:443"), ("2001:db8::1が", "xが"), ("addr=2001:db8:0:0:1:2:3:4,", "addr=x,"),
                      ("::ffff:192.0.2.1", "::x"), ("2001:db8::1/64", "x/64"), ("IPv6アドレス2001:db8::abcd", "IPv6アドレスx"),
                      ("TCP 2001:db8:10:1:211:22ff:fe33:4455.51000 > 2001:db8:ffff::1.443 rejected", "TCP x > x rejected"),
                      ("src=2001:db8:10:1:211:22ff:fe33:4455/128", "src=x/128"), ("addr 2001:DB8:10:1:211:22FF:FE33:4455", "addr x"),
                      ("fe80::211:22ff:fe33:4455%lan1", "x%lan1"), ("64:ff9b::192.0.2.1", "x"), ("2002:c000:20a::1", "x"),
                      ("14:04:20 std::string v3.6.0 192.0.2.x", "14:04:20 std::string v3.6.0 192.0.2.x"), ("a::b", "x")]:
        assert mask_text(raw) == want, (raw, mask_text(raw), want)
        assert mask_text(want) == want, want  # idempotent
    probe4 = mask_json({"stream": {"job": "syslog"}, "values": [["1", "[INSPECT] LAN2[in] TCP 2001:db8:10:1:211:22ff:fe33:4455.51000 > 2001:db8:ffff::1.443"]],
                        "metric": {"instance": "[2001:db8::5]:9100", "reason": "from 2001:db8::9"},
                        "alerts": [{"labels": {"alertname": "X", "instance": "2001:db8::7"}, "annotations": {"summary": "2001:db8::7 down"}}]})
    flat = json.dumps(probe4)
    assert "4455" not in flat and "::5]" not in flat and "::9" not in flat and "::7 " not in flat and "::1." not in flat, flat
    assert probe4["metric"]["instance"] == "[x]:9100" and probe4["alerts"][0]["annotations"]["summary"] == "x down", probe4
    assert re.fullmatch(r"2001:db8::x~[0-9a-f]{12}", probe4["alerts"][0]["labels"]["instance"])  # exact value: structured + token
    # never an exception out of masking: a page with the reviewer's inputs goes through (r3 a3 / a4)
    page = {"status": "success", "data": {"resultType": "streams", "result": [{"stream": {"job": "syslog"}, "values": [
        ["1", "Login failed user=ed.:2001:db8::192.0.2.1"], ["2", "a.::1.2.3.4"], ["3", "seen e.:1.2.3.4::1.2.3.4"]]}]}}
    body, _ = masked_body(json.dumps(page).encode(), "application/json")
    assert b"192.0.2.1" not in body and b"1.2.3.4" not in body and json.loads(body)["status"] == "success", body

    def plan(p):
        url, post, err = route("GET", p)
        return (urllib.parse.unquote_plus(url) if url else None), post, err
    lq = lambda s, extra="&limit=200": f"{LOKI_RANGE}?query={q(s)}{extra}"
    pq = lambda s: "/prom/api/v1/query?query=" + q(s)

    # every adversarial probe is rejected
    for probe in LOKI_PROBES:
        assert plan(lq(probe))[2][0] == 400, probe
    for probe in PROM_PROBES:
        assert plan(pq(probe))[2][0] == 400, probe
    forged = tok[:-1] + ("0" if tok[-1] != "0" else "1")
    for probe in ('x{dst_ip="%s"}' % forged, 'x{dst_ip="198.51.100.x~%s"}' % tok[-12:]):
        assert plan(pq(probe))[2][0] == 400, probe

    # UI shapes pass; Loki only ever sees the selector
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"} |= `Rejected` != "SSID=home-main"', "&limit=200&start=10&end=20&direction=forward"))
    assert url is None and post == LogSpec('{job="syslog",host="rtx1300"}', [("|=", "Rejected"), ("!=", "SSID=home-main")], 200, "forward", 10 * 10**9, 20 * 10**9)
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"} |= "192.0.2.x" |= "10:443"'))  # Codex suffix probe: allowed, but
    assert url is None and post.filters == [("|=", "192.0.2.x"), ("|=", "10:443")] and "192" not in post.selector  # filtered here
    url, post, _ = plan(lq('{job="syslog",host="rtx1300"}', "&limit=40&direction=forward"))  # no filter: Loki answers directly
    assert 'query={job="syslog",host="rtx1300"}&' in url and "limit=40" in url and post == ([], 40, "forward")
    url, post, _ = plan(lq('sum by (host, severity) (count_over_time({job="syslog"}[900s]))', "&start=1&end=2&step=60"))
    assert post is None and "count_over_time({job=\"syslog\"}[900s])" in url
    # filtered volume counts: planned for local counting on masked lines, never sent to Loki with the filter
    url, spec, _ = plan(lq('sum by (severity) (count_over_time({job="syslog",host="rtx1300"} |= "Rejected" != `TCP` [60s]))',
                           "&start=1761300060&end=1761303600&step=60"))
    assert url is None and spec.selector == '{job="syslog",host="rtx1300"}' and spec.filters == [("|=", "Rejected"), ("!=", "TCP")]
    assert (spec.by, spec.first_ns, spec.step_ns, spec.range_ns, spec.evals) == (("severity",), 1761300060 * 10**9, 60 * 10**9, 60 * 10**9, 60)
    assert plan(lq('sum by (severity) (count_over_time({job="syslog"} |= "x" [60s]))', "&start=1&end=2"))[2][0] == 400  # step required
    assert plan(lq('sum by (severity) (count_over_time({job="syslog"} |= "x" [60s]))', "&start=1&end=99999999&step=1"))[2][0] == 400
    s1 = 10**9
    sp = CountSpec(("host", "severity"), "{}", [("|=", "Rejected")], 120 * s1, 60 * s1, 60 * s1, 3)  # evals at 120, 180, 240
    ent = [({"host": "a", "severity": "info"}, 61 * s1, "Rejected 203.0.113.x"),   # (60,120] -> 120
           ({"host": "a", "severity": "info"}, 120 * s1, "Rejected"),               # boundary: belongs to 120
           ({"host": "a", "severity": "info"}, 121 * s1, "Rejected"),               # -> 180
           ({"host": "b", "severity": "notice"}, 240 * s1, "Rejected"),             # -> 240
           ({"host": "b", "severity": "notice"}, 241 * s1, "Rejected"),             # after last eval: dropped
           ({"host": "a", "severity": "info"}, 150 * s1, "TCP 192.0.2.x:443"),      # filtered out
           ({"host": "a", "severity": "info"}, 59 * s1, "Rejected")]                # before first window: dropped
    got = {tuple(r["metric"].values()): r["values"] for r in count_buckets(sp, ent)[0]}
    assert got == {("a", "info"): [[120, "2"], [180, "1"]], ("b", "notice"): [[240, "1"]]}, got
    wide = sp._replace(by=("severity",), range_ns=120 * s1)  # range > step: a line counts in every window covering it
    assert {tuple(r["metric"].values()): r["values"] for r in count_buckets(wide, ent[:3])[0]} == {("info",): [[120, "2"], [180, "3"], [240, "1"]]}
    hidden = sp._replace(filters=[("|=", "113.x")])  # a filter only ever sees masked text
    assert count_buckets(hidden, [({}, 121 * s1, "UDP 203.0.113.x:9 > 192.168.100.x:161")])[0] == [{"metric": {}, "values": [[180, "1"]]}]
    assert count_buckets(hidden._replace(filters=[("|=", "113.5")]), [({}, 121 * s1, "UDP 203.0.113.x:9")])[0] == []

    def naive(spec, ents):  # reference: every eval point checks every line
        out = {}
        for k in range(spec.evals):
            t = spec.first_ns + k * spec.step_ns
            for labels, ts, line in ents:
                if t - spec.range_ns < ts <= t and all((b in line) == (op == "|=") for op, b in spec.filters):
                    per = out.setdefault(tuple(labels.get(b) for b in spec.by), {})
                    per[k] = per.get(k, 0) + 1
        return {key: [(k, n) for k, n in sorted(per.items())] for key, per in out.items()}
    as_idx = lambda spec, res: {tuple(r["metric"].get(b) for b in spec.by):
                                [(round((float(t) * 10**9 - spec.first_ns) / spec.step_ns), int(v)) for t, v in r["values"]] for r in res}
    rnd = random.Random(7)
    for _ in range(40):
        step_ns = rnd.choice([1, 7, 60]) * s1
        rs = CountSpec(("host", "severity"), "{}", rnd.choice([[], [("|=", "R")], [("!=", "R")]]), 1000 * s1, step_ns,
                       rnd.randint(1, 30) * step_ns // rnd.choice([1, 2, 3]) + rnd.randint(0, 3), rnd.randint(1, 40))
        span = rs.evals * step_ns + rs.range_ns
        ents = [({"host": rnd.choice("ab"), "severity": rnd.choice(["info", "notice"])}, 1000 * s1 - rs.range_ns + rnd.randint(-s1, span + s1),
                 rnd.choice(["R x", "T y"])) for _ in range(rnd.randint(0, 60))]
        ents += [(ents[0][0], 1000 * s1 + rnd.randint(0, rs.evals) * step_ns, "R edge")] if ents else []  # exact eval-point hits
        assert as_idx(rs, count_buckets(rs, ents)[0]) == naive(rs, ents), rs
    heavy = CountSpec(("severity",), "{}", [("|=", "R")], 0, s1, 1440 * s1, 11000)  # Codex case: 1440 s range, 1 s step
    lines = [({"severity": "info"}, rnd.randint(0, 11000 * s1), "R") for _ in range(100000)]
    t0 = time.monotonic()
    res, done = count_buckets(heavy, lines)  # no deadline: the image is also built on slow hardware / under emulation
    took = time.monotonic() - t0
    assert done
    print(f"count_buckets: 100k lines x 11000 points, 1440 s range / 1 s step: {took:.2f}s")
    if os.environ.get("OBS_SELFTEST_PERF") == "1":  # absolute bound only where the hardware is known (local / CI runs)
        assert took < 1.0, took
    assert sum(int(v) for r in res for _, v in r["values"]) > 100000 * 1000  # each line counted in many windows, at O(1) each
    # complexity guard on any hardware: a line's cost must not grow with the number of windows covering it
    # (a per-window loop would make the 1440-step range ~1440x slower than the 1-step one; the difference array ~1x)
    few = lines[:20000]

    def timed(spec):  # best of 3
        best = float("inf")
        for _ in range(3):
            t = time.monotonic()
            count_buckets(spec, few)
            best = min(best, time.monotonic() - t)
        return best
    ratio = timed(heavy) / max(timed(heavy._replace(range_ns=s1)), 1e-6)
    print(f"count_buckets: 1440-step range / 1-step range time ratio {ratio:.1f} (bound 20)")
    assert ratio < 20, ratio
    res, done = count_buckets(heavy, lines, time.monotonic() - 1)  # deadline already past: stops, reports partial
    assert not done and res == []

    # run_count paging against a fake Loki (backward pages of [start, end), newest first)
    def fake_loki(lines, delay=0.0, calls=None, sloppy=0):
        def page(selector, start, end, limit, timeout, direction="backward"):
            if calls is not None:
                calls.append(timeout)
            if delay > timeout:
                time.sleep(timeout)
                raise TimeoutError
            time.sleep(delay)
            back = direction == "backward"
            got = sorted((e for e in lines if start <= e[1] < end), key=lambda e: -e[1] if back else e[1])
            if sloppy and len(got) > limit:  # like real Loki: a full page that skips lines just inside its edge
                cut = got[limit - 1][1]
                got = [e for e in got if not (cut - sloppy < e[1] <= cut if back else cut <= e[1] < cut + sloppy)]
            return got[:limit]
        return page
    one = CountSpec(("severity",), "{}", [("|=", "R")], 10 * s1, 10 * s1, 10 * s1, 1)  # single window (0, 10 s]
    sev = {"severity": "info"}
    run = lambda lines, **kw: json.loads(run_count(one, fake_loki(lines, **{k: v for k, v in kw.items() if k in ("delay", "calls", "sloppy")}),
                                                   **{"overlap_ns": 0, **{k: v for k, v in kw.items() if k in ("page_size", "budget_s", "overlap_ns")}})[1])["data"]
    total = lambda d: sum(int(v) for r in d["result"] for _, v in r["values"])
    four = [(sev, 5 * s1, "R a"), (sev, 4 * s1, "R b"), (sev, 4 * s1, "R c"), (sev, 2 * s1, "R d")]  # Codex case: 2 share the edge
    d = run(four, page_size=3)  # page edge on the ts=4 instant: re-fetched inclusively, deduped, no warning
    assert total(d) == 4 and "warnings" not in d, d
    d = run(four, page_size=2)  # page 1 ends inside the instant (old code counted 3); page 2 is all ts=4 -> conservative warning
    assert total(d) == 4 and "one timestamp" in d["warnings"][0], d
    same = [(sev, 4 * s1, f"R {i}") for i in range(5)]  # more lines in one instant than a page holds
    d = run(same, page_size=2)
    assert 2 <= total(d) <= 5 and "one timestamp" in d["warnings"][0], d
    masked_dupes = [(sev, 6 * s1, "R a"), (sev, 5 * s1, "R b"), (sev, 4 * s1, "R 10.0.0.1"), (sev, 4 * s1, "R 10.0.0.2"),
                    (sev, 3 * s1, "R z")]  # the ts=4 pair is identical after masking: dedupe must use the raw line
    d = run(masked_dupes, page_size=3)
    assert total(d) == 5 and "warnings" not in d, d
    burst = [(sev, 9 * s1 - i * 1000, f"R {i}") for i in range(400)]  # 1 us apart; a page of 50 spans 50 us
    assert total(run(burst, page_size=50, sloppy=3000)) < 400  # without overlap, a sloppy page edge loses lines
    d = run(burst, page_size=50, sloppy=3000, overlap_ns=10000)  # overlap (10 us) > skipped span, < page span
    assert total(d) == 400 and "warnings" not in d, d
    d = run(four, page_size=2, overlap_ns=10**9)  # overlap larger than the data: tight retry, then step past
    assert total(d) == 4, d
    # run_log: keep scanning until `limit` filtered lines, in either direction, across sloppy page edges
    logs = [({"host": "h"}, 100 * s1 + i * 1000, ("Rejected 203.0.113.7" if i % 13 == 0 else "STA x")) for i in range(500)]
    truth = sorted((ts for _, ts, l in logs if "Rejected" in l))
    def run_l(direction, limit, **kw):
        spec = LogSpec("{}", [("|=", "Rejected")], limit, direction, 100 * s1, 101 * s1)
        page = fake_loki(logs, **{k: v for k, v in kw.items() if k in ("delay", "sloppy")})
        return json.loads(run_log(spec, page, **{k: v for k, v in kw.items() if k in ("page_size", "budget_s", "overlap_ns")})[1])["data"]
    got_ts = lambda d: [int(v[0]) for r in d["result"] for v in r["values"]]
    for direction in ("backward", "forward"):
        want = truth[::-1] if direction == "backward" else truth
        for limit in (5, 39, 1000):
            d = run_l(direction, limit, page_size=20, sloppy=3000, overlap_ns=10000)
            assert got_ts(d) == want[:limit] and "warnings" not in d, (direction, limit, d)
    d = run_l("backward", 5, page_size=20)
    assert all(v[1] == "Rejected 203.0.113.x" for r in d["result"] for v in r["values"])  # masked before filtering and returned
    d = run_l("backward", 1000, page_size=20, delay=0.05, budget_s=0.12, overlap_ns=0)  # budget ends mid-window: partial
    assert "partial result" in d["warnings"][0] and len(got_ts(d)) < len(truth), d
    rest = LogSpec("{}", [("|=", "Rejected")], 1000, "backward", 100 * s1, int(d["scanned_until"]))
    more = got_ts(json.loads(run_log(rest, fake_loki(logs), page_size=20, overlap_ns=0)[1])["data"])
    assert sorted(set(got_ts(d)) | set(more)) == truth  # continuing from scanned_until completes the window

    # window bounds: a page narrower than the 1 s overlap must not pull lines from outside [start, end)
    for direction in ("backward", "forward"):
        near = 100 * s1 + (900 * 10**6 if direction == "backward" else 0)  # dense burst at the edge being paged from
        win = [({"host": "h"}, near + i * 1000, "STA burst") for i in range(50)]
        win += [({"host": "h"}, 100 * s1 + 500 * 10**6, "Rejected inside")]
        win += [({"host": "h"}, 101 * s1 + 200 * 10**6, "Rejected after end"), ({"host": "h"}, 100 * s1 - 300 * 10**6, "Rejected before start")]
        spec = LogSpec("{}", [("|=", "Rejected")], 10, direction, 100 * s1, 101 * s1)
        for leaky in (False, True):  # leaky: an upstream that also returns lines outside the requested bounds
            honest = fake_loki(win)
            src = (lambda *a, h=honest: h(*a) + win[-2:]) if leaky else honest  # win[-2:] lie outside the window
            d = json.loads(run_log(spec, src, page_size=20)[1])["data"]
            assert [v[1] for r in d["result"] for v in r["values"]] == ["Rejected inside"], (direction, leaky, d)
    # limit reached on a page that omitted a line near its edge (Codex: matches at 9 and 6, 7 omitted):
    # keep scanning until the overlap has re-covered the cutoff, then pick the true first `limit`
    for direction, kinds in (("backward", {9: "R", 8: "S", 7: "R", 6: "R", 5: "S", 4: "S", 3: "S", 2: "S", 1: "S"}),
                             ("forward", {1: "R", 2: "S", 3: "R", 4: "R", 5: "S", 6: "S", 7: "S", 8: "S", 9: "S"})):
        lines9 = [({"host": "h"}, t * s1, f"{k} {t}") for t, k in kinds.items()]
        spec = LogSpec("{}", [("|=", "R")], 2, direction, 0, 10 * s1)
        d = json.loads(run_log(spec, fake_loki(lines9, sloppy=s1), page_size=3, overlap_ns=2 * s1)[1])["data"]
        want = [9 * s1, 7 * s1] if direction == "backward" else [1 * s1, 3 * s1]
        assert got_ts(d) == want and "warnings" not in d, (direction, d)

    # line cap hit mid-scan: continuing from scanned_until repeats nothing and covers the window
    global SCAN_MAX_LINES
    cap_was, SCAN_MAX_LINES = SCAN_MAX_LINES, 50
    try:
        for direction in ("backward", "forward"):
            lo, hi, out, calls_n = 100 * s1, 101 * s1, [], 0
            while True:
                calls_n += 1
                d = json.loads(run_log(LogSpec("{}", [("|=", "Rejected")], 1000, direction, lo, hi), fake_loki(logs), page_size=20)[1])["data"]
                out += got_ts(d)
                if "scanned_until" not in d:
                    break
                assert "line cap" in d["warnings"][0], d
                if direction == "backward":
                    hi = int(d["scanned_until"])
                else:
                    lo = int(d["scanned_until"]) + 1
            assert calls_n > 2 and len(out) == len(set(out)) and sorted(out) == truth, (direction, calls_n, len(out), len(set(out)))
        dense = [(sev, 5 * s1 + i * 1000, "R") for i in range(500)]  # 1 us apart: every 1 s overlap re-reads lines
        raw_read = []
        base = fake_loki(dense)
        spy = lambda *a: raw_read.append(len(p := base(*a))) or p
        d = json.loads(run_count(one, spy, page_size=20)[1])["data"]
        assert sum(raw_read) <= 50 + 20 and "line cap" in d["warnings"][0], (raw_read, d)  # cap counts raw lines read
    finally:
        SCAN_MAX_LINES = cap_was

    # an instant larger than a page hides a match, later matches still fill the limit: the gap must be reported
    same = [({"host": "h"}, 100 * s1 + 900 * 10**6, l) for l in ("STA a", "STA b", "STA c", "STA d", "Rejected same instant")]
    same += [({"host": "h"}, 100 * s1 + k * 10**8, "Rejected older") for k in (5, 4, 3)]
    d = json.loads(run_log(LogSpec("{}", [("|=", "Rejected")], 3, "backward", 100 * s1, 101 * s1), fake_loki(same), page_size=3, overlap_ns=0)[1])["data"]
    assert len(got_ts(d)) == 3 and "possible gaps" in d["warnings"][0] and "one timestamp" in d["warnings"][0], d
    cs = CountSpec(("severity",), "{}", [("|=", "Rejected")], 101 * s1, s1, 2 * s1, 1)
    d = json.loads(run_count(cs, fake_loki([({"severity": "info"}, ts, l) for _, ts, l in same]), page_size=3, overlap_ns=0)[1])["data"]
    assert "one timestamp" in d["warnings"][0], d
    leak_count = lambda sel, st, en, lim, to, dr="backward": [(sev, 5 * s1, "R in"), (sev, 30 * s1, "R out"), (sev, -5 * s1, "R out")]
    assert total(json.loads(run_count(one, leak_count, page_size=10)[1])["data"]) == 1

    calls = []  # slow upstream: per-page timeout is cut to the remaining budget, result is partial
    d = run([(sev, (9 - i) * s1, f"R {i}") for i in range(9)], page_size=2, delay=0.15, budget_s=0.4, calls=calls)
    assert all(t <= 0.4 for t in calls) and "time budget" in d["warnings"][0] and 2 <= total(d) < 9, (calls, d)
    try:  # nothing fetched within the budget: surfaces as a timeout (504), never past the budget
        t0 = time.monotonic()
        run(four, delay=5, budget_s=0.3)
        raise AssertionError("expected timeout")
    except TimeoutError:
        assert time.monotonic() - t0 < 1

    assert plan(lq('{job="syslog"}', "&limit=40&direction=sideways"))[2][0] == 400
    assert plan(lq('{job="syslog"}', "&limit=40&foo=1"))[2][0] == 400

    # line filters run on masked text: a hidden octet can never match
    streams = {"status": "success", "data": {"resultType": "streams", "stats": {"x": 1}, "result": [
        {"stream": {"host": "a"}, "values": [["3", "TCP 192.168.100.x:4 > 192.0.2.x:443"], ["1", "Rejected 203.0.113.x:23"]]},
        {"stream": {"host": "b"}, "values": [["2", "Rejected 198.51.100.x:23"]]}]}}
    f = lambda flt, lim=10, d="backward": [v[1] for s in apply_line_filters(streams, flt, lim, d)["data"]["result"] for v in s["values"]]
    assert f([("|=", "192.0.2.x"), ("|=", "10:443")]) == []
    assert f([("|=", "Rejected")], 1) == ["Rejected 198.51.100.x:23"]
    assert f([("|=", "Rejected")], 1, "forward") == ["Rejected 203.0.113.x:23"]
    assert f([("!=", "Rejected")]) == ["TCP 192.168.100.x:4 > 192.0.2.x:443"]
    assert "stats" not in apply_line_filters(streams, [], 10, "backward")["data"]

    # Prometheus: UI queries pass, tokens resolve, plain masks become prefix regexes
    assert plan(pq("up"))[0] == PROM + "/api/v1/query?query=up"
    assert plan("/prom/api/v1/alerts")[0] == PROM + "/api/v1/alerts"
    assert plan("/prom/api/v1/alerts?x=1")[2][0] == 400
    assert plan("/prom/api/v1/query_range?query=up&start=1761300000.123&end=1761303600.5&step=15")[0]
    assert plan("/prom/api/v1/query?query=up&time=" + q("10.0.0.1"))[2][0] == 400
    assert plan("/prom/api/v1/query?query=up&foo=bar")[2][0] == 400
    ui = '(sum by (instance) (rate(ifHCInOctets{job="snmp",instance="rtx1300",ifName="lan2"}[1m])) * 8 / 1e6) and on (instance) (up{job="snmp"} == 1)'
    assert plan(pq(ui))[0].endswith(ui)
    assert plan(pq("topk(3, demo_flow_bytes_total) > 1e9"))[0]  # ranking/comparison only see numbers; labels come back masked
    assert plan(pq('rate(x{dst_ip="%s"}[5m])' % tok))[0].endswith('rate(x{dst_ip="203.0.113.50"}[5m])')  # token round trip
    for v6 in ("2001:db8:1:2::x", "fe80::x", "64:ff9b::192.0.2.x", "2002::x"):  # flowd's masked IPv6 labels: exact match
        assert plan(pq('obs_flow_bytes_total{dst_ip="%s"}' % v6))[0].endswith('obs_flow_bytes_total{dst_ip="%s"}' % v6), v6
    assert plan(lq('{job="syslog"} |= "14:04:20" |= "10:443"'))[1].filters == [("|=", "14:04:20"), ("|=", "10:443")]  # times / ports
    assert plan(pq('sum(rate(x{dst_ip="203.0.113.x"}[5m]))'))[0].endswith('sum(rate(x{dst_ip=~"203[.]0[.]113[.][0-9]{1,3}"}[5m]))')
    assert plan(pq('x{dst_ip!="203.0.113.x"}'))[0].endswith('x{dst_ip!~"203[.]0[.]113[.][0-9]{1,3}"}')

    for path in ("/prom/api/v1/status/config", "/prom/api/v1/query/../admin/tsdb/snapshot", "/loki/loki/api/v1/push", "/loki/loki/api/v1/query"):
        assert plan(path)[2][0] == 403, path
    assert route("POST", pq("up"))[2][0] == 405
    assert request_role({}) == request_role({"X-Obs-Role": "admin"}) == request_role({"X-Obs-Role": " Viewer "}) == "viewer"  # no key: viewer
    global MAX_TOKENS
    keep, MAX_TOKENS = MAX_TOKENS, 3
    t1 = mask_value("198.51.100.1")
    for i in range(2, 6):
        mask_value(f"198.51.100.{i}")
    assert t1[-12:] not in TOKENS and len(TOKENS) <= 3 and mask_value("198.51.100.5")[-12:] in TOKENS  # LRU, bounded
    MAX_TOKENS = keep
    relay_selftest()
    tok = mask_value("203.0.113.50")  # (re-register the token the alert tests use)
    am_selftest(tok)
    pcap_api.selftest()
    evidence.selftest()
    correlate.selftest()
    print(f"selftest ok ({len(LOKI_PROBES) + len(PROM_PROBES) + 2} adversarial probes rejected)")


pcap_api.setup(sys.modules[__name__])
evidence.setup(sys.modules[__name__], pcap_api)
correlate.setup(sys.modules[__name__])

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        # The UI fires ~50 queries per refresh at once; the stdlib default backlog (5) drops SYNs,
        # which nginx reports as connect timeouts (504).
        KEY = shared_key(KEY_FILE, KEY)
        ThreadingHTTPServer.request_queue_size = 256
        ThreadingHTTPServer.daemon_threads = True
        ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
