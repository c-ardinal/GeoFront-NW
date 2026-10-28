"""Display-filter policy for the packet analysis API: an ALLOWLIST grammar, default deny.

A display filter runs on the raw packets, so it is an oracle on everything the screens mask. Only this grammar is
accepted, parsed into a tree and written out again (tshark only ever sees the rewritten text, never the user's):

  expr  := and ( ("||" | "or") and )*
  and   := unary ( ("&&" | "and") unary )*
  unary := ("!" | "not") unary | "(" expr ")" | atom
  atom  := FIELD [ OP VALUE | ["not"] "in" "{" VALUE ("," VALUE)* "}" ]

FIELD must be in FIELDS (curated, with a kind) or a protocol name (presence only). Kinds:
  num   numeric header fields (ports, flags, lengths, types, times): == != < > <= >= and number sets / ranges
  str   names (DNS query, SNI, HTTP Host, ...): == != contains, values in the hostname shape of str_value()
  v4 / v6 / mac  address fields: == != and sets, ONLY against opaque tokens of the same family (masked forms the
        screens were given); a raw address, a partial one, ordering, ranges, bitwise ops are not part of the grammar
  flag  presence only (analysis flags)
Everything else - leading-dot field references, slices, functions, arithmetic, field-to-field comparisons, layer
operators, macros, regex (matches / ~), bytes / checksum / payload fields, any unknown character - fails to parse.
"""
import re

FILTER_MAX = 512
MAX_FIELDS = 32
MAX_TOKENS = 200

FIELDS = {}
for _k, _names in {
    "num": """frame.len frame.cap_len frame.number frame.time_epoch frame.time_relative frame.time_delta
        frame.time_delta_displayed ip.ttl ip.proto ip.len ip.id ip.hdr_len ip.dsfield.dscp ip.dsfield.ecn ip.flags.df
        ip.flags.mf ip.frag_offset ipv6.nxt ipv6.hlim ipv6.plen ipv6.tclass ipv6.flow tcp.port tcp.srcport tcp.dstport
        tcp.len tcp.hdr_len tcp.flags tcp.flags.syn tcp.flags.ack tcp.flags.fin tcp.flags.reset tcp.flags.push
        tcp.flags.urg tcp.stream tcp.seq tcp.ack tcp.window_size tcp.window_size_value tcp.time_delta
        tcp.analysis.ack_rtt udp.port udp.srcport udp.dstport udp.length udp.stream icmp.type icmp.code icmpv6.type
        icmpv6.code vlan.id vlan.priority eth.type arp.opcode dns.id dns.qry.type dns.qry.class dns.flags.response
        dns.flags.rcode dns.count.answers dns.count.queries dns.resp.ttl dns.resp.type tls.handshake.type
        tls.record.content_type tls.record.version tls.handshake.version http.response.code http.content_length
        dhcp.option.dhcp ntp.stratum ntp.flags.mode""",
    "str": """dns.qry.name dns.resp.name tls.handshake.extensions_server_name http.host http.request.method
        http.request.uri http.user_agent dhcp.option.hostname frame.protocols""",
    "v4": "ip.addr ip.src ip.dst arp.src.proto_ipv4 arp.dst.proto_ipv4 dns.a",
    "v6": "ipv6.addr ipv6.src ipv6.dst dns.aaaa",
    "mac": "eth.addr eth.src eth.dst arp.src.hw_mac arp.dst.hw_mac",
    "flag": """tcp.analysis.flags tcp.analysis.retransmission tcp.analysis.fast_retransmission tcp.analysis.duplicate_ack
        tcp.analysis.lost_segment tcp.analysis.out_of_order tcp.analysis.zero_window http.request http.response""",
}.items():
    for _n in _names.split():
        FIELDS[_n] = _k
ADDRESS_KINDS = ("v4", "v6", "mac")

LEX = re.compile(r'\s+|"[A-Za-z0-9._\-]*"|==|!=|<=|>=|&&|\|\||[<>!(){},]|[A-Za-z0-9_:][A-Za-z0-9_.:~\-]*')  # ':' starts ::ffff:… tokens
FIELD_RE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*")
NUMBER = re.compile(r"-?(?:0x[0-9a-fA-F]{1,16}|\d{1,20}(?:\.\d{1,9})?)")
RANGE = re.compile(r"(\d{1,10})\.\.(\d{1,10})")
WORD_OPS = {"eq": "==", "ne": "!=", "lt": "<", "gt": ">", "le": "<=", "ge": ">=", "and": "&&", "or": "||", "not": "!"}
EQ_OPS = {"==", "!="}
NUM_OPS = EQ_OPS | {"<", ">", "<=", ">="}
TOK = {"v4": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.x~([0-9a-f]{12})"), "v6": re.compile(r"([0-9a-f:]*::x|::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.x|64:ff9b::\d{1,3}\.\d{1,3}\.\d{1,3}\.x)~([0-9a-f]{12})"),  # every v6_base form
       "mac": re.compile(r"((?:[0-9a-f]{2}:){3})xx:xx:xx~([0-9a-f]{12})")}
V4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
HOST_VALUE = re.compile(r"[A-Za-z0-9._\-]{1,100}")
HELP = ("表示フィルタは許可リスト方式です: プロトコル名 (dns など)、ポート・フラグ・長さなどの数値、名前 (dns.qry.name など)、"
        "アドレスは一覧・詳細から選んだ値 (伏せ字+トークン) との == / != / in {…}。それ以外の書き方は使えません")


class Refused(ValueError):
    pass


def str_value(v, shown=lambda v: True):
    """A name value: hostname characters only, and no part that could test the hidden part of an address written as
    text - every part between . _ - must hold a letter beyond a-f (so "cafe", "ff", "5", "a.b", "abcd)" are refused),
    and no digit next to a dot."""
    if not shown(v):  # content the screens would mask: never searchable
        raise Refused(f"画面で伏せ字になる値では絞り込めません: {v[:3]}…")
    if not HOST_VALUE.fullmatch(v) or re.search(r"\d\.|\.\d", v):
        raise Refused(f"名前の値はホスト名の形 (英字・数字・. - _) だけです: {v[:40]}")
    for part in re.split(r"[._\-]+", v):
        if part and not re.search(r"[g-zG-Z]", part):
            raise Refused(f"16 進数字や数字だけの部分 ({part[:20]}) を含む値は使えません (伏せ字の部分を試せてしまうため)")
    return '"' + v + '"'


def lex(text):
    pos, out = 0, []
    while pos < len(text):
        m = LEX.match(text, pos)
        if not m:
            raise Refused(f"使えない文字・書き方があります (位置 {pos + 1})。{HELP}")
        t = m.group(0)
        if not t.isspace():
            out.append(WORD_OPS.get(t.lower(), t) if t.lower() in WORD_OPS else t)
        pos = m.end()
    if len(out) > MAX_TOKENS:
        raise Refused("表示フィルタが長すぎます (要素が多すぎます)")
    return out


class Parser:
    """Recursive descent over the tokens; builds the rewritten filter as it goes."""

    def __init__(self, toks, kind_of, tokens, shown=lambda v: True):
        self.t, self.i, self.kind_of, self.tokens, self.fields, self.shown = toks, 0, kind_of, tokens, set(), shown

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def take(self, want=None):
        t = self.peek()
        if t is None or (want is not None and t != want):
            raise Refused(f"表示フィルタの書き方が違います ({'終わり' if t is None else t[:20]} の位置)。{HELP}")
        self.i += 1
        return t

    def expr(self):
        out = [self.conj()]
        while self.peek() == "||":
            self.take()
            out.append(self.conj())
        return " || ".join(out)

    def conj(self):
        out = [self.unary()]
        while self.peek() == "&&":
            self.take()
            out.append(self.unary())
        return " && ".join(out)

    def unary(self):
        t = self.peek()
        if t == "!":
            self.take()
            return "!" + self.unary()
        if t == "(":
            self.take()
            inner = self.expr()
            self.take(")")
            return "(" + inner + ")"
        return self.atom()

    def atom(self):
        f = self.take()
        if not FIELD_RE.fullmatch(f):
            raise Refused(f"フィールド名ではありません: {f[:30]}。{HELP}")
        self.fields.add(f)
        if len(self.fields) > MAX_FIELDS:
            raise Refused(f"フィールドは {MAX_FIELDS} 種類まで")
        kind = self.kind_of(f)
        if kind is None:
            raise Refused(f"{f}: このフィールドは絞り込みに使えません (許可リスト外。チェックサム・バイト列・内容そのものは不可)")
        op = self.peek()
        negate = op == "!" and self.peek(1) == "in"
        if op not in NUM_OPS | {"contains", "in"} and not negate:
            return f  # presence
        if kind in ("protocol", "flag"):
            raise Refused(f"{f}: プロトコル・フラグは有無 ({f} / !{f}) だけで絞り込めます")
        if negate:
            self.take()
        if self.peek() == "in":
            self.take()
            self.take("{")
            vals = [self.value(f, kind, in_set=True)]
            while self.peek() == ",":
                self.take()
                vals.append(self.value(f, kind, in_set=True))
            self.take("}")
            return f"{f} {'not in' if negate else 'in'} {{{', '.join(vals)}}}"
        self.take()
        if (kind == "num" and op == "contains") or (kind != "num" and op not in EQ_OPS and not (kind == "str" and op == "contains")):
            raise Refused(f"{f}: この比較 ({op}) は使えません (== / != {'/ contains ' if kind == 'str' else ''}だけ)")
        return f"{f} {op} {self.value(f, kind)}"

    def value(self, f, kind, in_set=False):
        v = self.take()
        if kind == "num":
            if NUMBER.fullmatch(v):
                return v
            r = RANGE.fullmatch(v)
            if r and in_set and int(r.group(1)) <= int(r.group(2)):  # ranges only inside a set
                return v
            raise Refused(f"{f}: 数値を指定してください ({v[:20]})")
        if kind == "str":
            return str_value(v[1:-1] if v.startswith('"') else v, self.shown)
        m = TOK[kind].fullmatch(v)
        if not m:
            raise Refused(f"{f}: アドレスは一覧・詳細から選んだ値 (伏せ字+トークン) で指定してください")
        real = self.tokens.get(m.group(2))
        fam = None if not real else "v4" if V4.fullmatch(real) else "mac" if MAC.fullmatch(real) else "v6"
        if fam != kind or (kind == "v4" and not real.startswith(m.group(1) + ".")):
            raise Refused("unknown or expired address token (or another address family); reload the page")
        return real


def check(text, protocols_of, tokens, shown=lambda v: True):
    """Display filter -> the filter for tshark. protocols_of(names) -> set of those names that are protocols;
    tokens: token -> real address. Raises Refused."""
    text = (text or "").strip()
    if len(text) > FILTER_MAX:
        raise Refused(f"表示フィルタは {FILTER_MAX} 文字まで")
    if not text:
        return ""
    toks = lex(text)
    toks = [{"contains": "contains", "in": "in"}.get(t.lower(), t) if t.lower() in ("contains", "in") else t for t in toks]
    unknown = sorted({t for t in toks if FIELD_RE.fullmatch(t) and t not in FIELDS and t not in ("in", "contains")})
    if len(unknown) > MAX_FIELDS:
        raise Refused(f"フィールドは {MAX_FIELDS} 種類まで")
    protos = protocols_of(unknown) if unknown else set()
    kind_of = lambda f: FIELDS.get(f) or ("protocol" if f in protos else None)
    p = Parser(toks, kind_of, tokens, shown)
    out = p.expr()
    if p.peek() is not None:
        raise Refused(f"表示フィルタの書き方が違います ({p.peek()[:20]} の位置)。{HELP}")
    return out


def selftest(tok_v4, tok_v6, tok_mac, tokens, shown=lambda v: True):
    protos = {"dns", "tcp", "udp", "ip", "arp", "frame", "eth", "tls", "http", "dhcp", "ntp", "icmp", "icmpv6", "ipv6", "vlan"}
    pad = [f"p{i:02d}" for i in range(70)]  # 65+ distinct names (Codex probe): never truncated, refused past 32
    protos |= set(pad)
    po = lambda names: {n for n in names if n in protos}
    ok = lambda f: check(f, po, tokens, shown)
    assert ok("") == "" and ok("dns") == "dns" and ok("tcp.port == 443 and !dns") == "tcp.port == 443 && !dns"
    assert ok(f"ip.addr == {tok_v4}") == f"ip.addr == {tokens[tok_v4[-12:]]}"
    assert ok(f"ipv6.addr == {tok_v6}").startswith("ipv6.addr == ")
    assert ok(f"ip.addr in {{{tok_v4}, {tok_v4}}} && frame.time_epoch >= 1792810800.5").startswith("ip.addr in {")
    assert ok('dns.qry.name contains "example"') == 'dns.qry.name contains "example"' and ok('http.host == "www.example.com"')
    assert ok("tcp.port in {80, 443, 8000..8080} || (udp.port == 53 && dns.flags.response == 1)")
    assert ok("dns.qry.name") == "dns.qry.name" and ok("ip.src") == "ip.src" and ok("tcp.analysis.retransmission")
    assert ok(" || ".join(pad[:31]) + " || dns")
    reviewer = " || ".join(pad[:64])
    probes = [
        # reviewer (h.py): padding past a 64-name window, MAC / checksum / numeric address comparisons, leading dots
        reviewer + " || eth.src > 02-00-5e-10-00-16", reviewer + " || eth.src == 02-00-5e-10-00-17", reviewer + " || ip.checksum == 0x0000",
        reviewer + " || ip.src > 3232261142", reviewer + " || ip.src > 192.168.100.0/24", " || ".join(pad[:65]),
        "eth.src > 02-00-5e-10-00-16", ".eth.src > 02-00-5e-10-00-16", ".eth.src == 02-00-5e-10-00-17", ".ip.checksum == 0x0000",
        ".ip.src == .ip.dst", "frame.len > 0 && .tcp.checksum > 0x8000", ".ip.checksum > 0x8000",
        'http.user_agent contains "abcd)"', 'dns.qry.name contains "-ff "', 'dns.qry.name contains "ab"', 'dns.qry.name == "cafe"',
        'http.host contains "5"', 'http.host contains "a.b"', 'http.host contains "x.5"', 'http.host contains "ff-ee"', "http.host contains ab",
        'dns.qry.name in {"ab", "cd"}', 'http.host contains "1"', 'dhcp.option.hostname contains "e"',
        # addresses: raw / masked without token / wrong family / ordering / bitwise / ranges
        "ip.src == 192.168.100.23", "ip.src == 192.168.100.x", f"ip.src > {tok_v4}", f"ip.src & 0.0.0.255", f"ipv6.addr == {tok_v4}",
        f"ip.addr == {tok_v6}", f"eth.addr == {tok_v4}", "ip.addr == 192.168.100.x~000000000000", f"ip.addr in {{{tok_v4}..{tok_v4}}}",
        "eth.addr == 02:00:5e:10:00:17", "ip.src == fe80::1", "ip.src == ip.dst", f"ip.src == {tok_v4} == 1",
        # not on the allowlist at all
        "ip.checksum == 0x1234", "tcp.checksum", "frame contains 05", "frame[26:4] == c0:a8:64:17", "data.data", "eth.src_resolved",
        "ip.src_host", "_ws.col.info contains x", "ntp.refid", "icmpv6.opt.linkaddr", "pim.cksum", "udp.payload",
        'dns.qry.name matches "^x"', "dns.qry.name ~ x", "string(ip.src) contains x", "len(ip.src) == 4", "upper(http.host) == X",
        "${ip.src}", "ip.src == $x", "@ip.src == 1", "ip.src#1 == x", "frame.len + 1 == 2", "frame.len == frame.cap_len",
        "tcp.port == 1 ; ls", "dns || ", "(dns", "dns)", "dns dns", "tcp.port == abc", "tcp.port == 1.2.3", "a" * 513,
        "tcp.port in {1..}", "tcp.port in {}", "tcp.port == 1..5", "tcp.port > 80..90", "tcp.port in {9..1}", "dns && !", "dns.qry.name == \"x\\\"y\"", "nosuch.field == 1", "nosuch.field",
        "tcp.flags.syn == 1 || tcp.port == 0x1 || ip.checksum", "dns.qry.name == example.de",
        'http.host == "hostc0a86417"', 'dns.qry.name contains "ESP_DDEEFF"', 'dns.qry.name contains "deadbeefz"', 'http.host == "wKhkFw=="',
        'dns.qry.name contains "zen-ab"', 'dhcp.option.hostname == "android-ab"', 'http.host contains "bad"',
    ]
    for f in probes:
        try:
            r = ok(f)
            raise AssertionError(f"accepted: {f[-60:]} -> {r[-60:]}")
        except Refused:
            pass
    return len(probes)
