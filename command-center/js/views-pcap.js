// Packet analysis modal ("解析"): capture / uploaded / demo pcap files analysed server-side by tshark in the analyzer
// sandbox, through mask-api's /pcap/ API. Everything shown arrives masked (IP / MAC as a.b.c.x, <64>::x,
// aa:bb:cc:xx:xx:xx with an opaque ~token, hex bytes of addresses as "xx"); tokens are only used to build filters.
// Layout: toolbar (file, upload, display filter, status) -> tabs -> packets (virtual list | detail tree + hex) or
// statistics (protocols, conversations, endpoints, I/O, names). Opened from GLOBAL TRAFFIC and the destination /
// source drawers ("この通信のパケット"), which pass a filter and a time window.
import { el, sortTable, lineChart, chartColors, legend, jstFull, jstClock, fmtBytes, has } from './util.js';
import { promQuery } from './api.js';
import { lv } from './views-common.js';

const PAGE = 500;
const MAX_ROWS_CSV = 5000;
const TOKEN = /~[0-9a-f]{12}$/;
const show = (a) => String(a || '').replace(TOKEN, ''); // masked address without its token
const ATTRIB = 'GeoIP: IP Geolocation by DB-IP (db-ip.com), CC BY 4.0';

async function api(path, params, opts = {}) {
  const r = await fetch(`/pcap/${path}${params ? `?${new URLSearchParams(params)}` : ''}`, { cache: 'no-store', ...opts });
  const body = await r.json().catch(() => null);
  if (!r.ok) {
    const e = new Error(body?.error || `/pcap/${path} HTTP ${r.status}`);
    e.kind = body?.errorType || (r.status >= 500 ? 'analyzer' : 'http');
    throw e;
  }
  return body;
}

// ---- drill-down filters (tokens from the flows on screen; never a raw address) ------------------------------
const tokenOf = (s) => (TOKEN.test(String(s)) ? String(s) : null);
// the filter field for a token's address family (the server refuses a token of another family)
// (MAC first; any other form with a ':' is IPv6, incl. ::ffff:a.b.c.x / 64:ff9b::a.b.c.x / 2002::x)
export const addrField = (tok) => (/^([0-9a-f]{2}:){3}xx:/.test(tok) ? 'eth.addr' : tok.includes(':') ? 'ipv6.addr' : 'ip.addr');
function addrFilter(tokens) {
  const t = [...new Set(tokens.filter(Boolean))].slice(0, 15);
  const by = new Map();
  for (const x of t) by.set(addrField(x), [...(by.get(addrField(x)) || []), x]);
  return [...by].map(([f, xs]) => (xs.length === 1 ? `${f} == ${xs[0]}` : `${f} in {${xs.join(', ')}}`)).join(' || ');
}
// address fields the server's filter allowlist accepts (the tree offers "絞り込む" only for these)
const FILTERABLE = new Set(['ip.addr', 'ip.src', 'ip.dst', 'ipv6.addr', 'ipv6.src', 'ipv6.dst', 'eth.addr', 'eth.src', 'eth.dst',
  'arp.src.proto_ipv4', 'arp.dst.proto_ipv4', 'arp.src.hw_mac', 'arp.dst.hw_mac', 'dns.a', 'dns.aaaa']);
// opts: { dest: {cc, city, ip}, flows } | { src: host } | {}
export async function drillFilter(opts) {
  if (opts.dest) {
    const d = opts.dest;
    if (d.ip) {
      return tokenOf(d.ip) ? { filter: addrFilter([tokenOf(d.ip)]), what: `宛先 ${show(d.ip)}` }
        : { filter: '', what: `宛先 ${show(d.ip)}`, note: 'この宛先 (IPv6 は /64 で伏せた値) では絞り込めないため、フィルタなしで開きます' };
    }
    const ips = [...(opts.flows || [])].filter((f) => f.cc === d.cc && (!d.city || f.city === d.city)).sort((a, b) => b.bps - a.bps).map((f) => tokenOf(f.ip));
    const n = new Set(ips.filter(Boolean)).size;
    return { filter: addrFilter(ips), what: `宛先 ${d.city ? `${d.city}, ${d.cc}` : d.cc} (${Math.min(n, 15)}${n > 15 ? ` / ${n}` : ''} アドレス)` };
  }
  if (opts.src) {
    if (tokenOf(opts.src)) return { filter: addrFilter([opts.src]), what: `送信元 ${show(opts.src)}` };
    const res = await promQuery(`obs_flow_host_info{src_host=${lv(opts.src)}}`).catch(() => []);
    const toks = res.map((r) => tokenOf(r.metric.ip));
    return { filter: addrFilter(toks), what: `送信元 ${opts.src}`, note: toks.length ? '' : 'このホストのアドレスが分からないため、フィルタなしで開きます' };
  }
  return { filter: '', what: '' };
}

// ---- file list ----------------------------------------------------------------------------------
const RING_TIME = /_(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.pcapng?$/;
function fileLabel(f) {
  const m = f.kind === 'ring' && f.name.match(RING_TIME);
  const when = m ? jstFull.format(new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]))) : jstFull.format(new Date(f.mtime * 1000));
  const name = f.kind === 'demo' ? `${f.name} (合成)` : f.kind === 'upload' ? f.name : when;
  return `${name} · ${fmtBytes(f.size)}${f.kind === 'upload' ? ` · ${when}` : ''}${f.recording ? ' · 記録中' : ''}`;
}
function pickFile(files, wanted, since) {
  const all = [...files.ring, ...files.upload, ...files.demo];
  if (wanted && all.some((f) => f.id === wanted)) return wanted;
  const ring = files.ring.filter((f) => !f.recording && (!since || f.mtime >= since));
  return (ring[0] || files.ring.find((f) => !f.recording) || files.upload[0] || files.demo[0])?.id || '';
}

// ---- view ---------------------------------------------------------------------------------------
export function analysisView(init = {}) {
  const st = { files: null, file: '', filter: init.filter || '', total: null, pages: new Map(), sel: null, tab: 'packets', stats: null, statsKey: null,
    seq: 0, ops: null, t0: null, statSub: { conv: 'ip', ends: 'ip' } };
  const ui = {};
  let rowH = 24;
  let dseq = 0; // detail requests: only the newest one renders

  function setMsg(text, kind = '') {
    ui.msg.textContent = text || '';
    ui.msg.className = `pa-msg ${kind}`;
    ui.input.setAttribute('aria-invalid', String(kind === 'err-filter'));
  }
  function setStatus(text) { ui.status.textContent = text; }

  async function loadFiles(prefer) {
    const files = await api('files');
    st.files = files;
    const groups = [['キャプチャ (リング)', files.ring], ['アップロード', files.upload], ['デモ', files.demo]];
    ui.file.replaceChildren(...groups.filter(([, l]) => l.length).map(([label, list]) => {
      const g = el('optgroup');
      g.label = label;
      for (const f of list) {
        const o = el('option', '', fileLabel(f));
        o.value = f.id;
        o.disabled = !!f.recording;
        g.append(o);
      }
      return g;
    }));
    if (!ui.file.options.length) ui.file.append(el('option', '', 'ファイルなし'));
    st.file = pickFile(files, prefer, init.since);
    ui.file.value = st.file;
    const c = files.capture || {};
    ui.capture.textContent = c.state === 'running'
      ? `キャプチャ中: ${c.iface} · NIC の受信ドロップ ${has(c.nic_rx_dropped) ? c.nic_rx_dropped : '—'} · dumpcap の欠落 ${has(c.dumpcap_dropped) ? c.dumpcap_dropped : '—'} · リング ${has(c.ring_bytes) ? fmtBytes(c.ring_bytes) : '—'}`
      : c.state === 'stopped' ? `キャプチャ停止中${c.error ? `: ${c.error}` : ''}` : 'キャプチャ: 無効 (アップロード・デモの pcap を解析できます)';
    ui.capture.classList.toggle('pa-warn', c.state === 'stopped');
    ui.del.hidden = !st.file.startsWith('upload:');
  }

  // ---- packet list (virtual, paged) ----
  async function page(p) {
    if (st.pages.has(p)) return st.pages.get(p);
    const my = st.seq;
    const req = api('packets', { file: st.file, filter: st.filter, offset: p * PAGE, limit: PAGE }).then((r) => {
      if (my !== st.seq) return null;
      st.total = r.total;
      if (st.t0 === null && r.rows.length && p === 0) st.t0 = r.rows[0][1];
      return r;
    });
    st.pages.set(p, req);
    try { return await req; } catch (e) { st.pages.delete(p); throw e; }
  }
  async function run() {
    st.seq += 1;
    dseq += 1; // a detail still loading belongs to the previous list: dropped when it arrives
    st.pages = new Map();
    st.total = null;
    st.sel = null;
    st.t0 = null;
    st.stats = null;
    ui.spacer.replaceChildren();
    ui.spacer.style.height = '0px';
    ui.tree.replaceChildren(el('p', 'na', 'パケットを選ぶと詳細と 16 進表示が出ます'));
    ui.hex.replaceChildren();
    if (!st.file || !st.file.includes(':')) { setStatus('—'); setMsg('解析できるファイルがありません。pcap をアップロードしてください'); return; }
    setStatus('解析中…');
    setMsg('');
    const my = st.seq;
    try {
      const r = await page(0);
      if (!r || my !== st.seq) return;
      setStatus(`${r.total.toLocaleString()} packets${has(r.elapsed_ms) ? ` · tshark ${(r.elapsed_ms / 1000).toFixed(1)} s` : ''}`);
      if (!r.total) setMsg(st.filter ? 'フィルタに一致するパケットはありません' : 'パケットがありません');
      if (r.truncated) setMsg(`先頭 ${r.total.toLocaleString()} パケットまで表示しています (上限)。フィルタで絞ってください`, 'warn');
      ui.spacer.style.height = `${r.total * rowH}px`;
      ui.list.scrollTop = 0;
      paint();
      if (st.tab !== 'packets') loadStats();
    } catch (e) {
      if (my !== st.seq) return;
      setStatus('—');
      setMsg(e.message, e.kind === 'rejected' ? 'err-filter' : 'err');
    }
  }
  const rowId = (i) => `pa-r-${i}`;
  let painting = false;
  let paintGen = 0; // only the latest paint may write the rows (pages arrive out of order while scrolling)
  const viewport = () => {
    const first = Math.max(0, Math.floor(ui.list.scrollTop / rowH) - 10);
    return [first, Math.min(st.total - 1, first + Math.ceil(ui.list.clientHeight / rowH) + 20)];
  };
  function paint() {
    if (painting) return;
    painting = true;
    requestAnimationFrame(async () => {
      painting = false;
      if (!st.total) return;
      const gen = ++paintGen;
      const [first, last] = viewport();
      const my = st.seq;
      const pages = [...new Set([Math.floor(first / PAGE), Math.floor(last / PAGE)])];
      let got;
      try { got = await Promise.all(pages.map(page)); } catch (e) { if (gen === paintGen) setMsg(e.message, 'err'); return; }
      if (gen !== paintGen || my !== st.seq || got.some((g) => !g)) return;
      const [f2, l2] = viewport();
      if (f2 !== first || l2 !== last) { paint(); return; } // scrolled while waiting: paint the new viewport instead
      const rows = [];
      for (let i = first; i <= last; i++) {
        const pg = got[pages.indexOf(Math.floor(i / PAGE))];
        const r = pg?.rows[i - Math.floor(i / PAGE) * PAGE];
        if (r) rows.push(packetRow(i, r));
      }
      ui.spacer.replaceChildren(...rows);
    });
  }
  function packetRow(i, r) {
    const [no, t, src, dst, proto, len, info] = r;
    const d = el('div', `pa-row${st.sel?.i === i ? ' sel' : ''}`);
    d.id = rowId(i);
    d.setAttribute('role', 'option');
    d.setAttribute('aria-selected', String(st.sel?.i === i));
    d.style.top = `${i * rowH}px`;
    const rel = st.t0 === null ? '' : (t - st.t0).toFixed(3);
    d.append(el('span', 'n', no), el('span', 'n', rel), el('span', 'pa-a', show(src)), el('span', 'pa-a', show(dst)), el('span', 'pa-p', proto), el('span', 'n', len), el('span', 'pa-i', info));
    d.title = `#${no} ${jstFull.format(new Date(t * 1000))} JST · ${show(src)} → ${show(dst)} · ${proto} · ${len} B · ${info}`;
    d.addEventListener('click', () => select(i, r));
    return d;
  }
  async function select(i, r) {
    if (i < 0 || i >= (st.total || 0)) return;
    if (!r) {
      const pg = await page(Math.floor(i / PAGE));
      r = pg?.rows[i % PAGE];
      if (!r) return;
    }
    st.sel = { i, no: r[0] };
    const top = i * rowH;
    if (top < ui.list.scrollTop + rowH) ui.list.scrollTop = Math.max(0, top - rowH);
    else if (top + rowH > ui.list.scrollTop + ui.list.clientHeight) ui.list.scrollTop = top + 2 * rowH - ui.list.clientHeight;
    ui.list.setAttribute('aria-activedescendant', rowId(i));
    for (const n of ui.spacer.children) { const on = n.id === rowId(i); n.classList.toggle('sel', on); n.setAttribute('aria-selected', String(on)); }
    paint();
    detail(r[0]);
  }
  function onListKey(e) {
    const vis = Math.max(1, Math.floor(ui.list.clientHeight / rowH) - 1);
    const cur = st.sel ? st.sel.i : -1;
    const to = { ArrowDown: cur + 1, ArrowUp: cur - 1, PageDown: cur + vis, PageUp: cur - vis, Home: 0, End: (st.total || 1) - 1 }[e.key];
    if (to === undefined || !st.total) return;
    e.preventDefault();
    select(Math.max(0, Math.min(st.total - 1, to)));
  }

  // ---- detail: tree + hex with cross-highlight ----
  async function detail(no) {
    const my = ++dseq;
    ui.tree.replaceChildren(el('p', 'na', `#${no} 解析中…`));
    let d;
    try { d = await api('packet', { file: st.file, no }); } catch (e) { if (my === dseq) ui.tree.replaceChildren(el('p', 'pa-msg err', e.message)); return; }
    if (my !== dseq) return;
    const nodes = [];
    const build = (n, depth) => {
      const label = el('span', 'pt-l', n.s || n.n);
      const wrap = n.c ? el('details', 'pt-node') : el('div', 'pt-node pt-leaf');
      const head = n.c ? el('summary', 'pt-s') : wrap;
      if (n.c) { head.append(label); wrap.append(head); wrap.open = n.k === 'proto' && n.n !== 'frame'; } else wrap.append(label);
      if (!n.c) { wrap.tabIndex = 0; wrap.setAttribute('role', 'button'); }
      head.setAttribute('aria-label', `${n.s || n.n}${n.z ? `, bytes ${n.p}–${n.p + n.z - 1}` : ''}`);
      const rec = { n, wrap, head };
      nodes.push(rec);
      const pick = (e) => { e.stopPropagation(); mark(rec, false); };
      head.addEventListener('click', pick);
      head.addEventListener('focus', () => mark(rec, false));
      if (!n.c) head.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') pick(e); });
      if (n.v && TOKEN.test(n.v) && FILTERABLE.has(n.n)) { // an address: offer it as a filter (by its token)
        const b = el('button', 'link-btn pt-f', '絞り込む');
        b.type = 'button';
        b.title = `${n.n} == ${show(n.v)}`;
        b.setAttribute('aria-label', `filter on ${n.n} == ${show(n.v)}`);
        b.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); addFilter(`${n.n} == ${n.v}`); });
        (n.c ? head : wrap).append(b);
      }
      for (const c of n.c || []) wrap.append(build(c, depth + 1));
      return wrap;
    };
    const tree = el('div', 'pt');
    tree.setAttribute('aria-label', `packet ${no} details`);
    for (const n of d.tree) tree.append(build(n, 0));
    ui.tree.replaceChildren(tree);
    // hex: 16 bytes a line; masked bytes are "xx" / "·"
    const spans = [];
    const lines = [];
    for (let off = 0; off < d.bytes.length; off += 16) {
      const line = el('div', 'hx-line');
      const hexes = el('span', 'hx-h');
      const asc = el('span', 'hx-a');
      for (let i = off; i < Math.min(off + 16, d.bytes.length); i++) {
        const b = d.bytes[i];
        const h = el('span', b === null ? 'hx-b hx-m' : 'hx-b', b === null ? 'xx' : b);
        const ch = b === null ? '·' : (() => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : '.'; })();
        const a = el('span', b === null ? 'hx-c hx-m' : 'hx-c', ch);
        h.dataset.i = a.dataset.i = String(i);
        spans[i] = [h, a];
        hexes.append(h);
        asc.append(a);
      }
      line.append(el('span', 'hx-o', off.toString(16).padStart(4, '0')), hexes, asc);
      lines.push(line);
    }
    const hex = el('div', 'hx');
    hex.setAttribute('aria-label', `bytes of packet ${no}: ${d.bytes.length} bytes, ${d.masked} masked`);
    hex.append(...lines);
    hex.addEventListener('click', (e) => {
      const i = Number(e.target.dataset?.i);
      if (!Number.isInteger(i)) return;
      const inside = nodes.filter((x) => x.n.z > 0 && x.n.p <= i && i < x.n.p + x.n.z);
      const best = inside.sort((a, b) => a.n.z - b.n.z)[0];
      if (best) mark(best, true);
    });
    ui.hex.replaceChildren(hex, el('p', 'pa-note', `${d.bytes.length} bytes · ${d.masked} bytes masked (xx)`));
    let lastRec = null;
    function mark(rec, fromHex) {
      for (const s of spans.flat()) s?.classList.remove('hx-sel');
      lastRec?.head.classList.remove('pt-sel');
      lastRec = rec;
      rec.head.classList.add('pt-sel');
      for (let i = rec.n.p; i < rec.n.p + rec.n.z; i++) for (const s of spans[i] || []) s.classList.add('hx-sel');
      if (fromHex) {
        for (let p = rec.wrap.parentElement; p && p !== tree; p = p.parentElement) if (p.tagName === 'DETAILS') p.open = true;
        rec.head.scrollIntoView({ block: 'nearest' });
        rec.head.focus({ preventScroll: true });
      }
    }
  }

  async function exportPackets() {
    if (!st.total) return;
    const n = Math.min(st.total, MAX_ROWS_CSV);
    const rows = [];
    for (let p = 0; p * PAGE < n; p++) rows.push(...((await page(p))?.rows || []));
    download('pcap-packets.csv', [['no', 'time (JST)', 'source', 'destination', 'protocol', 'length', 'info'],
      ...rows.slice(0, n).map(([no, t, a, b, pr, len, info]) => [no, jstFull.format(new Date(t * 1000)), show(a), show(b), pr, len, info])]);
    if (st.total > n) setMsg(`CSV は先頭 ${n.toLocaleString()} パケットです (全 ${st.total.toLocaleString()})`, 'warn');
  }
  function addFilter(expr) {
    const cur = ui.input.value.trim();
    ui.input.value = cur ? `(${cur}) && ${expr}` : expr;
    apply();
  }
  function apply() {
    st.filter = ui.input.value.trim();
    showTab('packets');
    run();
  }

  // ---- statistics ----
  async function loadStats() {
    const key = `${st.file}|${st.filter}`;
    if (st.statsKey === key && st.stats) { renderStats(); return; }
    const gen = (st.statsGen = (st.statsGen || 0) + 1); // a newer request (file / filter changed) wins
    st.statsKey = key;
    st.stats = null;
    ui.stats.replaceChildren(el('p', 'na', '統計を計算中…'));
    let res;
    try {
      res = await api('stats', { file: st.file, filter: st.filter });
    } catch (e) {
      if (gen !== st.statsGen) return;
      ui.stats.replaceChildren(el('p', 'pa-msg err', e.message));
      st.statsKey = null;
      return;
    }
    if (gen !== st.statsGen || st.statsKey !== key) return; // stale: discarded
    st.stats = res;
    renderStats();
  }
  function csvButton(name, head, rows) {
    const b = el('button', 'link-btn', 'CSV');
    b.type = 'button';
    b.title = 'masked values only';
    b.setAttribute('aria-label', `${name}: export CSV (masked)`);
    b.addEventListener('click', () => download(`pcap-${name}.csv`, [head, ...rows]));
    return b;
  }
  function tableBlock(title, cols, rows, onRow, csvName) {
    const sec = el('section', 'v-sec');
    const h = el('h3', 'v-h', title);
    h.append(csvButton(csvName, cols.map((c) => c.label), rows.map((r) => cols.map((c) => (c.fmt ? c.fmt(r[c.key], r) : r[c.key])))));
    const t = sortTable(cols, { key: cols.find((c) => c.num)?.key, desc: true }, (r) => r.key);
    t.update(rows, onRow);
    const box = el('div', 'pa-tbl');
    box.append(t.el);
    sec.append(h, box);
    return sec;
  }
  const pct = (v, all) => (all ? `${((100 * v) / all).toFixed(1)} %` : '—');
  function renderStats() {
    const s = st.stats;
    if (!s) return;
    s.ord = s.ord || ordinals(s);
    const ord = s.ord;
    const tab = st.tab;
    let body;
    if (tab === 'phs') {
      const rows = s.phs.map(([path, frames, bytes]) => ({ key: path, proto: `${'  '.repeat(path.split(':').length - 1)}${path.split(':').pop()}`, path, frames, bytes }));
      body = tableBlock('プロトコル階層 / PROTOCOL HIERARCHY', [
        { key: 'proto', label: 'protocol', fmt: (v) => v }, { key: 'frames', label: 'packets', num: true }, { key: 'fp', label: '% packets', fmt: (_, r) => pct(r.frames, s.packets) },
        { key: 'bytes', label: 'bytes', num: true }, { key: 'bp', label: '% bytes', fmt: (_, r) => pct(r.bytes, s.bytes) }], rows,
      (r) => addFilter(r.path.split(':').pop()), 'protocols');
      body.querySelector('table').classList.add('pa-phs');
    } else if (tab === 'conv' || tab === 'ends') {
      const sub = st.statSub[tab];
      const opts = tab === 'conv' ? [['IPv4/6', 'ip'], ['TCP', 'tcp'], ['UDP', 'udp']] : [['IP', 'ip'], ['Ethernet', 'eth']];
      const seg = el('div', 'seg pa-sub');
      seg.setAttribute('role', 'group');
      seg.setAttribute('aria-label', tab === 'conv' ? 'conversation type' : 'endpoint type');
      for (const [label, v] of opts) {
        const b = el('button', 'seg-btn', label);
        b.type = 'button';
        b.setAttribute('aria-pressed', String(v === sub));
        b.addEventListener('click', () => { st.statSub[tab] = v; renderStats(); });
        seg.append(b);
      }
      const t0 = s.t0;
      if (tab === 'conv') {
        const pair = sub !== 'ip';
        const rows = s.conv[sub].map(([a, b, fab, bab, fba, bba, first, last]) => ({
          key: `${pair ? a.addr + a.port : a}|${pair ? b.addr + b.port : b}`, a: pair ? `${ord(a.addr)}:${a.port}` : ord(a), b: pair ? `${ord(b.addr)}:${b.port}` : ord(b),
          ta: pair ? a.addr : a, tb: pair ? b.addr : b, pa: pair ? a.port : null, pb: pair ? b.port : null,
          fab, bab, fba, bba, start: first - t0, dur: last - first }));
        body = tableBlock(`会話 / CONVERSATIONS · ${sub.toUpperCase()}`, [
          { key: 'a', label: 'A' }, { key: 'b', label: 'B' }, { key: 'fab', label: 'pkts A→B', num: true }, { key: 'bab', label: 'bytes A→B', num: true },
          { key: 'fba', label: 'pkts B→A', num: true }, { key: 'bba', label: 'bytes B→A', num: true },
          { key: 'start', label: 'start s', num: true, fmt: (v) => v.toFixed(3) }, { key: 'dur', label: 'duration s', num: true, fmt: (v) => v.toFixed(3) }], rows,
        (r) => addFilter([`${addrField(r.ta)} == ${r.ta}`, `${addrField(r.tb)} == ${r.tb}`, ...(r.pa ? [`${sub}.port == ${r.pa}`, `${sub}.port == ${r.pb}`] : [])].join(' && ')), `conversations-${sub}`);
      } else {
        const rows = s.endpoints[sub].map(([a, ftx, btx, frx, brx]) => ({ key: a, addr: ord(a), tok: a, ftx, btx, frx, brx }));
        body = tableBlock(`端点 / ENDPOINTS · ${sub === 'ip' ? 'IP' : 'ETHERNET'}`, [
          { key: 'addr', label: 'address (masked)' }, { key: 'ftx', label: 'pkts sent', num: true }, { key: 'btx', label: 'bytes sent', num: true },
          { key: 'frx', label: 'pkts received', num: true }, { key: 'brx', label: 'bytes received', num: true }], rows,
        (r) => (TOKEN.test(r.tok) ? addFilter(`${addrField(r.tok)} == ${r.tok}`) : null), `endpoints-${sub}`);
      }
      body.querySelector('.v-h').append(seg);
    } else if (tab === 'io') {
      body = el('section', 'v-sec');
      const h = el('h3', 'v-h', `I/O グラフ / I/O GRAPH · ${s.io.step} s 毎`);
      h.append(csvButton('io', ['time (JST)', 'packets', 'bytes'], s.io.buckets.map(([t, f, b]) => [jstFull.format(new Date(t * 1000)), f, b])));
      body.append(h);
      const colors = chartColors();
      for (const [label, idx, unit] of [['packets / interval', 1, ''], ['bytes / interval', 2, ' B']]) {
        const series = [{ name: label, color: colors[idx - 1], points: s.io.buckets.map((b) => [b[0], b[idx]]) }];
        const c = el('canvas', 'chart');
        c.setAttribute('role', 'img');
        const vals = series[0].points.map((p) => p[1]);
        c.setAttribute('aria-label', `${label}: ${vals.length} intervals, max ${vals.length ? Math.max(...vals) : 0}${unit}`);
        const wrap = el('div', 'chart-wrap small');
        wrap.append(c, legend(series));
        body.append(wrap);
        requestAnimationFrame(() => lineChart(c, series, { t0: s.t0, t1: Math.max(s.t1, s.t0 + s.io.step), step: s.io.step, tfmt: ioAxis(s.t0, s.t1) }));
      }
      body.append(el('p', 'pa-note', `キャプチャ時刻 ${jstFull.format(new Date(s.t0 * 1000))} – ${jstFull.format(new Date(s.t1 * 1000))} JST · ${s.packets.toLocaleString()} packets / ${fmtBytes(s.bytes)}`));
    } else {
      body = el('div', 'pa-names');
      for (const [k, title, field] of [['dns', 'DNS 問い合わせ名', 'dns.qry.name'], ['sni', 'TLS SNI', 'tls.handshake.extensions_server_name'], ['http', 'HTTP Host', 'http.host']]) {
        const rows = (s.names[k] || []).map(([name, n]) => ({ key: name, name, n }));
        body.append(tableBlock(title, [{ key: 'name', label: 'name (masked)' }, { key: 'n', label: 'packets', num: true }], rows,
          (r) => (/[\d:]/.test(r.name) ? setMsg(`${r.name}: 数字や : を含む名前はフィルタにできません (伏せ字の部分を試せてしまうため)`, 'warn') : addFilter(`${field} == "${r.name}"`)), `names-${k}`));
      }
    }
    ui.stats.replaceChildren(body);
  }

  // ---- tabs ----
  const TABS = [['packets', 'パケット'], ['phs', 'プロトコル'], ['conv', '会話'], ['ends', '端点'], ['io', 'I/O'], ['names', 'DNS·SNI·Host']];
  function showTab(name) {
    st.tab = name;
    for (const b of ui.tabs.children) { const on = b.dataset.tab === name; b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; }
    ui.packets.hidden = name !== 'packets';
    ui.stats.hidden = name === 'packets';
    if (name !== 'packets' && st.file.includes(':')) loadStats();
    if (name === 'packets') paint();
  }

  // ---- upload / delete ----
  async function upload(file) {
    if (!file) return;
    setMsg(`アップロード中: ${file.name} (${fmtBytes(file.size)})…`);
    try {
      const r = await api('upload', { name: file.name }, { method: 'POST', body: file, headers: { 'Content-Type': 'application/octet-stream', 'X-Obs-Csrf': '1' } });
      setMsg(`アップロードしました${r.removed?.length ? ` (容量上限のため古いもの ${r.removed.length} 件を削除)` : ''}`);
      await loadFiles(r.id);
      run();
    } catch (e) {
      setMsg(`アップロードできません: ${e.message}`, 'err');
    }
  }
  async function delUpload() {
    const name = st.file.replace(/^upload:/, '');
    try {
      await api(`upload/${encodeURIComponent(name)}`, null, { method: 'DELETE', headers: { 'X-Obs-Csrf': '1' } });
      setMsg('削除しました');
      await loadFiles();
      run();
    } catch (e) { setMsg(`削除できません: ${e.message}`, 'err'); }
  }

  return {
    title: 'Packet analysis · 解析', src: 'none', note: 'stored captures · IP/MAC masked',
    mount(body) {
      const root = el('div', 'pa');
      const bar = el('div', 'pa-bar');
      const fl = el('label', 'fld pa-file', 'ファイル');
      ui.file = el('select');
      fl.append(ui.file);
      ui.file.addEventListener('change', () => { st.file = ui.file.value; ui.del.hidden = !st.file.startsWith('upload:'); run(); });
      ui.pick = el('input');
      ui.pick.type = 'file';
      ui.pick.accept = '.pcap,.pcapng,.cap';
      ui.pick.hidden = true;
      ui.pick.addEventListener('change', () => { upload(ui.pick.files[0]); ui.pick.value = ''; });
      ui.up = el('button', 'link-btn ops-btn', 'アップロード');
      ui.up.type = 'button';
      ui.up.addEventListener('click', () => ui.pick.click());
      ui.del = el('button', 'link-btn ops-btn', '削除');
      ui.del.type = 'button';
      ui.del.hidden = true;
      ui.del.addEventListener('click', delUpload);
      const form = el('form', 'pa-filter');
      const il = el('label', 'fld', '表示フィルタ (Wireshark)');
      ui.input = el('input');
      ui.input.type = 'text';
      ui.input.maxLength = 512;
      ui.input.spellcheck = false;
      ui.input.autocomplete = 'off';
      ui.input.placeholder = 'dns || tls.handshake.type == 1';
      ui.input.value = st.filter;
      il.append(ui.input);
      const go = el('button', 'link-btn ops-btn', '適用');
      go.type = 'submit';
      const clr = el('button', 'link-btn ops-btn', '解除');
      clr.type = 'button';
      clr.addEventListener('click', () => { ui.input.value = ''; apply(); });
      form.append(il, go, clr);
      form.addEventListener('submit', (e) => { e.preventDefault(); apply(); });
      ui.status = el('span', 'pa-status', '—');
      ui.status.setAttribute('role', 'status');
      const csv = el('button', 'link-btn ops-btn', 'CSV');
      csv.type = 'button';
      csv.title = `packet list, first ${MAX_ROWS_CSV} rows, masked`;
      csv.setAttribute('aria-label', 'export the packet list as CSV (masked)');
      csv.addEventListener('click', exportPackets);
      bar.append(fl, ui.up, ui.del, ui.pick, form, ui.status, csv);
      ui.msg = el('div', 'pa-msg');
      ui.msg.setAttribute('role', 'alert');
      ui.ctx = el('div', 'pa-ctx');
      ui.capture = el('span', 'pa-cap');
      ui.ctx.append(el('span', '', init.what ? `引き継ぎ: ${init.what}${init.since ? ' · 直近 15 分のリングファイル' : ''}${init.note ? ` · ${init.note}` : ''}` : ''), ui.capture);
      ui.tabs = el('div', 'pa-tabs');
      ui.tabs.setAttribute('role', 'tablist');
      ui.tabs.setAttribute('aria-label', 'analysis views');
      for (const [k, label] of TABS) {
        const b = el('button', 'seg-btn', label);
        b.type = 'button';
        b.dataset.tab = k;
        b.setAttribute('role', 'tab');
        b.addEventListener('click', () => showTab(k));
        ui.tabs.append(b);
      }
      ui.tabs.addEventListener('keydown', (e) => {
        const i = TABS.findIndex(([k]) => k === st.tab);
        const to = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key];
        if (to === undefined) return;
        e.preventDefault();
        const k = TABS[(to + TABS.length) % TABS.length][0];
        showTab(k);
        ui.tabs.querySelector(`[data-tab="${k}"]`).focus();
      });
      ui.packets = el('div', 'pa-pk');
      ui.list = el('div', 'pa-list');
      ui.list.tabIndex = 0;
      ui.list.setAttribute('role', 'listbox');
      ui.list.setAttribute('aria-label', 'packets (arrow keys move, details appear on the right)');
      const head = el('div', 'pa-row pa-head');
      head.setAttribute('aria-hidden', 'true');
      for (const [t, c] of [['No.', 'n'], ['Time s', 'n'], ['Source', ''], ['Destination', ''], ['Proto', ''], ['Len', 'n'], ['Info', '']]) head.append(el('span', c, t));
      ui.spacer = el('div', 'pa-spacer');
      ui.list.append(ui.spacer);
      ui.list.addEventListener('scroll', paint, { passive: true });
      ui.list.addEventListener('keydown', onListKey);
      const lw = el('div', 'pa-lw');
      lw.append(head, ui.list);
      const det = el('div', 'pa-det');
      ui.tree = el('div', 'pa-tree');
      ui.hex = el('div', 'pa-hex');
      det.append(ui.tree, ui.hex);
      ui.packets.append(lw, det);
      ui.stats = el('div', 'pa-stats');
      ui.stats.hidden = true;
      ui.foot = el('p', 'pa-foot', `IP/MAC は伏せ字です (一覧・詳細・16 進・統計・CSV のすべて)。伏せ字を外す操作は認証の導入までできません。暗号化された中身は解読しません。 · ${ATTRIB}`);
      root.append(bar, ui.msg, ui.ctx, ui.tabs, ui.packets, ui.stats, ui.foot);
      body.append(root);
      rowH = parseFloat(getComputedStyle(ui.list).getPropertyValue('--pa-row')) || 24;
      showTab('packets');
      api('ops').then((o) => { if (!o.writable) { ui.up.disabled = true; ui.del.disabled = true; ui.up.title = o.reason; ui.up.textContent = 'アップロード (不可)'; ui.up.setAttribute('aria-label', `upload disabled: ${o.reason}`); } }).catch(() => {});
      promQuery('obs_geoip_db_info').then((res) => {
        const m = res.map((r) => `${r.metric.db} ${r.metric.month || '?'}`).join(', ');
        if (m) ui.foot.textContent += ` (DB-IP Lite ${m})`;
      }).catch(() => {});
      loadFiles(init.file).then(run).catch((e) => { setStatus('—'); setMsg(`ファイル一覧を取得できません: ${e.message}`, 'err'); });
      setTimeout(() => ui.input.focus(), 0);
    },
    update() {},
  };
}

// Masked addresses look alike ("192.168.100.x"): each distinct one in a statistics result gets a stable #n for this
// view (built from the opaque tokens, in the order of the endpoint list; the token itself is never shown)
function ordinals(s) {
  const m = new Map();
  const add = (a) => { if (TOKEN.test(String(a)) && !m.has(a)) m.set(a, m.size + 1); };
  for (const k of ['ip', 'eth']) for (const [a] of s.endpoints[k] || []) add(a);
  for (const [a, b] of s.conv.ip) { add(a); add(b); }
  for (const k of ['tcp', 'udp']) for (const [a, b] of s.conv[k]) { add(a.addr); add(b.addr); }
  return (a) => (m.has(a) ? `${show(a)} #${m.get(a)}` : show(a));
}
// I/O axis: seconds from the first packet for short captures, JST HH:MM:SS for longer ones
function ioAxis(t0, t1) {
  const span = t1 - t0;
  return span <= 900 ? (t) => `+${(t - t0).toFixed(span < 60 ? 1 : 0)} s` : (t) => jstClock.format(new Date(t * 1000));
}

function download(name, rows) {
  // OWASP CSV injection: a cell that a spreadsheet would read as a formula gets a leading apostrophe
  const esc = (v) => {
    let s = String(v ?? '');
    if (/^[=+\-@\t\r]/.test(s.trimStart()) || /^[\t\r]/.test(s)) s = `'${s}`;
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const blob = new Blob([`﻿${rows.map((r) => r.map(esc).join(',')).join('\n')}\n`], { type: 'text/csv;charset=utf-8' });
  const a = el('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
