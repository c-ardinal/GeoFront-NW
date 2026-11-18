// Network map (P5): the globe's slot can show the network instead (same place, same size; the switch is a button in the
// globe's own controls, the choice kept in localStorage). Built from the device inventory (/obs/config.json: parent /
// parent_if / uplink_if, the WAN interface) plus LLDP neighbours when the devices answer LLDP-MIB; every link says where
// it comes from (台帳 / LLDP / 台帳+LLDP). Light: HTML nodes and link chips over one SVG of lines; the layout is a pure,
// deterministic function of the graph and the width, computed again only when one of them changes (never per frame).
// Every poll only updates texts and classes. States come from the same snapshot as the wallboard (PLAYBACK: the cursor).
import { $, el, has, fixed, badge, clickable, refocus } from './util.js';

const KEY = 'cc-globe-view';
const SVGNS = 'http://www.w3.org/2000/svg';
export const INTERNET = '__internet__';
const NODE_W = 172, NODE_H = 60, H_GAP = 18, V_GAP = 70, PAD = 16, CHIP_H = 24;
const MAX_NEIGHBOURS = 12;
const SRC_TEXT = { inv: '台帳', lldp: 'LLDP', both: '台帳+LLDP' };

// ---- graph (pure) ----------------------------------------------------------------------------------------------------
// a host name loses its domain (rtx1300.home.lan -> rtx1300); an address-like or masked sysName (192.168.100.x~token,
// 2001:db8::x) is kept whole, so different neighbours never collapse into one node
const norm = (s) => { const x = String(s || '').trim().toLowerCase(); return /^[a-z][a-z0-9_-]*\.[a-z]/.test(x) ? x.split('.')[0] : x; };
const portsAgree = (a, b) => !a || !b || String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
// devices: [{ name, kind }] in inventory order; links: [{ device, parent, parent_if, uplink_if }]; wan: { device, ifName } | null;
// lldp: [{ instance, local, remote, remotePort }]
export function buildGraph(devices, links, wan, lldp) {
  const nodes = new Map();
  const order = [];
  const add = (n) => { if (!nodes.has(n.id)) { nodes.set(n.id, n); order.push(n.id); } return nodes.get(n.id); };
  if (wan && devices.some((d) => d.name === wan.device)) add({ id: INTERNET, type: 'internet', label: 'インターネット', kind: 'WAN 先' });
  for (const d of devices) add({ id: d.name, type: 'device', label: d.name, kind: String(d.kind || 'other').toUpperCase() });
  const edges = [];
  const parentOf = new Map();
  const edge = (e) => { edges.push(e); if (e.tree) parentOf.set(e.to, e.from); return e; };
  if (nodes.has(INTERNET)) edge({ from: INTERNET, to: wan.device, src: 'inv', pIf: null, cIf: wan.ifName, tree: true, wan: true });
  for (const l of links || []) {
    if (!nodes.has(l.device) || !nodes.has(l.parent) || parentOf.has(l.device)) continue;
    edge({ from: l.parent, to: l.device, src: 'inv', pIf: l.parent_if || null, cIf: l.uplink_if || null, tree: true });
  }
  // the top: the internet node, else the first device without a parent; attached = reaches it
  const rootOf = (id) => { let cur = id; const seen = new Set(); while (parentOf.has(cur) && !seen.has(cur)) { seen.add(cur); cur = parentOf.get(cur); } return cur; };
  const depthOf = (id) => { let d = 0, cur = id; const seen = new Set(); while (parentOf.has(cur) && !seen.has(cur)) { seen.add(cur); cur = parentOf.get(cur); d++; } return d; };
  const topId = () => (nodes.has(INTERNET) ? INTERNET : order.find((id) => !parentOf.has(id)));
  const attached = (id) => rootOf(id) === topId();
  const rank = (id) => order.indexOf(id);
  let neighbours = 0;
  for (const r of [...(lldp || [])].sort((a, b) => rank(a.instance) - rank(b.instance) || String(a.remote).localeCompare(String(b.remote)))) {
    const a = r.instance;
    if (!nodes.has(a) || nodes.get(a).type !== 'device') continue;
    const bName = devices.find((d) => norm(d.name) === norm(r.remote))?.name;
    if (bName === a) continue;
    if (bName) {
      // merged only into a link between the same two devices whose known ports agree (an unknown side agrees with
      // anything); a different port pair is another (or a misconfigured) connection: drawn as its own LLDP line
      const between = edges.filter((e) => !e.wan && ((e.from === a && e.to === bName) || (e.from === bName && e.to === a)));
      const ex = between.find((e) => {
        const [mine, theirs] = e.from === a ? [e.pIf, e.cIf] : [e.cIf, e.pIf];
        return portsAgree(mine, r.local) && portsAgree(theirs, r.remotePort);
      });
      if (ex) {
        if (ex.src === 'inv') ex.src = 'both';
        const fromA = ex.from === a;
        ex.pIf = ex.pIf || (fromA ? r.local : r.remotePort) || null;
        ex.cIf = ex.cIf || (fromA ? r.remotePort : r.local) || null;
        continue;
      }
      if (between.length) {
        const [p, c] = [between[0].from, between[0].to];
        edge({ from: p, to: c, src: 'lldp', pIf: (p === a ? r.local : r.remotePort) || null, cIf: (p === a ? r.remotePort : r.local) || null, tree: false });
        continue;
      }
      // LLDP-only link: the side attached to the top is the parent (both or neither: the one closer to the top, then the
      // inventory order); a device that already has a parent keeps it and this link is drawn as an extra line
      const aFirst = attached(a) !== attached(bName) ? attached(a) : depthOf(a) !== depthOf(bName) ? depthOf(a) < depthOf(bName) : rank(a) < rank(bName);
      const [p, c] = aFirst ? [a, bName] : [bName, a];
      const pIf = p === a ? r.local : r.remotePort;
      const cIf = p === a ? r.remotePort : r.local;
      edge({ from: p, to: c, src: 'lldp', pIf: pIf || null, cIf: cIf || null, tree: !parentOf.has(c) && rootOf(p) !== c });
      continue;
    }
    const id = `lldp:${norm(r.remote) || '?'}`;
    if (!nodes.has(id)) {
      if (neighbours >= MAX_NEIGHBOURS) continue;
      neighbours++;
      add({ id, type: 'neighbour', label: String(r.remote || '?'), kind: 'LLDP', via: { instance: a, ifName: r.local } });
    }
    if (!edges.some((e) => e.to === id)) edge({ from: a, to: id, src: 'lldp', pIf: r.local || null, cIf: r.remotePort || null, tree: true });
  }
  const roots = order.filter((id) => !parentOf.has(id));
  const top = nodes.has(INTERNET) ? [INTERNET] : roots.slice(0, 1);
  const orphans = roots.filter((id) => !top.includes(id));
  return { nodes, order, edges, parentOf, top, orphans };
}

// Tidy tree: leaves take consecutive slots in DFS (inventory) order, a parent sits over the middle of its children;
// devices without a known connection come last, in their own row. -> { pos: Map(id -> { x, y, depth }), w, h }
export function layout(g, width) {
  const kids = new Map();
  for (const e of g.edges) if (e.tree) kids.set(e.from, [...(kids.get(e.from) || []), e.to]);
  for (const [k, v] of kids) kids.set(k, v.sort((a, b) => g.order.indexOf(a) - g.order.indexOf(b)));
  const slot = new Map(), depth = new Map();
  let leaves = 0, maxDepth = 0;
  const visit = (id, d, seen) => {
    if (seen.has(id)) return;
    seen.add(id);
    depth.set(id, d);
    maxDepth = Math.max(maxDepth, d);
    const ch = (kids.get(id) || []).filter((c) => !seen.has(c));
    if (!ch.length) { slot.set(id, leaves++); return; }
    for (const c of ch) visit(c, d + 1, seen);
    const xs = ch.map((c) => slot.get(c)).filter((x) => x !== undefined);
    slot.set(id, (Math.min(...xs) + Math.max(...xs)) / 2);
  };
  const seen = new Set();
  for (const t of g.top) visit(t, 0, seen);
  const orphanDepth = g.orphans.length ? (seen.size ? maxDepth + 1 : 0) : -1;
  for (const o of g.orphans) visit(o, orphanDepth, seen); // an orphan's own subtree (e.g. its LLDP neighbours) follows it
  const n = Math.max(1, leaves);
  const w = Math.max(width, n * (NODE_W + H_GAP) + 2 * PAD);
  const sw = (w - 2 * PAD) / n;
  const pos = new Map();
  for (const [id, s] of slot) pos.set(id, { x: PAD + (s + 0.5) * sw, y: PAD + depth.get(id) * (NODE_H + V_GAP), depth: depth.get(id) });
  const rows = Math.max(...[...depth.values()], 0) + 1;
  return { pos, w, h: PAD * 2 + rows * NODE_H + (rows - 1) * V_GAP, orphanDepth };
}

// ---- values per node / link (from the wallboard snapshot) ----------------------------------------------------------
function nodeState(id, g, s) {
  const n = g.nodes.get(id);
  if (n.type === 'neighbour') return ['none', '—', 'not monitored (LLDP neighbour only)'];
  if (!s) return ['unknown', 'STALE', 'no current data'];
  if (n.type === 'internet') {
    const e = g.edges.find((x) => x.wan);
    const oper = s.m.ifOper.get(`${e.to}|${e.cIf}`);
    return oper === 1 ? ['ok', 'UP', 'WAN link up'] : oper === 2 ? ['crit st-down', 'DOWN', 'WAN link down'] : ['unknown', 'STALE', 'WAN state unknown'];
  }
  const up = s.m.up.get(id);
  return up === 1 ? ['ok', 'UP', 'SNMP answering'] : up === 0 ? ['crit st-down', 'DOWN', 'SNMP not answering'] : ['unknown', 'STALE', 'no current data'];
}
// the interface whose values a link shows: the parent's port, else the child's uplink
function linkIf(e, g) {
  if (e.wan) return { inst: e.to, ifName: e.cIf };
  const dev = (id) => g.nodes.get(id)?.type === 'device';
  if (e.pIf && dev(e.from)) return { inst: e.from, ifName: e.pIf };
  if (e.cIf && dev(e.to)) return { inst: e.to, ifName: e.cIf };
  return null;
}
function linkValues(e, g, s) {
  const at = linkIf(e, g);
  if (!at || !s) return { at, util: undefined, err: undefined, oper: undefined };
  const k = `${at.inst}|${at.ifName}`;
  const i = s.m.ifIn.get(k), o = s.m.ifOut.get(k), sp = s.m.ifSpeed.get(k);
  return { at, util: has(i) && has(o) && sp ? (100 * Math.max(i, o)) / sp : undefined, err: s.m.ifErr.get(k), oper: s.m.ifOper.get(k) };
}
const linkKind = (v) => (v.oper === 2 ? 'crit' : !has(v.util) ? 'unknown' : v.util >= 90 ? 'crit' : v.util >= 70 || v.err > 0 ? 'warn' : 'ok');

// ---- view switch -----------------------------------------------------------------------------------------------------
const st = { on: false, g: null, gKey: '', lay: null, w: 0, snap: null, nav: null, hooks: null, els: new Map(), chips: [] };
const stored = () => { try { return localStorage.getItem(KEY) === 'topo'; } catch { return false; } };
export const isOn = () => st.on;
export function initTopology(hooks) {
  st.hooks = hooks; // { setGlobe(shown), onChange(on), nav }
  st.nav = hooks.nav;
  $('g-view').addEventListener('click', () => setOn(!st.on, true));
  new ResizeObserver(() => { if (st.on) render(); }).observe($('topo'));
  $('topo').addEventListener('keydown', onKey);
  setOn(stored(), false);
}
function setOn(on, persist) {
  st.on = on;
  if (persist) { try { localStorage.setItem(KEY, on ? 'topo' : 'globe'); } catch { /* storage unavailable: kept for this page view */ } }
  $('topo').hidden = !on;
  $('p-globe').classList.toggle('topo-on', on);
  const b = $('g-view');
  b.textContent = on ? '地球儀' : 'ネットワーク図';
  b.setAttribute('aria-pressed', String(on));
  b.title = on ? '地球儀 (通信先) へ切替' : 'ネットワーク図 (機器の接続関係) へ切替';
  st.hooks.setGlobe(!on);
  st.hooks.onChange(on);
  if (on) render();
}

// ---- data in -----------------------------------------------------------------------------------------------------------
// cfg: /obs/config.json (devices, links, wan); lldpRows: Prometheus lldpRemSysName vector; snap: the poll's snapshot
export function update(cfg, devices, lldpRows, snap) {
  const lldp = (lldpRows || []).map((r) => ({ instance: r.metric.instance, local: r.metric.lldpLocPortId, remote: r.metric.lldpRemSysName, remotePort: r.metric.lldpRemPortId }))
    .filter((r) => r.instance && r.remote);
  const g = buildGraph(devices, cfg?.links, cfg?.wan ?? null, lldp);
  const key = JSON.stringify([g.order, g.edges, [...g.nodes.values()].map((n) => n.label)]);
  if (key !== st.gKey) { st.g = g; st.gKey = key; st.lay = null; }
  st.snap = snap;
  if (st.on) render();
}
export function summary() {
  if (!st.g) return '';
  const lldp = st.g.edges.filter((e) => e.src !== 'inv').length;
  return `${st.g.nodes.size} nodes · ${st.g.edges.length} links${lldp ? ` · LLDP ${lldp}` : ' · LLDP none'}`;
}

// ---- drawing ------------------------------------------------------------------------------------------------------------
function render() {
  const box = $('topo');
  if (!st.g || !box.clientWidth) return;
  const cs = getComputedStyle(box);
  const width = box.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
  const height = box.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom);
  if (!st.lay || st.w !== width || st.h !== height) { st.w = width; st.h = height; st.lay = layout(st.g, width); refocus(box, build); }
  paint();
}
function build() {
  const { g, lay } = st;
  const box = $('topo');
  const canvas = el('div', 'topo-canvas');
  canvas.style.width = `${lay.w}px`;
  canvas.style.height = `${lay.h}px`;
  canvas.style.marginTop = `${Math.max(0, Math.floor((st.h - lay.h) / 3))}px`; // a short map sits in the upper middle of the slot
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('class', 'topo-svg');
  svg.setAttribute('width', lay.w);
  svg.setAttribute('height', lay.h);
  svg.setAttribute('aria-hidden', 'true');
  canvas.append(svg);
  if (g.orphans.length && lay.orphanDepth >= 0) {
    const y = PAD + lay.orphanDepth * (NODE_H + V_GAP) - 22;
    const t = el('div', 'topo-row-note', '接続先未設定 (台帳に parent 未指定の機器)');
    t.style.top = `${y}px`;
    canvas.append(t);
  }
  st.els = new Map();
  st.chips = [];
  const ps = [...lay.pos.values()];
  const pitch = Math.min(lay.w, ...ps.flatMap((p, i) => ps.slice(i + 1).filter((q) => q.depth === p.depth).map((q) => Math.abs(q.x - p.x)))); // closest neighbours in a row
  for (const e of g.edges) {
    const a = lay.pos.get(e.from), b = lay.pos.get(e.to);
    if (!a || !b) continue;
    const path = document.createElementNS(SVGNS, 'path');
    const ax = a.x, ay = a.y + NODE_H, bx = b.x, by = b.y;
    const mid = ay + 16;
    path.setAttribute('d', e.tree && by > ay ? `M${ax},${ay} V${mid} H${bx} V${by}` : `M${ax},${a.y + NODE_H / 2} L${bx},${b.y + NODE_H / 2}`);
    path.setAttribute('class', `topo-link src-${e.src}${e.tree ? '' : ' extra'}`);
    svg.append(path);
    const chip = el('div', `topo-chip src-${e.src}`);
    // anchored at its bottom centre just above the child (or the middle of an extra line); a narrow map wraps it upwards
    const cx = e.tree && by > ay ? bx : (ax + bx) / 2;
    const cy = e.tree && by > ay ? by - 6 : (a.y + b.y + NODE_H) / 2 + CHIP_H / 2;
    chip.style.left = `${cx}px`;
    chip.style.top = `${cy}px`;
    chip.style.maxWidth = `${Math.max(NODE_W, Math.min(pitch, lay.w) - 12)}px`;
    const at = linkIf(e, g);
    const ifText = [e.pIf, e.cIf].filter(Boolean).join(' ↔ ') || 'IF 不明';
    chip.append(el('span', 'tc-src', SRC_TEXT[e.src]), el('span', 'tc-if', ifText), el('span', 'tc-util'), el('span', 'tc-err'));
    const label = `link ${e.from === INTERNET ? 'internet' : e.from} - ${e.to} (${SRC_TEXT[e.src]})`;
    if (at) clickable(chip, () => st.nav.iface(`${at.inst}|${at.ifName}`), label);
    else { chip.dataset.fkey = label; chip.setAttribute('role', 'note'); }
    chip.dataset.edge = String(g.edges.indexOf(e));
    canvas.append(chip);
    st.chips.push({ chip, e, path });
  }
  for (const id of g.order) {
    const p = lay.pos.get(id);
    if (!p) continue;
    const n = g.nodes.get(id);
    const node = el('div', `topo-node t-${n.type}`);
    node.style.left = `${p.x - NODE_W / 2}px`;
    node.style.top = `${p.y}px`;
    node.style.width = `${NODE_W}px`;
    node.style.height = `${NODE_H}px`;
    node.dataset.node = id;
    const head = el('div', 'tn-h');
    head.append(el('span', 'tn-name', n.label), el('span', 'tn-kind', n.kind));
    const foot = el('div', 'tn-f');
    foot.append(el('span', 'tn-st'), el('span', 'tn-x'));
    node.append(head, foot);
    const open = n.type === 'internet' ? () => { const e = g.edges.find((x) => x.wan); st.nav.iface(`${e.to}|${e.cIf}`); }
      : n.type === 'neighbour' ? () => st.nav.iface(`${n.via.instance}|${n.via.ifName}`) : () => st.nav.device(id);
    clickable(node, open, `node ${id}`);
    canvas.append(node);
    st.els.set(id, node);
  }
  box.replaceChildren(canvas);
}
function paint() {
  const { g } = st;
  const s = st.snap;
  for (const [id, node] of st.els) {
    const n = g.nodes.get(id);
    const [kind, text, why] = nodeState(id, g, s);
    const b = badge(kind, text);
    b.title = why;
    node.querySelector('.tn-st').replaceChildren(b);
    const firing = n.type === 'device' && s ? s.alerts.filter((a) => a.state === 'firing' && a.labels.instance === id).length : 0;
    const surges = n.type === 'internet' && s ? s.surges.length : 0;
    const x = node.querySelector('.tn-x');
    x.textContent = n.type === 'internet' ? (surges ? `急増 ${surges}` : '') : firing ? `警報 ${firing}` : '';
    x.className = `tn-x ${surges || firing ? 'tn-hot' : ''}`;
    node.classList.toggle('tn-down', text === 'DOWN');
    node.setAttribute('aria-label', `${n.label} (${n.kind}): ${text}${firing ? `, ${firing} firing alerts` : ''}${surges ? `, ${surges} traffic surges` : ''}. open details`);
  }
  for (const { chip, e, path } of st.chips) {
    const v = linkValues(e, g, s);
    const k = v.at ? linkKind(v) : 'unknown';
    chip.querySelector('.tc-util').textContent = v.at ? `${has(v.util) ? fixed(v.util, 0) : '—'} %` : '';
    chip.querySelector('.tc-err').textContent = !v.at ? '' : !has(v.err) ? 'ERR —' : v.err > 0 ? 'ERR あり' : 'ERR なし';
    chip.classList.remove('k-ok', 'k-warn', 'k-crit', 'k-unknown');
    chip.classList.add(`k-${k}`);
    path.classList.remove('k-ok', 'k-warn', 'k-crit', 'k-unknown');
    path.classList.add(`k-${k}`);
    const where = v.at ? `${v.at.inst} ${v.at.ifName}` : 'no interface';
    chip.title = `${SRC_TEXT[e.src]} · ${where} · utilization ${has(v.util) ? `${fixed(v.util, 1)} %` : '—'} (rate 2 min) · errors ${has(v.err) ? `${fixed(v.err, 1)}/min` : '—'}${v.oper === 2 ? ' · link DOWN' : ''}`;
    if (v.at) chip.setAttribute('aria-label', `${chip.dataset.fkey}: ${chip.title}. open interface details`);
  }
  $('topo').setAttribute('aria-label', `ネットワーク図: ${summary()}`);
}

// keyboard: Tab walks nodes and links; arrows move between nodes (up = parent, down = first child, left / right = same row)
function onKey(e) {
  const cur = e.target.closest?.('.topo-node');
  if (!cur || !['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) return;
  const id = cur.dataset.node;
  const { g, lay } = st;
  let next = null;
  if (e.key === 'ArrowUp') next = g.parentOf.get(id);
  else if (e.key === 'ArrowDown') next = g.edges.find((x) => x.tree && x.from === id && lay.pos.has(x.to))?.to;
  else {
    const row = [...lay.pos].filter(([, p]) => p.depth === lay.pos.get(id).depth).sort((a, b) => a[1].x - b[1].x).map(([k]) => k);
    next = row[row.indexOf(id) + (e.key === 'ArrowRight' ? 1 : -1)];
  }
  if (!next || !st.els.has(next)) return;
  e.preventDefault();
  st.els.get(next).focus();
}

// scripted-test hook (read-only)
export const testState = () => (st.g ? { on: st.on, nodes: st.g.order, edges: st.g.edges.map((e) => ({ ...e })), w: st.lay?.w, h: st.lay?.h } : { on: st.on });
