// Building blocks shared by modal and drawer views: sections, stat tiles, charts (canvas line charts plus HTML/SVG
// bars, sparklines, timelines, stacked columns) and the table / card list. Layout order in every view:
// summary tiles -> charts -> detail list.
import { el, clickable, lineChart, legend, chartColors, has, fixed, badge, refocus, jstHm, maskText, SEV_KEYS, SEV_LEVELS, SEV_BAD, sevKey, now, SCRAPE_S } from './util.js';
import { promRange, getJson } from './api.js';
import { sevKind, totalBps, FLOW_TEXT } from './panels.js';

export function section(title, meta) {
  const wrap = el('section', 'v-sec');
  const h = el('h3', 'v-h', title);
  if (meta) h.append(el('span', 'v-meta', meta));
  const body = el('div', 'v-body');
  wrap.append(h, body);
  return { wrap, body, head: h };
}
// Definition list; values: string | number | { text, cls } ; missing -> "—" (never 0)
export function kv(pairs) {
  const dl = el('dl', 'dlist');
  for (const [k, v, unit] of pairs) {
    dl.append(el('dt', '', k));
    const missing = isMissing(v);
    const text = missing ? '\u2014' : typeof v === 'object' ? v.text : String(v);
    const dd = el('dd', `${missing ? 'na' : ''} ${typeof v === 'object' && v?.cls ? v.cls : ''}`, text);
    if (unit && !missing) dd.append(el('span', 'u', unit));
    dl.append(dd);
  }
  return dl;
}
export function linkBtn(text, fn, label) {
  const b = el('button', 'link-btn', text);
  b.type = 'button';
  if (label) b.setAttribute('aria-label', label);
  b.addEventListener('click', (e) => { e.stopPropagation(); fn(); });
  return b;
}
export function linkList(items) {
  const ul = el('ul', 'link-list');
  for (const [text, fn, cls] of items) {
    const li = el('li', cls || '');
    clickable(li, fn, text);
    li.textContent = text;
    ul.appendChild(li);
  }
  if (!items.length) ul.appendChild(el('li', 'na', 'none'));
  return ul;
}
export const nf = (v, d = 1) => fixed(v, d);
export const mbps = (bps) => (has(bps) ? bps / 1e6 : undefined);
const isMissing = (v) => v === undefined || v === null || v === '—' || v === '\u2014' || (typeof v === 'number' && !Number.isFinite(v));
// Rebuild a container's children without dropping keyboard focus from a [data-fkey] item inside it.
export const putIn = (box, ...nodes) => refocus(box, () => box.replaceChildren(...nodes));

// ---- range data (Prometheus) ---------------------------------------------------------------
const stepFor = (secs) => Math.max(15, Math.round(secs / 240 / 15) * 15);
// `$RATE` in a query becomes the rate window, Grafana $__rate_interval style: max(step + 1 scrape, 4 scrapes), so
// consecutive windows overlap by one scrape and no counter increase falls between two evaluation points.
// Scrape gates: `and` is evaluated per step of a range query, so points where the source's latest scrape failed become
// gaps (rate() over a look-back window would otherwise keep drawing decaying values for a DOWN target).
export const SNMP_UP = 'and on (instance) (up{job="snmp"} == 1)';
export const FLOWS_UP = 'and on () (up{job="flows"} == 1)';
export let FLOWS_DOWN = 'flow source DOWN: flow data UNKNOWN';
const NO_FLOW_SOURCE = 'no flow source configured (capture off)';
export function setNoFlowSource() {
  FLOWS_DOWN = NO_FLOW_SOURCE;
  Object.assign(FLOW_TEXT, { status: 'no flow source (capture off)', row: NO_FLOW_SOURCE, arcs: NO_FLOW_SOURCE });
}
// a view without flow data is STALE only when a flow source is configured (and DOWN); otherwise it just says so
export function flowsMissing(snap) {
  if (snap.flowsConfigured !== false) throw new Error(FLOWS_DOWN);
}
// queries: [{ q, name(metric) }] -> { series: [{ name, metric, qi, points }], step, win, t0, t1 }, or null when a newer
// request on the same token (range switch / next poll) superseded this one.
export async function fetchRange(token, queries, secs) {
  const step = stepFor(secs);
  const win = `${Math.max(step + SCRAPE_S, 4 * SCRAPE_S)}s`;
  const my = (token.seq = (token.seq || 0) + 1);
  const results = await Promise.all(queries.map((x) => promRange(x.q.replaceAll('$RATE', win), secs, step)));
  if (my !== token.seq) return null;
  const t1 = now() / 1000;
  const series = results.flatMap((res, qi) => res.map((r) => ({ name: queries[qi].name(r.metric), metric: r.metric, qi, points: r.values.map(([t, v]) => [Number(t), Number(v)]) })));
  return { series, step, win, t0: t1 - secs, t1 };
}

// ---- canvas line chart block -----------------------------------------------------------------
export function chartBlock(cls = '') {
  const wrap = el('div', `chart-wrap ${cls}`);
  const canvas = el('canvas', 'chart');
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', 'chart: loading');
  const leg = el('div', 'chart-legend');
  const note = el('div', 'chart-note');
  wrap.append(canvas, leg, note);
  return { wrap, canvas, leg, note };
}
// Canvas charts are redrawn from their last data on window resize only (one shared listener; blocks that left the
// DOM are dropped on the next resize or draw, so repeated open/close keeps nothing alive).
const live = new Set();
let resizeQueued = false;
window.addEventListener('resize', () => {
  if (resizeQueued) return;
  resizeQueued = true;
  requestAnimationFrame(() => {
    resizeQueued = false;
    for (const b of live) if (b.canvas.isConnected) paint(b); else live.delete(b);
  });
});
function paint(b) {
  if (b.canvas.clientWidth) lineChart(b.canvas, b.data.series, b.data.opts);
}
const summary = (series, unit) => series.map((s) => {
  const vs = s.points.map((p) => p[1]);
  return `${s.name}: now ${vs.length ? fixed(vs[vs.length - 1], 2) : '—'}, max ${vs.length ? fixed(Math.max(...vs), 2) : '—'}${unit ? ` ${unit}` : ''}`;
}).join('; ');
// Draws all series; empty result -> "no data in window" note (no zero line). Returns the fetched range (or null).
export async function drawRange(block, queries, secs, unit, label = '') {
  const r = await fetchRange(block, queries, secs);
  if (!r) return null;
  const colors = chartColors();
  const series = r.series.map((s, i) => ({ ...s, color: colors[i % colors.length] }));
  block.data = { series, opts: { t0: r.t0, t1: r.t1, step: r.step, unit: '' } };
  for (const b of live) if (!b.canvas.isConnected) live.delete(b);
  live.add(block);
  paint(block);
  block.leg.replaceChildren(legend(series));
  block.canvas.setAttribute('aria-label', series.length ? `${label || 'line chart'}, last ${Math.round(secs / 60)} min. ${summary(series, unit)}` : `${label || 'chart'}: no data in window`);
  block.note.textContent = series.length ? `step ${r.step} s · rate window ${r.win} \u00B7 gaps = no samples / source DOWN (not 0)` : 'no data in window';
  return r;
}
export function rangeSelect(options, initial, onChange, label = 'time range') {
  const g = el('div', 'seg');
  g.setAttribute('role', 'group');
  g.setAttribute('aria-label', label);
  const btns = options.map(([text, val]) => {
    const b = el('button', 'seg-btn', text);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(val === initial));
    b.addEventListener('click', () => { for (const x of btns) x.setAttribute('aria-pressed', String(x === b)); onChange(val); });
    return b;
  });
  g.append(...btns);
  return g;
}
// PromQL label value literal
export const lv = (v) => `"${String(v).replace(/["\\]/g, '\\$&')}"`;

// ---- stat tiles ----------------------------------------------------------------------------------
// Status is always icon + text, never colour alone.
const ICON = { ok: '\u25CF', warn: '\u25B2', crit: '\u25A0', unknown: '?', info: '\u25C6' };
export const kindOf = (k) => String(k || 'none').split(' ')[0]; // upState() kinds like 'crit st-down' -> 'crit'
// items: [{ label, value: number|string|undefined, d, unit, kind, status, sub, spark: { series, ...sparkOpts } }]
export function tiles(items) {
  const box = el('div', 'tiles');
  for (const t of items) {
    const missing = isMissing(t.value);
    const k = kindOf(t.kind);
    const tile = el('div', `tile tile-${k}`);
    const v = el('div', `tile-v ${missing ? 'na' : ''}`, missing ? '\u2014' : typeof t.value === 'number' ? t.value.toFixed(t.d ?? 1) : String(t.value));
    if (t.unit && !missing) v.append(el('span', 'u', t.unit));
    tile.append(el('div', 'tile-l', t.label), v);
    if (t.status) tile.append(el('div', `tile-st st-text-${k}`, `${ICON[k] ? `${ICON[k]} ` : ''}${t.status}`));
    if (t.sub) tile.append(el('div', 'tile-s', t.sub));
    if (t.spark && t.spark.series.some((s) => s.points.length > 1)) tile.append(sparkSvg(t.spark.series, t.spark));
    box.append(tile);
  }
  return box;
}
// Now vs. window average of a series, as tile sub text.
export function vsAvg(points, d = 1, unit = '') {
  if (!points?.length) return undefined;
  const vs = points.map((p) => p[1]);
  const avg = vs.reduce((a, b) => a + b, 0) / vs.length;
  return `avg ${avg.toFixed(d)} · peak ${Math.max(...vs).toFixed(d)}${unit ? ` ${unit}` : ''}`;
}

// ---- SVG sparkline (decorative: the value is always printed next to it) -----------------------------
const SVGNS = 'http://www.w3.org/2000/svg';
// series: [{ points: [[t, v]], cls: 'sp-1'|'sp-2' }]; gaps (> 2 steps) are breaks, never 0.
export function sparkSvg(series, { t0, t1, max, step = 60, cls = '' } = {}) {
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('class', `spark ${cls}`);
  svg.setAttribute('viewBox', '0 0 100 32');
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const pts = series.flatMap((s) => s.points);
  if (!pts.length) return svg;
  const a = t0 ?? Math.min(...pts.map((p) => p[0]));
  const b = t1 ?? Math.max(...pts.map((p) => p[0]));
  const top = (max ?? Math.max(...pts.map((p) => p[1]))) * 1.1 || 1;
  const x = (t) => (((t - a) / (b - a || 1)) * 100).toFixed(2);
  const y = (v) => (31 - (Math.min(v, top) / top) * 30).toFixed(2);
  for (const s of series) {
    let d = '';
    s.points.forEach(([t, v], i) => { d += `${i === 0 || t - s.points[i - 1][0] > step * 2 ? 'M' : 'L'}${x(t)},${y(v)}`; });
    const p = document.createElementNS(SVGNS, 'path');
    p.setAttribute('d', d);
    p.setAttribute('class', s.cls || 'sp-1');
    svg.append(p);
  }
  return svg;
}

// ---- horizontal bar ranking ------------------------------------------------------------------------
// items: [{ label, value, extra, segs: [{ v, cls, name }], cls, onOpen, key }]; bar length is relative to the largest value;
// a missing value is "—" with an empty track (never a zero-length bar that reads as 0).
export function rankBars(items, { unit = 'Mbps', d = 2, head = ['', unit, 'share'], empty = 'none' } = {}) {
  const box = el('div', 'rank');
  if (!items.length) { box.append(el('div', 'na', empty)); return box; }
  const max = Math.max(0, ...items.map((i) => i.value).filter(has)) || 1;
  const h = el('div', 'rank-row rank-head');
  h.setAttribute('aria-hidden', 'true');
  h.append(el('span', 'rank-l', head[0]), el('span', ''), el('span', 'rank-v', head[1]), el('span', 'rank-x', head[2]));
  box.append(h);
  for (const it of items) {
    const r = el('div', `rank-row ${it.cls || ''}`);
    const bar = el('div', 'rank-bar');
    if (has(it.value)) {
      for (const s of it.segs || [{ v: it.value, cls: 'seg-1', name: '' }]) {
        const seg = el('span', `vw-seg ${s.cls}`);
        seg.style.width = `${Math.max(0, (100 * s.v) / max)}%`;
        if (s.name) seg.title = `${s.name} ${fixed(s.v, d)} ${unit}`;
        bar.append(seg);
      }
    }
    const segText = it.segs ? ` (${it.segs.map((s) => `${s.name} ${fixed(s.v, d)}`).join(', ')})` : '';
    r.append(el('span', 'rank-l', it.label), bar, el('span', `rank-v ${has(it.value) ? '' : 'na'}`, fixed(it.value, d)), el('span', 'rank-x', it.extra ?? ''));
    r.title = `${it.label}: ${fixed(it.value, d)} ${unit}${segText}${it.extra ? `, ${it.extra}` : ''}`;
    if (it.onOpen) {
      clickable(r, it.onOpen, `details for ${it.key || it.label}`);
      r.setAttribute('aria-label', `${r.title}. open details`);
    }
    box.append(r);
  }
  return box;
}
// Flow direction split as stacked segments (Mbps). Inbound first / colour 1, the same order and colours the line
// charts get for `sum by (direction)` (Prometheus returns series sorted by label value).
export const DIR_KEYS = [{ cls: 'sw-1', name: '↓ inbound' }, { cls: 'sw-2', name: '↑ outbound' }];
export const IO_KEYS = [{ cls: 'sw-1', name: '↓ in' }, { cls: 'sw-2', name: '↑ out' }];
export const dirSegs = (flows) => [
  { v: mbps(totalBps(flows.filter((f) => f.dir === 'inbound'))), cls: 'seg-1', name: '↓ in' },
  { v: mbps(totalBps(flows.filter((f) => f.dir === 'outbound'))), cls: 'seg-2', name: '↑ out' },
];
// Opaque, per-view stable token for a raw IP (focus keys must be unique per row but may never carry an address, NFR-09)
export function ipTokens() {
  const m = new Map();
  return (ip) => { if (!m.has(ip)) m.set(ip, `ip${m.size + 1}`); return m.get(ip); };
}
export const pct = (v, all) => (all && has(v) ? (100 * v) / all : undefined);
export const shareText = (v) => (has(v) ? `${v.toFixed(1)} %` : '');
// Swatch legend for HTML charts: keys [{ cls, name }]
export function keyLegend(keys) {
  const d = el('div', 'legend-row');
  for (const k of keys) {
    const i = el('span', 'lg');
    i.append(el('i', `sw ${k.cls}`), document.createTextNode(k.name));
    d.append(i);
  }
  return d;
}
function timeAxis(t0, t1) {
  const ax = el('div', 'tl-axis');
  ax.setAttribute('aria-hidden', 'true');
  for (let i = 0; i <= 4; i++) {
    const s = el('span', '', jstHm.format(new Date((t0 + ((t1 - t0) * i) / 4) * 1000)));
    s.style.left = `${i * 25}%`;
    ax.append(s);
  }
  return ax;
}

// ---- timeline: per-lane active spans over a window -----------------------------------------------------
// lanes: [{ label, key, spans: [[tStart, tEnd, cls, text]], onOpen }]
export function timeline(lanes, t0, t1, empty = 'nothing active in window') {
  const box = el('div', 'tl');
  if (!lanes.length) { box.append(el('div', 'na', empty)); return box; }
  const pos = (t) => Math.max(0, Math.min(100, ((t - t0) / (t1 - t0)) * 100));
  for (const ln of lanes) {
    const r = el('div', 'tl-row');
    const track = el('div', 'tl-track');
    const desc = [];
    for (const [a, b, cls, text] of ln.spans) {
      const s = el('span', `tl-span ${cls}`);
      s.style.left = `${pos(a)}%`;
      s.style.width = `max(2px, ${pos(b) - pos(a)}%)`;
      s.title = `${text} ${jstHm.format(new Date(a * 1000))}–${jstHm.format(new Date(b * 1000))}`;
      track.append(s);
      desc.push(s.title);
    }
    const l = el('span', 'tl-l', ln.label);
    l.title = ln.label;
    r.append(l, track);
    const label = `${ln.label}: ${desc.join(', ') || 'not active in window'}`;
    if (ln.onOpen) { clickable(r, ln.onOpen, `details for ${ln.key || ln.label}`); r.setAttribute('aria-label', `${label}. open details`); }
    else { track.setAttribute('role', 'img'); track.setAttribute('aria-label', label); }
    box.append(r);
  }
  const ax = el('div', 'tl-row tl-axis-row');
  ax.append(el('span', 'tl-l'), timeAxis(t0, t1));
  box.append(ax);
  return box;
}

// ---- alert timeline lanes from the ALERTS series (one lane per alert label set; resolved alerts included) ----
export const ALERT_KEYS = [{ cls: 'tl-crit', name: 'firing · critical' }, { cls: 'tl-warn', name: 'firing · warning' }, { cls: 'tl-info', name: 'firing · info' }, { cls: 'tl-pending', name: 'pending' }];
export const alertKey = (labels) => JSON.stringify(Object.entries(labels).filter(([k]) => k !== '__name__' && k !== 'alertstate').sort());
export function alertLanes(r, alerts, nav) {
  const cur = new Map(alerts.map((a) => [alertKey(a.labels), a]));
  const lanes = new Map();
  for (const s of r.series) {
    const k = alertKey(s.metric);
    const ln = lanes.get(k) || { key: k, metric: s.metric, spans: [] };
    const state = s.metric.alertstate;
    const cls = state === 'pending' ? 'tl-pending' : `tl-${sevKind(s.metric.severity)[0]}`;
    let start = null, prev = null;
    for (const [t] of s.points) {
      if (start === null) start = t;
      else if (t - prev > r.step * 2) { ln.spans.push([start, prev + r.step, cls, state]); start = t; } // gap = not active / no data
      prev = t;
    }
    if (start !== null) ln.spans.push([start, Math.min(prev + r.step, r.t1), cls, state]);
    lanes.set(k, ln);
  }
  return [...lanes.values()].map((ln) => {
    const a = cur.get(ln.key);
    const m = ln.metric;
    const where = [m.instance, m.ifName].filter(Boolean).map((x) => maskText(String(x))).join(' ');
    ln.spans.sort((x, y) => x[0] - y[0]);
    return { label: `${a ? '' : '(resolved) '}${m.alertname}${where ? ` · ${where}` : ''}`, key: `${m.alertname} ${where}`, spans: ln.spans, active: a ? 1 : 0, onOpen: a ? () => nav.alert(a) : null };
  }).sort((x, y) => y.active - x.active || x.spans[0][0] - y.spans[0][0]);
}

// ---- stacked columns over time (syslog severity volume)---------------------------------------------
// cols: [{ t, vals: { key: n } }] evenly spaced; keys: [{ k, cls, name }]
// mark: optional time (s) drawn as a vertical marker
// warnings: server notes that the counts are partial (shown as a note under the chart; nothing when empty)
// edge: seconds the first bucket starts before the window (Loki step alignment); noted, never hidden
export function stackCols(cols, keys, t0, t1, label, mark, warnings = [], edge = 0) {
  const box = el('div', 'cols-chart');
  const plot = el('div', 'cols');
  if (has(mark)) {
    const m = el('i', 'cols-mark');
    m.style.left = `${Math.max(0, Math.min(100, ((mark - t0) / (t1 - t0)) * 100))}%`;
    plot.append(m);
  }
  const totals = cols.map((c) => keys.reduce((a, k) => a + (c.vals[k.k] || 0), 0));
  const max = Math.max(1, ...totals);
  cols.forEach((c, i) => {
    const col = el('div', 'vw-col');
    for (const k of keys) {
      const v = c.vals[k.k] || 0;
      if (!v) continue;
      const s = el('span', `vw-seg ${k.cls}`);
      s.style.height = `${(100 * v) / max}%`;
      col.append(s);
    }
    col.title = `${jstHm.format(new Date(c.t * 1000))}: ${totals[i]} lines${keys.filter((k) => c.vals[k.k]).map((k) => ` · ${k.name} ${c.vals[k.k]}`).join('')}`;
    plot.append(col);
  });
  const sums = keys.filter((k) => cols.some((c) => c.vals[k.k])).map((k) =>`${k.name} ${cols.reduce((a, c) => a + (c.vals[k.k] || 0), 0)}`).join(', ');
  const peak = totals.length ? cols[totals.indexOf(Math.max(...totals))] : null;
  plot.setAttribute('role', 'img');
  plot.setAttribute('aria-label', `${label}: ${totals.reduce((a, b) => a + b, 0)} lines (${sums})${peak ? `; peak ${Math.max(...totals)} at ${jstHm.format(new Date(peak.t * 1000))}` : ''}`);
  const yl = el('div', 'cols-y', `max ${max}`);
  yl.setAttribute('aria-hidden', 'true');
  const present = keys.filter((k) => cols.some((c) => c.vals[k.k])); // legend lists the levels that occur (all when none)
  box.append(yl, plot, timeAxis(t0, t1), keyLegend(present.length ? present : keys));
  if (warnings.length) {
    const partial = `partial: oldest buckets may be undercounted — ${warnings.map(maskText).join(' · ')}`;
    plot.setAttribute('aria-label', `${plot.getAttribute('aria-label')}. ${partial}`);
    box.append(el('div', 'chart-note cols-partial', partial));
  }
  if (edge > 0) box.append(el('div', 'chart-note', `oldest column starts ${Math.round(edge)} s before the window (server bucket alignment); tiles count exactly the window`));
  return box;
}
// syslog severities (SEV_KEYS / SEV_LEVELS / SEV_BAD / sevKey) live in util.js; re-exported for the views
export { SEV_KEYS, SEV_LEVELS, SEV_BAD, sevKey };
// Loki: line counts per severity in even buckets over [now - secs, now] for a LogQL selector (with line filters).
// The query succeeded, so an absent bucket is a known 0 lines. Returns null when superseded.
export async function sevBuckets(token, selector, secs, endS) {
  const step = Math.max(60, Math.round(secs / 30 / 60) * 60);
  // The window is (end - secs, end] with end = now, i.e. the span of the line list, so the newest lines always count.
  // Evaluation times differ by path: Loki itself rounds range-query timestamps UP to step multiples, while mask-api's
  // filtered path evaluates at exactly the requested times. So:
  //  - totals (tiles) come from ONE evaluation at exactly `end` over [secs]. mask-api only accepts range <= 1440 x step,
  //    so that query uses step a = ceil(secs / 1440) s and `end` is rounded UP to a multiple of a (<= 15 s at 6 h,
  //    later than now, so nothing recent is lost); both paths then evaluate at exactly `end`;
  //  - buckets are built from the evaluation times actually returned. Each point T covers (T - step, T]; a point is kept
  //    iff that interval overlaps the window, so no edge bucket is dropped and none is counted twice. On the aligned
  //    path the first bucket can begin before the window (ragged edge: reported in `edge`, the tiles stay exact).
  const a = Math.max(1, Math.ceil(secs / 1440));
  const t1 = Math.ceil(Math.ceil(endS ?? now() / 1000) / a) * a;
  const t0 = t1 - secs;
  const my = (token.seq = (token.seq || 0) + 1);
  const url = (q, start, end, st) => `/loki/loki/api/v1/query_range?query=${encodeURIComponent(q)}&start=${start}&end=${end}&step=${st}`;
  const [d, dt] = await Promise.all([
    getJson(url(`sum by (severity) (count_over_time(${selector} [${step}s]))`, t0, t1, step)),
    getJson(url(`sum by (severity) (count_over_time(${selector} [${secs}s]))`, t1, t1, a)),
  ]);
  if (my !== token.seq) return null;
  const times = new Set();
  for (const r of d.result) for (const [t] of r.values) times.add(Number(t));
  // grid of evaluation times in the phase the server used (absent points in a successful query = 0 lines)
  const phase = times.size ? ((([...times][0] % step) + step) % step) : t1 % step;
  let first = t0 + ((phase - (t0 % step) + step) % step);
  if (first <= t0) first += step;
  const cols = [];
  for (let t = first; t - step < t1; t += step) cols.push({ t, vals: {} });
  const at = new Map(cols.map((c) => [c.t, c]));
  for (const r of d.result) {
    const k = sevKey(r.metric.severity);
    for (const [t, v] of r.values) { const c = at.get(Number(t)); if (c) c.vals[k] = (c.vals[k] || 0) + Number(v); }
  }
  const totals = {};
  for (const r of dt.result) {
    const k = sevKey(r.metric.severity);
    const last = r.values[r.values.length - 1];
    if (last) totals[k] = (totals[k] || 0) + Number(last[1]);
  }
  // mask-api answers HTTP 200 with data.warnings when its line cap was hit: the counts are partial, not wrong-as-zero
  const warnings = [...new Set([d, dt].flatMap((x) => (Array.isArray(x.warnings) ? x.warnings.map(String) : [])))];
  const edge = cols.length ? Math.max(0, t0 - (cols[0].t - step)) : 0; // seconds the first bucket reaches before the window
  return { cols, totals, t0, t1, step, warnings, edge };
}
// Summary tiles of a sevBuckets() result. A capped (partial) count is shown as a lower bound ("≥ n") with a
// "partial" marker, so it never reads as a complete count (and a 0 never reads as "none").
export function sevTiles(r) {
  const partial = r.warnings?.length > 0;
  // exact window totals (one evaluation at end); bucket sums only as a fallback for callers without them
  const tot = r.totals || r.cols.reduce((a, c) => { for (const [k, n] of Object.entries(c.vals)) a[k] = (a[k] || 0) + n; return a; }, {});
  const s = (k) => tot[k] || 0;
  const total = Object.values(tot).reduce((a, b) => a + b, 0); // every returned severity
  const ce = SEV_BAD.reduce((a, k) => a + s(k), 0), w = s('warning');
  const v = (n) => (partial ? `≥ ${n}` : n);
  const sub = partial ? 'partial: line cap hit, may be undercounted' : undefined;
  const of = partial ? 'of counted lines' : 'of lines';
  const none = partial ? 'none counted (partial)' : 'none';
  return tiles([
    { label: 'Lines in window', value: v(total), d: 0, sub, ...(partial ? { kind: 'warn', status: 'partial count' } : {}) },
    { label: 'ERROR or worse', value: v(ce), d: 0, kind: ce ? 'crit' : partial ? 'unknown' : 'ok', status: ce ? `${shareText(pct(ce, total))} ${of}` : none, sub },
    { label: 'WARN', value: v(w), d: 0, kind: w ? 'warn' : partial ? 'unknown' : 'ok', status: w ? `${shareText(pct(w, total))} ${of}` : none, sub },
    { label: 'NOTICE / INFO / DEBUG', value: v(total - ce - w), d: 0, sub: sub || (s('other') ? `incl. ${s('other')} other` : undefined) },
  ]);
}

// ---- small multiples: one mini chart per item on a shared y-scale ------------------------------------
// items: [{ label, key, badge: [kind, text], series: [{ points, cls }], vals: [[label, value, unit]], onOpen }]
export function multiples(items, { t0, t1, step, max }) {
  const grid = el('div', 'multiples');
  for (const it of items) {
    const c = el('div', 'mult');
    const h = el('div', 'mult-h');
    if (it.badge) h.append(badge(it.badge[0], it.badge[1]));
    h.append(el('span', 'mult-t', it.label));
    const vals = el('div', 'mult-vals');
    for (const [l, v, unit] of it.vals) {
      const s = el('span', `mv ${isMissing(v) ? 'na' : ''}`, `${l} ${isMissing(v) ? '\u2014' : v}`);
      if (unit && !isMissing(v)) s.append(el('span', 'u', unit));
      vals.append(s);
    }
    const svg = sparkSvg(it.series, { t0, t1, step, max });
    c.append(h, vals, svg);
    if (!it.series.some((s) => s.points.length)) c.append(el('div', 'mult-nd', 'no data in window'));
    if (it.onOpen) { clickable(c, it.onOpen, `details for ${it.key || it.label}`); c.setAttribute('aria-label', `${it.label} ${it.badge?.[1] || ''}: ${it.vals.map(([l, v, u]) => `${l} ${isMissing(v) ? 'no data' : `${v}${u ? ` ${u}` : ''}`}`).join(', ')}. open details`); }
    grid.append(c);
  }
  if (!items.length) grid.append(el('div', 'na', 'none'));
  return grid;
}
// Prometheus range series -> Map(key -> points) for small multiples / tile sparks
export const seriesBy = (r, qi, keyFn) => new Map((r?.series || []).filter((s) => s.qi === qi).map((s) => [keyFn(s.metric), s.points]));
export const maxOf = (...maps) => Math.max(0, ...maps.flatMap((m) => [...m.values()].flatMap((pts) => pts.map((p) => p[1]))));

// ---- table / card list with one shared sort state ------------------------------------------------------
// cols: [{ key, label, num, fmt(v, row) }]; card(row) -> { title, badge: [kind, text], fields: [[label, text, unit]], extra: Node, cls }.
// The chosen view is remembered per list in localStorage; phones (< 768 px) default to cards.
const PHONE = '(max-width: 767px)';
function storedMode(id) {
  try { const v = localStorage.getItem(`cc-view-${id}`); if (v === 'table' || v === 'cards') return v; } catch { /* storage unavailable */ }
  return window.matchMedia(PHONE).matches ? 'cards' : 'table';
}
function storeMode(id, m) {
  try { localStorage.setItem(`cc-view-${id}`, m); } catch { /* storage unavailable: choice not persisted */ }
}
const cmp = (k, desc) => (a, b) => {
  const x = a[k], y = b[k];
  const xm = isMissing(x), ym = isMissing(y);
  if (xm || ym) return xm === ym ? 0 : xm ? 1 : -1; // missing values always last
  const d = typeof x === 'number' ? x - y : String(x).localeCompare(String(y));
  return desc ? -d : d;
};
// keyOf(row): stable identity of a row (never a metric), used as the focus key of its table button and card so a live
// refresh can hand keyboard focus back to the same row; defaults to the first non-numeric column.
export function dataView(id, cols, initial, card, keyOf) {
  const idCol = cols.find((c) => !c.num) || cols[0];
  const rowKey = (r) => String(keyOf ? keyOf(r) : r[idCol.key]);
  const st = { key: initial?.key ?? cols[0].key, desc: initial?.desc ?? false, rows: [], onRow: null, mode: storedMode(id) };
  const root = el('div', 'dv');
  const table = el('table', 'tbl');
  const thead = el('thead'), tbody = el('tbody');
  table.append(thead, tbody);
  const grid = el('div', 'cards');
  // cards-mode sort controls (the table sorts from its header)
  const sortBar = el('div', 'dv-sort');
  const sl = el('label', 'fld-inline', '並び替え ');
  const sel = el('select');
  for (const c of cols) { const o = el('option', '', c.label); o.value = c.key; sel.append(o); }
  sel.addEventListener('change', () => { st.key = sel.value; st.desc = !!cols.find((c) => c.key === st.key)?.num; render(); });
  sl.append(sel);
  const dir = el('button', 'seg-btn');
  dir.type = 'button';
  dir.addEventListener('click', () => { st.desc = !st.desc; render(); });
  sortBar.append(sl, dir);
  const toggle = rangeSelect([['表', 'table'], ['カード', 'cards']], st.mode, (m) => { st.mode = m; storeMode(id, m); render(); }, '表示切替 (table / cards)');
  toggle.classList.add('dv-toggle');
  root.append(sortBar, table, grid);
  const missingText = (c, v, r) => (c.fmt ? c.fmt(v, r) : isMissing(v) ? '\u2014' : String(v));
  let headSort = null; // the header is rebuilt only when the sort changes, so a live refresh never steals its focus
  function head() {
    const sig = `${st.key}|${st.desc}`;
    if (sig === headSort) return;
    headSort = sig;
    const refocusKey = thead.contains(document.activeElement) ? st.key : null;
    const tr = el('tr');
    for (const c of cols) {
      const th = el('th', c.num ? 'n' : '');
      const b = el('button', 'th-btn', c.label);
      b.type = 'button';
      const active = st.key === c.key;
      th.setAttribute('aria-sort', active ? (st.desc ? 'descending' : 'ascending') : 'none');
      if (active) b.append(el('span', 'sort-ind', st.desc ? ' \u25BC' : ' \u25B2'));
      b.addEventListener('click', () => { st.desc = st.key === c.key ? !st.desc : !!c.num; st.key = c.key; render(); });
      b.dataset.col = c.key;
      th.append(b);
      tr.append(th);
    }
    thead.replaceChildren(tr);
    if (refocusKey) thead.querySelector(`[data-col="${CSS.escape(refocusKey)}"]`)?.focus();
  }
  function rowsTable(sorted) {
    const trs = sorted.map((r) => {
      const tr = el('tr');
      const texts = cols.map((c) => missingText(c, r[c.key], r));
      cols.forEach((c, i) => {
        const td = el('td', `${c.num ? 'n' : ''} ${isMissing(r[c.key]) && !c.fmt ? 'na' : ''}`, texts[i]);
        td.title = texts[i];
        tr.append(td);
      });
      if (st.onRow) {
        // the row is clickable by mouse; a real button in the first cell serves keyboard/AT
        const open = () => st.onRow(r);
        tr.classList.add('clickable');
        tr.addEventListener('click', open);
        const b = el('button', 'cell-btn', texts[0]);
        b.type = 'button';
        b.setAttribute('aria-label', `details for ${texts.slice(0, 3).join(' ')}`);
        b.dataset.fkey = `row ${rowKey(r)}`;
        b.addEventListener('click', (e) => { e.stopPropagation(); open(); });
        tr.firstChild.replaceChildren(b);
      }
      return tr;
    });
    if (!trs.length) {
      const td = el('td', 'na', 'no data');
      td.colSpan = cols.length;
      trs.push(el('tr'));
      trs[0].append(td);
    }
    putIn(tbody, ...trs);
  }
  function rowsCards(sorted) {
    const cs = sorted.map((r) => {
      const m = card(r);
      const c = el('div', `card ${m.cls || ''}`);
      const h = el('div', 'card-h');
      if (m.badge) h.append(badge(m.badge[0], m.badge[1]));
      h.append(el('span', 'card-t', m.title));
      if (m.sub) { const sub = el('span', 'card-sub', m.sub); sub.title = m.sub; h.append(sub); } // ellipsised on narrow cards
      const dl = el('dl', 'card-f');
      for (const [l, v, unit] of m.fields) {
        const g = el('div');
        const dd = el('dd', isMissing(v) ? 'na' : '', isMissing(v) ? '\u2014' : String(v));
        if (unit && !isMissing(v)) dd.append(el('span', 'u', unit));
        g.append(el('dt', '', l), dd);
        dl.append(g);
      }
      c.append(h, dl);
      if (m.extra) c.append(m.extra);
      if (st.onRow) {
        clickable(c, () => st.onRow(r), `card ${m.title} ${m.sub || ''}`.trim());
        c.dataset.fkey = `card ${rowKey(r)}`;
      }
      return c;
    });
    if (!cs.length) cs.push(el('div', 'na', 'no data'));
    putIn(grid, ...cs);
  }
  function render() {
    const sorted = [...st.rows].sort(cmp(st.key, st.desc));
    const cards = st.mode === 'cards';
    table.hidden = cards;
    grid.hidden = !cards;
    sortBar.hidden = !cards;
    sel.value = st.key;
    dir.textContent = st.desc ? '\u25BC 降順' : '\u25B2 昇順';
    dir.setAttribute('aria-label', `sort direction: ${st.desc ? 'descending' : 'ascending'}`);
    if (cards) rowsCards(sorted); else { head(); rowsTable(sorted); }
  }
  return {
    el: root, toggle,
    update(rows, onRow) { st.rows = rows; st.onRow = onRow || null; render(); },
  };
}
// Section holding a data view, with the 表 / カード toggle in its heading.
export function listSection(title, meta, dv) {
  const s = section(title, meta);
  s.head.append(dv.toggle);
  s.body.append(dv.el);
  return s;
}
