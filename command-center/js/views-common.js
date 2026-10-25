// Building blocks shared by modal and drawer views.
import { el, clickable, lineChart, legend, chartColors, has, fixed } from './util.js';
import { promRange } from './api.js';

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
    const missing = v === undefined || v === null || v === '—' || (typeof v === 'number' && !Number.isFinite(v));
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

export function chartBlock(cls = '') {
  const wrap = el('div', `chart-wrap ${cls}`);
  const canvas = el('canvas', 'chart');
  const leg = el('div', 'chart-legend');
  const note = el('div', 'chart-note');
  wrap.append(canvas, leg, note);
  return { wrap, canvas, leg, note };
}
const stepFor = (secs) => Math.max(15, Math.round(secs / 240 / 15) * 15);
// queries: [{ q, name(metric) }]; draws all series; empty result -> "no data in window" note (no zero line).
// `$RATE` in a query becomes the rate window: at least one step (so long ranges average every sample instead of
// sampling 1 min out of each step) and at least 4 scrape intervals.
const SCRAPE_S = 15;
export async function drawRange(block, queries, secs, unit) {
  const step = stepFor(secs);
  const win = `${Math.max(step, 4 * SCRAPE_S)}s`;
  const my = (block.seq = (block.seq || 0) + 1); // a newer request (range switch / next poll) supersedes this one
  const results = await Promise.all(queries.map((x) => promRange(x.q.replaceAll('$RATE', win), secs, step)));
  if (my !== block.seq) return;
  const colors = chartColors();
  const series = [];
  results.forEach((res, qi) => {
    for (const r of res) {
      series.push({ name: queries[qi].name(r.metric), color: colors[series.length % colors.length], points: r.values.map(([t, v]) => [Number(t), Number(v)]) });
    }
  });
  const t1 = Date.now() / 1000;
  lineChart(block.canvas, series, { t0: t1 - secs, t1, step, unit });
  block.leg.replaceChildren(legend(series));
  block.note.textContent = series.length ? `step ${step} s · rate window ${win} \u00B7 gaps = no samples (not zero)` : 'no data in window';
}
export function rangeSelect(options, initial, onChange) {
  const g = el('div', 'seg');
  g.setAttribute('role', 'group');
  const btns = options.map(([label, val]) => {
    const b = el('button', 'seg-btn', label);
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
