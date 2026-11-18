// 推移 (F1): one metric family over a time range, from mask-api's server-side templates (/trend/series; the screen sends
// a family name and scope values only, never PromQL). Static SVG (no library, nothing animated: the same in LITE),
// drag on the chart to zoom into a span, ←/→ on the focused chart to read values, legend buttons hide / show a series.
// PLAYBACK: the window ends at the cursor. No value -> "—", gaps are drawn as gaps (never 0).
import { el, has, now, isPlayback, jstHm, jstFull, fmtBps } from './util.js';
import { getJson } from './api.js';
import { DEVICES, WAN } from './panels.js';
import { section, linkBtn } from './views-common.js';

const SVGNS = 'http://www.w3.org/2000/svg';
const MIN_SPAN_S = 300;
export const PRESETS = [['1h', 3600], ['6h', 6 * 3600], ['24h', 86400], ['7d', 7 * 86400], ['30d', 30 * 86400]];
const GROUPS = [['接続口', /^if_/], ['機器', /^(dev_|wlan_)/], ['外部回線', /^wan_/], ['通信先', /^flow_/], ['パケットキャプチャ', /^capture_/]];
const SCOPE_LABEL = { instance: '機器', ifName: 'IF', dst_country: '国 (2 文字)', asn: 'ASN', src_host: 'LAN 端末' };
const ALL = { instance: '全機器', ifName: '合計 (全 IF)', dst_country: '全件', asn: '全件', src_host: '全件' };
const PALETTE = ['var(--tr-1)', 'var(--tr-2)', 'var(--tr-3)', 'var(--tr-4)', 'var(--tr-5)', 'var(--tr-6)', 'var(--tr-7)', 'var(--tr-8)', 'var(--tr-9)'];

let familiesP = null; // the allow-list, asked once per page
const families = () => (familiesP ??= getJson('/trend/families').then((d) => d.families).catch((e) => { familiesP = null; throw e; }));

const pad = (n) => String(n).padStart(2, '0');
// <input type="datetime-local"> values are JST, like every time on the screens
export function toInput(ms) {
  const d = new Date(ms + 9 * 3600e3);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
export const fromInput = (v) => (v ? Date.parse(`${v}:00+09:00`) : NaN);
export const spanText = (s) => (s >= 86400 ? `${+(s / 86400).toFixed(1)} 日` : s >= 3600 ? `${+(s / 3600).toFixed(1)} 時間` : `${Math.round(s / 60)} 分`);

// value text in the family's unit (fixed decimals, so the legend's slots do not change width)
export function fmtVal(v, unit) {
  if (!has(v)) return '—';
  if (unit === 'bps') return fmtBps(v);
  const d = unit === '%' || unit === '日' ? 1 : Math.abs(v) >= 100 || unit === '台' || unit === '' ? 0 : 2;
  return `${v.toFixed(d)}${unit ? ` ${unit}` : ''}`;
}
const axisVal = (v, unit) => (unit === 'bps' ? fmtBps(v).replace(' ', '') : v >= 100 ? v.toFixed(0) : v.toFixed(v >= 10 ? 1 : 2));

// Range control shared with ログ検索: presets + 開始 / 終了 (JST). onChange({ preset, from, to }) with ms (custom only).
// maxS: the longest custom window in seconds, a number or a function (read when the window is applied)
export function rangeControl(state, { presets = PRESETS, maxS = Infinity, onChange }) {
  const lim = typeof maxS === 'function' ? maxS : () => maxS;
  const wrap = el('div', 'tr-range');
  const seg = el('div', 'seg');
  seg.setAttribute('role', 'group');
  seg.setAttribute('aria-label', '期間');
  const btns = [...presets, ['指定', 'custom']].map(([t, v]) => {
    const b = el('button', 'seg-btn', t);
    b.type = 'button';
    b.dataset.v = String(v);
    b.addEventListener('click', () => {
      if (v === 'custom') { custom.hidden = false; fi.focus(); mark('custom'); return; }
      state.preset = v;
      custom.hidden = true;
      mark(v);
      onChange();
    });
    return b;
  });
  const mark = (v) => btns.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === String(v))));
  seg.append(...btns);
  const custom = el('div', 'tr-custom');
  const mk = (label) => { const l = el('label', 'fld', label); const i = el('input'); i.type = 'datetime-local'; l.append(i); return [l, i]; };
  const [fl, fi] = mk('開始 (JST)');
  const [tl, ti] = mk('終了 (JST)');
  const apply = el('button', 'link-btn', 'この期間で表示');
  apply.type = 'button';
  const why = el('p', 'tr-why');
  why.setAttribute('role', 'status');
  apply.addEventListener('click', () => {
    const from = fromInput(fi.value), to = Math.min(fromInput(ti.value), now());
    const bad = !Number.isFinite(from) || !Number.isFinite(to) ? '開始と終了を入力してください'
      : to - from < MIN_SPAN_S * 1000 ? '期間は 5 分以上に設定してください'
        : to - from > lim() * 1000 ? `期間の上限は ${spanText(lim())}です` : '';
    why.textContent = bad;
    if (bad) return;
    Object.assign(state, { preset: 'custom', from, to });
    onChange();
  });
  custom.append(fl, tl, apply, why);
  custom.hidden = state.preset !== 'custom';
  const t1 = state.to || now();
  fi.value = toInput(state.from || t1 - 3600e3);
  ti.value = toInput(t1);
  mark(state.preset);
  wrap.append(seg, custom);
  return { wrap, mark };
}

// the window to show: a zoom span, the custom one, or the preset ending now (PLAYBACK: at the cursor)
export function windowOf(state) {
  const end = now();
  if (state.zoom.length) return { ...state.zoom[state.zoom.length - 1] };
  if (state.preset === 'custom') return { from: state.from, to: Math.min(state.to, end) };
  return { from: end - state.preset * 1000, to: end };
}

// ---- the chart ------------------------------------------------------------------------------------------------------
function svgEl(tag, attrs = {}) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}
const tickText = (t, span) => (span > 86400 ? jstFull.format(new Date(t * 1000)).slice(0, 11) : jstHm.format(new Date(t * 1000)));

// series: [{ label, color, points: [[t, v]] }] (visible ones); stacked: cumulative areas on the shared time grid
function layout(series, stacked, step) {
  if (!stacked) return series.map((s) => ({ ...s, lines: s.points.map(([t, v]) => [t, v, 0]) }));
  const times = [...new Set(series.flatMap((s) => s.points.map((p) => p[0])))].sort((a, b) => a - b);
  const base = new Map(times.map((t) => [t, 0]));
  return series.map((s) => {
    const at = new Map(s.points);
    const lines = times.filter((t) => at.has(t)).map((t) => { const lo = base.get(t); const hi = lo + at.get(t); base.set(t, hi); return [t, hi, lo]; });
    return { ...s, lines };
  });
}
// runs of points without a gap (> 2 steps apart): a gap is never bridged
function runs(pts, step) {
  const out = [];
  let cur = [];
  for (const p of pts) {
    if (cur.length && p[0] - cur[cur.length - 1][0] > step * 2) { out.push(cur); cur = []; }
    cur.push(p);
  }
  if (cur.length) out.push(cur);
  return out;
}

function drawChart(box, data, visible, opts) {
  const w = Math.max(280, Math.round(box.clientWidth || 600));
  const h = w < 500 ? 220 : 280;
  const padL = 76, padR = 12, padT = 10, padB = 26;
  const { from, to, step, unit, stacked } = data;
  const lay = layout(visible, stacked, step);
  const vmax = Math.max(unit === '%' ? 1 : 1e-9, ...lay.flatMap((s) => s.lines.map((p) => p[1]))) * 1.08;
  const x = (t) => padL + ((t - from) / (to - from)) * (w - padL - padR);
  const y = (v) => h - padB - (v / vmax) * (h - padB - padT);
  const svg = svgEl('svg', { class: 'tr-svg', viewBox: `0 0 ${w} ${h}`, width: w, height: h, 'aria-hidden': 'true' });
  for (let i = 0; i <= 4; i++) {
    const v = (vmax / 4) * i;
    svg.append(svgEl('line', { class: 'tr-grid', x1: padL, x2: w - padR, y1: y(v), y2: y(v) }));
    const tx = svgEl('text', { class: 'tr-ax', x: padL - 6, y: y(v) + 4, 'text-anchor': 'end' });
    tx.textContent = axisVal(v, unit);
    svg.append(tx);
  }
  const ticks = w < 500 ? 3 : 5;
  for (let i = 0; i <= ticks; i++) {
    const t = from + ((to - from) / ticks) * i;
    const tx = svgEl('text', { class: 'tr-ax', x: x(t), y: h - 7, 'text-anchor': i === 0 ? 'start' : i === ticks ? 'end' : 'middle' });
    tx.textContent = tickText(t, to - from);
    svg.append(tx);
  }
  for (const s of [...lay].reverse()) { // stacked: the lowest layer drawn last is fine either way; lines on top
    for (const r of runs(s.lines, step)) {
      if (stacked) {
        const top = r.map(([t, hi]) => `${x(t).toFixed(1)},${y(hi).toFixed(1)}`);
        const bot = [...r].reverse().map(([t, , lo]) => `${x(t).toFixed(1)},${y(lo).toFixed(1)}`);
        svg.append(svgEl('polygon', { class: 'tr-area', points: [...top, ...bot].join(' '), style: `fill:${s.color}` }));
      }
      const d = r.map(([t, v], i) => `${i ? 'L' : 'M'}${x(t).toFixed(1)},${y(v).toFixed(1)}`).join('');
      svg.append(svgEl('path', { class: 'tr-line', d: r.length === 1 ? `${d}h1` : d, style: `stroke:${s.color}` }));
    }
  }
  const cursor = svgEl('line', { class: 'tr-cursor', y1: padT, y2: h - padB, x1: -10, x2: -10 });
  const sel = svgEl('rect', { class: 'tr-sel', y: padT, height: h - padB - padT, x: 0, width: 0, visibility: 'hidden' });
  svg.append(cursor, sel);
  box.replaceChildren(svg);
  const tOf = (px) => from + ((px - padL) / (w - padL - padR)) * (to - from);
  return { svg, cursor, sel, x, tOf, padL, padR, w };
}

// ---- the view -----------------------------------------------------------------------------------------------------
// init: { family, instance, ifName, dst_country, asn, src_host, preset (seconds) }
export function trendView(init = {}) {
  const st = { family: init.family || 'if_bps', scope: {}, preset: init.preset || 3600, from: 0, to: 0, zoom: [], hidden: new Set(), key: '', data: null, seq: 0, readT: null };
  for (const k of Object.keys(SCOPE_LABEL)) if (init[k]) st.scope[k] = init[k];
  let fams = [], s = {}, chart = null, ctxRef = null, ro = null;
  const fam = () => fams.find((f) => f.family === st.family);
  const step = (span) => Math.max(30, Math.ceil(span / 599 / 30) * 30);

  function params() {
    const w = windowOf(st);
    const span = Math.round((w.to - w.from) / 1000);
    const t1 = Math.floor(w.to / 1000);
    const p = { family: st.family, from: String(t1 - span), to: String(t1) };
    for (const k of fam()?.scope || []) if (st.scope[k]) p[k] = st.scope[k];
    return { p, span, t1 };
  }
  async function load(force) {
    if (!fam()) return;
    const missing = fam().required.filter((k) => !st.scope[k]);
    if (missing.length) { show(null, `${missing.map((k) => SCOPE_LABEL[k]).join('・')}を選択してください`); return; }
    const { p, span, t1 } = params();
    // a preset window moves with time (live: the clock, PLAYBACK: the cursor): it is asked again once it has moved by a
    // step, not on every poll; its end is never rounded back (the newest values stay in it)
    const moving = !st.zoom.length && st.preset !== 'custom';
    const { from, to, ...rest } = p;
    const key = new URLSearchParams(moving ? { ...rest, span } : p).toString();
    if (!force && key === st.key && st.data && !(moving && Math.abs(t1 - st.lastTo) >= step(span))) return;
    const my = ++st.seq;
    s.status.textContent = '読込中…';
    try {
      const d = await getJson(`/trend/series?${new URLSearchParams(p)}`);
      if (my !== st.seq) return;
      st.lastTo = t1;
      st.key = key;
      st.data = d;
      show(d, '');
    } catch (e) {
      if (my !== st.seq) return;
      if (st.key !== key) { st.data = null; show(null, `読込不可: ${e.message}`); } // never another window's lines as this one's
      else s.status.textContent = `更新不可 (前回値を表示中): ${e.message}`;
      throw e;
    }
  }

  function legendRow(ser, i) {
    const b = el('button', 'tr-lg');
    b.type = 'button';
    const on = !st.hidden.has(ser.key);
    b.setAttribute('aria-pressed', String(on));
    const vals = ser.points.map((p) => p[1]);
    const last = vals.length ? vals[vals.length - 1] : undefined;
    const sw = el('i', 'tr-sw');
    sw.style.background = PALETTE[i % PALETTE.length];
    b.append(sw, el('span', 'tr-lg-n', ser.label), el('span', 'tr-lg-v', fmtVal(last, st.data.unit)), el('span', 'tr-lg-v', `最大 ${fmtVal(vals.length ? Math.max(...vals) : undefined, st.data.unit)}`));
    b.setAttribute('aria-label', `${ser.label}: 最新 ${fmtVal(last, st.data.unit)}、最大 ${fmtVal(vals.length ? Math.max(...vals) : undefined, st.data.unit)}。${on ? '表示中、クリックで非表示' : '非表示、クリックで表示'}`);
    b.addEventListener('click', () => { if (st.hidden.has(ser.key)) st.hidden.delete(ser.key); else st.hidden.add(ser.key); render(); });
    return b;
  }

  function readout() {
    const d = st.data;
    if (!d || st.readT === null || !chart) {
      s.read.textContent = ' ';
      chart?.cursor.setAttribute('x1', -10);
      chart?.cursor.setAttribute('x2', -10);
      return;
    }
    const t = d.from + Math.round((st.readT - d.from) / d.step) * d.step;
    const parts = d.series.filter((x) => !st.hidden.has(x.key)).map((x) => `${x.label} ${fmtVal(x.points.find((p) => Math.abs(p[0] - t) < d.step / 2)?.[1], d.unit)}`);
    s.read.textContent = `${jstFull.format(new Date(t * 1000))}  ${parts.join(' · ')}`;
    const px = chart.x(t);
    chart.cursor.setAttribute('x1', px);
    chart.cursor.setAttribute('x2', px);
  }

  function render() {
    const d = st.data;
    if (!d) return;
    const vis = d.series.map((x, i) => ({ ...x, color: PALETTE[i % PALETTE.length] })).filter((x) => !st.hidden.has(x.key));
    const any = d.series.some((x) => x.points.length);
    s.box.classList.toggle('tr-nodata', !any);
    if (!any) {
      chart = null;
      s.box.replaceChildren(el('div', 'tr-dash', '—'), el('p', 'tr-nd', '本期間の数値なし (0 値ではありません。未取得の指標、または機器・取得元の停止期間です)'));
    } else chart = drawChart(s.box, { ...d, step: d.step }, vis, {});
    s.legend.replaceChildren(...d.series.map(legendRow));
    const pts = Math.max(0, ...d.series.map((x) => x.points.length));
    s.note.textContent = `${spanText(d.to - d.from)} · 間隔 ${d.step} 秒 · 1 系列 ${pts} 点 (600 点まで)${d.stacked ? ' · 積み上げ' : ''}${d.folded ? ' · 上位 8 件と「その他」' : ''} · 線の途切れは数値なし (0 値ではない)`;
    s.box.setAttribute('aria-label', `${d.title}、${jstFull.format(new Date(d.from * 1000))} から ${jstFull.format(new Date(d.to * 1000))}。`
      + (any ? d.series.map((x) => { const v = x.points.map((p) => p[1]); return `${x.label}: 最新 ${fmtVal(v[v.length - 1], d.unit)}、最大 ${fmtVal(v.length ? Math.max(...v) : undefined, d.unit)}`; }).join('。') : '数値なし'));
    s.unzoom.disabled = !st.zoom.length;
    readout();
  }
  function show(d, msg) {
    s.status.textContent = msg || (isPlayback() ? '再生位置までの数値' : '');
    if (!d) {
      chart = null;
      s.box.classList.add('tr-nodata');
      s.box.replaceChildren(el('div', 'tr-dash', '—'), el('p', 'tr-nd', msg || ''));
      s.legend.replaceChildren();
      s.note.textContent = '';
      return;
    }
    s.title.textContent = `${d.title}${d.unit ? ` (${d.unit})` : ''}`;
    render();
  }

  // zoom: a stack of windows inside the current one ("拡大解除" pops); never shorter than the server's 5 min
  function zoomTo(t0, t1) {
    const cur = windowOf(st);
    let a = t0 * 1000, b = t1 * 1000;
    if (b - a < MIN_SPAN_S * 1000) { const m = (a + b) / 2; a = m - MIN_SPAN_S * 500; b = m + MIN_SPAN_S * 500; }
    if (a < cur.from) { b += cur.from - a; a = cur.from; }
    if (b > cur.to) { a = Math.max(cur.from, a - (b - cur.to)); b = cur.to; }
    st.zoom.push({ from: a, to: b });
    st.readT = null;
    load().catch(() => {});
  }
  function wireDrag() {
    let x0 = null;
    s.box.addEventListener('pointerdown', (e) => {
      if (!chart || e.button !== 0) return;
      x0 = e.offsetX;
      s.box.setPointerCapture(e.pointerId);
    });
    s.box.addEventListener('pointermove', (e) => {
      if (!chart) return;
      st.readT = chart.tOf(e.offsetX);
      readout();
      if (x0 === null) return;
      const a = Math.max(chart.padL, Math.min(x0, e.offsetX)), b = Math.min(chart.w - chart.padR, Math.max(x0, e.offsetX));
      chart.sel.setAttribute('x', a);
      chart.sel.setAttribute('width', Math.max(0, b - a));
      chart.sel.setAttribute('visibility', 'visible');
    });
    s.box.addEventListener('pointerup', (e) => {
      if (!chart || x0 === null) return;
      const a = Math.min(x0, e.offsetX), b = Math.max(x0, e.offsetX);
      x0 = null;
      chart.sel.setAttribute('visibility', 'hidden');
      if (b - a >= 8) zoomTo(chart.tOf(a), chart.tOf(b));
    });
    s.box.addEventListener('keydown', (e) => {
      const d = st.data;
      if (!d || !chart) return;
      const k = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity }[e.key];
      if (k === undefined) return;
      e.preventDefault();
      const t = st.readT ?? d.to;
      st.readT = Math.max(d.from, Math.min(d.to, Number.isFinite(k) ? t + k * d.step * (e.shiftKey ? 10 : 1) : k < 0 ? d.from : d.to));
      readout();
    });
    s.box.addEventListener('blur', () => { st.readT = null; readout(); });
  }

  function scopeControls(ctx) {
    const f = fam();
    s.scope.replaceChildren();
    if (!f) return;
    const ifsOf = (inst) => [...new Set([...(ctx?.snap?.m.ifInv?.keys() || []), ...(ctx?.snap?.m.ifSpeed?.keys() || [])]
      .filter((k) => k.startsWith(`${inst}|`)).map((k) => k.split('|')[1]))].sort();
    for (const k of f.scope) {
      const l = el('label', 'fld', SCOPE_LABEL[k]);
      let c;
      if (k === 'instance' || k === 'ifName') {
        c = el('select');
        const opts = k === 'instance' ? DEVICES : ifsOf(st.scope.instance);
        const list = [...(f.required.includes(k) ? [] : [['', ALL[k]]]), ...opts.map((v) => [v, v])];
        if (st.scope[k] && !list.some(([v]) => v === st.scope[k])) list.push([st.scope[k], st.scope[k]]);
        if (f.required.includes(k) && !st.scope[k] && list.length) st.scope[k] = list[0][0];
        for (const [v, t] of list) { const o = el('option', '', t); o.value = v; o.selected = v === (st.scope[k] || ''); c.append(o); }
        c.addEventListener('change', () => {
          st.scope[k] = c.value;
          if (k === 'instance') delete st.scope.ifName;
          changed(ctx);
        });
      } else {
        c = el('input');
        c.type = 'search';
        c.value = st.scope[k] || '';
        c.placeholder = ALL[k];
        c.maxLength = k === 'dst_country' ? 7 : 128;
        c.addEventListener('change', () => { st.scope[k] = k === 'dst_country' && c.value.trim().length === 2 ? c.value.trim().toUpperCase() : c.value.trim(); changed(ctx); });
      }
      l.append(c);
      s.scope.append(l);
    }
  }
  function changed(ctx) {
    st.zoom = [];
    st.hidden.clear();
    st.readT = null;
    scopeControls(ctx);
    load(true).catch(() => {});
  }

  return {
    title: '推移', src: 'prom',
    mount(body) {
      const bar = el('div', 'filters tr-bar');
      const fl = el('label', 'fld', '指標');
      s.fam = el('select');
      s.fam.addEventListener('change', () => {
        st.family = s.fam.value;
        if (st.family === 'wan_util' && WAN.instance && !st.scope.ifName) Object.assign(st.scope, { instance: WAN.instance, ifName: WAN.ifName });
        changed(ctxRef);
      });
      fl.append(s.fam);
      s.scope = el('div', 'tr-scope');
      bar.append(fl, s.scope);
      const range = rangeControl(st, { maxS: 31 * 86400, onChange: () => { st.zoom = []; load(true).catch(() => {}); } });
      s.unzoom = linkBtn('拡大解除', () => { st.zoom.pop(); st.readT = null; render(); load().catch(() => {}); });
      s.unzoom.disabled = true;
      const zin = linkBtn('中央を拡大', () => { const w = windowOf(st); const q = (w.to - w.from) / 4; zoomTo((w.from + q) / 1000, (w.to - q) / 1000); });
      const acts = el('div', 'tr-acts');
      acts.append(s.unzoom, zin);
      const sec = section('', '');
      s.title = sec.head;
      s.title.textContent = '推移';
      s.status = el('span', 'tr-status');
      s.status.setAttribute('role', 'status');
      s.box = el('div', 'tr-chart');
      s.box.tabIndex = 0;
      s.box.setAttribute('role', 'img');
      s.read = el('div', 'tr-read', ' ');
      s.read.setAttribute('aria-live', 'polite');
      s.legend = el('div', 'tr-legend');
      s.legend.setAttribute('role', 'group');
      s.legend.setAttribute('aria-label', '系列の表示 / 非表示');
      s.note = el('p', 'tr-note');
      const help = el('p', 'tr-help', 'グラフのドラッグで当該区間を拡大表示。グラフ選択後に ← → で数値を表示 (Shift で 10 単位移動)。凡例のクリックで当該系列を非表示。');
      sec.body.append(acts, s.status, s.box, s.read, s.legend, s.note, help);
      body.append(bar, range.wrap, sec.wrap);
      wireDrag();
      ro = new ResizeObserver(() => { if (st.data && s.box.isConnected) requestAnimationFrame(render); });
      ro.observe(s.box);
      families().then((list) => {
        fams = list;
        if (!fam()) st.family = list[0]?.family;
        s.fam.replaceChildren(...GROUPS.map(([g, re]) => {
          const og = el('optgroup');
          og.label = g;
          og.append(...list.filter((f) => re.test(f.family)).map((f) => { const o = el('option', '', f.title); o.value = f.family; o.selected = f.family === st.family; return o; }));
          return og;
        }));
        scopeControls(ctxRef);
        load(true).catch(() => {});
      }).catch((e) => show(null, `指標一覧の読込不可: ${e.message}`));
    },
    async update(ctx) {
      const first = !ctxRef;
      ctxRef = ctx;
      if (first && fams.length) scopeControls(ctx);
      if (!s.box.isConnected) { ro?.disconnect(); return; }
      await load(false);
    },
  };
}
