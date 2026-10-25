// Shared helpers: DOM, formatting, masking, list rows, sortable tables and line charts.

export const $ = (id) => document.getElementById(id);
export const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
export const REDUCED_MOTION = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---- formatting ----------------------------------------------------------------------
export const jstClock = new Intl.DateTimeFormat('ja-JP', { timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
export const jstHm = new Intl.DateTimeFormat('ja-JP', { timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', hour12: false });
export const jstFull = new Intl.DateTimeFormat('ja-JP', { timeZone: 'Asia/Tokyo', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
export function fmtBps(bps) {
  const u = [['G', 1e9], ['M', 1e6], ['k', 1e3]].find(([, v]) => bps >= v) || ['', 1];
  return `${(bps / u[1]).toFixed(bps >= 1e9 ? 2 : 1)} ${u[0]}bps`;
}
export function fmtBytes(b) {
  const u = [['GB', 1e9], ['MB', 1e6], ['kB', 1e3]].find(([, v]) => b >= v) || ['B', 1];
  return `${(b / u[1]).toFixed(1)} ${u[0]}`;
}
export function fmtUptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : `${h}h ${m}m`;
}
export function fmtDur(s) {
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return fmtUptime(s);
}
export const has = (v) => v !== undefined && v !== null && Number.isFinite(v);
export const fixed = (v, d = 1) => (has(v) ? v.toFixed(d) : '—');
export const SEV_SHORT = { informational: 'INFO', notice: 'NOTICE', warning: 'WARN', error: 'ERROR', critical: 'CRIT', alert: 'ALERT', emergency: 'EMERG', debug: 'DEBUG' };
export const SEVERITIES = ['critical', 'error', 'warning', 'notice', 'informational'];

// NFR-09: never show full IPs / MACs (no auth layer yet; unmasking needs SEC-03).
export function maskIp(ip) {
  const parts = String(ip || '').split('.');
  return parts.length === 4 ? `${parts.slice(0, 3).join('.')}.x` : 'masked';
}
export function maskText(s) {
  return s.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/g, '$1.x')
    .replace(/\b((?:[0-9a-f]{2}:){3})[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b/gi, '$1xx:xx:xx');
}
export function distKm(a, b) {
  const r = Math.PI / 180;
  const h = Math.sin(((b.lat - a.lat) * r) / 2) ** 2
    + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(((b.lng - a.lng) * r) / 2) ** 2;
  return 12742 * Math.asin(Math.sqrt(h));
}

// ---- wallboard row primitives (one list style for every panel) -----------------------
export function cell(text, cls = '', title) {
  const s = el('span', `c ${cls}`, text);
  s.title = title || text;
  return s;
}
export function num(v, d = 1, unit) {
  const s = cell(fixed(v, d), has(v) ? 'n' : 'n na', has(v) ? undefined : 'no data');
  if (unit && has(v)) s.append(el('span', 'u', unit));
  return s;
}
export function badge(kind, text) {
  const s = el('span', `st st-${kind}`, text);
  s.title = text;
  return s;
}
// A row; when onOpen is given the row is a keyboard-accessible button that opens related detail.
export function row(cells, cls = '', onOpen, label) {
  const r = el('div', `row ${cls}`);
  r.append(...cells);
  if (onOpen) clickable(r, onOpen, label);
  return r;
}
export function clickable(node, onOpen, label) {
  node.classList.add('clickable');
  node.tabIndex = 0;
  node.setAttribute('role', 'button');
  if (label) { node.setAttribute('aria-label', label); node.dataset.fkey = label; }
  node.addEventListener('click', (e) => { e.stopPropagation(); onOpen(); });
  node.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(); } });
  return node;
}
// Header row: a label starting with '#' is a numeric column (right-aligned).
export const head = (...labels) => row(labels.map((l) => (l.startsWith('#') ? cell(l.slice(1), 'n') : cell(l))), 'head');
export function bar(pct) {
  const b = el('span', 'bar');
  b.style.setProperty('--w', `${Math.max(0, Math.min(100, pct))}%`);
  return b;
}
// Replace a container's rows (wallboard panels rebuild on every poll) without dropping keyboard focus:
// the focused row is found again by its data-fkey in the new content.
export function put(id, rows) {
  const box = $(id);
  refocus(box, () => box.replaceChildren(...rows));
}
export function refocus(box, rebuild) {
  const a = document.activeElement;
  const key = a && box.contains(a) ? (a.closest('[data-fkey]')?.dataset.fkey ?? null) : null;
  rebuild();
  if (key === null) return;
  const next = [...box.querySelectorAll('[data-fkey]')].find((n) => n.dataset.fkey === key);
  // a row that no longer exists (e.g. a syslog line scrolled out) falls back to the panel's title button
  (next || box.closest('.panel')?.querySelector('.h-open'))?.focus({ preventScroll: true });
}
export function upState(v) {
  if (v === 1) return ['ok', 'UP'];
  if (v === 0) return ['crit st-down', 'DOWN'];
  return ['unknown', 'UNKNOWN'];
}

// Prometheus vector -> Map(key -> number)
export function vmap(result, ...keys) {
  return new Map(result.map((r) => [keys.map((k) => r.metric[k]).join('|'), Number(r.value[1])]));
}
export const scalar = (result) => (result.length ? Number(result[0].value[1]) : undefined);

// ---- sortable table (modals/drawers) -------------------------------------------------
// cols: [{ key, label, num, fmt(v,row), title(row) }]; rows: plain objects; onRow(row) opens detail.
export function sortTable(cols, initial) {
  const st = { key: initial?.key ?? cols[0].key, desc: initial?.desc ?? false, rows: [], onRow: null };
  const table = el('table', 'tbl');
  const thead = el('thead');
  const tbody = el('tbody');
  table.append(thead, tbody);
  function renderHead() {
    const tr = el('tr');
    for (const c of cols) {
      const th = el('th', c.num ? 'n' : '');
      const b = el('button', 'th-btn', c.label);
      b.type = 'button';
      const active = st.key === c.key;
      th.setAttribute('aria-sort', active ? (st.desc ? 'descending' : 'ascending') : 'none');
      if (active) b.append(el('span', 'sort-ind', st.desc ? ' ▼' : ' ▲'));
      b.addEventListener('click', () => { st.desc = st.key === c.key ? !st.desc : !!c.num; st.key = c.key; render(); });
      th.appendChild(b);
      tr.appendChild(th);
    }
    thead.replaceChildren(tr);
  }
  function render() {
    renderHead();
    const k = st.key;
    const sorted = [...st.rows].sort((a, b) => {
      const x = a[k], y = b[k];
      const xm = x === undefined || x === null || (typeof x === 'number' && !Number.isFinite(x));
      const ym = y === undefined || y === null || (typeof y === 'number' && !Number.isFinite(y));
      if (xm || ym) return xm === ym ? 0 : xm ? 1 : -1; // missing values always last
      const d = typeof x === 'number' ? x - y : String(x).localeCompare(String(y));
      return st.desc ? -d : d;
    });
    const trs = sorted.map((r) => {
      const tr = el('tr');
      for (const c of cols) {
        const v = r[c.key];
        const missing = v === undefined || v === null || (typeof v === 'number' && !Number.isFinite(v));
        const text = c.fmt ? c.fmt(v, r) : missing ? '—' : String(v);
        const td = el('td', `${c.num ? 'n' : ''} ${missing && !c.fmt ? 'na' : ''} ${c.cls ? c.cls(r) : ''}`, text);
        td.title = c.title ? c.title(r) : text;
        tr.appendChild(td);
      }
      if (st.onRow) {
        // keep table semantics: the row is clickable by mouse, and a real button in the first cell serves keyboard/AT
        const open = () => st.onRow(r);
        tr.classList.add('clickable');
        tr.addEventListener('click', open);
        const first = tr.firstChild;
        const b = el('button', 'cell-btn', first.textContent);
        b.type = 'button';
        b.setAttribute('aria-label', `details for ${cols.map((c) => tr.children[cols.indexOf(c)].textContent).slice(0, 3).join(' ')}`);
        b.addEventListener('click', (e) => { e.stopPropagation(); open(); });
        first.replaceChildren(b);
      }
      return tr;
    });
    if (!trs.length) {
      const tr = el('tr');
      const td = el('td', 'na', 'no data');
      td.colSpan = cols.length;
      tr.appendChild(td);
      trs.push(tr);
    }
    // live refresh must not steal keyboard focus from a row button
    const focused = tbody.contains(document.activeElement) ? document.activeElement.getAttribute('aria-label') : null;
    tbody.replaceChildren(...trs);
    if (focused) [...tbody.querySelectorAll('.cell-btn')].find((b) => b.getAttribute('aria-label') === focused)?.focus();
  }
  return {
    el: table,
    update(rows, onRow) { st.rows = rows; st.onRow = onRow || null; render(); },
  };
}

// ---- line chart -----------------------------------------------------------------------
// series: [{ name, color, points: [[tSec, v], ...] }]; gaps (> 2 steps) are drawn as breaks, never as 0.
export function lineChart(canvas, series, { t0, t1, step, unit = '' }) {
  const dpr = window.devicePixelRatio || 1;
  const w = (canvas.width = canvas.clientWidth * dpr);
  const h = (canvas.height = canvas.clientHeight * dpr);
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const padL = 56 * dpr, padB = 22 * dpr, padT = 8 * dpr, padR = 8 * dpr;
  const all = series.flatMap((s) => s.points.map((p) => p[1]));
  const vmax = Math.max(1, ...all) * 1.1;
  const x = (t) => padL + ((t - t0) / (t1 - t0)) * (w - padL - padR);
  const y = (v) => h - padB - (v / vmax) * (h - padB - padT);
  ctx.font = `${13 * dpr}px "IBM Plex Mono", monospace`;
  ctx.fillStyle = cssVar('--text-2');
  ctx.strokeStyle = cssVar('--frame');
  ctx.lineWidth = dpr;
  for (let i = 0; i <= 3; i++) {
    const v = (vmax / 3) * i;
    ctx.beginPath(); ctx.moveTo(padL, y(v)); ctx.lineTo(w - padR, y(v)); ctx.stroke();
    ctx.fillText(`${v >= 100 ? v.toFixed(0) : v.toFixed(1)}${unit}`, 4 * dpr, y(v) + 4 * dpr);
  }
  for (let i = 0; i <= 4; i++) {
    const t = t0 + ((t1 - t0) / 4) * i;
    const label = jstHm.format(new Date(t * 1000));
    ctx.fillText(label, Math.min(x(t) - 18 * dpr, w - 44 * dpr), h - 5 * dpr);
  }
  for (const s of series) {
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2 * dpr;
    ctx.beginPath();
    s.points.forEach(([t, v], i) => {
      const gap = i === 0 || t - s.points[i - 1][0] > step * 2;
      if (gap) ctx.moveTo(x(t), y(v)); else ctx.lineTo(x(t), y(v));
    });
    ctx.stroke();
  }
}
export function legend(series) {
  const d = el('div', 'legend-row');
  for (const s of series) {
    const i = el('span', 'lg');
    const sw = el('i');
    sw.style.background = s.color;
    i.append(sw, document.createTextNode(s.name));
    d.appendChild(i);
  }
  return d;
}
export function chartColors() {
  return [cssVar('--spark-1'), cssVar('--spark-2'), cssVar('--warn'), cssVar('--ok'), cssVar('--crit'), cssVar('--unknown')];
}
