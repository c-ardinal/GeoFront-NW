// 原因候補 (P5): what else happened around a moment (an alert, a traffic surge, a chosen time), from mask-api's
// read-only /correlate/events (masked like every other read). Always labelled as correlation CANDIDATES, never causes;
// the ordering rules come with the answer and are shown. Every item leads to its detail, to packet analysis (P3, the
// window's time and the item's host / destination) and to the evidence export (P4, the window).
// Also the traffic surge list (急増): Prometheus' surge recording rules (thresholds from .env, /obs/config.json).
import { el, jstClock, jstFull, now, isPlayback, maskText, fixed, badge, has } from './util.js';
import { fetchWithTimeout } from './api.js';
import { section, rangeSelect, dataView, listSection, putIn, tiles } from './views-common.js';
import { DEVICES, WAN } from './panels.js';
import { downloadEvidence, snapshotGate } from './evidence.js';

const HALVES = [['±5 分', 300], ['±10 分', 600], ['±30 分', 1800]];
const REFRESH_MS = 60000; // a live window still open at its end: asked again at most once a minute
const PB_REFETCH_MS = 10000; // playback: the window's end follows the cursor; asked again at most this often
const STEP_S = 30; // the server's evaluation step: an event may sit up to one step after the window's end
const KIND = {
  alert: (i) => (i.state === 'resolved' ? ['ok', '解消'] : ['crit', '発火']),
  device: (i) => (i.state === 'DOWN' ? ['crit', 'DOWN'] : ['ok', 'UP']),
  ifstate: (i) => (/DOWN/.test(i.state) ? ['crit', 'IF DOWN'] : ['ok', 'IF UP']),
  iferr: () => ['warn', 'IF エラー'],
  surge: () => ['warn', '急増'],
  syslog: (i) => (['emergency', 'alert', 'critical', 'error'].includes(i.sev) ? ['crit', i.sev === 'error' ? 'ERROR' : 'CRIT'] : ['warn', 'WARN']),
  notify: () => ['info', '通知'],
};
const REL = { 3: ['rel-hi', '関連 高'], 2: ['rel-mid', '関連 中'], 0: ['rel-lo', '同時期'] };
const toInput = (ms) => { const d = new Date(ms + 9 * 3600e3); return d.toISOString().slice(0, 16); };
const fromInput = (v) => (v ? Date.parse(`${v}:00+09:00`) : NaN);
const dtText = (s) => { const a = Math.abs(s); const t = a < 60 ? `${Math.round(a)}s` : `${Math.floor(a / 60)}m${String(Math.round(a % 60)).padStart(2, '0')}s`; return `${s < 0 ? '−' : '+'}${t}`; };

// Open 原因候補 views, clipped at once to a new playback position (main.js calls clipToCursor from the cursor setter):
// nothing after the cursor is ever on screen, whether or not a refetch is still in flight or has failed.
const VIEWS = new Set();
export function clipToCursor() {
  for (const v of VIEWS) if (!v.alive()) VIEWS.delete(v); else v.clip();
}

// anchor: { at: ms, label, ctx: { instance, ifName, host, cc, asn, alertname } }
export function correlateView(anchor) {
  const st = { at: anchor.at, half: 600, sort: 'rel', key: '', got: 0, data: null, seq: 0 };
  let s, lastCtx = null;
  // PLAYBACK: never past the cursor; live: never in the future. outside: the cursor is before the window's start
  const windowOf = () => {
    const end = now();
    const w = { from: st.at / 1000 - st.half, to: Math.min(end, st.at + st.half * 1000) / 1000, capped: st.at + st.half * 1000 > end };
    return { ...w, outside: w.to <= w.from };
  };
  async function load(force) {
    const w = windowOf();
    if (w.outside) return; // nothing to ask (and never a window that ends before it starts)
    const ctx = { ...anchor.ctx, ...(WAN.instance ? { wan_instance: WAN.instance, wan_ifName: WAN.ifName } : {}) };
    const q = new URLSearchParams(Object.entries({ at: (Math.min(st.at, w.to * 1000) / 1000).toFixed(3), from: w.from.toFixed(3), to: w.to.toFixed(3), ...ctx })
      .filter(([, v]) => v !== undefined && v !== null && v !== ''));
    const key = `${q.get('at')}|${st.half}|${JSON.stringify(anchor.ctx)}`;
    const toKey = Math.floor(w.to / STEP_S);
    const open = !isPlayback() && w.capped; // the window still reaches "now": new events may come in
    const moved = isPlayback() && key === st.key && toKey !== st.toKey; // the playback cursor moved inside the window (its end follows)
    const since = performance.now() - st.got;
    if (!force && key === st.key && !moved && !(open && since > REFRESH_MS)) return;
    if (!force && moved && since < PB_REFETCH_MS) return; // meanwhile render() hides what lies after the cursor
    st.key = key;
    st.toKey = toKey;
    const my = ++st.seq;
    s.status.textContent = '集めています…';
    try {
      const r = await fetchWithTimeout(`/correlate/events?${q}`, {}, 30000);
      const j = await r.json().catch(() => null);
      if (my !== st.seq) return;
      if (!r.ok || j?.status !== 'success') throw new Error(j?.error || `HTTP ${r.status}`);
      st.data = { ...j.data, capped: w.capped };
      st.got = performance.now();
    } catch (e) {
      if (my === st.seq) st.key = ''; // asked again on the next refresh (a transient failure does not stick)
      throw e;
    }
  }
  function itemRow(i, nav, win) {
    const row = el('div', `cr-item rel-${i.score}`);
    const [kk, kt] = (KIND[i.kind] || (() => ['none', i.kind]))(i);
    const [rc, rt] = REL[i.score] || REL[0];
    const head = el('div', 'cr-h');
    const t = el('span', 'cr-t', jstClock.format(new Date(i.t * 1000)));
    t.title = `${jstFull.format(new Date(i.t * 1000))} JST`;
    head.append(t, el('span', 'cr-dt', dtText(i.dt)), badge(kk, kt), el('span', `cr-rel ${rc}`, rt));
    const title = el('div', `cr-title ${i.kind === 'syslog' ? 'mono' : ''}`, maskText(String(i.title)));
    const why = el('div', 'cr-why', `関連: ${(i.why || []).join(' · ')}${i.before ? ' · 窓の開始時点で既に続いていた' : ''}`);
    const acts = el('div', 'cr-acts');
    // focus keys: a refreshed answer gives keyboard focus back to the same button of the same event
    const btn = (text, fn, label) => { const b = el('button', 'link-btn', text); b.type = 'button'; b.setAttribute('aria-label', label); b.dataset.fkey = `${text}|${i.kind}|${i.t}|${i.title}`; b.addEventListener('click', fn); acts.append(b); };
    const detail = detailOf(i, nav);
    if (detail) btn('詳細', detail, `details: ${i.title}`);
    btn('解析', () => nav.packets({ ...(i.kind === 'surge' ? { src: i.host } : {}), since: win.from, until: win.to }), `packet analysis around ${kt}`);
    btn('証跡', (e) => downloadEvidence({ ...evidenceScope(i), from: win.from.toFixed(3), to: win.to.toFixed(3) }, e.currentTarget, s.evStatus, { snapshot: s.snap.checked }), `export evidence of the window for ${kt}`);
    row.append(head, title, why, acts);
    return row;
  }
  function renderOutside(nav, w) {
    const cur = now();
    putIn(s.sum, tiles([
      { label: '基準時刻 (JST)', value: jstFull.format(new Date(st.at)) },
      { label: '窓', value: `${jstClock.format(new Date(w.from * 1000))}–${jstClock.format(new Date(st.at + st.half * 1000))}` },
      { label: '再生位置', value: jstClock.format(new Date(cur)), kind: 'warn', status: '窓の開始より前' },
    ]));
    const msg = el('p', 'na', `再生位置 (${jstClock.format(new Date(cur))}) はこの窓の開始より前です。再生位置より後の出来事は表示しません。`);
    const b = el('button', 'link-btn ops-btn', '再生位置を基準に開き直す');
    b.type = 'button';
    b.lang = 'ja';
    b.dataset.fkey = 'reanchor';
    b.addEventListener('click', () => { st.at = now(); st.key = ''; st.data = null; if (lastCtx) view.update(lastCtx).catch(() => {}); });
    putIn(s.list.body, msg, b);
    s.partial.textContent = '';
    s.status.textContent = '窓の外';
  }
  function render(nav, force = false) {
    if (!s) return;
    const d = st.data;
    const w = windowOf();
    // never an event after the playback cursor, also between two answers (live: the last step may end just after "now")
    const cur = w.to;
    const lim = isPlayback() ? cur : cur + STEP_S;
    const sig = `${st.sort}|${Math.round(lim * 1000)}|${w.outside}`; // ms: a sub-second seek back re-clips too
    if (!force && st.shown === d && st.shownSig === sig) return; // polls in between: nothing new to draw
    st.shown = d;
    st.shownSig = sig;
    if (w.outside) { renderOutside(nav, w); return; }
    if (!d) return;
    const shown = d.items.filter((i) => i.t <= lim);
    const items = st.sort === 'time' ? [...shown].sort((a, b) => a.t - b.t) : shown;
    const win = { from: d.window.from, to: Math.min(d.window.to, cur) }; // analysis / evidence: never past the cursor either
    const n = (k) => shown.filter((i) => i.score === k).length;
    putIn(s.sum, tiles([
      { label: '基準時刻 (JST)', value: jstFull.format(new Date(d.window.at * 1000)) },
      { label: '窓', value: `${jstClock.format(new Date(win.from * 1000))}–${jstClock.format(new Date(win.to * 1000))}`, sub: d.capped ? (isPlayback() ? '再生位置より後は含めません' : '現在より後はまだありません') : undefined },
      { label: '関連 高', value: n(3), d: 0, kind: n(3) ? 'warn' : 'none' },
      { label: '関連 中', value: n(2), d: 0 },
      { label: '同時期', value: n(0), d: 0 },
    ]));
    const list = items.length ? items.map((i) => itemRow(i, nav, win)) : [el('p', 'na', 'この窓に該当する出来事はありません')];
    if (d.truncated) list.push(el('p', 'v-meta-line', `上限 ${d.items.length} 件まで表示 (全 ${d.total} 件)`));
    putIn(s.list.body, ...list);
    s.rules.replaceChildren(...d.rules.map((r) => el('li', '', r)));
    s.partial.textContent = d.partial.length ? `一部の取得に失敗 (その分は欠けています): ${d.partial.map(maskText).join(' / ')}` : '';
    s.status.textContent = `${d.total} 件`;
  }
  const view = {
    title: `原因候補 · ${anchor.label}`, src: 'both',
    mount(body) {
      const notice = el('p', 'cr-notice', '相関の候補です。時間が近い・同じ機器などの簡単な規則で並べたもので、原因と断定するものではありません。');
      notice.setAttribute('role', 'note');
      const ctl = el('div', 'filters cr-ctl');
      const fl = el('label', 'fld', '基準時刻 (JST)');
      const input = el('input');
      input.type = 'datetime-local';
      input.value = toInput(st.at);
      input.addEventListener('change', () => { const v = fromInput(input.value); if (Number.isFinite(v)) { st.at = Math.min(v, now()); refresh(); } });
      fl.append(input);
      const refresh = () => { st.key = ''; if (lastCtx) view.update(lastCtx).catch(() => {}); };
      ctl.append(fl, rangeSelect(HALVES, st.half, (v) => { st.half = v; refresh(); }, '時間窓'),
        rangeSelect([['関連度順', 'rel'], ['時刻順', 'time']], st.sort, (v) => { st.sort = v; if (lastCtx) render(lastCtx.nav); }, '並べ順'));
      const status = el('span', 'cr-status');
      status.setAttribute('role', 'status');
      ctl.append(status);
      const rulesBox = el('details', 'cr-rules');
      rulesBox.append(el('summary', '', '並べ方の規則'), el('ul'));
      const list = section('同じ時間窓の出来事', '時刻 JST · Δ = 基準時刻からの差 · IP/MAC masked');
      const partial = el('p', 'v-meta-line cr-partial');
      partial.setAttribute('role', 'status');
      const ev = section('この窓の証跡', 'evidence zip · masked · read-only');
      const evBtn = el('button', 'link-btn ops-btn', '窓全体の証跡を出力');
      evBtn.type = 'button';
      evBtn.lang = 'ja';
      const evStatus = el('p', 'ops-note ops-status');
      evStatus.setAttribute('role', 'status');
      evBtn.addEventListener('click', () => {
        const d = st.data;
        if (d) downloadEvidence({ scope: 'all', from: d.window.from.toFixed(3), to: Math.min(d.window.to, windowOf().to).toFixed(3) }, evBtn, evStatus, { snapshot: snap.checked });
      });
      // screen snapshot for this window's exports (and each item's 「証跡」): off by default, not remembered
      const snapL = el('label', 'fld chk');
      const snap = el('input');
      snap.type = 'checkbox';
      snapL.title = '画面のスナップショット (PNG) を含める: このブラウザで今の画面 (伏せ字済み) を画像にします。項目ごとの「証跡」にも使います';
      snapL.append(snap, document.createTextNode(' 画面の画像'));
      snapshotGate(snap, snapL);
      const evRow = el('div', 'filters ops');
      evRow.append(evBtn, snapL);
      ev.body.append(evRow, evStatus);
      s = { sum: el('div'), list, rules: rulesBox.querySelector('ul'), partial, status, evStatus, snap };
      body.append(notice, ctl, s.sum, rulesBox, partial, list.wrap, ev.wrap);
      VIEWS.add(handle);
      if (lastCtx) render(lastCtx.nav, true); // back / breadcrumb: the last answer at once (into the new body), clipped
    },
    async update(ctx) {
      lastCtx = ctx;
      render(ctx.nav); // first clip what is shown to the current cursor, before (and whatever comes of) the fetch
      try { await load(false); } catch (e) {
        render(ctx.nav, true);
        s.status.textContent = `取得できません: ${maskText(String(e.message || e))}`;
        throw e;
      }
      render(ctx.nav);
    },
  };
  const handle = { alive: () => !!s && s.list.body.isConnected, clip: () => { if (lastCtx) render(lastCtx.nav); } };
  return view;
}

function detailOf(i, nav) {
  const alertOf = () => ({ labels: i.labels, state: i.state === 'resolved' ? 'inactive' : 'firing', activeAt: new Date(i.t * 1000).toISOString(), annotations: {} });
  if ((i.kind === 'alert' || i.kind === 'notify') && i.labels?.alertname) return () => nav.alert(alertOf());
  if (i.kind === 'device' && DEVICES.includes(i.instance)) return () => nav.device(i.instance);
  if ((i.kind === 'ifstate' || i.kind === 'iferr') && i.instance && i.ifName) return () => nav.iface(`${i.instance}|${i.ifName}`);
  if (i.kind === 'surge' && i.host) return () => nav.src(i.host);
  if (i.kind === 'syslog') return () => nav.logline({ ts: i.ts, line: i.title, host: i.instance, sev: i.sev });
  return null;
}
function evidenceScope(i) {
  const L = i.labels || {};
  if ((i.kind === 'alert' || i.kind === 'notify') && L.alertname) return { scope: 'alert', alertname: L.alertname, instance: L.instance, ifName: L.ifName, severity: L.severity };
  if ((i.kind === 'ifstate' || i.kind === 'iferr') && DEVICES.includes(i.instance) && i.ifName) return { scope: 'iface', instance: i.instance, ifName: i.ifName };
  if (DEVICES.includes(i.instance)) return { scope: 'device', instance: i.instance };
  if (i.kind === 'surge' && i.host) return { scope: 'src', host: i.host };
  return { scope: 'all' };
}

// ---- traffic surges (modal) --------------------------------------------------------------------------------------
export const SURGE = { factor: 3, min_kbps: 200, baseline: '1h' };
export function setSurgeConfig(c) {
  if (c && typeof c === 'object') for (const k of Object.keys(SURGE)) if (c[k] !== undefined) SURGE[k] = c[k];
}
export const surgeRule = () => `直近 5 分の通信量が ${SURGE.min_kbps} kbps 以上で、平常 (${SURGE.baseline} の中央値、5 分前まで) の ${SURGE.factor} 倍を超えた端末 × 通信先 (国 / ASN)`;
// Prometheus results -> [{ host, cc, asn, ratio, bps, base }]
export function surgeRows(ratio, bps, base) {
  const key = (m) => `${m.src_host}|${m.dst_country}|${m.asn}`;
  const b = new Map(bps.map((r) => [key(r.metric), Number(r.value[1])]));
  const a = new Map(base.map((r) => [key(r.metric), Number(r.value[1])]));
  return ratio.map((r) => ({ host: r.metric.src_host || '?', cc: r.metric.dst_country || 'Unknown', asn: r.metric.asn || '', ratio: Number(r.value[1]),
    bps: b.get(key(r.metric)), base: a.get(key(r.metric)) })).sort((x, y) => y.ratio - x.ratio);
}
export function surgeModal() {
  const dv = dataView('surges', [
    { key: 'host', label: '端末' }, { key: 'cc', label: '通信先 (国)' }, { key: 'asn', label: 'ASN', fmt: (v) => v || '—' },
    { key: 'mbps', label: '直近 5 分 Mbps', num: true, fmt: (v) => fixed(v, 2) }, { key: 'baseMbps', label: '平常 Mbps', num: true, fmt: (v) => fixed(v, 2) },
    { key: 'ratio', label: '倍率', num: true, fmt: (v) => (has(v) ? `×${fixed(v, 1)}` : '—') },
  ], { key: 'ratio', desc: true }, (r) => ({ title: `${r.host} → ${r.cc}`, sub: r.asn, badge: ['warn', '急増'], fields: [['直近 5 分', fixed(r.mbps, 2), 'Mbps'], ['平常', fixed(r.baseMbps, 2), 'Mbps'], ['倍率', `×${fixed(r.ratio, 1)}`]] }),
  (r) => `${r.host}|${r.cc}|${r.asn}`);
  let s;
  return {
    title: '急増 (端末 × 通信先)', src: 'prom',
    mount(body) {
      s = { sum: el('div'), rule: el('p', 'v-p'), list: listSection('急増中', '行を選ぶと、その前後の原因候補を開きます', dv) };
      body.append(s.sum, s.rule, s.list.wrap);
    },
    async update(ctx) {
      const sn = ctx.snap;
      const rows = (sn.surges || []).map((r) => ({ ...r, mbps: has(r.bps) ? r.bps / 1e6 : undefined, baseMbps: has(r.base) ? r.base / 1e6 : undefined }));
      putIn(s.sum, tiles([
        { label: '急増中', value: sn.flowsOk ? rows.length : undefined, d: 0, kind: !sn.flowsOk ? 'unknown' : rows.length ? 'warn' : 'ok', status: !sn.flowsOk ? 'flow data unknown' : rows.length ? '下の一覧' : 'なし' },
        { label: '判定', value: `×${SURGE.factor}`, sub: `≥ ${SURGE.min_kbps} kbps · 平常 = ${SURGE.baseline} の中央値` },
      ]));
      s.rule.textContent = `判定: ${surgeRule()}。閾値は .env の SURGE_FACTOR / SURGE_MIN_KBPS / SURGE_BASELINE です。急増は「いつもより多い」ことだけを示し、問題があるとは限りません。`;
      dv.update(rows, (r) => ctx.nav.correlate({ at: now(), label: `急増 ${r.host} → ${r.cc}`, ctx: { host: r.host, cc: r.cc, asn: r.asn } }));
    },
  };
}
