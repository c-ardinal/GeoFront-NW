// ログ検索 (F1): syslog lines by device / severity / facility / keyword (or a restricted regex) over a window up to the
// Loki retention, through mask-api /logsearch/ (LogQL built there from these values only; the keyword is matched on the
// masked lines). Newest first, one page at a time, the matches marked; lines per time bucket as a small histogram
// (select a bar to narrow the window to it). A selected line leads to its detail, 原因候補 and the evidence export.
// PLAYBACK: the window ends at the cursor when the search runs.
import { el, now, jstFull, sevName, maskText } from './util.js';
import { getJson } from './api.js';
import { DEVICES } from './panels.js';
import { section, linkBtn } from './views-common.js';
import { rangeControl, windowOf, spanText } from './views-trend.js';
import { downloadEvidence } from './evidence.js';

const SVGNS = 'http://www.w3.org/2000/svg';
const PAGE = 100;
const PRESETS = [['15m', 900], ['1h', 3600], ['6h', 6 * 3600], ['24h', 86400], ['7d', 7 * 86400], ['30d', 30 * 86400]];
const AROUND_S = 600; // evidence: ±10 min around the selected line

let facetsP = null;
const facets = () => (facetsP ??= getJson('/logsearch/facets').catch((e) => { facetsP = null; throw e; }));

const lineText = (e) => e.parts.map((p) => p[0]).join('');
const idOf = (e) => `${e.ts}|${e.host}|${lineText(e)}`;
const msOf = (ts) => Number(BigInt(ts) / 1000000n);

function histogram(h, onPick) {
  const wrap = el('div', 'ls-hist');
  const n = h.counts.length;
  const max = Math.max(1, ...h.counts);
  const w = 600, ht = 64;
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${w} ${ht}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('class', 'ls-svg');
  svg.setAttribute('aria-hidden', 'true');
  const bars = h.counts.map((c, i) => {
    const r = document.createElementNS(SVGNS, 'rect');
    const bh = c ? Math.max(2, (c / max) * (ht - 2)) : 0;
    r.setAttribute('x', String((i * w) / n + 0.5));
    r.setAttribute('width', String(Math.max(1, w / n - 1)));
    r.setAttribute('y', String(ht - bh));
    r.setAttribute('height', String(bh));
    r.setAttribute('class', 'ls-col');
    svg.append(r);
    return r;
  });
  const box = el('div', 'ls-hbox');
  box.tabIndex = 0;
  box.setAttribute('role', 'slider');
  box.setAttribute('aria-valuemin', '0');
  box.setAttribute('aria-valuemax', String(n - 1));
  const total = h.counts.reduce((a, b) => a + b, 0);
  box.setAttribute('aria-label', `時間ごとの件数 (${h.step / 60} 分ごと、${n} 本、合計 ${total} 件)。← → で棒を選び、Enter でその時間に絞ります`);
  const tip = el('div', 'ls-tip', ' ');
  tip.setAttribute('aria-live', 'polite');
  let cur = -1;
  const t0Of = (i) => h.from + i * h.step;
  const pick = (i) => {
    cur = Math.max(0, Math.min(n - 1, i));
    bars.forEach((b, j) => b.classList.toggle('ls-cur', j === cur));
    box.setAttribute('aria-valuenow', String(cur));
    const a = t0Of(cur), b = Math.min(h.to, a + h.step);
    tip.textContent = `${jstFull.format(new Date(a * 1000))} 〜 ${jstFull.format(new Date(b * 1000)).slice(-8)}  ${h.counts[cur]} 件 (押すかEnterでこの時間に絞る)`;
    box.setAttribute('aria-valuetext', tip.textContent);
  };
  const narrow = () => { if (cur >= 0) onPick(t0Of(cur) * 1000, Math.min(h.to, t0Of(cur) + h.step) * 1000); };
  box.addEventListener('pointermove', (e) => pick(Math.floor((e.offsetX / box.clientWidth) * n)));
  box.addEventListener('click', (e) => { pick(Math.floor((e.offsetX / box.clientWidth) * n)); narrow(); });
  box.addEventListener('keydown', (e) => {
    const k = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity }[e.key];
    if (k !== undefined) { e.preventDefault(); pick(Number.isFinite(k) ? (cur < 0 ? n - 1 : cur + k) : k < 0 ? 0 : n - 1); }
    else if (e.key === 'Enter') { e.preventDefault(); narrow(); }
  });
  box.append(svg);
  const axis = el('div', 'ls-axis');
  axis.append(el('span', '', jstFull.format(new Date(h.from * 1000)).slice(0, 11)), el('span', '', `最大 ${max} 件 / ${spanText(h.step)}`), el('span', '', jstFull.format(new Date(h.to * 1000)).slice(0, 11)));
  wrap.append(box, axis, tip);
  return wrap;
}

// init: { host, severity, facility, q, regex, preset (seconds) }
export function logSearchView(init = {}) {
  const f = { host: init.host || '', severity: init.severity || '', facility: '', q: init.q || '', regex: !!init.regex };
  const st = { preset: init.preset || 3600, from: 0, to: 0, zoom: [], entries: [], next: null, seq: 0, sel: null, ran: false, at: null };
  let s = {}, ctxRef = null, retention = 30 * 86400, range;

  // the window and the filter of the running search (st.at, st.f): its next pages ask exactly the same, whatever the form
  // says by then
  const query = (extra = {}) => {
    const w = st.at, q = st.f;
    const p = { from: (w.from / 1000).toFixed(3), to: (w.to / 1000).toFixed(3), ...extra };
    for (const k of ['host', 'severity', 'facility', 'q']) if (q[k]) p[k] = q[k];
    if (q.q && q.regex) p.regex = '1';
    return new URLSearchParams(p).toString();
  };
  async function search() {
    st.at = windowOf(st); // fixed for this search and its next pages (PLAYBACK: ends at the cursor now)
    st.f = { ...f };
    st.entries = [];
    st.next = null;
    st.sel = null;
    st.ran = true;
    const my = ++st.seq;
    s.count.textContent = '検索中…';
    s.more.hidden = true;
    s.list.replaceChildren();
    s.hist.replaceChildren(el('div', 'ls-hwait', '件数を数えています…'));
    renderSel();
    const lines = getJson(`/logsearch/lines?${query({ limit: PAGE })}`).then((d) => { if (my === st.seq) addPage(d); })
      .catch((e) => { if (my === st.seq) failed(e); });
    const hist = getJson(`/logsearch/hist?${query()}`).then((h) => {
      if (my !== st.seq) return;
      const note = h.partial.length ? el('p', 'ls-partial', `新しい側から数えた途中までの件数です (${h.counted_from ? `${jstFull.format(new Date(h.counted_from * 1000))} より前は少なく出ています` : '古い側は少なく出ています'})`) : null;
      s.hist.replaceChildren(histogram(h, (a, b) => { st.zoom = []; Object.assign(st, { preset: 'custom', from: a, to: b }); range.mark('custom'); search(); }), ...(note ? [note] : []));
    }).catch((e) => { if (my === st.seq) s.hist.replaceChildren(el('div', 'ls-hwait', `件数を数えられません: ${maskText(e.message)}`)); });
    await Promise.all([lines, hist]);
  }
  async function older() {
    if (!st.next) return;
    const my = st.seq;
    s.more.disabled = true;
    try {
      const d = await getJson(`/logsearch/lines?${query({ limit: PAGE, before: st.next })}`);
      if (my === st.seq) addPage(d);
    } catch (e) {
      if (my === st.seq) s.count.textContent = `${s.count.textContent} · 続きを読めません: ${maskText(e.message)}`;
    } finally {
      s.more.disabled = false;
    }
  }
  function failed(e) {
    s.count.textContent = e.rejected ? `この条件では検索できません: ${maskText(e.message)}` : `検索できません: ${maskText(e.message)}`;
    s.list.replaceChildren(el('div', 'na', '—'));
  }
  function addPage(d) {
    const have = new Set(st.entries.map(idOf));
    const fresh = d.entries.filter((e) => !have.has(idOf(e)));
    st.entries.push(...fresh);
    st.next = d.next_before;
    s.list.append(...fresh.map(row));
    if (!st.entries.length) s.list.replaceChildren(el('div', 'na', st.next ? 'ここまでに一致する行はありません。続きを読むと、さらに古い側を探します' : '一致する行はありません'));
    const w = st.at;
    s.count.textContent = `${st.entries.length} 行 (新しい順) · ${jstFull.format(new Date(w.from))} 〜 ${jstFull.format(new Date(w.to))}`
      + (st.next ? '' : ' · 期間の最後まで読みました') + (d.partial.length ? ` · 途中で止めました (${d.partial.join(', ')})` : '');
    s.more.hidden = !st.next;
  }
  function row(e) {
    const r = el('div', `log ls-row sev-${e.severity}`);
    r.tabIndex = 0;
    r.setAttribute('role', 'button');
    const t = jstFull.format(new Date(msOf(e.ts)));
    const m = el('span', 'log-m');
    for (const [text, hit] of e.parts) m.append(hit ? el('mark', 'ls-hit', text) : document.createTextNode(text));
    r.append(el('span', 'ls-t', t), el('span', 'log-h', e.host), el('span', 'log-s', sevName(e.severity)), m);
    r.setAttribute('aria-label', `${t} ${e.host} ${sevName(e.severity)} ${lineText(e)}。選ぶと原因候補と証跡に進めます`);
    const choose = () => { st.sel = e; for (const x of s.list.children) x.classList.toggle('ls-sel', x === r); renderSel(); };
    r.addEventListener('click', choose);
    r.addEventListener('keydown', (k) => { if (k.key === 'Enter' || k.key === ' ') { k.preventDefault(); choose(); } });
    return r;
  }
  function renderSel() {
    const e = st.sel;
    s.selBar.hidden = !e;
    if (!e) return;
    const ms = msOf(e.ts);
    s.selText.textContent = `選択: ${jstFull.format(new Date(ms))} ${e.host}`;
  }

  function act(kind) {
    const e = st.sel;
    if (!e || !ctxRef) return;
    const ms = msOf(e.ts);
    const line = { ts: e.ts, host: e.host, sev: e.severity, line: lineText(e) };
    if (kind === 'detail') ctxRef.nav.logline(line);
    if (kind === 'corr') ctxRef.nav.correlate({ at: ms, label: `syslog ${e.host} ${jstFull.format(new Date(ms))}`, ctx: e.host && e.host !== 'unknown' ? { host: e.host, instance: e.host } : {} });
    if (kind === 'evidence') {
      const to = Math.min(now(), ms + AROUND_S * 1000) / 1000, from = ms / 1000 - AROUND_S;
      const scope = DEVICES.includes(e.host) ? { scope: 'device', instance: e.host } : { scope: 'all' };
      downloadEvidence({ ...scope, from: from.toFixed(3), to: to.toFixed(3) }, s.evBtn, s.evStatus);
    }
  }

  const selectEl = (label, opts, key) => {
    const l = el('label', 'fld', label);
    const c = el('select');
    for (const [t, v] of opts) { const o = el('option', '', t); o.value = v; o.selected = v === f[key]; c.append(o); }
    c.addEventListener('change', () => { f[key] = c.value; });
    l.append(c);
    return { l, c };
  };
  return {
    title: 'ログ検索', src: 'loki',
    mount(body) {
      const form = el('form', 'filters ls-bar');
      form.addEventListener('submit', (e) => { e.preventDefault(); st.zoom = []; search().catch(() => {}); });
      const hosts = [...new Set([...DEVICES, ...(f.host ? [f.host] : [])])];
      const dev = selectEl('機器', [['すべて', ''], ...hosts.map((d) => [d, d]), ['台帳にない送信元 (unknown)', 'unknown']], 'host');
      const sev = selectEl('重要度', [['すべて', ''], ...['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'informational', 'debug'].map((v) => [sevName(v), v])], 'severity');
      s.fac = selectEl('facility', [['すべて', '']], 'facility');
      const ql = el('label', 'fld ls-q', '語句 (大文字と小文字は区別しません)');
      const qi = el('input');
      qi.type = 'search';
      qi.value = f.q;
      qi.maxLength = 128;
      qi.placeholder = '例 Rejected、203.0.113.x';
      qi.addEventListener('input', () => { f.q = qi.value; });
      ql.append(qi);
      const rl = el('label', 'fld chk');
      const ri = el('input');
      ri.type = 'checkbox';
      ri.checked = f.regex;
      ri.addEventListener('change', () => { f.regex = ri.checked; });
      rl.append(ri, document.createTextNode(' 正規表現'));
      rl.title = '64 文字まで。繰り返しの入れ子、先読み・後読み、後方参照は使えません。長さの決まらない繰り返し (* + {m,n}) は 1 か所まで。? はそれと一緒なら 1 か所、なければ 4 か所まで';
      const go = el('button', 'link-btn ls-go', '検索');
      go.type = 'submit';
      form.append(dev.l, sev.l, s.fac.l, ql, rl, go);
      range = rangeControl(st, { presets: PRESETS, maxS: () => retention, onChange: () => { st.zoom = []; search().catch(() => {}); } });
      const hs = section('時間ごとの件数', '同じ条件 · 棒を選ぶとその時間に絞ります');
      s.hist = el('div');
      hs.body.append(s.hist);
      const ls = section('行', '新しい順 · 一致した部分に印 · IP/MAC は伏せ字');
      s.count = el('div', 'v-meta-line');
      s.count.setAttribute('role', 'status');
      s.selBar = el('div', 'filters ops ls-selbar');
      s.selText = el('span', 'ls-seltext');
      s.evBtn = linkBtn('前後 10 分の証跡を出力', () => act('evidence'));
      s.evStatus = el('p', 'ops-note ops-status');
      s.evStatus.setAttribute('role', 'status');
      s.selBar.append(s.selText, linkBtn('この行の詳細', () => act('detail')), linkBtn('この時刻の原因候補', () => act('corr')), s.evBtn);
      s.selBar.hidden = true;
      s.list = el('div', 'v-logs tall ls-list');
      s.more = linkBtn('さらに古い行を読む', () => older());
      s.more.hidden = true;
      ls.body.append(s.count, s.selBar, s.evStatus, s.list, s.more);
      body.append(form, range.wrap, hs.wrap, ls.wrap);
      facets().then((d) => {
        retention = d.retention_s || retention;
        for (const v of d.facilities) { const o = el('option', '', v); o.value = v; s.fac.c.append(o); }
        s.fac.l.hidden = !d.facilities.length; // nothing parsed: no empty filter
      }).catch(() => { s.fac.l.hidden = true; });
    },
    async update(ctx) {
      ctxRef = ctx;
      if (!st.ran) await search(); // the first search on open; later ones only when asked (a search is not polled)
    },
  };
}
