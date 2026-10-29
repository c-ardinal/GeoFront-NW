// Detail drawer views: device, interface, destination, source host, alert, syslog line, collection job.
// Each drawer reads top-down: summary tiles -> charts / relation bars -> detail lists.
import { el, has, fixed, fmtUptime, fmtDur, maskIp, maskText, jstFull, upState, now, isPlayback } from './util.js';
import { lokiLogs, promRules } from './api.js';
import { DEVICES, byKey, totalBps, ifaceRows, logRow, sevKind, FLOW_TEXT, isWlx, lastSeen, fmtSeen, seenKind } from './panels.js';
import {
  section, kv, linkList, chartBlock, drawRange, fetchRange, mbps, lv, putIn, tiles, vsAvg, rankBars, keyLegend, timeline, alertLanes, alertKey,
  ALERT_KEYS, stackCols, SEV_KEYS, SEV_BAD, sevBuckets, multiples, seriesBy, maxOf, ipTokens, DIR_KEYS, IO_KEYS, dirSegs, pct, shareText, SNMP_UP, FLOWS_UP, FLOWS_DOWN, flowsMissing,
} from './views-common.js';
import { alertOpsSection } from './alerting.js';
import { evidenceSection } from './evidence.js';

const HOUR = 3600;
const nsOf = (ms) => BigInt(Math.round(ms)) * 1000000n;
const min = (a, b) => (a < b ? a : b); // BigInt-safe
const errKind = (v) => (has(v) ? (v > 0 ? 'warn' : 'ok') : 'unknown');
const errStatus = (v) => (has(v) ? (v > 0 ? 'errors seen' : 'none') : 'unknown');
// tile spark from one series of a fetched range (qi = query index)
const sparkOf = (r, qi, cls) => (r ? { series: [{ points: r.series.find((s) => s.qi === qi)?.points || [], cls }], t0: r.t0, t1: r.t1, step: r.step } : null);
const pointsOf = (r, qi) => r?.series.find((s) => s.qi === qi)?.points;

// res: lokiLogs() result; a partial scan or server warnings are stated under the list (never silently short)
function logList(host, entries, nav, markTs, res) {
  const box = el('div', 'v-logs');
  for (const e of entries) {
    const r = logRow(e, nav.logline);
    if (markTs && e.ts === markTs) r.classList.add('log-mark');
    box.appendChild(r);
  }
  const partial = res?.scannedUntil != null;
  if (!entries.length) box.appendChild(el('div', 'na', partial ? `no syslog lines from ${host} in the part scanned so far — more may exist` : `no syslog lines from ${host} in window`));
  const notes = [];
  if (partial) notes.push(`partial scan — more lines may exist (scanned to ${jstFull.format(new Date(Number(BigInt(res.scannedUntil) / 1000000n)))} JST)`);
  if (res?.warnings.length) notes.push(res.warnings.map((w) => maskText(w)).join(' · '));
  if (!notes.length) return box;
  const wrap = el('div');
  const note = el('div', 'v-meta-line scan-note', notes.join(' · '));
  note.setAttribute('role', 'status');
  wrap.append(note, box);
  return wrap;
}
const sevChart = (r, label, mark) => stackCols(r.cols, SEV_KEYS, r.t0, r.t1, label, mark, r.warnings, r.edge);

// "推移を見る" / "ログを検索" (F1): the same item over a longer window, in the 推移 / ログ検索 views
let lastNav = null;
const nav = () => lastNav;
function deepSection(items) {
  const s = section('長い期間で見る', '推移 · ログ検索 · 伏せ字のまま');
  const row = el('div', 'filters ops');
  for (const [text, open] of items) {
    const b = el('button', 'link-btn ops-btn', text);
    b.type = 'button';
    b.lang = 'ja';
    b.addEventListener('click', () => { if (nav()) open(nav()); });
    row.append(b);
  }
  s.body.append(row);
  return s;
}

// ---- device ------------------------------------------------------------------------------
export function deviceView(name) {
  let s, lastR = null;
  const chart = chartBlock(), mtok = {}, stok = {};
  return {
    title: `Device ${name.toUpperCase()}`, src: 'both',
    mount(body) {
      s = { sum: el('div'), chart: section('Traffic, last 1 h', 'sum of all interfaces, Mbps'), ifs: section('Interfaces, last 1 h', 'Mbps · same y-scale · click for details'),
        alerts: section('Related firing alerts'), sev: section('Syslog volume, last 1 h', 'lines by severity · empty column = 0 lines'), logs: section('Syslog', `last 50 lines from ${name}`) };
      s.chart.body.append(chart.wrap);
      s.ifBox = el('div');
      s.ifs.body.append(s.ifBox, keyLegend(IO_KEYS));
      body.append(s.sum, s.chart.wrap, s.ifs.wrap, s.alerts.wrap, s.sev.wrap, s.logs.wrap,
        deepSection([['推移を見る', (n) => n.trend({ family: 'if_bps', instance: name })], ['ログを検索', (n) => n.logsearch({ host: name })]]).wrap,
        evidenceSection(() => ({ scope: 'device', instance: name })).wrap);
    },
    async update(ctx) {
      lastNav = ctx.nav;
      const { m } = ctx.snap;
      const [kind, text] = upState(m.up.get(name));
      const isUp = m.up.get(name) === 1;
      const rel = ctx.snap.alerts.filter((a) => a.state === 'firing' && a.labels.instance === name);
      const err = m.devErr.get(name);
      const sum = () => putIn(s.sum, tiles([
        { label: 'Status', value: text, kind, status: isUp ? 'SNMP answering' : 'no current SNMP data' },
        { label: 'Uptime', value: isUp && has(m.uptime.get(name)) ? fmtUptime(m.uptime.get(name)) : undefined },
        { label: 'Last seen', value: has(lastSeen(m, name)) ? fmtSeen(lastSeen(m, name)) : undefined, kind: seenKind(lastSeen(m, name)), status: 'last successful SNMP scrape' },
        { label: 'Traffic ↓ (sum)', value: m.devIn.get(name), unit: 'Mbps', sub: vsAvg(pointsOf(lastR, 0), 1) && `1 h ${vsAvg(pointsOf(lastR, 0), 1)}`, spark: sparkOf(lastR, 0, 'sp-1') },
        { label: 'Traffic ↑ (sum)', value: m.devOut.get(name), unit: 'Mbps', sub: vsAvg(pointsOf(lastR, 1), 1) && `1 h ${vsAvg(pointsOf(lastR, 1), 1)}`, spark: sparkOf(lastR, 1, 'sp-2') },
        { label: 'Errors', value: err, unit: '/min', kind: errKind(err), status: errStatus(err) },
        { label: 'WLAN clients', value: isWlx(name) ? m.clients.get(name) : 'n/a', d: 0 },
        { label: 'Firing alerts', value: rel.length, d: 0, kind: rel.length ? 'crit' : 'ok', status: rel.length ? 'see below' : 'none' },
      ]));
      sum();
      const ifs = ifaceRows(m, ctx.seenIf).filter((r) => r.inst === name);
      putIn(s.alerts.body, linkList(rel.map((a) => [`${sevKind(a.labels.severity)[1]}  ${a.labels.alertname} ${a.labels.ifName || ''}`, () => ctx.nav.alert(a)])));
      const sel = `instance=${lv(name)},job="snmp"`;
      await Promise.all([
        drawRange(chart, [
          { q: `sum(rate(ifHCInOctets{${sel}}[$RATE]) ${SNMP_UP}) * 8 / 1e6`, name: () => '↓ in Mbps' },
          { q: `sum(rate(ifHCOutOctets{${sel}}[$RATE]) ${SNMP_UP}) * 8 / 1e6`, name: () => '↑ out Mbps' },
        ], HOUR, 'Mbps', `${name} traffic`).then((r) => { if (r) { lastR = r; sum(); } }),
        fetchRange(mtok, [{ q: `(rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => 'in' }, { q: `(rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => 'out' }], HOUR)
          .then((r) => {
            if (!r) return;
            const ins = seriesBy(r, 0, (mt) => mt.ifName), outs = seriesBy(r, 1, (mt) => mt.ifName);
            putIn(s.ifBox, multiples(ifs.map((x) => ({
              label: x.ifName, key: x.key, badge: [x.oper === 1 ? 'ok' : x.oper === 2 ? 'warn' : 'unknown', x.operText], onOpen: () => ctx.nav.iface(x.key),
              series: [{ points: ins.get(x.ifName) || [], cls: 'sp-1' }, { points: outs.get(x.ifName) || [], cls: 'sp-2' }],
              vals: [['↓', fixed(x.in), 'Mbps'], ['↑', fixed(x.out), 'Mbps'], ['util', fixed(x.util), '%']],
            })), { t0: r.t0, t1: r.t1, step: r.step, max: maxOf(ins, outs) }));
          }),
        sevBuckets(stok, `{job="syslog",host=${lv(name)}}`, HOUR).then((r) => { if (r) putIn(s.sev.body, sevChart(r, `${name} syslog lines per ${r.step / 60} min`)); }),
        lokiLogs(`{job="syslog",host=${lv(name)}}`, { startNs: String(nsOf(now() - HOUR * 1000)), endNs: String(nsOf(now())), limit: 50 })
          .then((res) => putIn(s.logs.body, logList(name, res.entries, ctx.nav, null, res))),
      ]);
    },
  };
}

// ---- interface ------------------------------------------------------------------------
export function ifaceView(key) {
  const [inst, ifName] = key.split('|');
  let s, lastR = null;
  const traffic = chartBlock(), errs = chartBlock('small');
  return {
    title: `Interface ${inst} ${ifName}`, src: 'prom',
    mount(body) {
      s = { sum: el('div'), t: section('Traffic, last 1 h', 'Mbps'), e: section('Errors, last 1 h', 'per minute'), info: section('Interface') };
      s.t.body.append(traffic.wrap);
      s.e.body.append(errs.wrap);
      body.append(s.sum, s.t.wrap, s.e.wrap, s.info.wrap,
        deepSection([['推移を見る', (n) => n.trend({ family: 'if_bps', instance: inst, ifName })], ['エラーの推移', (n) => n.trend({ family: 'if_errors', instance: inst, ifName })],
          ['ログを検索', (n) => n.logsearch({ host: inst, q: ifName })]]).wrap,
        evidenceSection(() => ({ scope: 'iface', instance: inst, ifName })).wrap);
    },
    async update(ctx) {
      lastNav = ctx.nav;
      const r = ifaceRows(ctx.snap.m, ctx.seenIf).find((x) => x.key === key) || { operText: 'UNKNOWN' };
      const operKind = r.oper === 1 ? 'ok' : r.oper === 2 ? 'warn' : 'unknown';
      const uKind = !has(r.util) ? 'unknown' : r.util >= 90 ? 'crit' : r.util >= 70 ? 'warn' : 'ok';
      const sum = () => putIn(s.sum, tiles([
        { label: 'Oper status', value: r.operText, kind: operKind, status: { ok: 'link up', warn: 'link down', unknown: 'no current data' }[operKind] },
        { label: '↓ in', value: r.in, unit: 'Mbps', sub: vsAvg(pointsOf(lastR, 0), 1) && `1 h ${vsAvg(pointsOf(lastR, 0), 1)}`, spark: sparkOf(lastR, 0, 'sp-1') },
        { label: '↑ out', value: r.out, unit: 'Mbps', sub: vsAvg(pointsOf(lastR, 1), 1) && `1 h ${vsAvg(pointsOf(lastR, 1), 1)}`, spark: sparkOf(lastR, 1, 'sp-2') },
        { label: 'Utilization', value: r.util, unit: '%', kind: uKind, status: { ok: 'headroom', warn: 'busy (≥ 70 %)', crit: 'saturated (≥ 90 %)', unknown: 'unknown' }[uKind], sub: 'max of in / out' },
        { label: 'Errors', value: r.err, unit: '/min', kind: errKind(r.err), status: errStatus(r.err) },
        { label: 'Speed', value: has(r.speed) ? String(r.speed) : undefined, unit: 'Mbps' },
      ]));
      sum();
      putIn(s.info.body, kv([['Description', r.descr], ['Device', inst], ['ifName', ifName]]), linkList([[`Parent device: ${inst.toUpperCase()}`, () => ctx.nav.device(inst)]]));
      const sel = `instance=${lv(inst)},ifName=${lv(ifName)},job="snmp"`;
      await Promise.all([
        drawRange(traffic, [
          { q: `(rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↓ in' },
          { q: `(rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↑ out' },
        ], HOUR, 'Mbps', `${inst} ${ifName} traffic`).then((x) => { if (x) { lastR = x; sum(); } }),
        drawRange(errs, [
          { q: `(rate(ifInErrors{${sel}}[$RATE]) * 60) ${SNMP_UP}`, name: () => 'in errors' },
          { q: `(rate(ifOutErrors{${sel}}[$RATE]) * 60) ${SNMP_UP}`, name: () => 'out errors' },
        ], HOUR, '/min', `${inst} ${ifName} errors`),
      ]);
    },
  };
}

// "この通信のパケット": opens packet analysis narrowed to this destination / host (filter + last 15 min of the ring)
function packetsSection(open) {
  const s = section('Packets', 'stored captures · masked');
  const b = el('button', 'link-btn ops-btn', 'この通信のパケット');
  b.type = 'button';
  b.lang = 'ja';
  b.setAttribute('aria-label', 'Packets of this traffic: open packet analysis with a filter for it');
  b.addEventListener('click', () => { if (nav()) open(); });
  s.body.append(b, el('p', 'v-p', 'Opens packet analysis with a filter for these addresses (from the last 15 min of the capture ring; the demo opens its synthetic pcap).'));
  return s;
}

// ---- destination (country / city / unknown IP) -------------------------------------------------
export function destView(d) {
  const tok = ipTokens(); // unique, address-free focus keys for rows that only differ by a masked IP
  const label = d.ip ? `Unknown ${maskIp(d.ip)}` : d.city ? `${d.city}, ${d.cc}` : `Country ${d.cc}`;
  const match = (f) => (d.ip ? f.ip === d.ip : f.cc === d.cc && (!d.city || f.city === d.city));
  let s;
  const chart = chartBlock();
  return {
    title: `Destination ${label}`, src: 'prom',
    mount(body) {
      s = { sum: el('div'), src: section('Source hosts talking to it', 'Mbps · share of this destination\'s traffic'), ips: section('Destination IPs', 'masked (NFR-09) · Mbps'),
        t: section('Trend, last 1 h', 'Mbps by direction'), note: section('Geo confidence'), pk: packetsSection(() => nav().packets({ dest: d })) };
      s.srcBox = el('div');
      s.src.body.append(s.srcBox, keyLegend(DIR_KEYS));
      s.t.body.append(chart.wrap);
      body.append(s.sum, s.src.wrap, s.t.wrap, s.ips.wrap, s.note.wrap, s.pk.wrap,
        ...(!d.cc ? [] : [deepSection([['推移を見る (ASN ごと)', (n) => n.trend({ family: 'flow_asn', dst_country: d.cc })],
          ['推移を見る (端末ごと)', (n) => n.trend({ family: 'flow_host', dst_country: d.cc })]]).wrap]),
        evidenceSection(() => (d.ip ? { scope: 'dest', ip: d.ip } : { scope: 'dest', cc: d.cc, city: d.city })).wrap);
    },
    async update(ctx) {
      lastNav = ctx.nav;
      const ok = ctx.snap.flowsOk; // flow source DOWN: every figure is unknown ("—"), never 0
      const fl = ctx.snap.flows.filter(match);
      const all = totalBps(ctx.snap.flows);
      const bps = ok ? totalBps(fl) : undefined;
      const out = ok ? totalBps(fl.filter((f) => f.dir === 'outbound')) : undefined;
      const srcs = [...byKey(fl, (f) => f.src).values()].sort((a, b) => b.bps - a.bps);
      const unknown = d.cc === 'Unknown';
      putIn(s.sum, tiles([
        { label: 'Total', value: mbps(bps), d: 2, unit: 'Mbps', kind: ok ? 'none' : 'unknown', status: ok ? undefined : FLOW_TEXT.status },
        { label: '↓ inbound', value: ok ? mbps(bps - out) : undefined, d: 2, unit: 'Mbps' },
        { label: '↑ outbound', value: mbps(out), d: 2, unit: 'Mbps' },
        { label: 'Share of all flow', value: ok ? pct(bps, all) : undefined, unit: '%' },
        { label: 'Source hosts', value: ok ? srcs.filter((g) => g.bps > 0).length : undefined, d: 0 },
        { label: 'Location', value: unknown ? 'Unknown' : d.city || d.cc, kind: unknown ? 'unknown' : 'info', status: unknown ? 'no GeoIP result' : 'GeoIP estimate',
          sub: [...new Set(fl.map((f) => f.asn).filter(Boolean))].join(', ') || undefined },
      ]));
      putIn(s.srcBox, ok ? rankBars(srcs.map((g) => ({ label: g.key, value: mbps(g.bps), extra: shareText(pct(g.bps, bps)), segs: dirSegs(g.flows), onOpen: () => ctx.nav.src(g.key) })),
        { head: ['host', 'Mbps', 'of dest'] }) : el('p', 'na', FLOWS_DOWN));
      const ips = [...byKey(fl, (f) => f.ip).values()].sort((a, b) => b.bps - a.bps);
      putIn(s.ips.body, ok ? rankBars(ips.map((g) => ({ label: `${maskIp(g.key)}  ${g.flows[0].city || '(no GeoIP)'}`, key: tok(g.key), value: mbps(g.bps), extra: shareText(pct(g.bps, bps)),
        cls: g.flows[0].lat === null ? 'rank-unknown' : '',
        onOpen: () => ctx.nav.dest(g.flows[0].lat === null ? { cc: 'Unknown', ip: g.key } : { cc: g.flows[0].cc, city: g.flows[0].city }) })), { head: ['IP (masked)', 'Mbps', 'of dest'] }) : el('p', 'na', FLOWS_DOWN));
      s.note.body.replaceChildren(el('p', 'v-p', unknown
        ? 'No GeoIP result: counted as Unknown (kept in totals and shares); no location is estimated or drawn (TC-007).'
        : 'Location is a GeoIP estimate of the destination (synthetic in this demo). Arcs show a logical relation, not a physical route.'));
      const sel = d.ip ? `dst_ip=${lv(d.ip)}` : `dst_country=${lv(d.cc)}${d.city ? `,dst_city=${lv(d.city)}` : ''}`;
      await drawRange(chart, [{ q: `sum by (direction) (rate(obs_flow_bytes_total{${sel}}[$RATE]) ${FLOWS_UP}) * 8 / 1e6`, name: (mt) => mt.direction }], HOUR, 'Mbps', `${label} traffic by direction`);
      if (!ok) flowsMissing(ctx.snap);
    },
  };
}

// ---- source host ------------------------------------------------------------------------
export function srcView(host) {
  const tok = ipTokens(); // unique, address-free focus keys for rows that only differ by a masked IP
  let s;
  const chart = chartBlock();
  return {
    title: `Source ${host}`, src: 'prom',
    mount(body) {
      s = { sum: el('div'), cc: section('Destinations by country', 'Mbps · share of this host\'s traffic'), dst: section('Destinations', 'country / city / masked IP'), t: section('Trend, last 1 h', 'Mbps by direction'),
        pk: packetsSection(() => nav().packets({ src: host })) };
      s.ccBox = el('div');
      s.cc.body.append(s.ccBox, keyLegend(DIR_KEYS));
      s.t.body.append(chart.wrap);
      body.append(s.sum, s.cc.wrap, s.t.wrap, s.dst.wrap, s.pk.wrap,
        deepSection([['推移を見る (国ごと)', (n) => n.trend({ family: 'flow_country', src_host: host })]]).wrap,
        evidenceSection(() => ({ scope: 'src', host })).wrap);
    },
    async update(ctx) {
      lastNav = ctx.nav;
      const ok = ctx.snap.flowsOk; // flow source DOWN: every figure is unknown ("—"), never 0
      const fl = ctx.snap.flows.filter((f) => f.src === host);
      const bps = ok ? totalBps(fl) : undefined;
      const out = ok ? totalBps(fl.filter((f) => f.dir === 'outbound')) : undefined;
      const all = totalBps(ctx.snap.flows);
      const ccs = [...byKey(fl, (f) => f.cc).values()].sort((a, b) => b.bps - a.bps);
      putIn(s.sum, tiles([
        { label: 'Total', value: mbps(bps), d: 2, unit: 'Mbps', kind: ok ? 'none' : 'unknown', status: ok ? undefined : FLOW_TEXT.status },
        { label: '↑ outbound', value: mbps(out), d: 2, unit: 'Mbps' },
        { label: '↓ inbound', value: ok ? mbps(bps - out) : undefined, d: 2, unit: 'Mbps' },
        { label: 'Share of all flow', value: ok ? pct(bps, all) : undefined, unit: '%' },
        { label: 'Destinations', value: ok ? new Set(fl.filter((f) => f.bps > 0).map((f) => f.ip)).size : undefined, d: 0, sub: ok ? `${ccs.filter((g) => g.key !== 'Unknown').length} countries` : undefined },
      ]));
      putIn(s.ccBox, ok ? rankBars(ccs.map((g) => ({ label: g.key === 'Unknown' ? 'Unknown ?' : g.key, key: g.key, value: mbps(g.bps), extra: shareText(pct(g.bps, bps)), segs: dirSegs(g.flows),
        cls: g.key === 'Unknown' ? 'rank-unknown' : '', onOpen: () => ctx.nav.dest({ cc: g.key }) })), { head: ['country', 'Mbps', 'of host'] }) : el('p', 'na', FLOWS_DOWN));
      const dst = [...byKey(fl, (f) => f.ip).values()].sort((a, b) => b.bps - a.bps);
      putIn(s.dst.body, ok ? rankBars(dst.map((g) => {
        const f = g.flows[0];
        return { label: `${f.cc} ${f.city || '(no GeoIP)'} ${maskIp(g.key)}`, key: tok(g.key), value: mbps(g.bps), extra: shareText(pct(g.bps, bps)), cls: f.lat === null ? 'rank-unknown' : '',
          onOpen: () => ctx.nav.dest(f.lat === null ? { cc: 'Unknown', ip: g.key } : { cc: f.cc, city: f.city }) };
      }), { head: ['destination', 'Mbps', 'of host'] }) : el('p', 'na', FLOWS_DOWN));
      await drawRange(chart, [{ q: `sum by (direction) (rate(obs_flow_bytes_total{src_host=${lv(host)}}[$RATE]) ${FLOWS_UP}) * 8 / 1e6`, name: (mt) => mt.direction }], HOUR, 'Mbps', `${host} traffic by direction`);
      if (!ok) flowsMissing(ctx.snap);
    },
  };
}

// ---- alert --------------------------------------------------------------------------------
// "原因候補" (P5): what else happened around this moment, opened as the next drawer view
function correlateSection(anchorOf, what) {
  const s = section('原因候補', '相関の候補 · 前後 10 分 · 因果は断定しません');
  const b = el('button', 'link-btn ops-btn', `${what}の前後に起きたこと`);
  b.type = 'button';
  b.lang = 'ja';
  b.setAttribute('aria-label', `Correlation candidates: what else happened around ${what}`);
  b.addEventListener('click', () => { if (nav()) nav().correlate(anchorOf()); });
  s.body.append(b, el('p', 'v-p', '同じ時間窓の警報・機器や IF の状態変化・エラー・急増・syslog・通知記録を、関連の近い順に並べます (相関の候補であり、原因とは限りません)。'));
  return s;
}

export function alertView(alert0) {
  let s;
  let rules = null;
  const id = alertKey(alert0.labels);
  const tok = {};
  return {
    title: `Alert ${alert0.labels.alertname}`, src: 'both',
    mount(body) {
      s = { sum: el('div'), ops: alertOpsSection(), tl: section('Timeline', 'firing / pending spans of this alert'), labels: section('Labels'), ann: section('Annotations'),
        rule: section('Rule', 'from /api/v1/rules'), rel: section('Related'), logs: section('Syslog around activation', '±5 min') };
      s.tlBox = el('div');
      s.tl.body.append(s.tlBox, keyLegend(ALERT_KEYS));
      const ev = evidenceSection(() => ({ scope: 'alert', alertname: alert0.labels.alertname, instance: alert0.labels.instance, ifName: alert0.labels.ifName, severity: alert0.labels.severity }),
        () => Date.parse(alert0.activeAt));
      const cr = correlateSection(() => {
        const t = Date.parse(alert0.activeAt);
        const L = alert0.labels;
        return { at: Math.min(now(), Number.isFinite(t) ? t : now()), label: `警報 ${L.alertname}${L.instance ? ` ${L.instance}` : ''}`,
          ctx: { instance: L.instance, ifName: L.ifName, alertname: L.alertname } };
      }, 'この警報');
      body.append(s.sum, s.ops.wrap, cr.wrap, ev.wrap, s.tl.wrap, s.labels.wrap, s.ann.wrap, s.rule.wrap, s.rel.wrap, s.logs.wrap);
    },
    async update(ctx) {
      lastNav = ctx.nav;
      const cur = ctx.snap.alerts.find((a) => alertKey(a.labels) === id);
      const a = cur || alert0;
      s.ops.update(a, cur?.state === 'firing');
      const active = Date.parse(a.activeAt);
      const anchor = has(active) ? active : now(); // playback without ALERTS_FOR_STATE: around the cursor
      const [kind, sevText] = sevKind(a.labels.severity);
      putIn(s.sum, tiles([
        { label: 'State', value: cur ? a.state.toUpperCase() : 'RESOLVED', kind: cur ? (a.state === 'firing' ? kind : 'warn') : 'ok', status: cur ? (a.state === 'firing' ? 'firing now' : 'pending (for: not yet met)') : 'no longer in the alert list' },
        { label: 'Severity', value: sevText, kind, status: a.labels.severity || 'none' },
        { label: 'Active for', value: cur && has(active) ? fmtDur((now() - active) / 1000) : undefined, sub: has(active) ? `since ${jstFull.format(new Date(active))}` : 'activation time not recorded' },
        { label: 'Value', value: has(Number(a.value)) ? Number(a.value) : a.value, d: 2 },
      ]));
      s.labels.body.replaceChildren(kv(Object.entries(a.labels).map(([k, v]) => [k, maskText(String(v))])));
      s.ann.body.replaceChildren(kv(Object.entries(a.annotations || {}).map(([k, v]) => [k, maskText(String(v))])));
      const sel = `ALERTS{${Object.entries(a.labels).map(([k, v]) => `${k}=${lv(v)}`).join(',')}}`;
      const secs = Math.min(24 * HOUR, Math.max(HOUR, Math.ceil((now() - anchor) / 1000) + 600));
      const tlP = fetchRange(tok, [{ q: sel, name: () => '' }], secs).then((r) => { if (r) putIn(s.tlBox, timeline(alertLanes(r, ctx.snap.alerts, ctx.nav).map((l) => ({ ...l, onOpen: null })), r.t0, r.t1, 'not active in window')); });
      const inst = a.labels.instance;
      const rel = [];
      if (DEVICES.includes(inst)) rel.push([`Device ${inst.toUpperCase()}`, () => ctx.nav.device(inst)]);
      if (DEVICES.includes(inst) && a.labels.ifName) rel.push([`Interface ${inst} ${a.labels.ifName}`, () => ctx.nav.iface(`${inst}|${a.labels.ifName}`)]);
      putIn(s.rel.body, linkList(rel));
      if (!rules) rules = await promRules();
      const rule = rules.find((r) => r.name === a.labels.alertname);
      s.rule.body.replaceChildren(rule ? kv([['Expression', rule.query], ['for', rule.duration ? `${rule.duration} s` : '0 s'], ['Rule health', rule.health]]) : el('p', 'na', 'rule not found'));
      const logsP = DEVICES.includes(inst)
        ? lokiLogs(`{job="syslog",host=${lv(inst)}}`, { startNs: String(nsOf(anchor - 300000)), endNs: String(nsOf(Math.min(now(), anchor + 300000))), limit: 100 })
          .then((res) => putIn(s.logs.body, logList(inst, res.entries.slice(-40), ctx.nav, null, res)))
        : Promise.resolve(s.logs.body.replaceChildren(el('p', 'na', 'not a syslog-emitting device')));
      await Promise.all([tlP, logsP]);
    },
  };
}

// ---- syslog line context -------------------------------------------------------------------
export function loglineView(e) {
  let s;
  // the context around a line does not change: fetched once per data time (live: once; playback: again when the cursor
  // moved, so nothing after the cursor is shown), re-rendered on every mount (back / breadcrumb)
  let around = null, aroundRes = null, vol = null, at = null;
  const tok = {};
  const tMs = Number(e.ts.slice(0, 13));
  return {
    title: `Syslog ${e.host}`, src: 'loki',
    mount(body) {
      s = { sum: el('div'), line: section('Line'), vol: section('Host volume around the line', '±10 min · lines by severity · marker = this line'), ctx: section('Context', '±20 lines from the same host') };
      body.append(s.sum, s.line.wrap, s.vol.wrap, s.ctx.wrap,
        deepSection([['ログを検索', (n) => n.logsearch({ host: e.host, severity: e.sev, preset: 86400 })]]).wrap);
    },
    async update(ctx) {
      lastNav = ctx.nav;
      const pos = isPlayback() ? now() : 'live';
      if (pos !== at) { around = aroundRes = vol = null; at = pos; s.ctx.body.replaceChildren(); }
      if (s.ctx.body.childElementCount) return; // already rendered into the current mount, for this data time
      const kind = SEV_BAD.includes(e.sev) ? 'crit' : e.sev === 'warning' ? 'warn' : 'info'; // emergency / alert count as crit too
      s.sum.replaceChildren(tiles([
        { label: 'Time (JST)', value: jstFull.format(new Date(tMs)) },
        { label: 'Host', value: e.host },
        { label: 'Severity', value: e.sev.toUpperCase(), kind, status: e.sev },
      ]));
      s.line.body.replaceChildren(logList(e.host, [e], ctx.nav, e.ts), linkList(DEVICES.includes(e.host) ? [[`Device ${e.host.toUpperCase()}`, () => ctx.nav.device(e.host)]] : []));
      const volP = vol ? Promise.resolve(vol) : sevBuckets(tok, `{job="syslog",host=${lv(e.host)}}`, 1200, Math.min(now(), tMs + 600000) / 1000).then((r) => (vol = r || vol));
      if (!around) {
        const t = BigInt(e.ts);
        aroundRes = await lokiLogs(`{job="syslog",host=${lv(e.host)}}`, { startNs: String(t - 600000000000n), endNs: String(min(t + 600000000000n, BigInt(now()) * 1000000n)), limit: 1000, direction: 'forward' }); // never past the playback cursor
        const all = aroundRes.entries;
        const i = Math.max(0, all.findIndex((x) => x.ts === e.ts && x.line === e.line));
        around = all.slice(Math.max(0, i - 20), i + 21);
      }
      const v = await volP;
      if (v) s.vol.body.replaceChildren(sevChart(v, `${e.host} syslog lines per ${v.step / 60} min`, tMs / 1000));
      s.ctx.body.replaceChildren(logList(e.host, around, ctx.nav, e.ts, aroundRes));
    },
  };
}

// ---- collection job ----------------------------------------------------------------------
export function jobView(job) {
  let s;
  const dur = chartBlock(), up = chartBlock('small');
  return {
    title: `Job ${job}`, src: 'prom',
    mount(body) {
      s = { sum: el('div'), t: section('Targets', 'scrape duration, ms · last sample age'), d: section('Scrape duration, last 1 h', 'ms'), u: section('up, last 1 h', '1 = success, 0 = failed') };
      s.d.body.append(dur.wrap);
      s.u.body.append(up.wrap);
      body.append(s.sum, s.t.wrap, s.d.wrap, s.u.wrap);
    },
    async update(ctx) {
      const ts = ctx.snap.targets.filter((t) => t.job === job);
      const upN = ts.filter((t) => t.up === 1).length;
      const maxDur = ts.some((t) => has(t.dur)) ? Math.max(...ts.filter((t) => has(t.dur)).map((t) => t.dur * 1000)) : undefined;
      const ages = ts.filter((t) => t.up === 1 && has(t.age)).map((t) => t.age);
      const maxAge = ages.length ? Math.max(...ages) : undefined;
      putIn(s.sum, tiles([
        { label: 'Targets UP', value: `${upN} / ${ts.length}`, kind: upN === ts.length ? 'ok' : upN ? 'warn' : 'crit', status: upN === ts.length ? 'all scraping' : `DOWN: ${ts.filter((t) => t.up !== 1).map((t) => maskText(t.instance)).join(', ')}` },
        { label: 'Slowest scrape', value: maxDur, d: 0, unit: 'ms' },
        { label: 'Oldest sample (UP)', value: maxAge, d: 0, unit: 's', kind: has(maxAge) ? (maxAge > 60 ? 'warn' : 'ok') : 'unknown', status: has(maxAge) ? (maxAge > 60 ? 'stale sample' : 'fresh') : 'unknown' },
      ]));
      putIn(s.t.body, rankBars(ts.map((t) => ({
        label: `${t.up === 1 ? 'UP' : 'DOWN'}  ${maskText(t.instance)}`, key: t.instance, value: has(t.dur) ? t.dur * 1000 : undefined, extra: has(t.age) ? `${fixed(t.age, 0)} s ago` : '—',
        cls: t.up === 1 ? 'rank-ok' : 'rank-crit', onOpen: DEVICES.includes(t.instance) ? () => ctx.nav.device(t.instance) : null,
      })), { unit: 'ms', d: 0, head: ['target', 'scrape ms', 'last sample'] }));
      await Promise.all([
        drawRange(dur, [{ q: `scrape_duration_seconds{job=${lv(job)}} * 1000`, name: (mt) => maskText(mt.instance) }], HOUR, 'ms', `${job} scrape duration`),
        drawRange(up, [{ q: `up{job=${lv(job)}}`, name: (mt) => maskText(mt.instance) }], HOUR, '', `${job} up`),
      ]);
    },
  };
}
