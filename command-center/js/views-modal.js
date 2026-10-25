// Panel-title modals: the full, unabridged data behind each wallboard panel.
// Every modal reads top-down: summary tiles (is it OK / what stands out) -> charts -> detail list (表 / カード).
import { el, has, fixed, fmtUptime, fmtBytes, fmtDur, maskIp, maskText, jstFull, sortTable, upState, bar, refocus } from './util.js';
import { promQuery, lokiLogs, lokiMetric, logqlString } from './api.js';
import { DEVICES, byKey, totalBps, ifaceRows, wlanRows, wanValues, logRow, sevKind } from './panels.js';
import {
  section, chartBlock, drawRange, fetchRange, rangeSelect, mbps, lv, linkBtn, putIn, tiles, vsAvg, rankBars, keyLegend, timeline,
  stackCols, SEV_KEYS, sevBuckets, sevTiles, SEV_LEVELS, SEV_BAD, sevKey, multiples, seriesBy, maxOf, dataView, listSection, alertLanes, alertKey, ipTokens, ALERT_KEYS, DIR_KEYS, IO_KEYS, dirSegs, pct, shareText, SNMP_UP, FLOWS_UP, FLOWS_DOWN,
} from './views-common.js';

const fmtN = (d) => (v) => fixed(v, d);
const CORE_SEV = ['critical', 'error', 'warning', 'notice', 'informational']; // always shown on cards, extra levels when > 0
const HOUR = 3600;
const sumDef = (vals) => { const v = vals.filter(has); return v.length ? v.reduce((a, b) => a + b, 0) : undefined; };
const grid2 = (...secs) => { const g = el('div', 'v-grid2'); g.append(...secs.map((s) => s.wrap)); return g; };
const flowsDownTiles = (labels) => tiles(labels.map((label) => ({ label, value: undefined, kind: 'unknown', status: 'flow source DOWN' })));
// small "share of total" bar for cards; label carries the number for AT
function shareBar(p) {
  const b = bar(has(p) ? p : 0);
  b.classList.add('card-bar');
  b.setAttribute('aria-hidden', 'true');
  return b;
}

// ---- devices ------------------------------------------------------------------------------
export function devicesModal() {
  let dv, sum, mult;
  const tok = {};
  const subs = new Map(); // per-device interface tables are built once so their sort state survives refreshes
  return {
    title: 'Device status — all fields', src: 'prom',
    mount(body) {
      sum = el('div');
      const ch = section('Traffic per device, last 1 h', 'Mbps · same y-scale for every device');
      mult = el('div');
      ch.body.append(mult, keyLegend(IO_KEYS));
      dv = dataView('devices', [
        { key: 'name', label: 'Device' }, { key: 'status', label: 'Status' }, { key: 'uptime', label: 'Uptime', num: true, fmt: (v) => (has(v) ? fmtUptime(v) : '—') },
        { key: 'in', label: '↓ Mbps', num: true, fmt: fmtN(1) }, { key: 'out', label: '↑ Mbps', num: true, fmt: fmtN(1) },
        { key: 'err', label: 'Errors /min', num: true, fmt: fmtN(1) }, { key: 'clients', label: 'WLAN clients', num: true, fmt: (v, r) => (r.name.startsWith('wlx') ? fixed(v, 0) : 'n/a') },
        { key: 'ifCount', label: 'Interfaces', num: true },
      ], { key: 'name' }, (r) => ({
        title: r.name.toUpperCase(), badge: r.badge,
        fields: [['↓', fixed(r.in), 'Mbps'], ['↑', fixed(r.out), 'Mbps'], ['Errors', fixed(r.err), '/min'],
          ['Uptime', has(r.uptime) ? fmtUptime(r.uptime) : undefined], ['WLAN clients', r.name.startsWith('wlx') ? fixed(r.clients, 0) : 'n/a'], ['Interfaces', r.ifCount]],
      }), (r) => r.name);
      const ls = listSection('Devices', 'click a row / card for details', dv);
      const ifSec = section('Interfaces per device');
      for (const d of DEVICES) {
        const sub = sortTable(ifCols());
        subs.set(d, sub);
        const w = el('div', 'v-sub');
        w.append(el('h4', 'v-h4', d.toUpperCase()), sub.el);
        ifSec.body.appendChild(w);
      }
      body.append(sum, ch.wrap, ls.wrap, ifSec.wrap);
    },
    async update(ctx) {
      const { m } = ctx.snap;
      const ifs = ifaceRows(m, ctx.seenIf);
      const rows = DEVICES.map((d) => {
        const [kind, text] = upState(m.up.get(d));
        return { name: d, status: text, badge: [kind, text], uptime: m.up.get(d) === 1 ? m.uptime.get(d) : undefined,
          in: m.devIn.get(d), out: m.devOut.get(d), err: m.devErr.get(d), clients: m.clients.get(d), ifCount: ifs.filter((r) => r.inst === d).length };
      });
      const online = rows.filter((r) => r.status === 'UP').length;
      const down = rows.filter((r) => r.status !== 'UP').map((r) => `${r.name} ${r.status}`);
      const err = sumDef(rows.map((r) => r.err));
      const firing = ctx.snap.alerts.filter((a) => a.state === 'firing' && DEVICES.includes(a.labels.instance)).length;
      putIn(sum, tiles([
        { label: 'Online', value: `${online} / ${DEVICES.length}`, kind: online === DEVICES.length ? 'ok' : 'crit', status: down.length ? down.join(', ') : 'all UP' },
        { label: 'Traffic ↓ (sum)', value: sumDef(rows.map((r) => r.in)), unit: 'Mbps', sub: down.length ? 'UP devices only' : undefined },
        { label: 'Traffic ↑ (sum)', value: sumDef(rows.map((r) => r.out)), unit: 'Mbps', sub: down.length ? 'UP devices only' : undefined },
        { label: 'Errors', value: err, unit: '/min', kind: has(err) ? (err > 0 ? 'warn' : 'ok') : 'unknown', status: has(err) ? (err > 0 ? 'errors seen' : 'none') : 'unknown' },
        { label: 'WLAN clients', value: sumDef(rows.filter((r) => r.name.startsWith('wlx')).map((r) => r.clients)), d: 0 },
        { label: 'Firing alerts', value: firing, d: 0, kind: firing ? 'crit' : 'ok', status: firing ? 'see Alerts' : 'none' },
      ]));
      dv.update(rows, (r) => ctx.nav.device(r.name));
      for (const d of DEVICES) subs.get(d).update(ifs.filter((r) => r.inst === d), (r) => ctx.nav.iface(r.key));
      const sel = 'job="snmp"';
      const r = await fetchRange(tok, [
        { q: `sum by (instance) (rate(ifHCInOctets{${sel}}[$RATE]) ${SNMP_UP}) * 8 / 1e6`, name: () => 'in' },
        { q: `sum by (instance) (rate(ifHCOutOctets{${sel}}[$RATE]) ${SNMP_UP}) * 8 / 1e6`, name: () => 'out' },
      ], HOUR);
      if (!r) return;
      const ins = seriesBy(r, 0, (mt) => mt.instance), outs = seriesBy(r, 1, (mt) => mt.instance);
      putIn(mult, multiples(rows.map((x) => ({
        label: x.name.toUpperCase(), key: x.name, badge: x.badge, onOpen: () => ctx.nav.device(x.name),
        series: [{ points: ins.get(x.name) || [], cls: 'sp-1' }, { points: outs.get(x.name) || [], cls: 'sp-2' }],
        vals: [['↓', fixed(x.in), 'Mbps'], ['↑', fixed(x.out), 'Mbps']],
      })), { t0: r.t0, t1: r.t1, step: r.step, max: maxOf(ins, outs) }));
    },
  };
}
const ifCols = () => [
  { key: 'operText', label: 'Oper' }, { key: 'inst', label: 'Device' }, { key: 'ifName', label: 'ifName' }, { key: 'descr', label: 'ifDescr' },
  { key: 'speed', label: 'Speed Mbps', num: true, fmt: fmtN(0) }, { key: 'in', label: '↓ Mbps', num: true, fmt: fmtN(1) },
  { key: 'out', label: '↑ Mbps', num: true, fmt: fmtN(1) }, { key: 'util', label: 'Util %', num: true, fmt: fmtN(1) }, { key: 'err', label: 'Errors /min', num: true, fmt: fmtN(1) },
];
const operBadge = (r) => [r.oper === 1 ? 'ok' : r.oper === 2 ? 'warn' : 'unknown', r.operText];

// ---- destinations ------------------------------------------------------------------------
export function destModal() {
  let dv, sum, rank, lastR = null;
  const trend = chartBlock(), tok = ipTokens();
  return {
    title: 'Destinations — all countries, cities and Unknown', src: 'prom',
    mount(body) {
      sum = el('div');
      const s1 = section('Traffic by country', 'Mbps · share of all flow bytes');
      rank = el('div');
      s1.body.append(rank, keyLegend([...DIR_KEYS, { cls: 'sw-unknown', name: 'Unknown (no GeoIP), hatched' }]));
      const s2 = section('Total flow, last 1 h', 'Mbps by direction');
      s2.body.append(trend.wrap);
      dv = dataView('dest', [
        { key: 'cc', label: 'Country' }, { key: 'city', label: 'City' }, { key: 'asn', label: 'ASN' }, { key: 'ip', label: 'IP (masked)' },
        { key: 'mbps', label: 'Mbps', num: true, fmt: fmtN(2) }, { key: 'share', label: 'Share %', num: true, fmt: fmtN(1) },
        { key: 'bytes', label: 'Bytes / 15 min', num: true, fmt: (v) => (has(v) ? fmtBytes(v) : '—') }, { key: 'srcs', label: 'Source hosts', num: true },
      ], { key: 'mbps', desc: true }, (r) => ({
        title: r.city, sub: `${r.cc} · ${r.ip}`, badge: r.geo ? ['info', 'GEO'] : ['unknown', 'UNKNOWN'], cls: r.geo ? '' : 'card-unknown',
        fields: [['Mbps', fixed(r.mbps, 2)], ['Share', fixed(r.share), '%'], ['15 min', has(r.bytes) ? fmtBytes(r.bytes) : undefined], ['Sources', r.srcs], ['ASN', r.asn]],
        extra: shareBar(r.share),
      }), (r) => tok(r.rawIp));
      const ls = listSection('All destinations', 'IPs masked (NFR-09) · bytes = increase over the last 15 min', dv);
      body.append(sum, grid2(s1, s2), ls.wrap,
        el('p', 'v-p', 'Share uses all flow bytes as the denominator (Unknown included). Unknown = no GeoIP result, never given a guessed location (TC-007).'));
    },
    async update(ctx) {
      const ok = ctx.snap.flowsOk;
      const trendP = drawRange(trend, [{ q: `sum by (direction) (rate(demo_flow_bytes_total[$RATE]) ${FLOWS_UP}) * 8 / 1e6`, name: (mt) => mt.direction }], HOUR, 'Mbps', 'Total flow by direction');
      if (!ok) { // flow source DOWN: drop the rows (an empty source would read as 0 Mbps / 0 destinations) and mark the view stale
        putIn(sum, flowsDownTiles(['Total flow', 'Destinations', 'Countries', 'Unknown share', 'Top country']));
        putIn(rank, el('p', 'na', FLOWS_DOWN));
        dv.update([]);
        await trendP;
        throw new Error(FLOWS_DOWN);
      }
      const [bytes, r] = await Promise.all([promQuery('sum by (dst_ip) (increase(demo_flow_bytes_total[15m]))'), trendP]);
      lastR = r || lastR;
      const bmap = new Map(bytes.map((x) => [x.metric.dst_ip, Number(x.value[1])]));
      const flows = ctx.snap.flows;
      const all = totalBps(flows);
      const countries = [...byKey(flows, (f) => f.cc).values()].sort((a, b) => b.bps - a.bps);
      const unk = countries.find((g) => g.key === 'Unknown');
      const top = countries.find((g) => g.key !== 'Unknown');
      const ips = [...byKey(flows, (f) => f.ip).values()];
      putIn(sum, tiles([
        { label: 'Total flow', value: mbps(all), d: 2, unit: 'Mbps', sub: vsAvg(sumPoints(lastR), 2), spark: lastR && { series: lastR.series.map((s, i) => ({ points: s.points, cls: `sp-${(i % 2) + 1}` })), t0: lastR.t0, t1: lastR.t1, step: lastR.step } },
        { label: 'Destinations', value: ips.length, d: 0, sub: 'distinct IPs' },
        { label: 'Countries', value: countries.filter((g) => g.key !== 'Unknown').length, d: 0 },
        { label: 'Unknown share', value: pct(unk?.bps || 0, all), unit: '%', kind: unk ? 'unknown' : 'ok', status: unk ? `${byKey(unk.flows, (f) => f.ip).size} IPs without GeoIP` : 'all located' },
        { label: 'Top country', value: top?.key, sub: top ? `${shareText(pct(top.bps, all))} of all flow` : undefined },
      ]));
      const TOP = 10;
      const shown = countries.slice(0, TOP), rest = countries.slice(TOP);
      putIn(rank, rankBars([
        ...shown.map((g) => ({ label: g.key === 'Unknown' ? 'Unknown ?' : g.key, key: g.key, value: mbps(g.bps), extra: shareText(pct(g.bps, all)),
          segs: dirSegs(g.flows), cls: g.key === 'Unknown' ? 'rank-unknown' : '', onOpen: () => ctx.nav.dest({ cc: g.key }) })),
        ...(rest.length ? [{ label: `+${rest.length} others`, value: mbps(rest.reduce((a, g) => a + g.bps, 0)), extra: shareText(pct(rest.reduce((a, g) => a + g.bps, 0), all)), cls: 'rank-sub' }] : []),
      ], { head: ['country', 'Mbps', 'share'] }));
      dv.update(ips.map((g) => {
        const f = g.flows[0];
        return { cc: f.cc, city: f.city || '(no GeoIP)', asn: f.asn || undefined, ip: maskIp(g.key), rawIp: g.key, geo: f.lat !== null,
          mbps: mbps(g.bps), share: pct(g.bps, all), bytes: bmap.get(g.key), srcs: new Set(g.flows.filter((x) => x.bps > 0).map((x) => x.src)).size };
      }), (x) => ctx.nav.dest(x.geo ? { cc: x.cc, city: x.city } : { cc: 'Unknown', ip: x.rawIp }));
    },
  };
}
// sum of range series at each timestamp (for "avg / peak" of a total)
function sumPoints(r) {
  if (!r?.series.length) return null;
  const m = new Map();
  for (const s of r.series) for (const [t, v] of s.points) m.set(t, (m.get(t) || 0) + v);
  return [...m.entries()].sort((a, b) => a[0] - b[0]);
}

// ---- sources ----------------------------------------------------------------------------
export function srcModal() {
  let dv, sum, rank;
  return {
    title: 'Source hosts — all', src: 'prom',
    mount(body) {
      sum = el('div');
      const s1 = section('Traffic by source host', 'Mbps · ↑ outbound / ↓ inbound · share of all flow bytes');
      rank = el('div');
      s1.body.append(rank, keyLegend(DIR_KEYS));
      dv = dataView('src', [
        { key: 'host', label: 'Host' }, { key: 'mbps', label: 'Mbps', num: true, fmt: fmtN(2) }, { key: 'out', label: '↑ out Mbps', num: true, fmt: fmtN(2) },
        { key: 'in', label: '↓ in Mbps', num: true, fmt: fmtN(2) }, { key: 'share', label: 'Share %', num: true, fmt: fmtN(1) }, { key: 'dests', label: 'Destinations', num: true },
      ], { key: 'mbps', desc: true }, (r) => ({
        title: r.host, fields: [['Mbps', fixed(r.mbps, 2)], ['Share', fixed(r.share), '%'], ['↑ out', fixed(r.out, 2), 'Mbps'], ['↓ in', fixed(r.in, 2), 'Mbps'], ['Destinations', r.dests]],
        extra: shareBar(r.share),
      }), (r) => r.host);
      body.append(sum, s1.wrap, listSection('All source hosts', 'click for the host\'s destinations', dv).wrap);
    },
    async update(ctx) {
      if (!ctx.snap.flowsOk) {
        putIn(sum, flowsDownTiles(['Source hosts', 'Total flow', 'Top host', '↑ outbound']));
        putIn(rank, el('p', 'na', FLOWS_DOWN));
        dv.update([]);
        throw new Error(FLOWS_DOWN);
      }
      const flows = ctx.snap.flows;
      const all = totalBps(flows);
      const groups = [...byKey(flows, (f) => f.src).values()].sort((a, b) => b.bps - a.bps);
      const out = totalBps(flows.filter((f) => f.dir === 'outbound'));
      putIn(sum, tiles([
        { label: 'Source hosts', value: groups.length, d: 0 },
        { label: 'Total flow', value: mbps(all), d: 2, unit: 'Mbps' },
        { label: 'Top host', value: groups[0]?.key, sub: groups[0] ? `${shareText(pct(groups[0].bps, all))} of all flow` : undefined },
        { label: '↑ outbound', value: pct(out, all), unit: '%', sub: `↓ inbound ${shareText(pct(all - out, all)) || '—'}` },
      ]));
      putIn(rank, rankBars(groups.map((g) => ({ label: g.key, value: mbps(g.bps), extra: shareText(pct(g.bps, all)), segs: dirSegs(g.flows), onOpen: () => ctx.nav.src(g.key) })), { head: ['host', 'Mbps', 'share'] }));
      dv.update(groups.map((g) => ({
        host: g.key, mbps: mbps(g.bps), in: dirSegs(g.flows)[0].v, out: dirSegs(g.flows)[1].v,
        share: pct(g.bps, all), dests: new Set(g.flows.filter((f) => f.bps > 0).map((f) => f.ip)).size,
      })), (r) => ctx.nav.src(r.host));
    },
  };
}

// ---- unknown geo -------------------------------------------------------------------------
export function unknownModal() {
  let dv, sum, rank;
  const tok = ipTokens();
  return {
    title: 'Unknown GeoIP destinations', src: 'prom',
    mount(body) {
      sum = el('div');
      const s1 = section('Traffic per Unknown destination', 'Mbps · share of all flow bytes');
      rank = el('div');
      s1.body.append(rank, keyLegend(DIR_KEYS));
      dv = dataView('unknown', [{ key: 'ip', label: 'IP (masked)' }, { key: 'mbps', label: 'Mbps', num: true, fmt: fmtN(2) }, { key: 'share', label: 'Share %', num: true, fmt: fmtN(1) },
        { key: 'srcs', label: 'Source hosts', num: true }], { key: 'mbps', desc: true }, (r) => ({
        title: r.ip, badge: ['unknown', 'UNKNOWN'], cls: 'card-unknown', fields: [['Mbps', fixed(r.mbps, 2)], ['Share', fixed(r.share), '%'], ['Sources', r.srcs]], extra: shareBar(r.share),
      }), (r) => tok(r.rawIp));
      body.append(el('p', 'v-p', 'No GeoIP result: counted in all totals as Unknown, never given a guessed location (TC-007).'), sum, s1.wrap, listSection('All Unknown destinations', 'IPs masked (NFR-09)', dv).wrap);
    },
    async update(ctx) {
      if (!ctx.snap.flowsOk) {
        putIn(sum, flowsDownTiles(['Unknown destinations', 'Unknown traffic', 'Share of all flow', 'Source hosts']));
        putIn(rank, el('p', 'na', FLOWS_DOWN));
        dv.update([]);
        throw new Error(FLOWS_DOWN);
      }
      const all = totalBps(ctx.snap.flows);
      const unkFlows = ctx.snap.flows.filter((f) => f.lat === null);
      const groups = [...byKey(unkFlows, (f) => f.ip).values()].sort((a, b) => b.bps - a.bps);
      const ub = totalBps(unkFlows);
      putIn(sum, tiles([
        { label: 'Unknown destinations', value: groups.length, d: 0, kind: groups.length ? 'unknown' : 'ok', status: groups.length ? 'no GeoIP result' : 'none' },
        { label: 'Unknown traffic', value: mbps(ub), d: 2, unit: 'Mbps' },
        { label: 'Share of all flow', value: pct(ub, all), unit: '%' },
        { label: 'Source hosts', value: new Set(unkFlows.filter((f) => f.bps > 0).map((f) => f.src)).size, d: 0, sub: 'talking to Unknown' },
      ]));
      putIn(rank, rankBars(groups.map((g) => ({ label: maskIp(g.key), key: tok(g.key), value: mbps(g.bps), extra: shareText(pct(g.bps, all)), segs: dirSegs(g.flows), cls: 'rank-unknown',
        onOpen: () => ctx.nav.dest({ cc: 'Unknown', ip: g.key }) })), { head: ['IP (masked)', 'Mbps', 'share'], empty: 'no Unknown destinations' }));
      dv.update(groups.map((g) => ({ ip: maskIp(g.key), rawIp: g.key, mbps: mbps(g.bps), share: pct(g.bps, all), srcs: new Set(g.flows.filter((f) => f.bps > 0).map((f) => f.src)).size })),
        (r) => ctx.nav.dest({ cc: 'Unknown', ip: r.rawIp }));
    },
  };
}

// ---- WAN ----------------------------------------------------------------------------------
export function wanModal() {
  let secs = HOUR, sum, last;
  const traffic = chartBlock('tall'), util = chartBlock(), errs = chartBlock('small');
  const pts = (res) => (res?.[0]?.values || []).map(([t, v]) => [Number(t), Number(v)]);
  return {
    title: 'WAN — RTX1300 LAN2', src: 'prom',
    mount(body) {
      sum = el('div');
      const sel = rangeSelect([['1 h', HOUR], ['6 h', 6 * HOUR], ['24 h', 24 * HOUR]], secs, (v) => { secs = v; if (last) this.update(last).catch(() => {}); });
      const s1 = section('Throughput', 'Mbps'), s2 = section('Utilization', '% of link speed'), s3 = section('Errors', 'per minute');
      s1.head.append(sel);
      s1.body.append(traffic.wrap); s2.body.append(util.wrap); s3.body.append(errs.wrap);
      body.append(sum, s1.wrap, grid2(s2, s3));
    },
    async update(ctx) {
      last = ctx;
      const w = wanValues(ctx.snap.m);
      const down = pts(ctx.snap.sDown), up = pts(ctx.snap.sUp);
      const spark = (p, cls) => ({ series: [{ points: p, cls }], step: 15, t0: Date.now() / 1000 - 900, t1: Date.now() / 1000 });
      const uMax = has(w.utilD) || has(w.utilU) ? Math.max(w.utilD ?? 0, w.utilU ?? 0) : undefined;
      const uKind = !has(uMax) ? 'unknown' : uMax >= 90 ? 'crit' : uMax >= 70 ? 'warn' : 'ok';
      putIn(sum, tiles([
        { label: '↓ download now', value: w.down, unit: 'Mbps', sub: vsAvg(down, 1) && `15 min ${vsAvg(down, 1)}`, spark: spark(down, 'sp-1') },
        { label: '↑ upload now', value: w.up, unit: 'Mbps', sub: vsAvg(up, 1) && `15 min ${vsAvg(up, 1)}`, spark: spark(up, 'sp-2') },
        { label: 'Utilization ↓ / ↑', value: has(w.utilD) ? `${fixed(w.utilD)} / ${fixed(w.utilU)}` : undefined, unit: '%', kind: uKind,
          status: { ok: 'headroom', warn: 'busy (≥ 70 %)', crit: 'saturated (≥ 90 %)', unknown: 'unknown' }[uKind] },
        { label: 'Errors', value: w.err, unit: '/min', kind: has(w.err) ? (w.err > 0 ? 'warn' : 'ok') : 'unknown', status: has(w.err) ? (w.err > 0 ? 'errors seen' : 'none') : 'unknown' },
        { label: 'Link speed', value: has(w.speed) ? String(w.speed) : undefined, unit: 'Mbps' },
      ]));
      const sel = 'job="snmp",instance="rtx1300",ifName="lan2"';
      await Promise.all([
        drawRange(traffic, [{ q: `(rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↓ in' }, { q: `(rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↑ out' }], secs, 'Mbps', 'WAN throughput'),
        drawRange(util, [{ q: `(rate(ifHCInOctets{${sel}}[$RATE]) * 8 / (ifHighSpeed{${sel}} * 1e6) * 100) ${SNMP_UP}`, name: () => 'util ↓ %' },
          { q: `(rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / (ifHighSpeed{${sel}} * 1e6) * 100) ${SNMP_UP}`, name: () => 'util ↑ %' }], secs, '%', 'WAN utilization'),
        drawRange(errs, [{ q: `((rate(ifInErrors{${sel}}[$RATE]) + rate(ifOutErrors{${sel}}[$RATE])) * 60) ${SNMP_UP}`, name: () => 'errors /min' }], secs, '/min', 'WAN errors'),
      ]);
    },
  };
}

// ---- interfaces ----------------------------------------------------------------------------
export function ifacesModal() {
  let dv, sum, mult, chartSec, selKey = null, openBtn, last;
  const chart = chartBlock('tall'), tok = {};
  return {
    title: 'Interfaces — full table', src: 'prom',
    mount(body) {
      sum = el('div');
      const ms = section('Every interface, last 1 h', 'Mbps · same y-scale · click to select');
      mult = el('div');
      ms.body.append(mult, keyLegend(IO_KEYS));
      dv = dataView('ifaces', ifCols(), { key: 'inst' }, (r) => ({
        title: `${r.inst} ${r.ifName}`, sub: r.descr, badge: operBadge(r), cls: r.key === selKey ? 'card-sel' : '',
        fields: [['↓', fixed(r.in), 'Mbps'], ['↑', fixed(r.out), 'Mbps'], ['Util', fixed(r.util), '%'], ['Errors', fixed(r.err), '/min'], ['Speed', fixed(r.speed, 0), 'Mbps']],
        extra: shareBar(r.util),
      }), (r) => r.key);
      chartSec = section('Selected interface, last 1 h', 'click a row, card or mini chart to select');
      openBtn = linkBtn('open interface details →', () => last && selKey && last.nav.iface(selKey));
      openBtn.hidden = true;
      chartSec.head.append(openBtn);
      chartSec.body.append(chart.wrap);
      body.append(sum, ms.wrap, chartSec.wrap, listSection('All interfaces', '', dv).wrap);
    },
    async update(ctx) {
      last = ctx;
      const rows = ifaceRows(ctx.snap.m, ctx.seenIf);
      const select = (k) => { selKey = k; this.update(ctx).catch(() => {}); };
      const n = (t) => rows.filter((r) => r.operText === t).length;
      const busiest = [...rows].filter((r) => has(r.util)).sort((a, b) => b.util - a.util)[0];
      const err = sumDef(rows.map((r) => r.err));
      putIn(sum, tiles([
        { label: 'Oper UP', value: `${n('UP')} / ${rows.length}`, kind: n('UP') === rows.length ? 'ok' : 'warn', status: n('UP') === rows.length ? 'all up' : 'not all up' },
        { label: 'Oper DOWN', value: n('DOWN'), d: 0, kind: n('DOWN') ? 'warn' : 'ok', status: n('DOWN') ? 'link down' : 'none' },
        { label: 'UNKNOWN', value: n('UNKNOWN'), d: 0, kind: n('UNKNOWN') ? 'unknown' : 'ok', status: n('UNKNOWN') ? 'device not answering' : 'none' },
        { label: 'Busiest', value: busiest?.util, unit: '%', sub: busiest ? `${busiest.inst} ${busiest.ifName}` : undefined, ...(has(busiest?.util) && busiest.util >= 70 ? { kind: 'warn', status: 'busy (≥ 70 %)' } : {}) },
        { label: 'Errors (sum)', value: err, unit: '/min', kind: has(err) ? (err > 0 ? 'warn' : 'ok') : 'unknown', status: has(err) ? (err > 0 ? 'errors seen' : 'none') : 'unknown' },
      ]));
      dv.update(rows, (r) => select(r.key));
      const sel = 'job="snmp"';
      const multP = fetchRange(tok, [{ q: `(rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => 'in' }, { q: `(rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => 'out' }], HOUR)
        .then((r) => {
          if (!r) return;
          const key = (mt) => `${mt.instance}|${mt.ifName}`;
          const ins = seriesBy(r, 0, key), outs = seriesBy(r, 1, key);
          putIn(mult, multiples(rows.map((x) => ({
            label: `${x.inst} ${x.ifName}`, key: x.key, badge: operBadge(x), onOpen: () => select(x.key),
            series: [{ points: ins.get(x.key) || [], cls: 'sp-1' }, { points: outs.get(x.key) || [], cls: 'sp-2' }],
            vals: [['↓', fixed(x.in), 'Mbps'], ['↑', fixed(x.out), 'Mbps']],
          })), { t0: r.t0, t1: r.t1, step: r.step, max: maxOf(ins, outs) }));
          for (const c of mult.querySelectorAll('.mult')) c.classList.toggle('mult-sel', c.dataset.fkey === `details for ${selKey}`);
        });
      chart.wrap.hidden = !selKey; // no empty chart frame before anything is selected
      if (!selKey) { await multP; return; }
      const [inst, ifName] = selKey.split('|');
      chartSec.head.firstChild.textContent = `${inst} ${ifName}, last 1 h `;
      openBtn.hidden = false;
      const s = `instance=${lv(inst)},ifName=${lv(ifName)},job="snmp"`;
      await Promise.all([multP, drawRange(chart, [{ q: `(rate(ifHCInOctets{${s}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↓ in Mbps' }, { q: `(rate(ifHCOutOctets{${s}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↑ out Mbps' }], HOUR, 'Mbps', `${inst} ${ifName} traffic`)]);
    },
  };
}

// ---- wireless ---------------------------------------------------------------------------------
export function wlanModal() {
  let dv, sum, rank;
  const chart = chartBlock();
  return {
    title: 'Wireless clients (demo metric)', src: 'prom',
    mount(body) {
      sum = el('div');
      const s1 = section('Clients per AP / SSID', 'stacked by band');
      rank = el('div');
      s1.body.append(rank, keyLegend([{ cls: 'sw-1', name: '2.4 GHz' }, { cls: 'sw-2', name: '5 GHz' }]));
      const s2 = section('Clients by band, last 1 h', 'all APs');
      s2.body.append(chart.wrap);
      dv = dataView('wlan', [{ key: 'inst', label: 'AP' }, { key: 'ssid', label: 'SSID' }, { key: 'b24', label: '2.4 GHz', num: true, fmt: fmtN(0) },
        { key: 'b5', label: '5 GHz', num: true, fmt: fmtN(0) }, { key: 'total', label: 'Total', num: true, fmt: fmtN(0) }], { key: 'inst' }, (r) => ({
        title: r.ssid, sub: r.inst, badge: has(r.total) ? ['ok', 'LIVE'] : ['unknown', 'UNKNOWN'],
        fields: [['2.4 GHz', fixed(r.b24, 0)], ['5 GHz', fixed(r.b5, 0)], ['Total', fixed(r.total, 0)]],
      }), (r) => r.key);
      body.append(el('p', 'v-p', 'demo_wlan_clients is a synthetic metric; real WLX MIB availability is unconfirmed.'), sum, grid2(s1, s2), listSection('All AP / SSID', '', dv).wrap);
    },
    async update(ctx) {
      const rows = wlanRows(ctx.snap, ctx.seenWlan);
      const b24 = sumDef(rows.map((r) => r.b24)), b5 = sumDef(rows.map((r) => r.b5));
      const tot = has(b24) || has(b5) ? (b24 ?? 0) + (b5 ?? 0) : undefined;
      const aps = [...new Set(rows.map((r) => r.inst))];
      const live = aps.filter((a) => rows.some((r) => r.inst === a && has(r.total)));
      putIn(sum, tiles([
        { label: 'Clients (total)', value: tot, d: 0 },
        { label: '2.4 GHz', value: b24, d: 0, sub: has(tot) && tot ? `${shareText(pct(b24, tot))} of clients` : undefined },
        { label: '5 GHz', value: b5, d: 0, sub: has(tot) && tot ? `${shareText(pct(b5, tot))} of clients` : undefined },
        { label: 'APs reporting', value: `${live.length} / ${aps.length}`, kind: live.length === aps.length ? 'ok' : 'unknown', status: live.length === aps.length ? 'all reporting' : `no data: ${aps.filter((a) => !live.includes(a)).join(', ')}` },
      ]));
      putIn(rank, rankBars(rows.map((r) => ({ label: `${r.inst} ${r.ssid}`, value: r.total, extra: '',
        segs: [{ v: r.b24 ?? 0, cls: 'seg-1', name: '2.4 GHz' }, { v: r.b5 ?? 0, cls: 'seg-2', name: '5 GHz' }], onOpen: () => ctx.nav.device(r.inst) })), { unit: 'clients', d: 0, head: ['AP SSID', 'clients', ''], empty: 'no data' }));
      dv.update(rows, (r) => ctx.nav.device(r.inst));
      await drawRange(chart, [{ q: `sum by (band) (demo_wlan_clients ${SNMP_UP})`, name: (mt) => mt.band }], HOUR, 'clients', 'Wi-Fi clients by band');
    },
  };
}

// ---- alerts ------------------------------------------------------------------------------------
export function alertsModal() {
  let dv, sum, tl, last, secs = 6 * HOUR;
  const tok = {};
  return {
    title: 'Alerts — firing and pending', src: 'prom',
    mount(body) {
      sum = el('div');
      const s1 = section('Timeline', 'firing / pending spans per alert · resolved alerts included');
      s1.head.append(rangeSelect([['1 h', HOUR], ['6 h', 6 * HOUR], ['24 h', 24 * HOUR]], secs, (v) => { secs = v; if (last) this.update(last).catch(() => {}); }));
      tl = el('div');
      s1.body.append(tl, keyLegend(ALERT_KEYS));
      dv = dataView('alerts', [
        { key: 'state', label: 'State' }, { key: 'severity', label: 'Severity' }, { key: 'name', label: 'Alert' }, { key: 'instance', label: 'Instance' },
        { key: 'ifName', label: 'ifName' }, { key: 'activeAt', label: 'Active since (JST)', fmt: (v) => jstFull.format(new Date(v)) },
        { key: 'dur', label: 'Duration', num: true, fmt: (v) => fmtDur(v) }, { key: 'value', label: 'Value', num: true, fmt: fmtN(2) },
        { key: 'summary', label: 'Summary' },
      ], { key: 'dur', desc: true }, (r) => ({
        title: r.name, sub: [r.instance, r.ifName].filter(Boolean).join(' '), badge: sevKind(r.severity), cls: r.state === 'pending' ? 'card-pending' : '',
        fields: [['State', r.state], ['Active for', fmtDur(r.dur)], ['Since', jstFull.format(new Date(r.activeAt))], ['Value', fixed(r.value, 2)]],
        extra: r.summary ? el('p', 'card-note', r.summary) : null,
      }), (r) => maskText(alertKey(r.raw.labels)));
      body.append(sum, s1.wrap, listSection('Firing and pending alerts', '', dv).wrap);
    },
    async update(ctx) {
      last = ctx;
      const al = ctx.snap.alerts;
      const firing = al.filter((a) => a.state === 'firing');
      const cnt = (s) => firing.filter((a) => a.labels.severity === s).length;
      const crit = cnt('critical'), warn = cnt('warning');
      const longest = al.length ? Math.max(...al.map((a) => (Date.now() - Date.parse(a.activeAt)) / 1000)) : undefined;
      putIn(sum, tiles([
        { label: 'Firing', value: firing.length, d: 0, kind: crit ? 'crit' : warn ? 'warn' : firing.length ? 'info' : 'ok', status: crit ? 'critical firing' : warn ? 'warning firing' : firing.length ? 'info only' : 'all clear' },
        { label: 'Critical', value: crit, d: 0, ...(crit ? { kind: 'crit', status: 'firing' } : {}) },
        { label: 'Warning', value: warn, d: 0, ...(warn ? { kind: 'warn', status: 'firing' } : {}) },
        { label: 'Info / other', value: firing.length - crit - warn, d: 0 },
        { label: 'Pending', value: al.length - firing.length, d: 0, sub: 'waiting for the rule\'s for:' },
        { label: 'Longest active', value: has(longest) ? fmtDur(longest) : undefined },
      ]));
      dv.update(al.map((a) => ({
        state: a.state, severity: a.labels.severity, name: a.labels.alertname, instance: a.labels.instance, ifName: a.labels.ifName,
        activeAt: Date.parse(a.activeAt), dur: (Date.now() - Date.parse(a.activeAt)) / 1000, value: Number(a.value), summary: a.annotations.summary, raw: a,
      })), (r) => ctx.nav.alert(r.raw));
      const r = await fetchRange(tok, [{ q: 'ALERTS', name: () => '' }], secs);
      if (r) putIn(tl, timeline(alertLanes(r, al, ctx.nav), r.t0, r.t1, 'no alert was active in this window'));
    },
  };
}

// ---- syslog viewer ---------------------------------------------------------------------------------
const PAGE = 200;
const REJECTED = 'この条件は検索できません: 完全なアドレス / 部分アドレス (例 113.50) は指定できません。伏せた形 (例 203.0.113.x) で指定してください。';
export function logsModal(init = {}) {
  const f = { host: init.host || '', sev: init.sev || '', text: init.text || '', win: init.win || 900, follow: true };
  let list, count, more, scanNote, sum, chartBox, cs, staleTag, chartNote, entries = [], cursorEnd = null, partial = false, ctxRef, seq = 0, shown = null, chartShown = null;
  const ctok = {};
  const filterKey = () => `${query()}|${f.win}`; // which filter the lines on screen belong to
  const lineId = (x) => `${x.ts}|${x.host}|${x.sev}|${x.line}`;
  // unloaded: nothing on screen belongs to the current filter (first open, load failed, rejected)
  const listState = () => (shown !== filterKey() ? 'unloaded' : !entries.length && partial ? 'loaded-empty-partial' : 'loaded');
  // visible note for a partial scan and any server warnings (masked again here as a second guard)
  const showScan = (isPartial, warnings, until) => {
    const parts = [];
    if (isPartial) parts.push(`partial scan — more may exist (scanned back to ${jstFull.format(new Date(Number(BigInt(until) / 1000000n)))} JST); "load older lines" continues from there`);
    if (warnings.length) parts.push(warnings.map((w) => maskText(w)).join(' · '));
    scanNote.textContent = parts.join(' · ');
    scanNote.hidden = !parts.length;
  };
  const query = () => {
    const m = [`job="syslog"`];
    if (f.host) m.push(`host=${lv(f.host)}`);
    if (f.sev) m.push(`severity=${lv(f.sev)}`);
    return `{${m.join(',')}}${f.text ? ` |= ${logqlString(f.text)}` : ''}`;
  };
  async function load(reset) {
    const endNs = reset ? BigInt(Date.now()) * 1000000n : cursorEnd;
    const startNs = BigInt(Date.now() - f.win * 1000) * 1000000n;
    if (endNs <= startNs) { more.disabled = true; return; }
    const my = ++seq; // a newer filter change supersedes slower, older responses
    let got, res;
    try {
      res = await lokiLogs(query(), { startNs: String(startNs), endNs: String(endNs), limit: PAGE });
      got = res.entries;
    } catch (e) {
      if (my !== seq) throw e;
      if (e.rejected) {
        entries = [];
        shown = null;
        more.disabled = true;
        showScan(false, []);
        list.replaceChildren(el('div', 'na', REJECTED));
        count.textContent = 'filter rejected by server (NFR-09)';
        return;
      }
      if (reset && shown !== filterKey()) {
        // lines on screen belong to another filter: never leave them looking like this filter's result
        entries = [];
        shown = null;
        more.disabled = true;
        showScan(false, []);
        list.replaceChildren(el('div', 'na', 'load failed: results for this filter are not available (previous results cleared). Retrying on the next refresh.'));
        count.textContent = 'load failed · no results shown for the current filter';
      } else count.textContent = `${count.textContent.replace(/ · load failed.*$/, '')} · load failed, showing last loaded lines`;
      throw e;
    }
    if (my !== seq) return;
    shown = filterKey();
    // defense in depth: overlapping continuations must not show a line twice (identity = ts + stream labels + line)
    const have = new Set(reset ? [] : entries.map(lineId));
    entries = reset ? got : [...got.filter((x) => !have.has(lineId(x))), ...entries];
    // mask-api stopped scanning early (filtered query): the result is partial even with 0 or < PAGE matches, so
    // "load older" continues from where the scan stopped; only a complete short page means the window is exhausted
    partial = res.scannedUntil !== null;
    if (partial) cursorEnd = BigInt(res.scannedUntil);
    else if (got.length) cursorEnd = BigInt(got[0].ts) - 1n;
    more.disabled = !partial && got.length < PAGE;
    showScan(partial, res.warnings, res.scannedUntil);
    render();
  }
  // volume per severity for the same filter and window (tiles + stacked columns). Like the line list, the chart and
  // tiles on screen remember which filter produced them (chartShown): a failed load for another filter clears them,
  // a failed refresh of the same filter keeps them but marks them STALE until the next successful load.
  const markChart = (stale, note = '') => {
    for (const n of [sum, cs.wrap]) n.classList.toggle('vw-stale', stale);
    staleTag.hidden = !stale;
    chartNote.textContent = note;
  };
  async function chart() {
    const key = filterKey();
    const my = (ctok.seq || 0) + 1; // the seq sevBuckets() is about to take
    let r;
    try {
      r = await sevBuckets(ctok, query(), f.win);
    } catch (e) {
      if (key !== filterKey() || my !== ctok.seq) return; // superseded by a newer filter / request
      if (e.rejected) { chartShown = null; markChart(false); putIn(sum); putIn(chartBox, el('div', 'na', 'filter rejected by server (NFR-09): no chart')); return; }
      if (chartShown !== key) {
        chartShown = null;
        markChart(false);
        putIn(sum);
        putIn(chartBox, el('div', 'na', 'load failed: volume for this filter is not available (previous chart cleared). Retrying on the next refresh.'));
      } else markChart(true, 'load failed · showing the last loaded volume · retrying on the next refresh');
      throw e;
    }
    if (!r) return;
    chartShown = key;
    markChart(false);
    putIn(sum, sevTiles(r));
    putIn(chartBox, stackCols(r.cols, SEV_KEYS, r.t0, r.t1, `syslog lines per ${r.step / 60} min by severity`, undefined, r.warnings, r.edge));
  }
  const reload = () => Promise.all([load(true), chart()]).catch(() => {});
  function render() {
    refocus(list, () => list.replaceChildren(...[...entries].reverse().map((e) => logRow(e, ctxRef?.nav.logline))));
    if (!entries.length) list.appendChild(el('div', 'na', partial ? 'no matching lines in the part scanned so far — more may exist: load older lines to continue' : 'no lines match in window'));
    count.textContent = `${entries.length} line${entries.length === 1 ? '' : 's'} loaded · newest first${more.disabled ? ' · all lines in window loaded' : partial ? ' · partial scan' : ''}`;
  }
  const selectEl = (label, opts, val, on) => {
    const l = el('label', 'fld', label);
    const s = el('select');
    for (const [t, v] of opts) { const o = el('option', '', t); o.value = v; if (v === val) o.selected = true; s.appendChild(o); }
    s.addEventListener('change', () => on(s.value));
    l.appendChild(s);
    return l;
  };
  return {
    title: 'Syslog viewer', src: 'loki',
    mount(body) {
      const bar = el('form', 'filters');
      bar.addEventListener('submit', (e) => { e.preventDefault(); reload(); });
      bar.append(
        selectEl('Host', [['all', ''], ...DEVICES.map((d) => [d, d])], f.host, (v) => { f.host = v; reload(); }),
        selectEl('Severity', [['all', ''], ...SEV_LEVELS.map((x) => [x.name, x.k])], f.sev, (v) => { f.sev = v; reload(); }),
        selectEl('Window', [['15 min', '900'], ['1 h', '3600'], ['6 h', '21600']], String(f.win), (v) => { f.win = Number(v); reload(); }),
      );
      const tl = el('label', 'fld', 'Text contains');
      const ti = el('input');
      ti.type = 'search';
      ti.value = f.text;
      ti.placeholder = 'e.g. Rejected';
      ti.addEventListener('change', () => { f.text = ti.value; reload(); });
      tl.appendChild(ti);
      const fl = el('label', 'fld chk');
      const fc = el('input');
      fc.type = 'checkbox';
      fc.checked = f.follow;
      fc.addEventListener('change', () => { f.follow = fc.checked; });
      fl.append(fc, document.createTextNode(' follow live (newest page)'));
      bar.append(tl, fl);
      sum = el('div');
      cs = section('Volume by severity', 'lines per bucket for the current filter · empty column = 0 lines');
      staleTag = el('span', 'view-stale', 'STALE');
      staleTag.hidden = true;
      cs.head.append(staleTag);
      chartBox = el('div');
      chartNote = el('div', 'chart-note');
      cs.body.append(chartBox, chartNote);
      const ls = section('Lines');
      count = el('div', 'v-meta-line');
      scanNote = el('div', 'v-meta-line scan-note');
      scanNote.setAttribute('role', 'status');
      scanNote.hidden = true;
      list = el('div', 'v-logs tall');
      more = el('button', 'link-btn', 'load older lines');
      more.type = 'button';
      more.addEventListener('click', () => { f.follow = false; fc.checked = false; load(false).catch(() => {}); });
      ls.body.append(count, scanNote, list, more);
      body.append(bar, sum, cs.wrap, ls.wrap);
    },
    async update(ctx) {
      ctxRef = ctx;
      // polls reload the newest page only when following live or when nothing is loaded for this filter yet; a user's
      // "load older" continuation (follow off) is never reset, even when it has found 0 lines so far
      await Promise.all([f.follow || listState() === 'unloaded' ? load(true) : null, chart()]);
    },
  };
}

// ---- severity breakdown --------------------------------------------------------------------------
export function sevModal() {
  let dv, sum, rank, chartBox, win = 900, last, seq = 0;
  const ctok = {};
  const stack = (r) => {
    const box = el('div', 'stack');
    box.setAttribute('aria-hidden', 'true');
    for (const k of SEV_KEYS) if (r[k.k]) { const sg = el('span', `vw-seg ${k.cls}`); sg.style.width = `${(100 * r[k.k]) / (r.total || 1)}%`; box.append(sg); }
    return box;
  };
  return {
    title: 'Syslog severity — host × severity', src: 'loki',
    mount(body) {
      sum = el('div');
      const s0 = section('Volume by severity', 'all hosts · lines per bucket · empty column = 0 lines');
      s0.head.append(rangeSelect([['15 min', 900], ['1 h', 3600], ['6 h', 21600]], win, (v) => { win = v; if (last) this.update(last).catch(() => {}); }));
      chartBox = el('div');
      s0.body.append(chartBox);
      const s1 = section('Lines per host', 'stacked by severity · click for that host\'s lines');
      rank = el('div');
      s1.body.append(rank, keyLegend(SEV_KEYS));
      dv = dataView('sev', [{ key: 'host', label: 'Host' }, ...SEV_KEYS.map((x) => ({ key: x.k, label: x.name, num: true })), { key: 'total', label: 'Total', num: true }],
        { key: 'total', desc: true }, (r) => ({
          title: r.host, badge: SEV_BAD.some((k) => r[k]) ? ['crit', 'ERR'] : r.warning ? ['warn', 'WARN'] : ['ok', 'OK'],
          fields: [['Total', r.total], ...SEV_KEYS.filter((k) => r[k.k] || CORE_SEV.includes(k.k)).map((k) => [k.name, r[k.k]])], extra: stack(r),
        }), (r) => r.host);
      body.append(sum, s0.wrap, s1.wrap, listSection('Counts', 'host × severity in the window', dv).wrap);
    },
    async update(ctx) {
      last = ctx;
      const my = ++seq; // a newer range/poll request supersedes this one
      const [res, cr] = await Promise.all([lokiMetric(`sum by (host, severity) (count_over_time({job="syslog"}[${win}s]))`), sevBuckets(ctok, '{job="syslog"}', win)]);
      if (my !== seq) return;
      const rows = new Map();
      for (const r of res) {
        const h = r.metric.host || '?';
        const o = rows.get(h) || Object.fromEntries([['host', h], ...SEV_KEYS.map((x) => [x.k, 0]), ['total', 0]]); // query succeeded: absent = 0 events
        o[sevKey(r.metric.severity)] += Number(r.value[1]); // emergency / alert / debug / unexpected labels counted too
        o.total += Number(r.value[1]);
        rows.set(h, o);
      }
      const list = [...rows.values()].sort((a, b) => b.total - a.total);
      if (cr) {
        putIn(sum, sevTiles(cr));
        putIn(chartBox, stackCols(cr.cols, SEV_KEYS, cr.t0, cr.t1, `syslog lines per ${cr.step / 60} min by severity`, undefined, cr.warnings, cr.edge));
      }
      putIn(rank, rankBars(list.map((r) => ({ label: r.host, value: r.total, extra: '', segs: SEV_KEYS.map((k) => ({ v: r[k.k] || 0, cls: k.cls, name: k.name })),
        onOpen: () => ctx.nav.logs({ host: r.host, win }) })), { unit: 'lines', d: 0, head: ['host', 'lines', ''], empty: 'no lines in window' }));
      dv.update(list, (r) => ctx.nav.logs({ host: r.host, win }));
    },
  };
}

// ---- collection health ---------------------------------------------------------------------------
const FRESH_S = 60;
export function healthModal() {
  let dv, sum, ages;
  const dur = chartBlock('tall');
  return {
    title: 'Collection health — every target', src: 'prom',
    mount(body) {
      sum = el('div');
      const s1 = section('Scrape duration per target, last 1 h', 'ms');
      s1.body.append(dur.wrap);
      const s2 = section('Last sample age', `seconds · older than ${FRESH_S} s = stale`);
      ages = el('div');
      s2.body.append(ages, keyLegend([{ cls: 'sw-ok', name: 'UP' }, { cls: 'sw-crit', name: 'DOWN' }, { cls: 'sw-unknown', name: 'UNKNOWN' }]));
      dv = dataView('health', [
        { key: 'job', label: 'Job' }, { key: 'instance', label: 'Target' }, { key: 'upText', label: 'Up' },
        { key: 'durMs', label: 'Scrape ms', num: true, fmt: fmtN(0) }, { key: 'age', label: 'Last sample s ago', num: true, fmt: fmtN(0) },
      ], { key: 'job' }, (r) => ({
        title: maskText(r.instance), sub: r.job, badge: upBadge(r.up), fields: [['Scrape', fixed(r.durMs, 0), 'ms'], ['Last sample', fixed(r.age, 0), 's ago']],
      }), (r) => `${r.job}|${maskText(r.instance)}`);
      body.append(sum, grid2(s1, s2), listSection('Every target', 'click for the job', dv).wrap);
    },
    async update(ctx) {
      const ts = ctx.snap.targets.map((x) => ({ ...x, upText: x.up === 1 ? 'UP' : x.up === 0 ? 'DOWN' : 'UNKNOWN', durMs: has(x.dur) ? x.dur * 1000 : undefined }));
      const up = ts.filter((t) => t.up === 1).length;
      const down = ts.filter((t) => t.up !== 1);
      const slow = [...ts].filter((t) => has(t.durMs)).sort((a, b) => b.durMs - a.durMs)[0];
      const old = [...ts].filter((t) => t.up === 1 && has(t.age)).sort((a, b) => b.age - a.age)[0];
      putIn(sum, tiles([
        { label: 'Targets UP', value: `${up} / ${ts.length}`, kind: down.length ? 'crit' : 'ok', status: down.length ? `DOWN: ${down.map((t) => maskText(t.instance)).join(', ')}` : 'all scraping' },
        { label: 'Jobs', value: new Set(ts.map((t) => t.job)).size, d: 0 },
        { label: 'Slowest scrape', value: slow?.durMs, d: 0, unit: 'ms', sub: slow ? `${slow.job} ${maskText(slow.instance)}` : undefined },
        { label: 'Oldest sample (UP)', value: old?.age, d: 0, unit: 's', kind: has(old?.age) ? (old.age > FRESH_S ? 'warn' : 'ok') : 'unknown', status: has(old?.age) ? (old.age > FRESH_S ? 'stale sample' : 'fresh') : 'unknown' },
      ]));
      putIn(ages, rankBars([...ts].sort((a, b) => (b.age ?? -1) - (a.age ?? -1)).map((t) => ({
        label: `${t.job} ${maskText(t.instance)}`, value: t.age, extra: t.upText, cls: `rank-${upBadge(t.up)[0]}`, onOpen: () => ctx.nav.job(t.job),
      })), { unit: 's', d: 0, head: ['target', 's ago', 'up'] }));
      dv.update(ts, (r) => ctx.nav.job(r.job));
      await drawRange(dur, [{ q: 'scrape_duration_seconds * 1000', name: (mt) => `${mt.job} ${maskText(mt.instance)}` }], HOUR, 'ms', 'Scrape duration per target');
    },
  };
}
const upBadge = (v) => (v === 1 ? ['ok', 'UP'] : v === 0 ? ['crit', 'DOWN'] : ['unknown', 'UNKNOWN']);
