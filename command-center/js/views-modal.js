// Panel-title modals: the full, unabridged data behind each wallboard panel (sortable tables, larger charts).
import { el, has, fixed, fmtUptime, fmtBytes, fmtDur, maskIp, jstFull, SEV_SHORT, SEVERITIES, sortTable, upState } from './util.js';
import { promQuery, lokiLogs, lokiMetric, flattenStreams, logqlString } from './api.js';
import { DEVICES, byKey, totalBps, ifaceRows, wlanRows, wanValues, logRow } from './panels.js';
import { section, kv, chartBlock, drawRange, rangeSelect, mbps, lv, linkBtn } from './views-common.js';

const fmtN = (d) => (v) => fixed(v, d);
const HOUR = 3600;

// ---- devices ------------------------------------------------------------------------------
export function devicesModal() {
  let t, ifSec;
  const subs = new Map(); // per-device interface tables are built once so their sort state survives refreshes
  return {
    title: 'Device status — all fields', src: 'prom',
    mount(body) {
      t = sortTable([
        { key: 'name', label: 'Device' }, { key: 'status', label: 'Status' }, { key: 'uptime', label: 'Uptime', num: true, fmt: (v) => (has(v) ? fmtUptime(v) : '—') },
        { key: 'in', label: '↓ Mbps', num: true, fmt: fmtN(1) }, { key: 'out', label: '↑ Mbps', num: true, fmt: fmtN(1) },
        { key: 'err', label: 'Errors /min', num: true, fmt: fmtN(1) }, { key: 'clients', label: 'WLAN clients', num: true, fmt: (v, r) => (r.name.startsWith('wlx') ? fixed(v, 0) : 'n/a') },
        { key: 'ifCount', label: 'Interfaces', num: true },
      ]);
      ifSec = section('Interfaces per device');
      for (const d of DEVICES) {
        const sub = sortTable(ifCols());
        subs.set(d, sub);
        const w = el('div', 'v-sub');
        w.append(el('h4', 'v-h4', d.toUpperCase()), sub.el);
        ifSec.body.appendChild(w);
      }
      body.append(t.el, ifSec.wrap);
    },
    async update(ctx) {
      const { m } = ctx.snap;
      const ifs = ifaceRows(m, ctx.seenIf);
      t.update(DEVICES.map((d) => ({ name: d, status: upState(m.up.get(d))[1], uptime: m.up.get(d) === 1 ? m.uptime.get(d) : undefined,
        in: m.devIn.get(d), out: m.devOut.get(d), err: m.devErr.get(d), clients: m.clients.get(d), ifCount: ifs.filter((r) => r.inst === d).length })), (r) => ctx.nav.device(r.name));
      for (const d of DEVICES) subs.get(d).update(ifs.filter((r) => r.inst === d), (r) => ctx.nav.iface(r.key));
    },
  };
}
const ifCols = () => [
  { key: 'operText', label: 'Oper' }, { key: 'inst', label: 'Device' }, { key: 'ifName', label: 'ifName' }, { key: 'descr', label: 'ifDescr' },
  { key: 'speed', label: 'Speed Mbps', num: true, fmt: fmtN(0) }, { key: 'in', label: '↓ Mbps', num: true, fmt: fmtN(1) },
  { key: 'out', label: '↑ Mbps', num: true, fmt: fmtN(1) }, { key: 'util', label: 'Util %', num: true, fmt: fmtN(1) }, { key: 'err', label: 'Errors /min', num: true, fmt: fmtN(1) },
];

// ---- destinations ------------------------------------------------------------------------
export function destModal() {
  let t;
  return {
    title: 'Destinations — all countries, cities and Unknown', src: 'prom',
    mount(body) {
      body.append(el('p', 'v-p', 'Share uses all flow bytes as the denominator (Unknown included). Bytes = increase over the last 15 min. IPs masked (NFR-09).'));
      t = sortTable([
        { key: 'cc', label: 'Country' }, { key: 'city', label: 'City' }, { key: 'asn', label: 'ASN' }, { key: 'ip', label: 'IP (masked)' },
        { key: 'mbps', label: 'Mbps', num: true, fmt: fmtN(2) }, { key: 'share', label: 'Share %', num: true, fmt: fmtN(1) },
        { key: 'bytes', label: 'Bytes / 15 min', num: true, fmt: (v) => (has(v) ? fmtBytes(v) : '—') }, { key: 'srcs', label: 'Source hosts', num: true },
      ], { key: 'mbps', desc: true });
      body.append(t.el);
    },
    async update(ctx) {
      const bytes = await promQuery('sum by (dst_ip) (increase(demo_flow_bytes_total[15m]))');
      const bmap = new Map(bytes.map((r) => [r.metric.dst_ip, Number(r.value[1])]));
      const all = totalBps(ctx.snap.flows);
      t.update([...byKey(ctx.snap.flows, (f) => f.ip).values()].map((g) => {
        const f = g.flows[0];
        return { cc: f.cc, city: f.city || '(no GeoIP)', asn: f.asn || undefined, ip: maskIp(g.key), rawIp: g.key, geo: f.lat !== null,
          mbps: mbps(g.bps), share: all ? (100 * g.bps) / all : undefined, bytes: bmap.get(g.key), srcs: new Set(g.flows.filter((x) => x.bps > 0).map((x) => x.src)).size };
      }), (r) => ctx.nav.dest(r.geo ? { cc: r.cc, city: r.city } : { cc: 'Unknown', ip: r.rawIp }));
    },
  };
}

// ---- sources ----------------------------------------------------------------------------
export function srcModal() {
  let t;
  return {
    title: 'Source hosts — all', src: 'prom',
    mount(body) {
      t = sortTable([
        { key: 'host', label: 'Host' }, { key: 'mbps', label: 'Mbps', num: true, fmt: fmtN(2) }, { key: 'out', label: '↑ out Mbps', num: true, fmt: fmtN(2) },
        { key: 'in', label: '↓ in Mbps', num: true, fmt: fmtN(2) }, { key: 'share', label: 'Share %', num: true, fmt: fmtN(1) }, { key: 'dests', label: 'Destinations', num: true },
      ], { key: 'mbps', desc: true });
      body.append(t.el);
    },
    async update(ctx) {
      const all = totalBps(ctx.snap.flows);
      t.update([...byKey(ctx.snap.flows, (f) => f.src).values()].map((g) => ({
        host: g.key, mbps: mbps(g.bps), out: mbps(totalBps(g.flows.filter((f) => f.dir === 'outbound'))), in: mbps(totalBps(g.flows.filter((f) => f.dir === 'inbound'))),
        share: all ? (100 * g.bps) / all : undefined, dests: new Set(g.flows.filter((f) => f.bps > 0).map((f) => f.ip)).size,
      })), (r) => ctx.nav.src(r.host));
    },
  };
}

// ---- unknown geo -------------------------------------------------------------------------
export function unknownModal() {
  let t;
  return {
    title: 'Unknown GeoIP destinations', src: 'prom',
    mount(body) {
      body.append(el('p', 'v-p', 'No GeoIP result: counted in all totals as Unknown, never given a guessed location (TC-007).'));
      t = sortTable([{ key: 'ip', label: 'IP (masked)' }, { key: 'mbps', label: 'Mbps', num: true, fmt: fmtN(2) }, { key: 'srcs', label: 'Source hosts', num: true }], { key: 'mbps', desc: true });
      body.append(t.el);
    },
    async update(ctx) {
      t.update([...byKey(ctx.snap.flows.filter((f) => f.lat === null), (f) => f.ip).values()].map((g) => ({
        ip: maskIp(g.key), rawIp: g.key, mbps: mbps(g.bps), srcs: new Set(g.flows.filter((f) => f.bps > 0).map((f) => f.src)).size,
      })), (r) => ctx.nav.dest({ cc: 'Unknown', ip: r.rawIp }));
    },
  };
}

// ---- WAN ----------------------------------------------------------------------------------
export function wanModal() {
  let secs = HOUR, sum, last;
  const traffic = chartBlock('tall'), util = chartBlock(), errs = chartBlock('small');
  return {
    title: 'WAN — RTX1300 LAN2', src: 'prom',
    mount(body) {
      sum = el('div');
      const sel = rangeSelect([['1 h', HOUR], ['6 h', 6 * HOUR], ['24 h', 24 * HOUR]], secs, (v) => { secs = v; if (last) this.update(last).catch(() => {}); });
      const s1 = section('Throughput', 'Mbps'), s2 = section('Utilization', '% of link speed'), s3 = section('Errors', 'per minute');
      s1.head.append(sel);
      s1.body.append(traffic.wrap); s2.body.append(util.wrap); s3.body.append(errs.wrap);
      body.append(sum, s1.wrap, s2.wrap, s3.wrap);
    },
    async update(ctx) {
      last = ctx;
      const w = wanValues(ctx.snap.m);
      sum.replaceChildren(kv([['↓ now', fixed(w.down), 'Mbps'], ['↑ now', fixed(w.up), 'Mbps'], ['Util ↓ / ↑', has(w.utilD) ? `${fixed(w.utilD)} / ${fixed(w.utilU)}` : undefined, '%'],
        ['Errors', fixed(w.err), '/min'], ['Link speed', has(w.speed) ? String(w.speed) : undefined, 'Mbps']]));
      const sel = 'job="snmp",instance="rtx1300",ifName="lan2"';
      await Promise.all([
        drawRange(traffic, [{ q: `rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6`, name: () => '↓ in' }, { q: `rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6`, name: () => '↑ out' }], secs, ''),
        drawRange(util, [{ q: `rate(ifHCInOctets{${sel}}[$RATE]) * 8 / (ifHighSpeed{${sel}} * 1e6) * 100`, name: () => 'util ↓ %' },
          { q: `rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / (ifHighSpeed{${sel}} * 1e6) * 100`, name: () => 'util ↑ %' }], secs, ''),
        drawRange(errs, [{ q: `(rate(ifInErrors{${sel}}[$RATE]) + rate(ifOutErrors{${sel}}[$RATE])) * 60`, name: () => 'errors /min' }], secs, ''),
      ]);
    },
  };
}

// ---- interfaces ----------------------------------------------------------------------------
export function ifacesModal() {
  let t, chartSec, selKey = null, openBtn, last;
  const chart = chartBlock('tall');
  return {
    title: 'Interfaces — full table', src: 'prom',
    mount(body) {
      t = sortTable(ifCols(), { key: 'inst' });
      chartSec = section('Selected interface, last 1 h', 'click a row to select');
      openBtn = linkBtn('open interface details →', () => last && selKey && last.nav.iface(selKey));
      openBtn.hidden = true;
      chartSec.head.append(openBtn);
      chartSec.body.append(chart.wrap);
      body.append(t.el, chartSec.wrap);
    },
    async update(ctx) {
      last = ctx;
      const rows = ifaceRows(ctx.snap.m, ctx.seenIf);
      t.update(rows, (r) => { selKey = r.key; this.update(ctx).catch(() => {}); });
      if (!selKey) { chart.note.textContent = 'no interface selected'; return; }
      const [inst, ifName] = selKey.split('|');
      chartSec.head.firstChild.textContent = `${inst} ${ifName}, last 1 h `;
      openBtn.hidden = false;
      const sel = `instance=${lv(inst)},ifName=${lv(ifName)},job="snmp"`;
      await drawRange(chart, [{ q: `rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6`, name: () => '↓ in Mbps' }, { q: `rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6`, name: () => '↑ out Mbps' }], HOUR, '');
    },
  };
}

// ---- wireless ---------------------------------------------------------------------------------
export function wlanModal() {
  let t;
  const chart = chartBlock('tall');
  return {
    title: 'Wireless clients (demo metric)', src: 'prom',
    mount(body) {
      body.append(el('p', 'v-p', 'demo_wlan_clients is a synthetic metric; real WLX MIB availability is unconfirmed.'));
      t = sortTable([{ key: 'inst', label: 'AP' }, { key: 'ssid', label: 'SSID' }, { key: 'band', label: 'Band' }, { key: 'clients', label: 'Clients', num: true, fmt: fmtN(0) }]);
      const s = section('Client count, last 1 h', 'per AP / SSID / band');
      s.body.append(chart.wrap);
      body.append(t.el, s.wrap);
    },
    async update(ctx) {
      const rows = wlanRows(ctx.snap, ctx.seenWlan).flatMap((r) => [{ inst: r.inst, ssid: r.ssid, band: '2.4GHz', clients: r.b24 }, { inst: r.inst, ssid: r.ssid, band: '5GHz', clients: r.b5 }]);
      t.update(rows, (r) => ctx.nav.device(r.inst));
      await drawRange(chart, [{ q: 'demo_wlan_clients', name: (mt) => `${mt.instance} ${mt.ssid} ${mt.band}` }], HOUR, '');
    },
  };
}

// ---- alerts ------------------------------------------------------------------------------------
export function alertsModal() {
  let t;
  return {
    title: 'Alerts — firing and pending', src: 'prom',
    mount(body) {
      t = sortTable([
        { key: 'state', label: 'State' }, { key: 'severity', label: 'Severity' }, { key: 'name', label: 'Alert' }, { key: 'instance', label: 'Instance' },
        { key: 'ifName', label: 'ifName' }, { key: 'activeAt', label: 'Active since (JST)', fmt: (v) => jstFull.format(new Date(v)) },
        { key: 'dur', label: 'Duration', num: true, fmt: (v) => fmtDur(v) }, { key: 'value', label: 'Value', num: true, fmt: fmtN(2) },
        { key: 'summary', label: 'Summary' },
      ], { key: 'dur', desc: true });
      body.append(t.el);
    },
    async update(ctx) {
      t.update(ctx.snap.alerts.map((a) => ({
        state: a.state, severity: a.labels.severity, name: a.labels.alertname, instance: a.labels.instance, ifName: a.labels.ifName,
        activeAt: Date.parse(a.activeAt), dur: (Date.now() - Date.parse(a.activeAt)) / 1000, value: Number(a.value), summary: a.annotations.summary, raw: a,
      })), (r) => ctx.nav.alert(r.raw));
    },
  };
}

// ---- syslog viewer ---------------------------------------------------------------------------------
const PAGE = 200;
export function logsModal(init = {}) {
  const f = { host: init.host || '', sev: init.sev || '', text: init.text || '', win: init.win || 900, follow: true };
  let list, count, more, entries = [], oldestNs = null, ctxRef, seq = 0;
  const query = () => {
    const m = [`job="syslog"`];
    if (f.host) m.push(`host=${lv(f.host)}`);
    if (f.sev) m.push(`severity=${lv(f.sev)}`);
    return `{${m.join(',')}}${f.text ? ` |= ${logqlString(f.text)}` : ''}`;
  };
  async function load(reset) {
    const endNs = reset ? BigInt(Date.now()) * 1000000n : oldestNs - 1n;
    const startNs = BigInt(Date.now() - f.win * 1000) * 1000000n;
    if (endNs <= startNs) { more.disabled = true; return; }
    const my = ++seq; // a newer filter change supersedes slower, older responses
    const got = flattenStreams(await lokiLogs(query(), { startNs: String(startNs), endNs: String(endNs), limit: PAGE }));
    if (my !== seq) return;
    entries = reset ? got : [...got, ...entries];
    if (got.length) oldestNs = BigInt(got[0].ts);
    more.disabled = got.length < PAGE;
    render();
  }
  function render() {
    list.replaceChildren(...[...entries].reverse().map((e) => logRow(e, ctxRef?.nav.logline)));
    if (!entries.length) list.appendChild(el('div', 'na', 'no lines match in window'));
    count.textContent = `${entries.length} line${entries.length === 1 ? '' : 's'} loaded · newest first${more.disabled ? ' · all lines in window loaded' : ''}`;
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
      bar.addEventListener('submit', (e) => { e.preventDefault(); load(true).catch(() => {}); });
      bar.append(
        selectEl('Host', [['all', ''], ...DEVICES.map((d) => [d, d])], f.host, (v) => { f.host = v; load(true).catch(() => {}); }),
        selectEl('Severity', [['all', ''], ...SEVERITIES.map((s) => [SEV_SHORT[s], s])], f.sev, (v) => { f.sev = v; load(true).catch(() => {}); }),
        selectEl('Window', [['15 min', '900'], ['1 h', '3600'], ['6 h', '21600']], String(f.win), (v) => { f.win = Number(v); load(true).catch(() => {}); }),
      );
      const tl = el('label', 'fld', 'Text contains');
      const ti = el('input');
      ti.type = 'search';
      ti.value = f.text;
      ti.placeholder = 'e.g. Rejected';
      ti.addEventListener('change', () => { f.text = ti.value; load(true).catch(() => {}); });
      tl.appendChild(ti);
      const fl = el('label', 'fld chk');
      const fc = el('input');
      fc.type = 'checkbox';
      fc.checked = f.follow;
      fc.addEventListener('change', () => { f.follow = fc.checked; });
      fl.append(fc, document.createTextNode(' follow live (newest page)'));
      bar.append(tl, fl);
      count = el('div', 'v-meta-line');
      list = el('div', 'v-logs tall');
      more = el('button', 'link-btn', 'load older lines');
      more.type = 'button';
      more.addEventListener('click', () => { f.follow = false; fc.checked = false; load(false).catch(() => {}); });
      body.append(bar, count, list, more);
    },
    async update(ctx) {
      ctxRef = ctx;
      if (f.follow || !entries.length) await load(true);
    },
  };
}

// ---- severity breakdown --------------------------------------------------------------------------
export function sevModal() {
  let t, win = 900, last, seq = 0;
  return {
    title: 'Syslog severity — host × severity', src: 'loki',
    mount(body) {
      const s = section('Counts', 'click a row to open the syslog viewer for that host');
      s.head.append(rangeSelect([['15 min', 900], ['1 h', 3600], ['6 h', 21600]], win, (v) => { win = v; if (last) this.update(last).catch(() => {}); }));
      t = sortTable([{ key: 'host', label: 'Host' }, ...SEVERITIES.map((sv) => ({ key: sv, label: SEV_SHORT[sv], num: true })), { key: 'total', label: 'Total', num: true }], { key: 'total', desc: true });
      s.body.append(t.el);
      body.append(s.wrap);
    },
    async update(ctx) {
      last = ctx;
      const my = ++seq; // a newer range/poll request supersedes this one
      const res = await lokiMetric(`sum by (host, severity) (count_over_time({job="syslog"}[${win}s]))`);
      if (my !== seq) return;
      const rows = new Map();
      for (const r of res) {
        const h = r.metric.host || '?';
        const o = rows.get(h) || Object.fromEntries([['host', h], ...SEVERITIES.map((sv) => [sv, 0]), ['total', 0]]); // query succeeded: absent = 0 events
        o[r.metric.severity] = (o[r.metric.severity] || 0) + Number(r.value[1]);
        o.total += Number(r.value[1]);
        rows.set(h, o);
      }
      t.update([...rows.values()], (r) => ctx.nav.logs({ host: r.host, win }));
    },
  };
}

// ---- collection health ---------------------------------------------------------------------------
export function healthModal() {
  let t;
  const dur = chartBlock('tall');
  return {
    title: 'Collection health — every target', src: 'prom',
    mount(body) {
      t = sortTable([
        { key: 'job', label: 'Job' }, { key: 'instance', label: 'Target' }, { key: 'upText', label: 'Up' },
        { key: 'durMs', label: 'Scrape ms', num: true, fmt: fmtN(0) }, { key: 'age', label: 'Last sample s ago', num: true, fmt: fmtN(0) },
      ], { key: 'job' });
      const s = section('Scrape duration per target, last 1 h', 'ms');
      s.body.append(dur.wrap);
      body.append(t.el, s.wrap);
    },
    async update(ctx) {
      t.update(ctx.snap.targets.map((x) => ({ ...x, upText: x.up === 1 ? 'UP' : x.up === 0 ? 'DOWN' : 'UNKNOWN', durMs: has(x.dur) ? x.dur * 1000 : undefined })), (r) => ctx.nav.job(r.job));
      await drawRange(dur, [{ q: 'scrape_duration_seconds * 1000', name: (mt) => `${mt.job} ${mt.instance}` }], HOUR, '');
    },
  };
}
