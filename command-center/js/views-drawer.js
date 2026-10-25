// Detail drawer views: device, interface, destination, source host, alert, syslog line, collection job.
import { el, has, fixed, fmtUptime, fmtDur, maskIp, jstFull, upState } from './util.js';
import { lokiLogs, flattenStreams, promRules } from './api.js';
import { DEVICES, byKey, totalBps, ifaceRows, logRow, sevKind } from './panels.js';
import { section, kv, linkList, chartBlock, drawRange, mbps, lv, SNMP_UP, FLOWS_UP, FLOWS_DOWN } from './views-common.js';

const HOUR = 3600;
const nsOf = (ms) => BigInt(Math.round(ms)) * 1000000n;

function logList(host, entries, nav, markTs) {
  const box = el('div', 'v-logs');
  for (const e of entries) {
    const r = logRow(e, nav.logline);
    if (markTs && e.ts === markTs) r.classList.add('log-mark');
    box.appendChild(r);
  }
  if (!entries.length) box.appendChild(el('div', 'na', `no syslog lines from ${host} in window`));
  return box;
}

// ---- device ------------------------------------------------------------------------------
export function deviceView(name) {
  let s;
  const chart = chartBlock();
  return {
    title: `Device ${name.toUpperCase()}`, src: 'both',
    mount(body) {
      s = { sum: section('Status'), ifs: section('Interfaces'), chart: section('Traffic, last 1 h', 'sum of all interfaces, Mbps'),
        alerts: section('Related firing alerts'), logs: section('Syslog', `last 50 lines from ${name}`) };
      s.chart.body.append(chart.wrap);
      body.append(s.sum.wrap, s.ifs.wrap, s.chart.wrap, s.alerts.wrap, s.logs.wrap);
    },
    async update(ctx) {
      const { m } = ctx.snap;
      const [kind, text] = upState(m.up.get(name));
      const ut = m.up.get(name) === 1 ? m.uptime.get(name) : undefined;
      s.sum.body.replaceChildren(kv([
        ['Status', { text, cls: `st-text-${kind.split(' ')[0]}` }], ['Uptime', has(ut) ? fmtUptime(ut) : undefined],
        ['Traffic ↓ (sum)', fixed(m.devIn.get(name)), 'Mbps'], ['Traffic ↑ (sum)', fixed(m.devOut.get(name)), 'Mbps'],
        ['Errors', fixed(m.devErr.get(name)), '/min'],
        ['WLAN clients', name.startsWith('wlx') ? (m.clients.has(name) ? String(m.clients.get(name)) : undefined) : 'n/a'],
      ]));
      const ifs = ifaceRows(m, ctx.seenIf).filter((r) => r.inst === name);
      s.ifs.body.replaceChildren(linkList(ifs.map((r) => [`${r.operText.padEnd(7)} ${r.ifName}  ↓ ${fixed(r.in)} / ↑ ${fixed(r.out)} Mbps  util ${fixed(r.util)} %`, () => ctx.nav.iface(r.key), `if-${r.operText.toLowerCase()}`])));
      const rel = ctx.snap.alerts.filter((a) => a.state === 'firing' && a.labels.instance === name);
      s.alerts.body.replaceChildren(linkList(rel.map((a) => [`${sevKind(a.labels.severity)[1]}  ${a.labels.alertname} ${a.labels.ifName || ''}`, () => ctx.nav.alert(a)])));
      const sel = `instance=${lv(name)},job="snmp"`;
      const [, streams] = await Promise.all([
        drawRange(chart, [
          { q: `sum(rate(ifHCInOctets{${sel}}[$RATE]) ${SNMP_UP}) * 8 / 1e6`, name: () => '↓ in Mbps' },
          { q: `sum(rate(ifHCOutOctets{${sel}}[$RATE]) ${SNMP_UP}) * 8 / 1e6`, name: () => '↑ out Mbps' },
        ], HOUR, ''),
        lokiLogs(`{job="syslog",host=${lv(name)}}`, { startNs: String(nsOf(Date.now() - HOUR * 1000)), endNs: String(nsOf(Date.now())), limit: 50 }),
      ]);
      s.logs.body.replaceChildren(logList(name, flattenStreams(streams), ctx.nav));
    },
  };
}

// ---- interface ------------------------------------------------------------------------
export function ifaceView(key) {
  const [inst, ifName] = key.split('|');
  let s;
  const traffic = chartBlock(), errs = chartBlock('small');
  return {
    title: `Interface ${inst} ${ifName}`, src: 'prom',
    mount(body) {
      s = { sum: section('Status'), t: section('Traffic, last 1 h', 'Mbps'), e: section('Errors, last 1 h', 'per minute') };
      s.t.body.append(traffic.wrap);
      s.e.body.append(errs.wrap);
      body.append(s.sum.wrap, s.t.wrap, s.e.wrap);
    },
    async update(ctx) {
      const r = ifaceRows(ctx.snap.m, ctx.seenIf).find((x) => x.key === key) || { operText: 'UNKNOWN' };
      s.sum.body.replaceChildren(kv([
        ['Oper status', r.operText], ['Description', r.descr], ['Speed', has(r.speed) ? String(r.speed) : undefined, 'Mbps'],
        ['↓ in', fixed(r.in), 'Mbps'], ['↑ out', fixed(r.out), 'Mbps'], ['Utilization (max of in/out)', fixed(r.util), '%'],
        ['Errors', fixed(r.err), '/min'],
      ]), linkList([[`Parent device: ${inst.toUpperCase()}`, () => ctx.nav.device(inst)]]));
      const sel = `instance=${lv(inst)},ifName=${lv(ifName)},job="snmp"`;
      await Promise.all([
        drawRange(traffic, [
          { q: `(rate(ifHCInOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↓ in' },
          { q: `(rate(ifHCOutOctets{${sel}}[$RATE]) * 8 / 1e6) ${SNMP_UP}`, name: () => '↑ out' },
        ], HOUR, ''),
        drawRange(errs, [
          { q: `(rate(ifInErrors{${sel}}[$RATE]) * 60) ${SNMP_UP}`, name: () => 'in errors' },
          { q: `(rate(ifOutErrors{${sel}}[$RATE]) * 60) ${SNMP_UP}`, name: () => 'out errors' },
        ], HOUR, ''),
      ]);
    },
  };
}

// ---- destination (country / city / unknown IP) -------------------------------------------------
export function destView(d) {
  const label = d.ip ? `Unknown ${maskIp(d.ip)}` : d.city ? `${d.city}, ${d.cc}` : `Country ${d.cc}`;
  const match = (f) => (d.ip ? f.ip === d.ip : f.cc === d.cc && (!d.city || f.city === d.city));
  let s;
  const chart = chartBlock();
  return {
    title: `Destination ${label}`, src: 'prom',
    mount(body) {
      s = { sum: section('Summary'), ips: section('Destination IPs', 'masked (NFR-09)'), src: section('Source hosts talking to it'),
        t: section('Trend, last 1 h', 'Mbps by direction'), note: section('Geo confidence') };
      s.t.body.append(chart.wrap);
      body.append(s.sum.wrap, s.src.wrap, s.ips.wrap, s.t.wrap, s.note.wrap);
    },
    async update(ctx) {
      const ok = ctx.snap.flowsOk; // flow source DOWN: every figure is unknown ("—"), never 0
      const fl = ctx.snap.flows.filter(match);
      const all = totalBps(ctx.snap.flows);
      const bps = ok ? totalBps(fl) : undefined;
      const out = ok ? totalBps(fl.filter((f) => f.dir === 'outbound')) : undefined;
      s.sum.body.replaceChildren(kv([
        ['Country', d.cc], ['Cities', [...new Set(fl.map((f) => f.city).filter(Boolean))].join(', ') || undefined],
        ['ASN', [...new Set(fl.map((f) => f.asn).filter(Boolean))].join(', ') || undefined],
        ['Total', fixed(mbps(bps)), 'Mbps'], ['↓ inbound', fixed(mbps(bps - out)), 'Mbps'], ['↑ outbound', fixed(mbps(out)), 'Mbps'],
        ['Share of all flow bytes', all ? fixed((100 * bps) / all) : undefined, '%'],
      ]));
      const srcs = [...byKey(fl, (f) => f.src).values()].sort((a, b) => b.bps - a.bps);
      s.src.body.replaceChildren(ok ? linkList(srcs.map((g) => [`${g.key}  ${fixed(mbps(g.bps))} Mbps`, () => ctx.nav.src(g.key)])) : el('p', 'na', FLOWS_DOWN));
      const ips = [...byKey(fl, (f) => f.ip).values()].sort((a, b) => b.bps - a.bps);
      s.ips.body.replaceChildren(ok ? linkList(ips.map((g) => [`${maskIp(g.key)}  ${g.flows[0].city || '(no GeoIP)'}  ${fixed(mbps(g.bps))} Mbps`,
        () => ctx.nav.dest(g.flows[0].lat === null ? { cc: 'Unknown', ip: g.key } : { cc: g.flows[0].cc, city: g.flows[0].city })])) : el('p', 'na', FLOWS_DOWN));
      s.note.body.replaceChildren(el('p', 'v-p', d.cc === 'Unknown'
        ? 'No GeoIP result: counted as Unknown (kept in totals and shares); no location is estimated or drawn (TC-007).'
        : 'Location is a GeoIP estimate of the destination (synthetic in this demo). Arcs show a logical relation, not a physical route.'));
      const sel = d.ip ? `dst_ip=${lv(d.ip)}` : `dst_country=${lv(d.cc)}${d.city ? `,dst_city=${lv(d.city)}` : ''}`;
      await drawRange(chart, [{ q: `sum by (direction) (rate(demo_flow_bytes_total{${sel}}[$RATE]) ${FLOWS_UP}) * 8 / 1e6`, name: (mt) => mt.direction }], HOUR, '');
      if (!ok) throw new Error(FLOWS_DOWN);
    },
  };
}

// ---- source host ------------------------------------------------------------------------
export function srcView(host) {
  let s;
  const chart = chartBlock();
  return {
    title: `Source ${host}`, src: 'prom',
    mount(body) {
      s = { sum: section('Summary'), dst: section('Destinations', 'country / city / masked IP'), t: section('Trend, last 1 h', 'Mbps by direction') };
      s.t.body.append(chart.wrap);
      body.append(s.sum.wrap, s.dst.wrap, s.t.wrap);
    },
    async update(ctx) {
      const ok = ctx.snap.flowsOk; // flow source DOWN: every figure is unknown ("—"), never 0
      const fl = ctx.snap.flows.filter((f) => f.src === host);
      const bps = ok ? totalBps(fl) : undefined;
      const all = totalBps(ctx.snap.flows);
      s.sum.body.replaceChildren(kv([
        ['Total', fixed(mbps(bps)), 'Mbps'], ['Share of all flow bytes', all ? fixed((100 * bps) / all) : undefined, '%'],
        ['Destinations', ok ? String(new Set(fl.filter((f) => f.bps > 0).map((f) => f.ip)).size) : undefined],
      ]));
      const dst = [...byKey(fl, (f) => f.ip).values()].sort((a, b) => b.bps - a.bps);
      s.dst.body.replaceChildren(ok ? linkList(dst.map((g) => {
        const f = g.flows[0];
        return [`${f.cc.padEnd(8)} ${(f.city || '(no GeoIP)').padEnd(12)} ${maskIp(g.key)}  ${fixed(mbps(g.bps))} Mbps`,
          () => ctx.nav.dest(f.lat === null ? { cc: 'Unknown', ip: g.key } : { cc: f.cc, city: f.city })];
      })) : el('p', 'na', FLOWS_DOWN));
      await drawRange(chart, [{ q: `sum by (direction) (rate(demo_flow_bytes_total{src_host=${lv(host)}}[$RATE]) ${FLOWS_UP}) * 8 / 1e6`, name: (mt) => mt.direction }], HOUR, '');
      if (!ok) throw new Error(FLOWS_DOWN);
    },
  };
}

// ---- alert --------------------------------------------------------------------------------
const alertId = (a) => JSON.stringify(Object.entries(a.labels).sort());
export function alertView(alert0) {
  let s;
  let rules = null;
  const id = alertId(alert0);
  return {
    title: `Alert ${alert0.labels.alertname}`, src: 'both',
    mount(body) {
      s = { sum: section('State'), labels: section('Labels'), ann: section('Annotations'), rule: section('Rule', 'from /api/v1/rules'),
        rel: section('Related'), logs: section('Syslog around activation', '±5 min') };
      body.append(s.sum.wrap, s.labels.wrap, s.ann.wrap, s.rule.wrap, s.rel.wrap, s.logs.wrap);
    },
    async update(ctx) {
      const cur = ctx.snap.alerts.find((a) => alertId(a) === id);
      const a = cur || alert0;
      const active = Date.parse(a.activeAt);
      s.sum.body.replaceChildren(kv([
        ['State', cur ? a.state : 'no longer in the alert list (resolved)'], ['Severity', a.labels.severity],
        ['Active since', jstFull.format(new Date(active))], ['Duration', cur ? fmtDur((Date.now() - active) / 1000) : undefined],
        ['Value', has(Number(a.value)) ? fixed(Number(a.value), 2) : a.value],
      ]));
      s.labels.body.replaceChildren(kv(Object.entries(a.labels)));
      s.ann.body.replaceChildren(kv(Object.entries(a.annotations || {})));
      if (!rules) rules = await promRules();
      const rule = rules.find((r) => r.name === a.labels.alertname);
      s.rule.body.replaceChildren(rule ? kv([['Expression', rule.query], ['for', rule.duration ? `${rule.duration} s` : '0 s'], ['Rule health', rule.health]]) : el('p', 'na', 'rule not found'));
      const inst = a.labels.instance;
      const rel = [];
      if (DEVICES.includes(inst)) rel.push([`Device ${inst.toUpperCase()}`, () => ctx.nav.device(inst)]);
      if (DEVICES.includes(inst) && a.labels.ifName) rel.push([`Interface ${inst} ${a.labels.ifName}`, () => ctx.nav.iface(`${inst}|${a.labels.ifName}`)]);
      s.rel.body.replaceChildren(linkList(rel));
      if (DEVICES.includes(inst)) {
        const streams = await lokiLogs(`{job="syslog",host=${lv(inst)}}`, { startNs: String(nsOf(active - 300000)), endNs: String(nsOf(Math.min(Date.now(), active + 300000))), limit: 100 });
        s.logs.body.replaceChildren(logList(inst, flattenStreams(streams).slice(-40), ctx.nav));
      } else s.logs.body.replaceChildren(el('p', 'na', 'not a syslog-emitting device'));
    },
  };
}

// ---- syslog line context -------------------------------------------------------------------
export function loglineView(e) {
  let s;
  let around = null; // historical context does not change: fetched once, re-rendered on every mount (back / breadcrumb)
  return {
    title: `Syslog ${e.host}`, src: 'loki',
    mount(body) {
      s = { sum: section('Line'), ctx: section('Context', '±20 lines from the same host') };
      body.append(s.sum.wrap, s.ctx.wrap);
    },
    async update(ctx) {
      if (s.ctx.body.childElementCount) return; // already rendered into the current mount
      s.sum.body.replaceChildren(kv([['Time (JST)', jstFull.format(new Date(Number(e.ts.slice(0, 13))))], ['Host', e.host], ['Severity', e.sev]]),
        logList(e.host, [e], ctx.nav, e.ts), el('div', 'v-links'));
      s.sum.body.lastChild.append(linkList(DEVICES.includes(e.host) ? [[`Device ${e.host.toUpperCase()}`, () => ctx.nav.device(e.host)]] : []));
      if (!around) {
        const t = BigInt(e.ts);
        const streams = await lokiLogs(`{job="syslog",host=${lv(e.host)}}`, { startNs: String(t - 600000000000n), endNs: String(t + 600000000000n), limit: 1000, direction: 'forward' });
        const all = flattenStreams(streams);
        const i = Math.max(0, all.findIndex((x) => x.ts === e.ts && x.line === e.line));
        around = all.slice(Math.max(0, i - 20), i + 21);
      }
      s.ctx.body.replaceChildren(logList(e.host, around, ctx.nav, e.ts));
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
      s = { t: section('Targets'), d: section('Scrape duration, last 1 h', 'ms'), u: section('up, last 1 h', '1 = success, 0 = failed') };
      s.d.body.append(dur.wrap);
      s.u.body.append(up.wrap);
      body.append(s.t.wrap, s.d.wrap, s.u.wrap);
    },
    async update(ctx) {
      const ts = ctx.snap.targets.filter((t) => t.job === job);
      s.t.body.replaceChildren(linkList(ts.map((t) => [`${t.up === 1 ? 'UP  ' : 'DOWN'}  ${t.instance}  scrape ${fixed(t.dur * 1000, 0)} ms  last ${fixed(t.age, 0)} s ago`,
        () => (DEVICES.includes(t.instance) ? ctx.nav.device(t.instance) : null), t.up === 1 ? 'if-up' : 'if-down'])));
      await Promise.all([
        drawRange(dur, [{ q: `scrape_duration_seconds{job=${lv(job)}} * 1000`, name: (mt) => mt.instance }], HOUR, ''),
        drawRange(up, [{ q: `up{job=${lv(job)}}`, name: (mt) => mt.instance }], HOUR, ''),
      ]);
    },
  };
}
