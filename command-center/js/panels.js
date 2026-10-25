// Wallboard panel renderers. Rows open related detail through the `nav` callbacks (drawer views).
import { $, el, cell, num, badge, row, head, bar, put, refocus, upState, has, fmtUptime, maskIp, maskText, cssVar, jstClock, SEV_SHORT, SEVERITIES } from './util.js';

export const DEVICES = ['rtx1300', 'wlx413', 'wlx222'];
export const WAN = { instance: 'rtx1300', ifName: 'lan2' };
const DEST_TOP = 10;
const SRC_TOP = 6;
const LOG_LINES = 8;

// ---- flows aggregation (shared with modal/drawer views) ------------------------------
export function byKey(flows, keyFn) {
  const m = new Map();
  for (const f of flows) {
    const k = keyFn(f);
    const g = m.get(k) || { key: k, bps: 0, flows: [] };
    g.bps += f.bps;
    g.flows.push(f);
    m.set(k, g);
  }
  return m;
}
export const totalBps = (flows) => flows.reduce((a, f) => a + f.bps, 0);

// Ranking list: label | bar | Mbps | share (share keeps Unknown in the denominator).
function rankRows(groups, total, labelHead, top, onOpen) {
  const sorted = [...groups].sort((a, b) => b.bps - a.bps);
  const shown = sorted.slice(0, top);
  const rest = sorted.slice(top);
  const max = shown.length ? shown[0].bps : 1;
  const rows = [head(labelHead, '', '#Mbps', '#SHARE %')];
  for (const g of shown) {
    const unknown = g.label === 'Unknown';
    rows.push(row([cell(unknown ? 'Unknown ?' : g.label, 'name'), bar((100 * g.bps) / max),
      num(g.bps / 1e6), num(total ? (100 * g.bps) / total : undefined)], unknown ? 'unknown-row' : '',
    () => onOpen(g), `details for ${g.label}`));
  }
  if (rest.length) {
    const sum = rest.reduce((a, g) => a + g.bps, 0);
    rows.push(row([cell(`+${rest.length} others`, 'sub'), bar((100 * sum) / max), num(sum / 1e6), num(total ? (100 * sum) / total : undefined)], 'sep'));
  }
  return rows;
}

export function renderFlows(snap, nav) {
  if (!snap.flowsOk) { // flow source DOWN: say so instead of an empty ranking (which would read as 0 Mbps)
    const msg = () => cell('flow source DOWN · UNKNOWN', 'sub');
    put('dest', [head('COUNTRY', '', '#Mbps', '#SHARE %'), row([msg(), cell(''), num(undefined), num(undefined)])]);
    put('src', [head('HOST', '', '#Mbps', '#SHARE %'), row([msg(), cell(''), num(undefined), num(undefined)])]);
    put('unknown', [head('DESTINATION (MASKED)', '#Mbps'), row([msg(), num(undefined)])]);
    return;
  }
  const total = totalBps(snap.flows);
  const byCountry = [...byKey(snap.flows, (f) => f.cc).values()].map((g) => ({ ...g, label: g.key }));
  put('dest', rankRows(byCountry, total, 'COUNTRY', DEST_TOP, (g) => nav.dest({ cc: g.key })));
  const bySrc = [...byKey(snap.flows, (f) => f.src).values()].map((g) => ({ ...g, label: g.key }));
  put('src', rankRows(bySrc, total, 'HOST', SRC_TOP, (g) => nav.src(g.key)));

  const unk = [...byKey(snap.flows.filter((f) => f.lat === null), (f) => f.ip).values()];
  const unkRows = [head('DESTINATION (MASKED)', '#Mbps')];
  for (const g of unk) unkRows.push(row([cell(maskIp(g.key), 'name'), num(g.bps / 1e6)], '', () => nav.dest({ cc: 'Unknown', ip: g.key }), `details for ${maskIp(g.key)}`));
  if (!unk.length) unkRows.push(row([cell('none', 'sub'), cell('')]));
  put('unknown', unkRows);
}

export function renderDevices(m, nav) {
  const rows = [head('', 'DEVICE', '#↓ Mbps', '#↑ Mbps', '#ERR/m', '#CLI', '#UPTIME')];
  for (const d of DEVICES) {
    const [kind, text] = upState(m.up.get(d));
    const ut = m.up.get(d) === 1 ? m.uptime.get(d) : undefined; // uptime of a DOWN/UNKNOWN target is not current
    const isWlx = d.startsWith('wlx');
    rows.push(row([badge(kind, text), cell(d.toUpperCase(), 'name'),
      num(m.devIn.get(d)), num(m.devOut.get(d)), num(m.devErr.get(d)),
      isWlx ? num(m.clients.get(d), 0) : cell('n/a', 'n sub', 'not applicable'),
      cell(has(ut) ? fmtUptime(ut) : '—', has(ut) ? 'n' : 'n na')], '', () => nav.device(d), `details for ${d}`));
  }
  put('devices', rows);
  const online = DEVICES.filter((d) => m.up.get(d) === 1).length;
  const known = DEVICES.filter((d) => m.up.has(d)).length;
  const hr = $('dev-online');
  hr.textContent = known ? `${online} / ${DEVICES.length} online` : `— / ${DEVICES.length} online`;
  hr.classList.toggle('crit', known > 0 && online < DEVICES.length);
}

export function drawSpark(id, series, color, stepS) {
  const c = $(id);
  const w = (c.width = c.clientWidth * devicePixelRatio);
  const h = (c.height = c.clientHeight * devicePixelRatio);
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const pts = series.length ? series[0].values.map(([t, v]) => [Number(t), Number(v)]) : [];
  if (pts.length < 2) return;
  const t1 = Date.now() / 1000, t0 = t1 - 900;
  const vmax = Math.max(10, ...pts.map((p) => p[1])) * 1.15;
  const x = (t) => ((t - t0) / (t1 - t0)) * w;
  const y = (v) => h - (v / vmax) * h;
  ctx.strokeStyle = color;
  ctx.lineWidth = 2 * devicePixelRatio;
  ctx.beginPath();
  pts.forEach(([t, v], i) => {
    const gap = i === 0 || t - pts[i - 1][0] > stepS * 2; // missing samples = gap, never 0
    if (gap) ctx.moveTo(x(t), y(v)); else ctx.lineTo(x(t), y(v));
  });
  ctx.stroke();
}

export function wanValues(m) {
  const key = `${WAN.instance}|${WAN.ifName}`;
  const down = m.ifIn.get(key), up = m.ifOut.get(key), speed = m.ifSpeed.get(key);
  return { key, down, up, speed, err: m.ifErr.get(key),
    utilD: has(down) && speed ? (100 * down) / speed : undefined, utilU: has(up) && speed ? (100 * up) / speed : undefined };
}

export function renderWan(snap) {
  const w = wanValues(snap.m);
  $('wan-down').textContent = has(w.down) ? Math.round(w.down) : '—';
  $('wan-up').textContent = has(w.up) ? Math.round(w.up) : '—';
  drawSpark('spark-down', snap.sDown, cssVar('--spark-1'), 15);
  drawSpark('spark-up', snap.sUp, cssVar('--spark-2'), 15);
  put('wan-foot', [
    row([cell('UTIL ↓', 'sub'), num(w.utilD, 1, '%'), cell(''), cell('UTIL ↑', 'sub'), num(w.utilU, 1, '%')]),
    row([cell('ERRORS', 'sub'), num(w.err, 1, '/min'), cell(''), cell('LINK SPEED', 'sub'), num(w.speed, 0, 'Mbps')]),
  ]);
}

// Interface inventory: everything seen in the last hour, so a DOWN target keeps its rows as UNKNOWN.
export function ifaceRows(m, seen) {
  for (const k of [...m.ifInv.keys(), ...m.ifSpeed.keys()]) seen.add(k);
  return [...seen].sort().map((k) => {
    const [inst, ifName] = k.split('|');
    const oper = m.ifOper.get(k);
    const i = m.ifIn.get(k), o = m.ifOut.get(k), sp = m.ifSpeed.get(k);
    return { key: k, inst, ifName, oper, operText: oper === 1 ? 'UP' : oper === 2 ? 'DOWN' : 'UNKNOWN', in: i, out: o, speed: sp,
      util: has(i) && has(o) && sp ? (100 * Math.max(i, o)) / sp : undefined, err: m.ifErr.get(k), descr: m.ifDescr.get(k) };
  });
}

export function renderInterfaces(snap, seen, nav) {
  const rows = [head('', 'INTERFACE', '#↓ Mbps', '#↑ Mbps', '#UTIL %', '#ERR/m')];
  for (const r of ifaceRows(snap.m, seen)) {
    const kind = r.oper === 1 ? 'ok' : r.oper === 2 ? 'warn' : 'unknown';
    rows.push(row([badge(kind, r.operText), cell(`${r.inst} ${r.ifName}`, 'name'), num(r.in), num(r.out), num(r.util), num(r.err)],
      '', () => nav.iface(r.key), `details for ${r.inst} ${r.ifName}`));
  }
  put('ifaces', rows);
}

export function wlanRows(snap, seen) {
  const cur = new Map();
  for (const r of snap.wlanInv) seen.add(`${r.metric.instance}|${r.metric.ssid}`);
  for (const r of snap.wlan) {
    seen.add(`${r.metric.instance}|${r.metric.ssid}`);
    cur.set(`${r.metric.instance}|${r.metric.ssid}|${r.metric.band}`, Number(r.value[1]));
  }
  return [...seen].sort().map((k) => {
    const [inst, ssid] = k.split('|');
    const a = cur.get(`${k}|2.4GHz`), b = cur.get(`${k}|5GHz`);
    return { key: k, inst, ssid, b24: a, b5: b, total: has(a) && has(b) ? a + b : undefined };
  });
}

export function renderWlan(snap, seen, nav) {
  const rows = [head('AP', 'SSID', '#2.4 GHz', '#5 GHz', '#TOTAL')];
  for (const r of wlanRows(snap, seen)) {
    rows.push(row([cell(r.inst, 'name'), cell(r.ssid), num(r.b24, 0), num(r.b5, 0), num(r.total, 0)], '', () => nav.device(r.inst), `details for ${r.inst}`));
  }
  if (rows.length === 1) rows.push(row([cell('no data', 'sub')]));
  put('wlan', rows);
}

export const sevKind = (s) => ({ critical: ['crit', 'CRIT'], warning: ['warn', 'WARN'] }[s] || ['info', (s || 'INFO').toUpperCase().slice(0, 4)]);

export function renderAlerts(alerts, nav) {
  const firing = alerts.filter((a) => a.state === 'firing');
  const rows = firing.map((a) => {
    const [kind, text] = sevKind(a.labels.severity);
    const where = [a.labels.instance, a.labels.ifName].filter(Boolean).join(' ');
    return row([badge(kind, text), cell(a.labels.alertname, 'name', a.annotations.summary), cell(where, 'n sub')], '', () => nav.alert(a), `details for ${a.labels.alertname} ${where}`);
  });
  if (!firing.length) rows.push(row([badge('none', ''), cell('no firing alerts', 'sub')]));
  put('alerts', rows);
  const box = $('alerts');
  const hidden = box.scrollHeight > box.clientHeight;
  $('alert-count').textContent = `${firing.length} firing${hidden ? ' · scroll for more' : ''}`;
  // Red-alert mode / banner only for critical or warning; info alerts are listed but do not alarm.
  const alarming = firing.filter((a) => ['critical', 'warning'].includes(a.labels.severity));
  const banner = $('alert-banner');
  document.body.classList.toggle('red-alert', alarming.length > 0);
  banner.hidden = alarming.length === 0;
  const names = [...new Set(alarming.map((a) => `${a.labels.alertname}${a.labels.instance ? ` (${a.labels.instance})` : ''}`))];
  banner.textContent = alarming.length ? `ALERT ■ ${alarming.length} FIRING: ${names.join(' · ')}` : '';
  banner.title = banner.textContent;
}

export function renderHealth(snap, nav) {
  const j = snap.jobs;
  const rows = [head('', 'JOB', '#UP', '#SCRAPE ms', '#AGE s')];
  for (const job of [...j.total.keys()].sort()) {
    const up = j.up.get(job), tot = j.total.get(job);
    const [kind, text] = up === tot ? ['ok', 'UP'] : up > 0 ? ['warn', 'PART'] : ['crit', 'DOWN'];
    rows.push(row([badge(kind, text), cell(job, 'name'), cell(`${up}/${tot}`, 'n'), num(j.dur.get(job) * 1000, 0), num(j.age.get(job), 0)],
      '', () => nav.job(job), `details for job ${job}`));
  }
  rows.push(row([badge('none', ''), cell('syslog received (alloy)', 'sub'), cell(''), num(snap.alloyRx, 2), cell('lines/s', 'n sub')], 'sep'));
  rows.push(row([badge('none', ''), cell('log ingest (loki)', 'sub'), cell(''), num(snap.lokiRx, 2), cell('lines/s', 'n sub')]));
  put('health', rows);

  // top status bar: coverage + freshness of UP targets only; DOWN targets are named instead of inflating the age
  const upAll = [...j.up.values()].reduce((a, b) => a + b, 0);
  const totAll = [...j.total.values()].reduce((a, b) => a + b, 0);
  $('k-cover').textContent = totAll ? `${upAll}/${totAll}` : '—';
  $('k-cover').className = `k-v ${upAll < totAll ? 'warn' : ''}`;
  const fresh = has(snap.freshUp) ? `max age ${snap.freshUp.toFixed(0)} s` : 'age —';
  $('k-fresh').textContent = snap.down.length ? `DOWN: ${snap.down.join(', ')}` : fresh;
  $('k-fresh').className = `u ${snap.down.length ? 'crit' : ''}`;
  $('k-fresh').title = `${fresh} for up targets${snap.down.length ? `; down: ${snap.down.join(', ')}` : ''}`;
}

export function renderSeverity(result, nav) {
  const by = new Map(result.map((r) => [r.metric.severity, Number(r.value[1])]));
  // Query succeeded: a severity absent from the result had 0 events in the window (a known 0, not missing data).
  const total = [...by.values()].reduce((a, b) => a + b, 0);
  const max = Math.max(1, ...by.values());
  const rows = [head('LEVEL', '', '#COUNT')];
  for (const s of SEVERITIES) {
    const v = by.get(s) || 0;
    rows.push(row([cell(SEV_SHORT[s], 'name'), bar((100 * v) / max), num(v, 0)], `sev-${s}`, () => nav.logs({ sev: s }), `syslog lines with severity ${s}`));
  }
  rows.push(row([cell('TOTAL', 'sub'), cell(''), num(total, 0)], 'sep'));
  put('sev', rows);
}

export function logRow(e, onOpen) {
  const time = jstClock.format(new Date(Number(e.ts.slice(0, 13))));
  const masked = maskText(e.line);
  const r = el('div', `log sev-${e.sev}`);
  r.title = `${time} ${e.host} ${e.sev} ${masked}`;
  r.append(el('span', 'log-t', time), el('span', 'log-h', e.host), el('span', 'log-s', SEV_SHORT[e.sev] || e.sev.toUpperCase()), el('span', 'log-m', masked));
  if (onOpen) {
    r.classList.add('clickable');
    r.tabIndex = 0;
    r.setAttribute('role', 'button');
    r.addEventListener('click', () => onOpen(e));
    r.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onOpen(e); } });
    r.setAttribute('aria-label', `context for syslog line ${time} ${e.host}`);
    r.dataset.fkey = `log ${e.ts} ${e.host}`;
  }
  return r;
}

export function renderLogs(entries, seenLogs, nav) {
  const box = $('logs');
  refocus(box, () => {
  for (const e of entries) {
    const key = `${e.ts}|${e.host}|${e.line}`;
    if (seenLogs.has(key)) continue;
    seenLogs.add(key);
    box.appendChild(logRow(e, nav.logline));
  }
  while (box.children.length > LOG_LINES) box.removeChild(box.firstChild);
  });
}
