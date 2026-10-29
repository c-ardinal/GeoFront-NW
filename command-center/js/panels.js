// Wallboard panel renderers. Rows open related detail through the `nav` callbacks (drawer views).
import { $, el, cell, num, badge, row, head, bar, put, refocus, upState, has, fmtUptime, maskIp, maskText, cssVar, jstClock, SEV_KEYS, sevKey, sevName,
  WALLBOARD, LARGE, fitRows, uiZoom, setTicker, clearTicker, jstHm, fmtDur, now, isPlayback } from './util.js';

// The demo's three devices; replaced in place by the inventory (/obs/config.json) in prod, before the first render.
export const DEVICES = ['rtx1300', 'wlx413', 'wlx222'];
const WLX = new Set(['wlx413', 'wlx222']); // devices with a wireless client column
export function setDevices(list) {
  DEVICES.splice(0, DEVICES.length, ...list.map((d) => d.name));
  WLX.clear();
  // the device's driver says whether it has a client column (config.json `wireless`; older configs: kind wlx)
  for (const d of list) if (d.wireless ?? d.kind === 'wlx') WLX.add(d.name);
}
export const isWlx = (name) => WLX.has(name); // by the inventory kind's driver (demo: its two APs), never by name
// WAN interface: the demo's rtx1300 lan2; in prod the inventory's wan_interface (setWan). instance null = not configured.
export const WAN = { instance: 'rtx1300', ifName: 'lan2' };
// Exposure of the screens for the LAN indicator: a fresh exposure.json, else a fresh config.json (it carries OBS_BIND),
// else the remembered answers, which can only raise the warning: a remembered LAN address is still shown as LAN, a
// remembered loopback is not trusted (OBS_BIND may have changed since) -> "unknown". kind: local | lan | unknown.
// Deployment config changes (first answer after a timeout, `tools targets` with a new inventory): the screen is set
// up from config.json once at load, so a different config means reloading the page. Reloaded only while the wallboard
// is showing; during an investigation it waits until the user is back on the wallboard (Esc / BACK TO LIVE / idle).
const sortKeys = (v) => (Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v);
export const configDigest = (cfg) => (cfg ? JSON.stringify(sortKeys(cfg)) : null);
// The mode is re-read RELOAD_SETTLE_MS after the last notification: moving from a modal to a drawer briefly passes
// through WALLBOARD (closeModal, then the drawer opens), which must not count as being back on the wallboard.
const RELOAD_SETTLE_MS = 300;
export function configWatcher(applied, { mode, reload, defer = (f) => setTimeout(f, RELOAD_SETTLE_MS), cancel = clearTimeout }) {
  const appliedDigest = configDigest(applied);
  let pending = false;
  let timer = null;
  const due = () => {
    if (!pending) return;
    if (timer !== null) cancel(timer);
    timer = defer(() => {
      timer = null;
      if (pending && mode() === 'WALLBOARD') { pending = false; reload(); }
    });
  };
  return {
    offer(fresh) { // a freshly fetched config (never a remembered one)
      if (fresh && configDigest(fresh) !== appliedDigest) { pending = true; due(); }
    },
    modeChanged: due,
  };
}
const isLocalBind = (b) => /^127\./.test(b) || b === 'localhost' || b === '::1';
export function exposureOf(freshExp, freshCfg, cachedExp, cachedCfg) {
  // with the login (P7) the screens are not open to the LAN: nothing to warn about (a remembered answer counts: the
  // session may just have ended)
  if (freshExp?.access === 'auth' || (!freshExp && cachedExp?.access === 'auth')) {
    return { kind: 'auth', bind: String(freshExp?.bind || cachedExp?.bind || ''), cached: !freshExp };
  }
  const fresh = freshExp?.bind || freshCfg?.bind;
  if (fresh) return { kind: isLocalBind(String(fresh)) ? 'local' : 'lan', bind: String(fresh), cached: false };
  const old = cachedExp?.bind || cachedCfg?.bind;
  if (old && !isLocalBind(String(old))) return { kind: 'lan', bind: String(old), cached: true };
  return { kind: 'unknown', bind: old ? String(old) : '', cached: !!old };
}
export const WAN_NOT_CONFIGURED = 'WAN interface not configured';
export function setWan(w) {
  WAN.instance = typeof w?.device === 'string' && typeof w?.ifName === 'string' ? w.device : null;
  WAN.ifName = WAN.instance ? w.ifName : null;
}
export const wanSel = () => `job="snmp",instance="${WAN.instance}",ifName="${WAN.ifName}"`;
export const wanLabel = () => (WAN.instance ? `WAN · ${WAN.instance.toUpperCase()} ${WAN.ifName.toUpperCase()}` : 'WAN');
// Wireless clients: demo_wlan_clients is synthetic; in prod the WLX MIB for client counts is unconfirmed (values unknown).
export const WLAN = { unconfirmed: false };
// Missing flow data: the flow source is DOWN (STALE), or no flow source is configured (prod before P3: neutral).
// views-common.setNoFlowSource() switches the texts.
export const FLOW_TEXT = { status: 'flow source DOWN', row: 'flow source DOWN · UNKNOWN', arcs: 'flow source DOWN · arcs UNKNOWN' };
const DEST_TOP = 10;
const SRC_TOP = 6;
const UNKNOWN_TOP = 4;
const LOG_LINES = 8;
const ROW_PX = 22; // --row
const LOG_PX = 20; // #logs line-height

// Wallboard panels have a layout-defined height: a list shows as many rows as fit there (never more, so nothing is cut
// off; on large screens at least the desktop count, so extra height fills with rows). Tablet/phone panels grow with
// their content and use the base count.
function capacity(box, base, rowPx) {
  if (!WALLBOARD.matches) return base;
  const fit = fitRows(box, rowPx);
  return LARGE.matches ? Math.max(base, fit) : Math.min(base, fit);
}
// LARGE: the listed panels of a column keep their natural height (flex-basis). Spare height goes only to the `flex`
// panels, which turn it into more rows (the capacity-fitted ranking, the scrolling alert list) and give it back when the
// column is too short; rows never grow taller, so the row pitch stays the same in every panel.
// items: [panelId, flex, naturalPx?]; elsewhere the CSS layout applies.
function shareHeight(items) {
  for (const [pid] of items) $(pid).style.flex = LARGE.matches ? '0 0 auto' : '';
  if (!LARGE.matches) return;
  const need = items.map(([pid, , px]) => px ?? $(pid).offsetHeight);
  items.forEach(([pid, flex], i) => { $(pid).style.flex = `${flex ? 1 : 0} ${flex ? 1 : 0} ${need[i]}px`; });
}

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

// Ranking list: label | bar | Mbps | share (share keeps Unknown in the denominator). maxRows counts the head row and
// the "+N others" row.
function rankRows(groups, total, labelHead, maxRows, onOpen) {
  const sorted = [...groups].sort((a, b) => b.bps - a.bps);
  const shown = sorted.slice(0, Math.max(1, maxRows - 2));
  const rest = sorted.slice(shown.length);
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
    const msg = () => cell(FLOW_TEXT.row, 'sub');
    const wide = () => { const c = msg(); c.style.gridColumn = 'span 2'; return c; }; // label + bar columns: the text stays readable
    put('dest', [head('COUNTRY', '', '#Mbps', '#SHARE %'), row([wide(), num(undefined), num(undefined)])]);
    put('src', [head('HOST', '', '#Mbps', '#SHARE %'), row([wide(), num(undefined), num(undefined)])]);
    put('unknown', [head('DESTINATION (MASKED)', '#Mbps'), row([msg(), num(undefined)])]);
    return;
  }
  const total = totalBps(snap.flows);
  const byCountry = [...byKey(snap.flows, (f) => f.cc).values()].map((g) => ({ ...g, label: g.key }));
  // content-sized panel: capped so a long list cannot squeeze the panels above it; the rest is summed (full list in the modal)
  const unk = [...byKey(snap.flows.filter((f) => f.lat === null), (f) => f.ip).values()].sort((a, b) => b.bps - a.bps);
  const unkShown = unk.length > UNKNOWN_TOP + 1 ? unk.slice(0, UNKNOWN_TOP) : unk;
  const unkRows = [head('DESTINATION (MASKED)', '#Mbps')];
  for (const g of unkShown) unkRows.push(row([cell(maskIp(g.key), 'name'), num(g.bps / 1e6)], '', () => nav.dest({ cc: 'Unknown', ip: g.key }), `details for ${maskIp(g.key)}`));
  if (unkShown.length < unk.length) {
    const rest = unk.slice(unkShown.length);
    unkRows.push(row([cell(`+${rest.length} others`, 'sub'), num(rest.reduce((a, g) => a + g.bps, 0) / 1e6)], 'sep'));
  }
  if (!unk.length) unkRows.push(row([cell('none', 'sub'), cell('')]));
  put('unknown', unkRows);
  // after the content-sized panels below it, so the ranking is measured against its final height
  const bySrc = [...byKey(snap.flows, (f) => f.src).values()].map((g) => ({ ...g, label: g.key }));
  // dest wants every country (+ head); its rows beyond the panel are summed into "+N others" by capacity()
  const destBox = $('dest');
  const destNeed = destBox.offsetTop + 2 * parseFloat(getComputedStyle(destBox).paddingTop) + 2 + (byCountry.length + 1) * ROW_PX;
  put('src', rankRows(bySrc, total, 'HOST', SRC_TOP + 2, (g) => nav.src(g.key))); // content-sized: measured below
  shareHeight([['p-dest', true, destNeed], ['p-src', false]]);
  put('dest', rankRows(byCountry, total, 'COUNTRY', capacity($('dest'), DEST_TOP + 2, ROW_PX), (g) => nav.dest({ cc: g.key })));
}

// right column on LARGE screens: interfaces / wireless / alerts share the height
export function fitRightColumn() {
  shareHeight([['p-if', false], ['p-wlan', false], ['p-alerts', true]]);
}

// Last seen (seconds since the last successful SNMP scrape), DOWN devices included; a device known to Prometheus
// without a success in the last LAST_SEEN_MAX_S counts as that bound (shown "> 15 min"); not known at all: undefined.
// Thresholds as the freshness of the screens: >= 45 s late, >= 120 s stale.
export const LAST_SEEN_MAX_S = 900;
export const lastSeen = (m, d) => (m.lastOk.has(d) ? Math.min(m.lastOk.get(d), LAST_SEEN_MAX_S) : m.up.has(d) ? LAST_SEEN_MAX_S : undefined);
export const fmtSeen = (v) => (!has(v) ? '—' : v >= LAST_SEEN_MAX_S ? '> 15 min' : `${v.toFixed(0)} s`);
export const seenKind = (v) => (!has(v) ? 'unknown' : v >= 120 ? 'crit' : v >= 45 ? 'warn' : 'ok');

export function renderDevices(m, nav) {
  const rows = [head('', 'DEVICE', '#↓ Mbps', '#↑ Mbps', '#ERR/m', '#CLI', '#UPTIME')];
  for (const d of DEVICES) {
    const [kind, text] = upState(m.up.get(d));
    const ut = m.up.get(d) === 1 ? m.uptime.get(d) : undefined; // uptime of a DOWN/UNKNOWN target is not current
    rows.push(row([badge(kind, text), cell(d.toUpperCase(), 'name'),
      num(m.devIn.get(d)), num(m.devOut.get(d)), num(m.devErr.get(d)),
      isWlx(d) ? num(m.clients.get(d), 0) : cell('n/a', 'n sub', 'not applicable'),
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
  const px = devicePixelRatio * uiZoom();
  const w = (c.width = c.clientWidth * px);
  const h = (c.height = c.clientHeight * px);
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const pts = series.length ? series[0].values.map(([t, v]) => [Number(t), Number(v)]) : [];
  if (pts.length < 2) return;
  const t1 = now() / 1000, t0 = t1 - 900;
  const vmax = Math.max(10, ...pts.map((p) => p[1])) * 1.15;
  const x = (t) => ((t - t0) / (t1 - t0)) * w;
  const y = (v) => h - (v / vmax) * h;
  ctx.strokeStyle = color;
  ctx.lineWidth = 2 * px;
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
  if (!WAN.instance) { // nothing to measure: say so, never 0 and never STALE
    $('wan-down').textContent = '—';
    $('wan-up').textContent = '—';
    drawSpark('spark-down', [], cssVar('--spark-1'), 15);
    drawSpark('spark-up', [], cssVar('--spark-2'), 15);
    const note = cell(WAN_NOT_CONFIGURED, 'sub');
    note.style.gridColumn = '1 / -1'; // the whole foot row, not its first (label-width) column
    put('wan-foot', [row([note])]);
    return;
  }
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
  if (rows.length === 1 && WLAN.unconfirmed) { // prod: one unknown row per access point, never 0 clients
    for (const d of DEVICES.filter(isWlx)) {
      rows.push(row([cell(d, 'name'), cell('MIB unconfirmed', 'sub'), num(undefined, 0), num(undefined, 0), num(undefined, 0)], '', () => nav.device(d), `details for ${d}`));
    }
  }
  if (rows.length === 1) rows.push(row([cell('no data', 'sub')]));
  put('wlan', rows);
}

export const sevKind = (s) => ({ critical: ['crit', 'CRIT'], warning: ['warn', 'WARN'] }[s] || ['info', (s || 'INFO').toUpperCase().slice(0, 4)]);

// notify(alert) -> its notification state (alerting.js notifyState): a fixed-width slot per row (通知済 / 抑止中 /
// 確認済 / 未通知 / ...), the next repeat time in the large-screen detail line
export function renderAlerts(alerts, nav, notify) {
  const firing = alerts.filter((a) => a.state === 'firing');
  const rows = firing.map((a) => {
    const [kind, text] = sevKind(a.labels.severity);
    const where = [a.labels.instance, a.labels.ifName].filter(Boolean).join(' ');
    const nt = notify(a);
    const slot = badge(`${nt.kindClass} nt nt-${nt.kind}`, nt.label);
    slot.title = nt.text;
    // detail line (since / value / summary) is shown on large screens only (style.css), where the panel has room
    const since = Date.parse(a.activeAt);
    const detail = [Number.isFinite(since) && `since ${jstHm.format(new Date(since))} (${fmtDur((now() - since) / 1000)})`,
      a.value !== undefined && `value ${Number(a.value).toPrecision(3)}`, nt.nextText, a.annotations.summary].filter(Boolean).join(' · ');
    const r = row([badge(kind, text), cell(a.labels.alertname, 'name', a.annotations.summary), cell(where, 'n sub'), slot, cell(detail, 'al-detail sub')],
      '', () => nav.alert(a), `details for ${a.labels.alertname} ${where}`); // label = focus key: stays the same when the state changes
    r.setAttribute('aria-label', `details for ${a.labels.alertname} ${where}, notification: ${nt.label}`);
    return r;
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
  // PLAYBACK: the banner slot always shows "履歴再生 HH:MM:SS" (the time of the data on screen, fixed width), followed by
  // the alerts that were alarming then; it is neutral (not red) when there were none
  const pb = isPlayback();
  const pbText = pb ? `履歴再生 ${jstClock.format(new Date(now()))}` : '';
  banner.classList.toggle('pb-banner', pb);
  banner.classList.toggle('pb-quiet', pb && !alarming.length);
  banner.hidden = !pb && alarming.length === 0;
  const names = [...new Set(alarming.map((a) => `${a.labels.alertname}${a.labels.instance ? ` (${a.labels.instance})` : ''}`))];
  // Counts: the banner counts the alarming (critical + warning) alerts it names plus the total of firing alerts (incl.
  // info), which the alerts list header and tab also show. Counts sit in fixed-width slots and the prefix keeps one
  // shape, so 9 -> 10 alerts or an info alert appearing never shifts the names.
  // Every alarming name stays readable: the banner scrolls (ticker) when they do not fit on one line.
  const total = ` · ${firing.length} total`;
  const totalEl = el('span', 'tk-total');
  totalEl.append(' · ', el('span', 'tk-n', firing.length), ' total');
  const pbTag = () => (pb ? [el('span', 'tk-pb', pbText)] : []);
  const lead = [...pbTag(), el('span', 'tk-tag', 'ALERT ■ '), el('span', 'tk-n', alarming.length), ' CRIT/WARN', totalEl, ':'];
  if (alarming.length) setTicker(banner, lead, names.join(' · '));
  else if (pb) setTicker(banner, pbTag(), firing.length ? `no CRIT/WARN alerts at this time · ${firing.length} info` : 'no firing alerts at this time');
  else clearTicker(banner);
  banner.title = `${pb ? `${pbText} (data time, JST) · ` : ''}${alarming.length ? `ALERT ■ ${alarming.length} CRIT/WARN${total}: ${names.join(' · ')}` : pb ? 'no CRIT/WARN alerts at this time' : ''}`;
  // the banner is a button (always focusable while shown: tabindex in the markup); the announcement is a separate
  // live region, updated only when the alert set changes
  banner.setAttribute('aria-label', `${pb ? `${pbText}. ` : ''}${alarming.length ? `${alarming.length} critical or warning alerts firing: ${names.join(', ')}. Open the alert list` : 'No alerts'}`);
  const said = alarming.length ? `Alert: ${alarming.length} firing: ${names.join(', ')}` : '';
  if ($('alert-sr').textContent !== said) $('alert-sr').textContent = said;
  $('tab-alert-n').textContent = firing.length || '';
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
  const c = snap.capture; // capture profile only: flowd reports the capture service's state
  if (c) {
    const [kind, text] = c.up !== 1 ? ['crit', 'DOWN'] : c.drops > 0 || c.dumpDrops > 0 || c.over === 1 ? ['warn', 'DROP'] : ['ok', 'UP'];
    const why = c.over === 1 ? 'ring over its size limit' : `NIC rx drops in 5 min; dumpcap drops (ended sessions, 1 h): ${c.dumpDrops ?? '—'}`;
    rows.push(row([badge(kind, text), cell('packet capture', 'sub', why), cell(''), num(c.drops, 0), cell('NIC drop/5m', 'n sub')],
      '', () => nav.packets(), 'packet capture: open packet analysis'));
  }
  if (c || snap.geo.months.length) {
    const age = snap.geo.ageDays;
    const [kind, text] = age === null ? ['unknown', 'NONE'] : age > 45 ? ['warn', 'OLD'] : ['ok', 'OK'];
    rows.push(row([badge(kind, text), cell('GeoIP DB (DB-IP Lite)', 'sub', 'IP Geolocation by DB-IP, CC BY 4.0'), cell(''), num(age ?? undefined, 0), cell('days old', 'n sub')]));
  }
  put('health', rows);

}

// The five usual levels are always listed; emergency / alert / debug / unrecognised ("other") only when they have
// lines, so the rows always add up to TOTAL. When the panel is too short for them, they collapse into one
// "other levels" row, and as a last resort the column head row is dropped.
const SEV_MAIN = ['critical', 'error', 'warning', 'notice', 'informational'];
const SIDE_COLUMN = window.matchMedia('(min-width: 2400px) and (min-aspect-ratio: 21/10)'); // style.css ultrawide block
export function sevRows(result) {
  const by = new Map();
  // Query succeeded: a severity absent from the result had 0 events in the window (a known 0, not missing data).
  for (const r of result) { const k = sevKey(r.metric.severity); by.set(k, (by.get(k) || 0) + Number(r.value[1])); }
  const levels = SEV_KEYS.filter((x) => SEV_MAIN.includes(x.k) || by.get(x.k) > 0).map((x) => ({ ...x, v: by.get(x.k) || 0 }));
  return { levels, extras: levels.filter((x) => !SEV_MAIN.includes(x.k)), total: [...by.values()].reduce((a, b) => a + b, 0) };
}
export function renderSeverity(result, nav) {
  const { levels, extras, total } = sevRows(result);
  // rows that fit incl. head and TOTAL; unbounded where the panel is content-sized (below 1280, ultrawide side column)
  const room = WALLBOARD.matches && !SIDE_COLUMN.matches ? fitRows($('sev'), ROW_PX) : Infinity;
  const collapse = extras.length > 1 && levels.length + 2 > room;
  const shown = collapse ? levels.filter((x) => SEV_MAIN.includes(x.k)) : levels;
  const n = shown.length + (collapse ? 1 : 0) + 1;
  const max = Math.max(1, ...levels.map((x) => x.v));
  const rows = n + 1 <= room ? [head('LEVEL', '', '#COUNT')] : [];
  for (const x of shown) {
    const open = x.k === 'other' ? () => nav.logs({}) : () => nav.logs({ sev: x.k });
    rows.push(row([cell(x.name, 'name'), bar((100 * x.v) / max), num(x.v, 0)], `sev-${x.k}`, open, `syslog lines with severity ${x.k}`));
  }
  if (collapse) {
    const v = extras.reduce((a, x) => a + x.v, 0);
    const names = extras.map((x) => x.name).join(' / ');
    rows.push(row([cell(`other levels (${names})`, 'name', `${names}: ${extras.map((x) => x.v).join(' / ')}`), bar((100 * v) / max), num(v, 0)],
      'sev-other', () => nav.logs({}), `syslog lines with severity ${names}`));
  }
  rows.push(row([cell('TOTAL', 'sub'), cell(''), num(total, 0)], 'sep'));
  put('sev', rows);
}

export function logRow(e, onOpen) {
  const time = jstClock.format(new Date(Number(e.ts.slice(0, 13))));
  const masked = maskText(e.line);
  const r = el('div', `log sev-${e.sev}`);
  r.title = `${time} ${e.host} ${e.sev} ${masked}`;
  r.append(el('span', 'log-t', time), el('span', 'log-h', e.host), el('span', 'log-s', sevName(e.sev)), el('span', 'log-m', masked));
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

// The feed shows the newest lines that fit; a bounded buffer of recent lines (separate from the rendered rows, which
// seenLogs keeps from being re-added) lets the visible slice be rebuilt when the capacity changes in either direction.
const LOG_BUF = 500;
let logBuf = [];
let logNav = null;
export function renderLogs(entries, seenLogs, nav) {
  logNav = nav;
  const box = $('logs');
  refocus(box, () => {
    for (const e of entries) {
      const key = `${e.ts}|${e.host}|${e.line}`;
      if (seenLogs.has(key)) continue;
      seenLogs.add(key);
      logBuf.push(e);
      box.appendChild(logRow(e, nav.logline));
    }
    if (logBuf.length > LOG_BUF) logBuf = logBuf.slice(-LOG_BUF);
    fitLogRows(box);
  });
}
// rendered rows are always the tail of logBuf, in order
function fitLogRows(box) {
  const max = capacity(box, LOG_LINES, LOG_PX);
  while (box.children.length > max) box.removeChild(box.firstChild);
  for (let i = logBuf.length - box.children.length - 1; box.children.length < max && i >= 0; i--) {
    const r = logRow(logBuf[i], logNav.logline);
    r.style.animation = 'none'; // older lines coming back into view, not new arrivals
    box.prepend(r);
  }
}
// a new time position (playback seek, entering / leaving playback): the feed restarts from that position's lines
export function resetLogs(seenLogs) {
  seenLogs.clear();
  logBuf = [];
  $('logs').replaceChildren();
}
export const fitLogs = () => { if (logNav) refocus($('logs'), () => fitLogRows($('logs'))); };
