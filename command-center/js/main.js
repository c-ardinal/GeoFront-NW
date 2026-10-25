// Command-center entry: theme, polling, wallboard rendering, and wiring of modals/drawers/globe interactions.
// Reads Prometheus/Loki only through the same-origin nginx proxy. All data in this trial is SYNTHETIC (demo-gen).
import { $, el, vmap, scalar, jstClock, REDUCED_MOTION, LARGE, WALLBOARD } from './util.js';
import { promQuery, promRange, promAlerts, lokiRange, lokiMetric, flattenStreams } from './api.js';
import * as P from './panels.js';
import * as G from './globe.js';
import * as UI from './ui.js';
import * as M from './views-modal.js';
import * as D from './views-drawer.js';

const POLL_MS = 10000;
const STALE_AFTER_MS = POLL_MS * 2;
const PROM_PANELS = ['p-devices', 'p-dest', 'p-src', 'p-unknown', 'p-globe', 'p-wan', 'p-if', 'p-wlan', 'p-alerts', 'p-health'];
const LOKI_PANELS = ['p-logs', 'p-sev'];
const FLOW_PANELS = ['p-dest', 'p-src', 'p-unknown', 'p-globe'];
const FLOW_MAX_AGE_S = 60; // 4 scrape intervals

// ---- theme: default (v3) or "eva-film"; ?theme= overrides, choice persisted when storage is available ----
const THEMES = ['default', 'eva-film']; // toggle cycles in this order
const THEME_LABEL = { default: 'THEME: STD', 'eva-film': 'THEME: FILM' };
const THEME_ALIAS = { eva: 'eva-film' }; // the removed "eva" theme (stored or in old links) opens its successor
function readStoredTheme() {
  try { return localStorage.getItem('cc-theme'); } catch { return null; }
}
function applyTheme(name, persist) {
  const t = THEMES.includes(THEME_ALIAS[name] || name) ? THEME_ALIAS[name] || name : 'default';
  document.documentElement.dataset.theme = t;
  const [k, v] = THEME_LABEL[t].split(' ');
  $('theme-toggle').replaceChildren(el('span', 'tt-k', `${k} `), v); // phone shows the value only
  if (persist) { try { localStorage.setItem('cc-theme', t); } catch { /* storage unavailable: theme not persisted */ } }
}

// ---- state ----------------------------------------------------------------------------------
// seen* keep rows that disappear from Prometheus (target down) visible as UNKNOWN instead of vanishing.
const state = { promOkAt: -Infinity, lokiOkAt: -Infinity, promOkWall: 0, dataAgeAtOk: 0, waitFresh: false, saidMode: null, promErr: null, lokiErr: null, snap: null, seenLogs: new Set(), seenIf: new Set(), seenWlan: new Set() };

// ---- navigation: every "open related data" action goes through here ------------------------------
// Each drawer view carries its own globe selection; it is (re)applied whenever that view is shown,
// including via back/breadcrumb. Views without one clear the highlight.
function applyViewSelection(view) {
  const sel = view.selection || null;
  G.setSelection(sel);
  UI.setSelected(!!sel);
  if (sel && sel.type !== 'src' && view.flyTo) {
    const f = [...(state.snap?.flows || [])].sort((a, b) => b.bps - a.bps)
      .find((x) => x.lat !== null && (sel.type === 'dest' ? `${x.cc}|${x.city}` === sel.key : x.cc === sel.cc));
    if (f) G.flyTo(f.lat, f.lon);
    view.flyTo = false; // fly once on open, not on every return
  }
}
const withSel = (view, selection) => Object.assign(view, { selection, flyTo: true });
const nav = {
  device: (n) => UI.openDrawer(D.deviceView(n)),
  iface: (k) => UI.openDrawer(D.ifaceView(k)),
  dest: (d) => UI.openDrawer(withSel(D.destView(d), d.city ? { type: 'dest', key: `${d.cc}|${d.city}` }
    : d.cc && d.cc !== 'Unknown' ? { type: 'country', cc: d.cc } : null)), // Unknown has no location to highlight
  src: (h) => UI.openDrawer(withSel(D.srcView(h), { type: 'src', host: h })),
  alert: (a) => UI.openDrawer(D.alertView(a)),
  logline: (e) => UI.openDrawer(D.loglineView(e)),
  job: (j) => UI.openDrawer(D.jobView(j)),
  logs: (f) => UI.openModal(M.logsModal(f)),
};
const MODALS = {
  'p-devices': M.devicesModal, 'p-dest': M.destModal, 'p-src': M.srcModal, 'p-unknown': M.unknownModal, 'p-wan': M.wanModal,
  'p-if': M.ifacesModal, 'p-wlan': M.wlanModal, 'p-alerts': M.alertsModal, 'p-logs': () => M.logsModal(), 'p-sev': M.sevModal, 'p-health': M.healthModal,
};
function wirePanelTitles() {
  for (const [id, make] of Object.entries(MODALS)) {
    const h = document.querySelector(`#${id} > h2`);
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'h-open';
    b.setAttribute('aria-label', `${h.querySelector('.h-t').textContent}: open full data`);
    b.title = 'open full data';
    b.textContent = '⤢';
    h.insertBefore(b, h.querySelector('.h-r'));
    const open = () => UI.openModal(make());
    b.addEventListener('click', open);
    h.querySelector('.h-t').addEventListener('click', open);
    h.querySelector('.h-t').classList.add('h-click');
  }
}

// ---- polling ------------------------------------------------------------------------------------
// Device-derived values are only shown for targets whose latest scrape succeeded: rate() over a look-back window
// keeps returning decaying numbers (and 0 errors) for ~1-2 min after a target goes DOWN, which must not be shown.
const UP = 'on (instance) (up{job="snmp"} == 1)';
const gate = (expr) => `(${expr}) and ${UP}`;
const ERR_EXPR = '(rate(ifInErrors{job="snmp"}[2m]) + rate(ifOutErrors{job="snmp"}[2m])) * 60';
const WAN_SEL = `job="snmp",instance="${P.WAN.instance}",ifName="${P.WAN.ifName}"`;
const Q = {
  // gated like the SNMP values: a failed flows scrape must not keep showing decaying rates
  flows: '(sum by (src_host, dst_ip, dst_country, dst_city, lat, lon, asn, direction) (rate(demo_flow_bytes_total[2m])) * 8) and on () (up{job="flows"} == 1)',
  up: 'up{job="snmp"}',
  uptime: gate('sysUpTime{job="snmp"} / 100'),
  devIn: gate('sum by (instance) (rate(ifHCInOctets{job="snmp"}[1m])) * 8 / 1e6'),
  devOut: gate('sum by (instance) (rate(ifHCOutOctets{job="snmp"}[1m])) * 8 / 1e6'),
  devErr: gate(`sum by (instance) (${ERR_EXPR})`),
  clients: gate('sum by (instance) (demo_wlan_clients)'),
  ifIn: gate('rate(ifHCInOctets{job="snmp"}[1m]) * 8 / 1e6'),
  ifOut: gate('rate(ifHCOutOctets{job="snmp"}[1m]) * 8 / 1e6'),
  ifSpeed: gate('ifHighSpeed{job="snmp"}'),
  ifOper: gate('ifOperStatus{job="snmp"}'),
  ifErr: gate(ERR_EXPR),
  wlan: gate('demo_wlan_clients'),
  // inventory over the last hour, so a target that is down now still lists its rows as UNKNOWN
  ifInv: 'max_over_time(ifHighSpeed{job="snmp"}[1h])',
  wlanInv: 'max_over_time(demo_wlan_clients[1h])',
  upAll: 'up',
  tDur: 'scrape_duration_seconds',
  tAge: 'time() - timestamp(up)',
  // timestamp() must wrap the raw selector to get sample times; `and up == 1` keeps UP targets only
  // newest successful scrape: the age of the freshest data on screen, measured by Prometheus (no browser clock involved)
  freshMin: 'min(time() - (timestamp(up) and up == 1))',
  alloyRx: 'sum(rate(loki_source_syslog_entries_total[1m]))',
  lokiRx: 'sum(rate(loki_distributor_lines_received_total[1m]))',
};

function normFlows(res) {
  return res.map((r) => {
    const mt = r.metric;
    const geo = mt.lat !== '' && mt.lat !== undefined;
    return { src: mt.src_host, ip: mt.dst_ip, cc: mt.dst_country || 'Unknown', city: mt.dst_city || '', asn: mt.asn || '',
      lat: geo ? Number(mt.lat) : null, lon: geo ? Number(mt.lon) : null, dir: mt.direction, bps: Number(r.value[1]) };
  });
}

async function pollProm() {
  const names = Object.keys(Q);
  const [res, sDown, sUp, alerts] = await Promise.all([
    Promise.all(names.map((n) => promQuery(Q[n]))).then((vals) => Object.fromEntries(names.map((n, i) => [n, vals[i]]))),
    promRange(gate(`rate(ifHCInOctets{${WAN_SEL}}[1m]) * 8 / 1e6`), 900, 15),
    promRange(gate(`rate(ifHCOutOctets{${WAN_SEL}}[1m]) * 8 / 1e6`), 900, 15),
    promAlerts(),
  ]);
  const m = {
    up: vmap(res.up, 'instance'), uptime: vmap(res.uptime, 'instance'),
    devIn: vmap(res.devIn, 'instance'), devOut: vmap(res.devOut, 'instance'), devErr: vmap(res.devErr, 'instance'),
    clients: vmap(res.clients, 'instance'),
    ifIn: vmap(res.ifIn, 'instance', 'ifName'), ifOut: vmap(res.ifOut, 'instance', 'ifName'),
    ifSpeed: vmap(res.ifSpeed, 'instance', 'ifName'), ifOper: vmap(res.ifOper, 'instance', 'ifName'),
    ifErr: vmap(res.ifErr, 'instance', 'ifName'), ifInv: vmap(res.ifInv, 'instance', 'ifName'),
    ifDescr: new Map([...res.ifInv, ...res.ifSpeed].map((r) => [`${r.metric.instance}|${r.metric.ifName}`, r.metric.ifDescr])),
  };
  const key = (r) => `${r.metric.job}|${r.metric.instance}`;
  const dur = new Map(res.tDur.map((r) => [key(r), Number(r.value[1])]));
  const age = new Map(res.tAge.map((r) => [key(r), Number(r.value[1])]));
  const targets = res.upAll.map((r) => ({ job: r.metric.job, instance: r.metric.instance, up: Number(r.value[1]), dur: dur.get(key(r)), age: age.get(key(r)) }));
  const jobs = { up: new Map(), total: new Map(), dur: new Map(), age: new Map() };
  for (const t of targets) {
    jobs.up.set(t.job, (jobs.up.get(t.job) || 0) + t.up);
    jobs.total.set(t.job, (jobs.total.get(t.job) || 0) + 1);
    jobs.dur.set(t.job, Math.max(jobs.dur.get(t.job) || 0, t.dur ?? 0));
    jobs.age.set(t.job, Math.max(jobs.age.get(t.job) || 0, t.age ?? 0));
  }
  // flow source freshness: its scrape target must exist, be up and have a recent sample (else flow data is UNKNOWN)
  const flowsOk = targets.some((t) => t.job === 'flows' && t.up === 1 && t.age < FLOW_MAX_AGE_S);
  state.snap = {
    at: Date.now(), m, flowsOk, flows: flowsOk ? normFlows(res.flows) : [], wlan: res.wlan, wlanInv: res.wlanInv, alerts, targets, jobs, sDown, sUp,
    freshMin: scalar(res.freshMin), down: targets.filter((t) => t.up === 0).map((t) => t.instance).sort(),
    alloyRx: scalar(res.alloyRx), lokiRx: scalar(res.lokiRx),
  };
  const s = state.snap;
  P.renderDevices(m, nav); // before the flow rankings: they are fitted to the height the device list leaves
  P.renderFlows(s, nav);
  G.renderGlobe(s.flows);
  if (!flowsOk) $('arc-note').textContent = 'flow source DOWN · arcs UNKNOWN';
  P.renderWan(s);
  P.renderInterfaces(s, state.seenIf, nav);
  P.renderWlan(s, state.seenWlan, nav);
  P.renderAlerts(alerts, nav);
  P.renderHealth(s, nav);
  P.fitRightColumn();
}

async function pollLoki() {
  const [logs, sev] = await Promise.all([
    lokiRange('{job="syslog"}', 120, 40),
    lokiMetric('sum by (severity) (count_over_time({job="syslog"}[15m]))'),
  ]);
  P.renderLogs(flattenStreams(logs), state.seenLogs, nav);
  P.renderSeverity(sev, nav);
  if (state.seenLogs.size > 2000) state.seenLogs = new Set([...state.seenLogs].slice(-500));
}

async function poll() {
  const [p, l] = await Promise.allSettled([pollProm(), pollLoki()]);
  const now = mono();
  if (p.status === 'fulfilled') {
    state.promOkAt = now; state.promOkWall = Date.now(); state.promErr = null;
    // data age at this success, measured by Prometheus itself (no browser/host clock skew): newest sample of any UP target
    state.dataAgeAtOk = Math.max(0, Number.isFinite(state.snap?.freshMin) ? state.snap.freshMin : 0);
    armDeadman();
    state.waitFresh = false; // only a successful metrics update ends the resume guard
  } else state.promErr = String(p.reason);
  if (l.status === 'fulfilled') { state.lokiOkAt = now; state.lokiErr = null; } else state.lokiErr = String(l.reason);
  updateHealth();
  // header info slots may be cut to an ellipsis on narrow panels: the full text stays available as a tooltip
  for (const h of document.querySelectorAll('.panel > h2 .h-r')) h.title = h.textContent;
  if (state.snap) UI.refreshViews(ctx());
}
const ctx = () => {
  const now = mono();
  return { snap: state.snap, nav, seenIf: state.seenIf, seenWlan: state.seenWlan,
    promStale: now - state.promOkAt > STALE_AFTER_MS || !!state.promErr, lokiStale: now - state.lokiOkAt > STALE_AFTER_MS || !!state.lokiErr };
};

// ---- freshness (NFR-05 / NFR-10) -----------------------------------------------------------------
// One badge: state word + icon + colour, and the data age. LIVE: last successful metrics update at most one poll cycle
// late; DEGRADED: one cycle late, or some source failing (logs, flows, a DOWN target); STALE: two cycles without success.
// Times are monotonic (performance.now) and the age adds Prometheus' own sample age, so clock skew cannot distort it.
// Dead-man switch: every successful update restarts a CSS animation that reveals a STALE overlay after two cycles +
// margin; it runs on the compositor, so a stalled / throttled / frozen script can never leave "LIVE" on screen.
const mono = () => performance.now();
const DEGRADED_AFTER_MS = POLL_MS + 3000; // one cycle + request latency
const DEADMAN_MS = STALE_AFTER_MS + 5000;
function armDeadman() {
  const b = $('badge');
  b.style.setProperty('--deadman', `${DEADMAN_MS}ms`);
  b.dataset.arm = b.dataset.arm === 'a' ? 'b' : 'a'; // switching between two identical keyframes restarts the timer
}
function updateHealth() {
  const now = mono();
  const promLate = now - state.promOkAt;
  const promStale = promLate > STALE_AFTER_MS;
  const lokiStale = now - state.lokiOkAt > STALE_AFTER_MS;
  const flowStale = state.snap ? !state.snap.flowsOk : false;
  for (const id of PROM_PANELS) $(id).classList.toggle('stale', promStale || (flowStale && FLOW_PANELS.includes(id)));
  for (const id of LOKI_PANELS) $(id).classList.toggle('stale', lokiStale);
  const s = state.snap;
  const reasons = [
    state.promErr && `metrics: ${state.promErr}`, promStale ? 'metrics: no update for 2 cycles' : promLate > DEGRADED_AFTER_MS && 'metrics: update late',
    state.lokiErr && `logs: ${state.lokiErr}`, lokiStale && !state.lokiErr && 'logs: no update for 2 cycles',
    flowStale && 'flow source DOWN', s?.down.length && `targets DOWN: ${s.down.join(', ')}`,
  ].filter(Boolean);
  const mode = promStale || state.waitFresh ? 'STALE' : reasons.length ? 'DEGRADED' : 'LIVE';
  const age = Number.isFinite(state.promOkAt) ? Math.max(0, promLate / 1000 + state.dataAgeAtOk) : null;
  const b = $('badge');
  b.classList.remove('badge-live', 'badge-degraded', 'badge-stale');
  b.classList.add(`badge-${mode.toLowerCase()}`);
  b.querySelector('.b-long').textContent = mode;
  b.querySelector('.b-short').textContent = BADGE_SHORT[mode];
  b.querySelector('.b-age').textContent = age === null ? '—' : fmtAge(age);
  b.title = [`data age ${age === null ? 'unknown' : fmtAge(age)}`,
    state.promOkWall ? `last metrics update ${jstClock.format(new Date(state.promOkWall))} JST` : 'no successful update yet',
    ...(reasons.length ? reasons : ['all sources OK'])].join(' · ');
  // screen readers hear state changes only (with their reasons), never the ticking age
  const said = reasons.length && mode !== 'STALE' ? `${mode}: ${reasons.join('; ')}` : mode;
  if ($('badge-sr').textContent !== said && mode !== state.saidMode) { $('badge-sr').textContent = said; state.saidMode = mode; }
}
const BADGE_SHORT = { LIVE: 'LIVE', DEGRADED: 'DEGR', STALE: 'STALE' };
const fmtAge = (sec) => (sec < 60 ? `${Math.floor(sec)}s` : sec < 3600 ? `${Math.floor(sec / 60)}m` : `${Math.min(99, Math.floor(sec / 3600))}h`);

function tickClock() {
  if (document.hidden) return; // nothing to tick for a hidden tab (the dead-man switch keeps its own time)
  $('clock').textContent = jstClock.format(new Date());
  updateHealth();
}
// back from hidden / frozen: the values on screen may be old: STALE until the first fresh fetch, which starts now
document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  state.waitFresh = true;
  tickClock();
  poll();
});

// ---- screen tiers --------------------------------------------------------------------------------
// LARGE screens: the page is CSS-zoomed moderately (<= ZOOM_MAX) so it reads from a distance, while the zoomed layout
// still has more room than 1920x1080, which the lists fill with extra rows. style.css counter-zooms the globe host so
// WebGL renders at native resolution and pointer picking stays 1:1.
const ZOOM_MAX = 1.5;
const ZOOM_GAIN = 0.6; // share of the size ratio to 1920x1080 that goes into zoom (the rest becomes extra rows)
function applyScale() {
  const ratio = Math.min(innerWidth / 1920, innerHeight / 1080);
  const z = LARGE.matches ? Math.round(Math.min(ZOOM_MAX, Math.max(1, 1 + (ratio - 1) * ZOOM_GAIN)) * 100) / 100 : 1;
  const root = document.documentElement;
  if ((Number(root.style.getPropertyValue('--ui-zoom')) || 1) === z) return;
  root.style.zoom = z === 1 ? '' : String(z);
  root.style.setProperty('--ui-zoom', String(z));
  scheduleRefit(); // tier change: shared heights / stretched rows of the previous tier must be cleared now
}
// Layout-dependent rendering after any size change (window, orientation, banner/header height, tab switch):
// globe canvas size, list row counts, sparkline backing stores, syslog line count.
let refitTimer = 0;
function scheduleRefit() {
  clearTimeout(refitTimer);
  refitTimer = setTimeout(() => {
    G.fit();
    if (state.snap) { P.renderFlows(state.snap, nav); P.renderWan(state.snap); P.fitRightColumn(); }
    P.fitLogs();
  }, 120);
}
function initLayout() {
  applyScale();
  window.addEventListener('resize', applyScale);
  LARGE.addEventListener('change', scheduleRefit); // tier change without a zoom change (e.g. 2400 -> 2360 x 1080)
  new ResizeObserver(scheduleRefit).observe($('grid'));
  // sticky offsets / drawer top below the (wrapping) top bar on tablet and phone
  const bar = $('topbar');
  new ResizeObserver(() => document.documentElement.style.setProperty('--topbar-h', `${bar.offsetHeight}px`)).observe(bar);
  UI.initTabs(scheduleRefit);
  UI.initTopbar();
}

// ---- boot sequence -----------------------------------------------------------------------------
function boot() {
  const lines = ['NETWORK OBSERVATORY // COMMAND CENTER', 'LINK prometheus ............ OK', 'LINK loki .................. OK',
    'LOAD geo layer ............. OK', 'SOURCE: demo-gen (SYNTHETIC DATA)', 'ESTABLISHING LIVE FEED_'];
  const pre = $('boot-text');
  const done = () => $('boot').classList.add('gone');
  if (REDUCED_MOTION) { pre.textContent = lines.join('\n'); setTimeout(done, 600); return; }
  lines.forEach((l, i) => setTimeout(() => { pre.textContent += `${l}\n`; }, 250 + i * 330));
  setTimeout(done, 250 + lines.length * 330 + 500);
}

applyTheme(new URLSearchParams(location.search).get('theme') || readStoredTheme(), false);
initLayout();
$('theme-toggle').addEventListener('click', () => {
  applyTheme(THEMES[(THEMES.indexOf(document.documentElement.dataset.theme) + 1) % THEMES.length], true);
  G.styleGlobe();
  poll();
});
UI.initUi({ onClear: () => { G.setSelection(null); G.resetView(); }, onView: applyViewSelection });
// the alert banner is the way into the firing alerts: their full list on the wallboard, the alerts tab / panel below it
const openAlerts = () => (WALLBOARD.matches ? UI.openModal(M.alertsModal()) : UI.selectTab('alert'));
$('alert-banner').addEventListener('click', openAlerts);
$('alert-banner').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAlerts(); } });
G.initGlobe({ onDest: (key) => { const [cc, city] = key.split('|'); nav.dest({ cc, city }); }, onInteract: () => UI.touched() });
wirePanelTitles();
boot();
tickClock();
setInterval(tickClock, 1000);
poll();
setInterval(poll, POLL_MS);
// scripted-test hook (read-only): screen position of a destination on the globe
window.ccTest = { screenOf: G.screenOf, info: G.testInfo, selection: G.testSelection, mode: UI.mode };
