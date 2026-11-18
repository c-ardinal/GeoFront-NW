// Command-center entry: theme, polling, wallboard rendering, and wiring of modals/drawers/globe interactions.
// Reads Prometheus/Loki only through the same-origin nginx proxy. All data in this trial is SYNTHETIC (demo-gen).
import { $, el, vmap, scalar, has, jstClock, jstFull, REDUCED_MOTION, LARGE, WALLBOARD, now, isPlayback, setCursor, SCRAPE_S, RATE_WIN } from './util.js';
import { promQuery, promRange, promAlerts, promAlertsAt, lokiRange, lokiMetric, flattenStreams, amOps } from './api.js';
import * as P from './panels.js';
import * as G from './globe.js';
import * as UI from './ui.js';
import * as M from './views-modal.js';
import * as D from './views-drawer.js';
import { setNoFlowSource } from './views-common.js';
import * as AL from './alerting.js';
import * as PA from './views-pcap.js';
import * as PB from './playback.js';
import { downloadEvidence, snapshotGate } from './evidence.js';
import * as T from './topology.js';
import * as C from './correlate.js';
import { trendView } from './views-trend.js';
import { logSearchView } from './views-logsearch.js';

const POLL_MS = 10000;
const STALE_AFTER_MS = POLL_MS * 2;
const PROM_PANELS = ['p-devices', 'p-dest', 'p-src', 'p-unknown', 'p-globe', 'p-wan', 'p-if', 'p-wlan', 'p-alerts', 'p-health'];
const LOKI_PANELS = ['p-logs', 'p-sev'];
const FLOW_PANELS = ['p-dest', 'p-src', 'p-unknown', 'p-globe'];
const FLOW_MAX_AGE_S = 4 * SCRAPE_S;

// ---- theme: default (v3) or "film"; ?theme= overrides, choice persisted when storage is available ----
const THEMES = ['default', 'film']; // toggle cycles in this order
const THEME_LABEL = { default: 'THEME: STD', film: 'THEME: FILM' };
const THEME_ALIAS = { eva: 'film', 'eva-film': 'film' }; // older names (stored or in old links) open the same theme
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
// gen: bumped on every switch of the data time (playback enter / seek back / leave): an answer that was asked for the
// previous time is dropped instead of rendered
const state = { gen: 0, flowsConfigured: true, promOkAt: -Infinity, lokiOkAt: -Infinity, promOkWall: 0, dataAgeAtOk: 0, waitFresh: false, saidMode: null, promErr: null, lokiErr: null, snap: null, seenLogs: new Set(), seenIf: new Set(), seenWlan: new Set() };

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
  // 原因候補 around a moment (P5): anchor { at: ms, label, ctx }; the traffic surge list
  correlate: (anchor) => UI.openDrawer(C.correlateView(anchor)),
  surges: () => UI.openModal(C.surgeModal()),
  // 推移 / ログ検索 (F1): init = the family and scope / the filter to start with
  trend: (init) => UI.openModal(trendView(init)),
  logsearch: (init) => UI.openModal(logSearchView(init)),
  // packet analysis: opts { dest, src } narrow it to that traffic (filter from the flows' address tokens, last 15 min);
  // opts.since / opts.until (unix s): a ring file of that time span (a 原因候補 window)
  packets: async (opts = {}) => {
    const f = await PA.drillFilter({ ...opts, flows: state.snap?.flows || [] });
    const since = opts.since ?? (opts.dest || opts.src ? now() / 1000 - 900 : undefined);
    // a 原因候補 window is always handed over (the screen then says which file it opened); the 15 min default only with capture
    const cap = OBS.flowSource === 'capture' || opts.since !== undefined;
    UI.openModal(PA.analysisView({ ...f, since: cap ? since : undefined, until: cap ? opts.until : undefined }));
  },
};
const MODALS = {
  'p-devices': M.devicesModal, 'p-dest': M.destModal, 'p-src': M.srcModal, 'p-unknown': M.unknownModal, 'p-wan': M.wanModal,
  'p-if': M.ifacesModal, 'p-wlan': M.wlanModal, 'p-alerts': M.alertsModal, 'p-logs': () => M.logsModal(), 'p-sev': M.sevModal, 'p-health': M.healthModal,
};
// GeoIP note under the globe: whose data the locations are (CC BY 4.0 attribution) and its version
function renderGeoNote(geo) {
  const n = $('geo-note');
  const text = OBS.flowSource === 'pcap-replay' || OBS.flowSource === 'demo-gen' ? 'Locations: synthetic demo data'
    : geo.months.length ? `GeoIP: IP Geolocation by DB-IP (CC BY 4.0) · ${[...new Set(geo.months)].join('/')}` : 'GeoIP: no database (Unknown) · IP Geolocation by DB-IP, CC BY 4.0';
  if (n.textContent !== text) n.textContent = text;
}
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
  // GLOBAL TRAFFIC: the way into packet analysis (stored captures / uploads / the demo pcap)
  const g = document.querySelector('#p-globe > h2');
  const a = el('button', 'h-act', '解析');
  a.type = 'button';
  a.lang = 'ja';
  a.title = 'packet analysis (captured / uploaded pcap)';
  a.setAttribute('aria-label', 'Packet analysis: open captured or uploaded packets');
  a.addEventListener('click', () => nav.packets());
  g.insertBefore(a, g.querySelector('.h-r'));
  // 推移 / ログ検索 (F1): in the headings of the panels they extend (no item in the top bar)
  const headBtn = (panel, text, aria, open) => {
    const h = document.querySelector(`#${panel} > h2`);
    const b = el('button', 'h-act', text);
    b.type = 'button';
    b.lang = 'ja';
    b.title = aria;
    b.setAttribute('aria-label', aria);
    b.addEventListener('click', open);
    h.insertBefore(b, h.querySelector('.h-open'));
  };
  headBtn('p-wan', '推移', '推移: WAN 利用率の長期表示', () => nav.trend(P.WAN.instance ? { family: 'wan_util', instance: P.WAN.instance, ifName: P.WAN.ifName } : { family: 'if_bps' }));
  headBtn('p-if', '推移', '推移: インターフェースの通信量・エラーの長期表示', () => nav.trend({ family: 'if_bps', ...(P.WAN.instance ? { instance: P.WAN.instance, ifName: P.WAN.ifName } : {}) }));
  headBtn('p-logs', '検索', 'ログ検索: 語句・機器・重要度・期間による syslog 検索', () => nav.logsearch());
  // traffic surges (P5): the count in a fixed-width slot, opens the list
  const sb = el('button', 'h-act h-surge', '急増 —');
  sb.id = 'surge-btn';
  sb.type = 'button';
  sb.lang = 'ja';
  sb.addEventListener('click', () => nav.surges());
  g.insertBefore(sb, a);
}
function renderSurgeButton(s) {
  const b = $('surge-btn');
  const n = s.flowsOk ? s.surges.length : null;
  const text = `急増 ${n === null ? '—' : n}`;
  if (b.textContent !== text) b.textContent = text;
  b.classList.toggle('hot', !!n);
  b.title = n === null ? 'traffic surges: flow data unknown' : `traffic surges (host x destination above its baseline): ${n} · ${C.surgeRule()}`;
  b.setAttribute('aria-label', `${n === null ? 'traffic surges unknown' : `${n} traffic surges`}: open the list`);
}

// ---- polling ------------------------------------------------------------------------------------
// Device-derived values are only shown for targets whose latest scrape succeeded: rate() over a look-back window
// keeps returning decaying numbers (and 0 errors) for ~1-2 min after a target goes DOWN, which must not be shown.
const UP = 'on (instance) (up{job="snmp"} == 1)';
const gate = (expr) => `(${expr}) and ${UP}`;
const UP_TS = 'timestamp(up{job="snmp"}) and up{job="snmp"} == 1'; // timestamp() of the raw selector = the sample time
const ERR_EXPR = `(rate(ifInErrors{job="snmp"}[${RATE_WIN}]) + rate(ifOutErrors{job="snmp"}[${RATE_WIN}])) * 60`;
const Q = {
  // gated like the SNMP values: a failed flows scrape must not keep showing decaying rates
  flows: `(sum by (src_host, dst_ip, dst_country, dst_city, lat, lon, asn, direction) (rate(obs_flow_bytes_total[${RATE_WIN}])) * 8) and on () (up{job="flows"} == 1)`,
  uptime: gate('sysUpTime{job="snmp"} / 100'),
  // seconds since each device's last successful scrape, DOWN devices included; none within 15 min = no series (> 15 min)
  lastOk: `time() - max by (instance) (${UP_TS} or max_over_time((${UP_TS})[${P.LAST_SEEN_MAX_S}s:${SCRAPE_S}s]))`,
  devIn: gate(`sum by (instance) (rate(ifHCInOctets{job="snmp"}[${RATE_WIN}])) * 8 / 1e6`),
  devOut: gate(`sum by (instance) (rate(ifHCOutOctets{job="snmp"}[${RATE_WIN}])) * 8 / 1e6`),
  devErr: gate(`sum by (instance) (${ERR_EXPR})`),
  clients: gate('sum by (instance) (demo_wlan_clients)'),
  ifIn: gate(`rate(ifHCInOctets{job="snmp"}[${RATE_WIN}]) * 8 / 1e6`),
  ifOut: gate(`rate(ifHCOutOctets{job="snmp"}[${RATE_WIN}]) * 8 / 1e6`),
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
  alloyRx: `sum(rate(loki_source_syslog_entries_total[${RATE_WIN}]))`,
  lokiRx: `sum(rate(loki_distributor_lines_received_total[${RATE_WIN}]))`,
  // flowd: is its input live (capture running / replay loaded); the capture service and the GeoIP databases
  flowSrc: 'max(obs_flow_source_up)',
  capUp: 'max(obs_capture_up)',
  capDrop: 'sum(increase(obs_capture_nic_rx_dropped_total[5m]))', // NIC drops: the only live drop counter
  capDumpDrop: 'sum(increase(obs_capture_dumpcap_dropped_total[1h]))', // dumpcap's own, known when a session ends
  capRing: 'max(obs_capture_ring_bytes / obs_capture_ring_limit_bytes)',
  capOver: 'max(obs_capture_over_limit)',
  geoBuild: 'min(obs_geoip_db_build_timestamp_seconds)',
  geoInfo: 'obs_geoip_db_info',
  // P5: LLDP neighbours (network map; scraped every 2 min) and traffic surges (recording rules; only surging pairs exist)
  lldp: 'last_over_time(lldpRemSysName{job="lldp"}[10m])',
  surge: `obs_surge:flow_bps:ratio and on () (up{job="flows"} == 1)`,
  surgeBps: 'obs_surge:flow_bps:rate5m and on (src_host, dst_country, asn) obs_surge:flow_bps:ratio',
  surgeBase: 'last_over_time(obs_surge:flow_bps:baseline[10m]) and on (src_host, dst_country, asn) obs_surge:flow_bps:ratio',
};
const GEOIP_STALE_DAYS = 45;

const notifySlot = (a) => { const st = AL.notifyState(a); return { ...st, kindClass: AL.NT_KIND[st.kind], nextText: AL.nextText(st) }; };

function normFlows(res) {
  return res.map((r) => {
    const mt = r.metric;
    const geo = mt.lat !== '' && mt.lat !== undefined;
    return { src: mt.src_host, ip: mt.dst_ip, cc: mt.dst_country || 'Unknown', city: mt.dst_city || '', asn: mt.asn || '',
      lat: geo ? Number(mt.lat) : null, lon: geo ? Number(mt.lon) : null, dir: mt.direction, bps: Number(r.value[1]) };
  });
}

// inventories over the last hour and the GeoIP versions change slowly: LIVE asks for them once a minute (PLAYBACK at
// every position, as before)
const SLOW_Q = new Set(['ifInv', 'wlanInv', 'geoBuild', 'geoInfo', 'lldp']);
const SLOW_EVERY_MS = 60000;
const slow = { at: -Infinity, gen: -1, vals: {} };
async function promAll(pb, gen) {
  const reuse = !pb && slow.gen === gen && performance.now() - slow.at < SLOW_EVERY_MS;
  const names = Object.keys(Q).filter((n) => !(reuse && SLOW_Q.has(n)));
  const vals = await Promise.all(names.map((n) => promQuery(Q[n])));
  const res = { ...(reuse ? slow.vals : {}), ...Object.fromEntries(names.map((n, i) => [n, vals[i]])) };
  if (!reuse && !pb) Object.assign(slow, { at: performance.now(), gen, vals: Object.fromEntries([...SLOW_Q].map((n) => [n, res[n]])) });
  res.up = res.upAll.filter((r) => r.metric.job === 'snmp'); // = up{job="snmp"}, without a query of its own
  return res;
}

async function pollProm() {
  const gen = state.gen;
  const pb = isPlayback();
  const [res, sDown, sUp, alerts] = await Promise.all([
    promAll(pb, gen),
    P.WAN.instance ? promRange(gate(`rate(ifHCInOctets{${P.wanSel()}}[${RATE_WIN}]) * 8 / 1e6`), 900, 15) : [], // no WAN configured: nothing to ask
    P.WAN.instance ? promRange(gate(`rate(ifHCOutOctets{${P.wanSel()}}[${RATE_WIN}]) * 8 / 1e6`), 900, 15) : [],
    pb ? promAlertsAt() : promAlerts(), // playback: the alert list of that time, from the TSDB (ALERTS)
    pb ? null : AL.pollAlerting(), // notification state (Alertmanager / notify records): never fails, its own state says "unknown"
  ]);
  if (gen !== state.gen) throw new Error('superseded'); // asked for another data time
  const m = {
    up: vmap(res.up, 'instance'), uptime: vmap(res.uptime, 'instance'), lastOk: vmap(res.lastOk, 'instance'),
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
  // flowd also says whether its own input is live (the capture service running, the demo replay loaded)
  const flowSrc = scalar(res.flowSrc);
  const flowsOk = targets.some((t) => t.job === 'flows' && t.up === 1 && t.age < FLOW_MAX_AGE_S) && flowSrc !== 0;
  const geoBuild = scalar(res.geoBuild);
  const capture = res.capUp.length ? { up: scalar(res.capUp), drops: scalar(res.capDrop), dumpDrops: scalar(res.capDumpDrop), ring: scalar(res.capRing), over: scalar(res.capOver) } : null;
  state.snap = {
    at: now(), m, flowsOk, flowsConfigured: state.flowsConfigured, flows: flowsOk ? normFlows(res.flows) : [], wlan: res.wlan, wlanInv: res.wlanInv, alerts, targets, jobs, sDown, sUp,
    freshMin: scalar(res.freshMin), down: targets.filter((t) => t.up === 0).map((t) => t.instance).sort(),
    alloyRx: scalar(res.alloyRx), lokiRx: scalar(res.lokiRx), capture,
    geo: { ageDays: has(geoBuild) ? (now() / 1000 - geoBuild) / 86400 : null, months: res.geoInfo.map((r) => r.metric.month).filter(Boolean) },
    surges: flowsOk ? C.surgeRows(res.surge, res.surgeBps, res.surgeBase) : [],
  };
  const s = state.snap;
  P.renderDevices(m, nav); // before the flow rankings: they are fitted to the height the device list leaves
  P.renderFlows(s, nav);
  G.renderGlobe(s.flows);
  if (!flowsOk) $('arc-note').textContent = P.FLOW_TEXT.arcs;
  T.update(OBS.cfg, topoDevices(), res.lldp, s);
  if (T.isOn()) $('arc-note').textContent = T.summary();
  renderSurgeButton(s);
  renderGeoNote(s.geo);
  P.renderWan(s);
  P.renderInterfaces(s, state.seenIf, nav);
  P.renderWlan(s, state.seenWlan, nav);
  P.renderAlerts(alerts, nav, notifySlot);
  P.renderHealth(s, nav);
  P.fitRightColumn();
}

async function pollLoki() {
  const gen = state.gen;
  const [logs, sev] = await Promise.all([
    lokiRange('{job="syslog"}', 120, 40),
    lokiMetric('sum by (severity) (count_over_time({job="syslog"}[15m]))'),
  ]);
  if (gen !== state.gen) throw new Error('superseded');
  P.renderLogs(flattenStreams(logs), state.seenLogs, nav);
  P.renderSeverity(sev, nav);
  if (state.seenLogs.size > 2000) state.seenLogs = new Set([...state.seenLogs].slice(-500));
}

// Each source records its own answer as soon as it arrives: a slow Loki never delays the metrics freshness (and the
// reverse). Timed live polls never stack: a source still waiting for its previous answer (small host) is skipped this
// cycle; every other caller (playback batches, theme switch, resume, ACK) always asks both.
const busy = { prom: false, loki: false };
function recordProm(r) {
  if (!r.ok) { state.promErr = String(r.e); return; }
  state.promOkAt = mono(); state.promOkWall = Date.now(); state.promErr = null;
  // data age at this success, measured by Prometheus itself (no browser/host clock skew): newest sample of any UP target
  state.dataAgeAtOk = Math.max(0, Number.isFinite(state.snap?.freshMin) ? state.snap.freshMin : 0);
  armDeadman();
  state.waitFresh = false; // only a successful metrics update ends the resume guard
}
function recordLoki(r) {
  if (r.ok) { state.lokiOkAt = mono(); state.lokiErr = null; } else state.lokiErr = String(r.e);
}
async function poll(timed = false) {
  const gen = state.gen;
  const run = (key, fetchFn, record) => {
    if (timed && busy[key]) return null;
    busy[key] = true;
    return fetchFn().then((v) => ({ ok: true, v }), (e) => ({ ok: false, e })).then((r) => {
      busy[key] = false;
      if (gen !== state.gen) return; // the data time changed meanwhile: its own poll reports
      record(r);
      updateHealth();
    });
  };
  await Promise.all([run('prom', pollProm, recordProm), run('loki', pollLoki, recordLoki)]);
  if (gen !== state.gen) return;
  // header info slots may be cut to an ellipsis on narrow panels: the full text stays available as a tooltip
  for (const h of document.querySelectorAll('.panel > h2 .h-r')) h.title = h.textContent;
  // playback paces its batches on the whole refresh, open detail views included (their own range queries)
  if (state.snap) { const views = UI.refreshViews(ctx()); if (isPlayback()) await views; }
}
const ctx = () => {
  const now = mono();
  const pb = isPlayback(); // a paused playback is not late: only a failed fetch makes it stale
  return { snap: state.snap, nav, seenIf: state.seenIf, seenWlan: state.seenWlan,
    promStale: (!pb && now - state.promOkAt > STALE_AFTER_MS) || !!state.promErr, lokiStale: (!pb && now - state.lokiOkAt > STALE_AFTER_MS) || !!state.lokiErr };
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
  if (isPlayback()) { playbackHealth(); return; }
  const now = mono();
  const promLate = now - state.promOkAt;
  const promStale = promLate > STALE_AFTER_MS;
  const lokiStale = now - state.lokiOkAt > STALE_AFTER_MS;
  const flowStale = state.snap ? state.flowsConfigured && !state.snap.flowsOk : false; // no flow source configured: not a failure
  for (const id of PROM_PANELS) $(id).classList.toggle('stale', promStale || (flowStale && FLOW_PANELS.includes(id)));
  for (const id of LOKI_PANELS) $(id).classList.toggle('stale', lokiStale);
  const s = state.snap;
  const reasons = [
    state.promErr && `metrics: ${state.promErr}`, promStale ? 'metrics: no update for 2 cycles' : promLate > DEGRADED_AFTER_MS && 'metrics: update late',
    state.lokiErr && `logs: ${state.lokiErr}`, lokiStale && !state.lokiErr && 'logs: no update for 2 cycles',
    flowStale && 'flow source DOWN', s?.down.length && `targets DOWN: ${s.down.join(', ')}`,
    s?.capture && s.capture.up !== 1 && 'packet capture stopped', s?.capture?.drops > 0 && `capture NIC dropping packets (${Math.round(s.capture.drops)} / 5 min)`,
    s?.capture?.dumpDrops > 0 && `dumpcap dropped packets (${Math.round(s.capture.dumpDrops)} in the last hour, ended sessions)`,
    s?.capture?.over === 1 && 'capture ring over its size limit',
    OBS.flowSource === 'capture' && s?.geo.ageDays > GEOIP_STALE_DAYS && `GeoIP DB ${Math.floor(s.geo.ageDays)} days old (tools geoip update)`,
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
const BADGE_SHORT = { LIVE: 'LIVE', DEGRADED: 'DEGR', STALE: 'STALE', PLAYBACK: 'PLAY' };
// PLAYBACK: the badge says PLAYBACK (no age: the data time is the banner's 履歴再生 HH:MM:SS); a panel is STALE only when
// the fetch for the current position failed; the dead-man overlay is off (nothing is expected to update while paused)
function playbackHealth() {
  const s = state.snap;
  const flowStale = s ? state.flowsConfigured && !s.flowsOk : false;
  for (const id of PROM_PANELS) $(id).classList.toggle('stale', !!state.promErr || (flowStale && FLOW_PANELS.includes(id)));
  for (const id of LOKI_PANELS) $(id).classList.toggle('stale', !!state.lokiErr);
  const b = $('badge');
  b.classList.remove('badge-live', 'badge-degraded', 'badge-stale');
  b.classList.add('badge-playback');
  b.querySelector('.b-long').textContent = 'PLAYBACK';
  b.querySelector('.b-short').textContent = BADGE_SHORT.PLAYBACK;
  b.querySelector('.b-age').textContent = '';
  const errs = [state.promErr && `metrics: ${state.promErr}`, state.lokiErr && `logs: ${state.lokiErr}`, flowStale && 'flow source DOWN at that time'].filter(Boolean);
  b.title = [`playback: data as of ${jstFull.format(new Date(now()))} JST`, ...(errs.length ? errs : ['all sources answered'])].join(' · ');
  if (state.saidMode !== 'PLAYBACK') { $('badge-sr').textContent = 'PLAYBACK'; state.saidMode = 'PLAYBACK'; }
}
const fmtAge = (sec) => (sec < 60 ? `${Math.floor(sec)}s` : sec < 3600 ? `${Math.floor(sec / 60)}m` : `${Math.min(99, Math.floor(sec / 3600))}h`);

function tickClock() {
  if (document.hidden) return; // nothing to tick for a hidden tab (the dead-man switch keeps its own time)
  $('clock').textContent = jstClock.format(new Date());
  updateHealth();
}
// back from hidden / frozen: the values on screen may be old: STALE until the first fresh fetch, which starts now
document.addEventListener('visibilitychange', () => {
  if (document.hidden || isPlayback()) return; // playback: what is on screen is still the data of its position
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
  const lines = ['GEOFRONT-NW // COMMAND CENTER', 'LINK prometheus ............ OK', 'LINK loki .................. OK',
    'LOAD geo layer ............. OK', `SOURCE: ${OBS.source}`, 'ESTABLISHING LIVE FEED_'];
  const pre = $('boot-text');
  const done = () => $('boot').classList.add('gone');
  if (REDUCED_MOTION) { pre.textContent = lines.join('\n'); setTimeout(done, 600); return; }
  lines.forEach((l, i) => setTimeout(() => { pre.textContent += `${l}\n`; }, 250 + i * 330));
  setTimeout(done, 250 + lines.length * 330 + 500);
}

// ---- deployment info from the front proxy, applied before the bar fitter first measures and before the first render.
//   /obs/exposure.json: the address the screens are published on (OBS_BIND) and the access mode (open / auth). Without a
//     login beyond localhost (only before P7, or an unknown answer) the bar says so permanently; with the login it says
//     nothing (who is logged in is in the ⋯ menu).
//   /obs/config.json: profile, whether a flow source is configured, the inventory devices, OBS_BIND (setup step).
// Fresh answers are remembered; a remembered config keeps a prod screen from turning into the demo look when the proxy
// is slow. The exposure indicator trusts fresh answers only (panels.exposureOf); both are fetched again every
// OBS_REFRESH_MS, so a later recovery or an OBS_BIND change updates it. With no config at all the bar says so.
const OBS_REFRESH_MS = 60000;
// The login session ended (Authelia answers a background request with 401 or a redirect to its login screen): reload,
// so the browser shows the login screen instead of a screen going STALE. At most once a minute (no reload loop).
function loginLost(r) {
  if (!(r.status === 401 || (r.redirected && new URL(r.url).pathname.startsWith('/auth')))) return false;
  const last = Number(sessionStorage.getItem('obs-relogin') || 0);
  if (Date.now() - last > 60000) {
    sessionStorage.setItem('obs-relogin', String(Date.now()));
    location.reload();
  }
  return true;
}
const obsJson = (path) => fetch(path, { cache: 'no-store', signal: AbortSignal.timeout(3000) })
  .then((r) => {
    const lost = loginLost(r); // also for a non-OK answer (401)
    return r.ok && !lost ? r.json() : null;
  }).catch(() => null);
function stored(key) {
  try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; }
}
function store(key, value) {
  if (!value) return;
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}
async function fetchObs() {
  const cached = { exp: stored('obs-exposure'), cfg: stored('obs-config') };
  const [exp, cfg] = await Promise.all([obsJson('/obs/exposure.json'), obsJson('/obs/config.json')]);
  store('obs-exposure', exp);
  store('obs-config', cfg);
  return { exposure: P.exposureOf(exp, cfg, cached.exp, cached.cfg), cfg: cfg || cached.cfg, freshCfg: cfg };
}
const LAN_TEXT = '認証なしで LAN 公開中';
function renderExposure(x) {
  const lab = $('lan-label');
  const was = [lab.hidden, lab.textContent].join('|');
  if (x.kind === 'local' || x.kind === 'auth') {
    lab.hidden = true;
  } else {
    lab.textContent = x.kind === 'lan' ? LAN_TEXT : 'LAN 公開: 不明';
    lab.classList.toggle('lan-unknown', x.kind !== 'lan'); // short form in the compact bar
    lab.title = x.kind === 'lan'
      ? `OBS_BIND=${x.bind}: screens are published on the LAN without authentication${x.cached ? ' (last known; the proxy did not answer)' : ''}`
      : 'The proxy did not answer: the screens may be on the LAN without authentication';
    lab.hidden = false;
  }
  return was !== [lab.hidden, lab.textContent].join('|');
}
let cfgWatch = { offer() {}, modeChanged() {} };
// ⋯ menu: the logged-in user, the role and logout (mask-api /am/ops: the proxy's verified identity); nothing without a login
const ROLE_TEXT = { viewer: 'viewer (閲覧のみ)', operator: 'operator (抑止・確認・アップロード)', admin: 'admin (operator + 利用者の管理)' };
function renderLogin(o) {
  const on = !!(o?.auth && o.user);
  $('menu-user').hidden = !on;
  $('menu-logout').hidden = !on;
  $('menu-admin').hidden = !(on && o.role === 'admin');
  if (!on) return;
  $('menu-user-name').textContent = o.user;
  $('menu-role').textContent = ROLE_TEXT[o.role] || o.role;
}
const refreshLogin = () => amOps().then(renderLogin).catch(() => {});
function refreshExposure() {
  fetchObs().then(({ exposure, freshCfg }) => {
    if (renderExposure(exposure)) UI.refitTopbar(); // the bar's cached compaction does not track this item
    cfgWatch.offer(freshCfg);
  });
  refreshLogin();
}
const OBS = { profile: 'demo', source: 'demo-gen (SYNTHETIC DATA)', flowSource: 'pcap-replay', cfg: null };
// the network map's devices: the inventory's (config.json), in its order; the demo's three without a config
const topoDevices = () => (Array.isArray(OBS.cfg?.devices) ? OBS.cfg.devices.filter((d) => d && typeof d.name === 'string')
  : P.DEVICES.map((n) => ({ name: n, kind: n.slice(0, 3) })));
async function applyObsInfo() {
  const { exposure, cfg } = await fetchObs();
  OBS.cfg = cfg || null;
  C.setSurgeConfig(cfg?.surge);
  renderExposure(exposure);
  refreshLogin();
  cfgWatch = P.configWatcher(cfg, { mode: UI.mode, reload: () => location.reload() });
  setInterval(refreshExposure, OBS_REFRESH_MS);
  if (!cfg) { // never seen: neither the demo label nor prod assumptions
    const lab = document.querySelector('.demo-label');
    lab.textContent = 'CONFIG UNAVAILABLE';
    lab.title = '/obs/config.json did not answer: profile unknown';
    lab.classList.add('cfg-unknown');
    OBS.source = 'unknown (config unavailable)';
  }
  if (cfg?.flow_source !== undefined) OBS.flowSource = cfg.flow_source;
  if (!cfg || cfg.profile === 'demo') return;
  OBS.profile = String(cfg.profile);
  const devices = Array.isArray(cfg.devices) ? cfg.devices.filter((d) => d && typeof d.name === 'string') : [];
  P.setDevices(devices);
  P.setWan(cfg.wan);
  $('p-wan').querySelector('.h-t').textContent = P.wanLabel();
  P.WLAN.unconfirmed = true;
  $('p-wlan').querySelector('.h-r').textContent = 'MIB unconfirmed';
  OBS.source = `inventory (${devices.length} devices)`;
  state.flowsConfigured = cfg.flows_configured !== false;
  OBS.flowSource = cfg.flow_source ?? null;
  if (!state.flowsConfigured) setNoFlowSource();
  document.querySelector('.demo-label').hidden = true;
  document.title = document.title.replace(' (DEMO)', '');
}

applyTheme(new URLSearchParams(location.search).get('theme') || readStoredTheme(), false);
await applyObsInfo();
initLayout();
$('theme-toggle').addEventListener('click', () => {
  applyTheme(THEMES[(THEMES.indexOf(document.documentElement.dataset.theme) + 1) % THEMES.length], true);
  G.styleGlobe();
  poll();
});
UI.initUi({ onClear: () => { G.setSelection(null); G.resetView(); }, onView: applyViewSelection, onModeChange: () => cfgWatch.modeChanged() });
// the alert banner is the way into the firing alerts: their full list on the wallboard, the alerts tab / panel below it
const openAlerts = () => (WALLBOARD.matches ? UI.openModal(M.alertsModal()) : UI.selectTab('alert'));
$('alert-banner').addEventListener('click', openAlerts);
$('alert-banner').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAlerts(); } });
AL.setOnChange(() => poll()); // after an ACK / silence change: show its effect now, not at the next poll
G.initGlobe({ onDest: (key) => { const [cc, city] = key.split('|'); nav.dest({ cc, city }); }, onInteract: () => UI.touched() });
// network map in the globe's slot (P5): same place and size; the globe pauses while it is hidden
const GLOBE_TITLE = { ja: $('p-globe').querySelector('.h-ja').textContent, t: $('p-globe').querySelector('.h-t').textContent };
T.initTopology({
  nav,
  setGlobe: (shown) => { G.setShown(shown); if (!shown) G.hideCard(); },
  onChange: (on) => {
    const h = $('p-globe');
    h.querySelector('.h-ja').textContent = on ? '網構成' : GLOBE_TITLE.ja;
    h.querySelector('.h-t').textContent = on ? 'NETWORK MAP' : GLOBE_TITLE.t;
    if (on) $('arc-note').textContent = T.summary();
    else if (state.snap) G.renderGlobe(state.snap.flows); // its arc count back in the header
  },
});
// globe drawing mode (settings menu only): GPU / LITE, picked automatically or by hand (globe.js, render-mode.js)
function showRender(r) {
  const b = $('render-toggle');
  if (!r.probe) { b.textContent = 'RENDER: —'; b.disabled = true; b.title = 'globe unavailable'; return; }
  b.textContent = r.label;
  b.title = `Globe drawing (data unchanged): GPU = animated, at most 30 fps · LITE = static, drawn only on change · AUTO = LITE when WebGL is software-rendered. This browser: ${r.probe.gpu ? 'hardware' : 'software / none'} (${r.probe.renderer})`;
}
showRender(G.renderInfo());
$('render-toggle').addEventListener('click', () => showRender(G.cycleRender()));
wirePanelTitles();
// ---- playback: main.js owns the data time (util.now()); playback.js moves the cursor and paces the fetches ---------
const resetFeed = () => { state.gen++; P.resetLogs(state.seenLogs); };
PB.initPlayback({
  setTime: (ms) => { setCursor(ms); C.clipToCursor(); }, // an open 原因候補 never shows anything after the new position
  fetch: () => poll(),
  jump: resetFeed,
  live: () => { // back to LIVE: the wallboard, the last 15 min, live polling; STALE until the first live answer
    resetFeed();
    $('badge').classList.remove('badge-playback');
    state.saidMode = null;
    state.waitFresh = true;
    UI.clearAll();
    poll();
  },
  exportWindow: (button, status) => {
    const w = PB.pbWindow();
    downloadEvidence({ scope: 'all', from: (w.from / 1000).toFixed(3), to: (w.to / 1000).toFixed(3) }, button, status, { snapshot: $('pb-snap').checked });
  },
});
snapshotGate($('pb-snap'), $('pb-snap').parentElement);
$('pb-enter').addEventListener('click', () => { UI.closeMenu(); PB.enterDefault(); });
$('pb-corr').addEventListener('click', () => nav.correlate({ at: now(), label: `再生位置 ${jstClock.format(new Date(now()))}`, ctx: {} }));
boot();
tickClock();
setInterval(tickClock, 1000);
poll().then(() => { // link in the notifications (OBS_PUBLIC_URL/?open=alerts): the alert list, once there is data
  if (new URLSearchParams(location.search).get('open') === 'alerts') openAlerts();
});
setInterval(() => { if (!isPlayback()) poll(true); }, POLL_MS); // live polling is off during playback
// scripted-test hook (read-only): screen position of a destination on the globe
window.ccTest = { screenOf: G.screenOf, info: G.testInfo, selection: G.testSelection, mode: UI.mode, playback: PB.testState, enterPlayback: PB.enter, render: G.renderInfo, topology: T.testState };
