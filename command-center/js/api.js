// Read-only access to Prometheus/Loki through the same-origin nginx allowlist (/prom, /loki).
// Every window ends at now() (util.js): the wall clock live, the playback cursor in PLAYBACK.
import { now, isPlayback } from './util.js';

export async function getJson(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) {
    // mask-api refuses queries that could reveal a hidden address (errorType masked_query).
    const body = r.status === 400 ? await r.json().catch(() => null) : null;
    const err = new Error(body?.error || `${url.split('?')[0]} HTTP ${r.status}`);
    err.rejected = body?.errorType === 'masked_query';
    throw err;
  }
  const j = await r.json();
  if (j.status && j.status !== 'success') throw new Error(j.error || 'query failed');
  return j.data;
}
const nowS = () => now() / 1000;
const nowNs = () => BigInt(now()) * 1000000n;
// live instant queries stay exactly as before (Prometheus' own "now"); playback pins them to the cursor
export const promQuery = (q) => getJson(`/prom/api/v1/query?query=${encodeURIComponent(q)}${isPlayback() ? `&time=${nowS().toFixed(3)}` : ''}`).then((d) => d.result);
export function promRange(q, seconds, step) {
  const end = nowS();
  return getJson(`/prom/api/v1/query_range?query=${encodeURIComponent(q)}&start=${end - seconds}&end=${end}&step=${step}`).then((d) => d.result);
}
export const promAlerts = () => getJson('/prom/api/v1/alerts').then((d) => d.alerts);
export const promRules = () => getJson('/prom/api/v1/rules').then((d) => d.groups.flatMap((g) => g.rules));
// The alert list as of the playback cursor, in the shape of /api/v1/alerts: ALERTS gives name, labels and state,
// ALERTS_FOR_STATE the activation time. Value and annotations are not stored in the TSDB: left empty (shown as "—").
export async function promAlertsAt() {
  const [al, fs] = await Promise.all([promQuery('ALERTS'), promQuery('ALERTS_FOR_STATE')]);
  const strip = (m) => Object.fromEntries(Object.entries(m).filter(([k]) => k !== '__name__' && k !== 'alertstate'));
  const key = (m) => JSON.stringify(Object.entries(strip(m)).sort());
  const since = new Map(fs.map((r) => [key(r.metric), Number(r.value[1])]));
  return al.map((r) => {
    const t = since.get(key(r.metric));
    return { labels: strip(r.metric), state: r.metric.alertstate, activeAt: Number.isFinite(t) ? new Date(t * 1000).toISOString() : undefined, annotations: {} };
  });
}

// Loki log query; start/end in ns (strings ok). Returns streams.
const lokiLogData = (q, { startNs, endNs, limit = 200, direction = 'backward' }) =>
  getJson(`/loki/loki/api/v1/query_range?query=${encodeURIComponent(q)}&start=${startNs}&end=${endNs}&limit=${limit}&direction=${direction}`);
// Log lines (flattened, oldest first). A line-filtered query is scanned by mask-api, which may stop early: then it
// returns fewer than `limit` lines plus data.warnings and data.scanned_until (ns). scannedUntil !== null means the
// result is PARTIAL; continue with end=scannedUntil (backward) or start=scannedUntil+1 (forward).
export function lokiLogs(q, opts) {
  return lokiLogData(q, opts).then((d) => ({
    entries: flattenStreams(d.result),
    warnings: Array.isArray(d.warnings) ? d.warnings.map(String) : [],
    scannedUntil: d.scanned_until === undefined || d.scanned_until === null ? null : String(d.scanned_until),
  }));
}
export function lokiRange(q, seconds, limit) { // raw streams (wallboard feed; unfiltered selector, never partial)
  const end = nowNs();
  return lokiLogData(q, { startNs: String(end - BigInt(seconds) * 1000000000n), endNs: String(end), limit }).then((d) => d.result);
}
// Loki metric query through the allowed query_range path; returns the last point per series.
export function lokiMetric(q) {
  const end = Math.floor(nowS());
  return getJson(`/loki/loki/api/v1/query_range?query=${encodeURIComponent(q)}&start=${end - 60}&end=${end}&step=60`)
    .then((d) => d.result.map((r) => ({ metric: r.metric, value: r.values[r.values.length - 1] })));
}
// Flatten Loki streams into sorted entries (oldest first).
export function flattenStreams(streams) {
  const out = [];
  for (const s of streams) for (const [ts, line] of s.values) out.push({ ts, line, host: s.stream.host || '?', sev: s.stream.severity || '?' });
  return out.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
}
// ---- Alertmanager through mask-api (/am/): masked reads; silences are the only writes ----------------------------
// Writes carry X-Obs-Csrf (and the browser's Origin): mask-api refuses any write without both.
async function amJson(url, opts = {}) {
  const r = await fetch(url, { cache: 'no-store', ...opts });
  const body = await r.json().catch(() => null);
  if (!r.ok) throw new Error(body?.error || `${url} HTTP ${r.status}`);
  return body;
}
export const amAlerts = () => amJson('/am/api/v2/alerts');
export const amSilences = () => amJson('/am/api/v2/silences');
export const amOps = () => amJson('/am/ops');
const amWrite = (method, url, body) => amJson(url, { method, headers: { 'Content-Type': 'application/json', 'X-Obs-Csrf': '1' },
  ...(body ? { body: JSON.stringify(body) } : {}) });
export const createSilence = (body) => amWrite('POST', '/am/api/v2/silences', body);
export const expireSilence = (id) => amWrite('DELETE', `/am/api/v2/silence/${encodeURIComponent(id)}`);
// notify-relay's records of sent notifications (one JSON line per alert and receiver)
export function notifyLog(hours, limit) {
  const end = nowNs();
  return lokiLogs('{job="notify"}', { startNs: String(end - BigInt(hours * 3600) * 1000000000n), endNs: String(end), limit });
}

// ---- evidence export (mask-api /evidence/): read-only ----------------------------------------------------------
export const evidenceInfo = () => amJson('/evidence/info');

// LogQL string literal (backtick raw string cannot contain a backtick, so fall back to escaped quotes).
export function logqlString(s) {
  return s.includes('`') ? JSON.stringify(s) : `\`${s}\``;
}
