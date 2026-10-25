// Read-only access to Prometheus/Loki through the same-origin nginx allowlist (/prom, /loki).

export async function getJson(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`${url.split('?')[0]} HTTP ${r.status}`);
  const j = await r.json();
  if (j.status && j.status !== 'success') throw new Error(j.error || 'query failed');
  return j.data;
}
export const promQuery = (q) => getJson(`/prom/api/v1/query?query=${encodeURIComponent(q)}`).then((d) => d.result);
export function promRange(q, seconds, step) {
  const end = Date.now() / 1000;
  return getJson(`/prom/api/v1/query_range?query=${encodeURIComponent(q)}&start=${end - seconds}&end=${end}&step=${step}`).then((d) => d.result);
}
export const promAlerts = () => getJson('/prom/api/v1/alerts').then((d) => d.alerts);
export const promRules = () => getJson('/prom/api/v1/rules').then((d) => d.groups.flatMap((g) => g.rules));

// Loki log query; start/end in ns (strings ok). Returns streams.
export function lokiLogs(q, { startNs, endNs, limit = 200, direction = 'backward' }) {
  return getJson(`/loki/loki/api/v1/query_range?query=${encodeURIComponent(q)}&start=${startNs}&end=${endNs}&limit=${limit}&direction=${direction}`)
    .then((d) => d.result);
}
export function lokiRange(q, seconds, limit) {
  const end = BigInt(Date.now()) * 1000000n;
  return lokiLogs(q, { startNs: String(end - BigInt(seconds) * 1000000000n), endNs: String(end), limit });
}
// Loki metric query through the allowed query_range path; returns the last point per series.
export function lokiMetric(q) {
  const end = Math.floor(Date.now() / 1000);
  return getJson(`/loki/loki/api/v1/query_range?query=${encodeURIComponent(q)}&start=${end - 60}&end=${end}&step=60`)
    .then((d) => d.result.map((r) => ({ metric: r.metric, value: r.values[r.values.length - 1] })));
}
// Flatten Loki streams into sorted entries (oldest first).
export function flattenStreams(streams) {
  const out = [];
  for (const s of streams) for (const [ts, line] of s.values) out.push({ ts, line, host: s.stream.host || '?', sev: s.stream.severity || '?' });
  return out.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
}
// LogQL string literal (backtick raw string cannot contain a backtick, so fall back to escaped quotes).
export function logqlString(s) {
  return s.includes('`') ? JSON.stringify(s) : `\`${s}\``;
}
