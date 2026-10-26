// "証跡を出力": downloads the evidence zip that mask-api assembles server-side (/evidence/export, read-only, masked).
// The window is the playback window while playing back, else the last hour (an alert: from 10 min before it fired).
// No screen snapshot: a PNG of the page would need an extra library (README).
import { el, now, fmtBytes, maskText } from './util.js';
import { section } from './views-common.js';
import { pbWindow } from './playback.js';

const LIVE_S = 3600;
const BEFORE_ALERT_S = 600;
const MAX_S = 7 * 86400; // mask-api's window cap

// scope: { scope, instance?, ifName?, cc?, city?, ip?, host?, alertname?, severity? }; since: ms (alert activation)
export function windowFor(since) {
  const pb = pbWindow();
  if (pb) return { from: pb.from / 1000, to: pb.to / 1000 };
  const to = now() / 1000;
  const from = Number.isFinite(since) ? Math.max(to - MAX_S, Math.min(to - LIVE_S, since / 1000 - BEFORE_ALERT_S)) : to - LIVE_S;
  return { from, to };
}

export async function downloadEvidence(params, button, status) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''));
  button.disabled = true;
  status.textContent = '証跡を作成中… (サーバ側で伏せ字済みのデータを集めています)';
  try {
    const r = await fetch(`/evidence/export?${q}`, { cache: 'no-store' });
    if (!r.ok) {
      const j = await r.json().catch(() => null);
      throw new Error(j?.error || `HTTP ${r.status}`);
    }
    const blob = await r.blob();
    const name = /filename="([^"/\\]+)"/.exec(r.headers.get('Content-Disposition') || '')?.[1] || 'obs-evidence.zip';
    const a = el('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    status.textContent = `出力しました: ${name} (${fmtBytes(blob.size)})`;
    status.title = status.textContent;
  } catch (e) {
    status.textContent = `出力できません: ${maskText(String(e.message || e))}`;
    status.title = status.textContent;
  } finally {
    button.disabled = false;
  }
}

// optional packet statistics: a stored capture / upload / the demo pcap (never the raw packets)
async function pcapOptions(sel) {
  try {
    const r = await fetch('/pcap/files', { cache: 'no-store' });
    const f = r.ok ? await r.json() : null;
    const all = [...(f?.ring || []).filter((x) => !x.recording), ...(f?.upload || []), ...(f?.demo || [])];
    for (const x of all) { const o = el('option', '', `${x.kind}: ${x.name}`); o.value = x.id; sel.append(o); }
  } catch { /* no packet analysis: the export goes without it */ }
}

// drawer section: scopeOf() -> the scope params; sinceOf() -> optional alert activation (ms)
export function evidenceSection(scopeOf, sinceOf = () => undefined) {
  const s = section('証跡出力', 'evidence zip · masked · read-only');
  const row = el('div', 'filters ops');
  const b = el('button', 'link-btn ops-btn', '証跡を出力');
  b.type = 'button';
  b.lang = 'ja';
  b.setAttribute('aria-label', 'Export evidence: download a zip of the masked metrics, logs and alert history of this item');
  const l = el('label', 'fld', 'パケット統計');
  const sel = el('select');
  const none = el('option', '', '含めない');
  none.value = '';
  sel.append(none);
  l.append(sel);
  row.append(b, l);
  const status = el('p', 'ops-note ops-status');
  status.setAttribute('role', 'status');
  const note = el('p', 'v-p', 'メトリクス (CSV)・syslog・アラート履歴と通知記録・版情報を zip にします。期間は履歴再生中はその範囲、ライブでは直近 1 時間です。生アドレス・生 pcap は含みません。');
  s.body.append(row, status, note);
  pcapOptions(sel); // listed when the drawer opens
  b.addEventListener('click', () => {
    const w = windowFor(sinceOf());
    downloadEvidence({ ...scopeOf(), from: w.from.toFixed(3), to: w.to.toFixed(3), pcap: sel.value }, b, status);
  });
  return s;
}
