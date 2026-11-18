// "証跡を出力": downloads the evidence zip that mask-api assembles server-side (/evidence/export, read-only, masked).
// The window is the playback window while playing back, else the last hour (an alert: from 10 min before it fired).
// Optional screen snapshot (off by default; drawer, playback bar, 原因候補): a PNG made in this browser (snapshot.js) is
// sent with the request (POST, the write rules of the silences: with a login operator / admin only); when it cannot be
// made or sent, the zip is exported without it and the reason is shown. Without the permission the option is disabled
// with the reason.
import { el, now, fmtBytes, maskText } from './util.js';
import { amOps } from './api.js';
import { snapshotPng } from './snapshot.js';
import { section } from './views-common.js';
import { pbWindow } from './playback.js';

const LIVE_S = 3600;
const BEFORE_ALERT_S = 600;
const MAX_S = 7 * 86400; // mask-api's window cap
const SNAP_MAX = 8 * 2 ** 20; // bytes: the proxy's and mask-api's body cap (EVIDENCE_SNAPSHOT_MAX_MB, 8 MiB)
const SNAP_FALLBACK = new Set(['forbidden', 'csrf', 'snapshot']); // refused snapshot: export without it

// scope: { scope, instance?, ifName?, cc?, city?, ip?, host?, alertname?, severity? }; since: ms (alert activation)
export function windowFor(since) {
  const pb = pbWindow();
  if (pb) return { from: pb.from / 1000, to: pb.to / 1000 };
  const to = now() / 1000;
  const from = Number.isFinite(since) ? Math.max(to - MAX_S, Math.min(to - LIVE_S, since / 1000 - BEFORE_ALERT_S)) : to - LIVE_S;
  return { from, to };
}

const exportReq = (q, png) => fetch(`/evidence/export?${q}`, png
  ? { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'image/png', 'X-Obs-Csrf': '1' }, body: png }
  : { cache: 'no-store' });

// -> { png, why }: the screen as it is now (the page is cloned before anything here changes it)
async function takeSnapshot() {
  try {
    const png = await snapshotPng();
    return png.size > SNAP_MAX ? { png: null, why: `画像サイズ超過 (${fmtBytes(png.size)})` } : { png, why: '' };
  } catch (e) {
    return { png: null, why: String(e.message || e) };
  }
}

export async function downloadEvidence(params, button, status, { snapshot = false } = {}) {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''));
  const shot = snapshot ? takeSnapshot() : null;
  button.disabled = true;
  status.textContent = '証跡を作成中… (サーバ側でマスク処理済データを収集中)';
  try {
    let { png, why } = shot ? await shot : { png: null, why: '' };
    let r = await exportReq(q, png);
    if (png && !r.ok) {
      const j = await r.clone().json().catch(() => null);
      if (r.status === 413 || SNAP_FALLBACK.has(j?.errorType)) {
        why = j?.error || `HTTP ${r.status}`;
        png = null;
        r = await exportReq(q, null);
      }
    }
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
    const sent = png ? r.headers.get('X-Obs-Snapshot') || '' : ''; // what the server put in the zip
    if (png && sent !== 'included') why = sent ? `サーバ側で同梱失敗 (${sent})` : 'サーバ応答に記録なし';
    const snapNote = !snapshot ? '' : sent === 'included' ? ' · スナップショットあり' : ` · スナップショットなし: ${maskText(why)}`;
    status.textContent = `出力完了: ${name} (${fmtBytes(blob.size)})${snapNote}`;
    status.title = status.textContent;
  } catch (e) {
    status.textContent = `出力不可: ${maskText(String(e.message || e))}`;
    status.title = status.textContent;
  } finally {
    button.disabled = false;
  }
}

// The snapshot option: disabled with the reason when this login may not write (mask-api /am/ops, the same rule)
export function snapshotGate(input, label) {
  amOps().then((o) => {
    if (o?.writable) return;
    input.checked = false;
    input.disabled = true;
    label.classList.add('is-off');
    label.title = `画面画像の同梱不可: ${o?.reason || '操作可否の確認不能'}`;
  }).catch(() => {});
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
  const none = el('option', '', '同梱なし');
  none.value = '';
  sel.append(none);
  l.append(sel);
  const sl = el('label', 'fld chk');
  const snap = el('input');
  snap.type = 'checkbox'; // off by default, not remembered
  sl.title = '画面スナップショット (PNG) の同梱: 本ブラウザで現在の画面 (マスク処理済) を画像化';
  sl.append(snap, document.createTextNode(' 画面の画像'));
  snapshotGate(snap, sl);
  row.append(b, l, sl);
  const status = el('p', 'ops-note ops-status');
  status.setAttribute('role', 'status');
  const note = el('p', 'v-p', 'メトリクス (CSV)・syslog・アラート履歴と通知記録・版情報を zip 化します。期間は履歴再生中は再生範囲、ライブ時は直近 1 時間です。生アドレス・生 pcap は対象外です。「画面の画像」選択時は現在画面の PNG (snapshot.png) も同梱します (ログイン有効時は operator 以上)。');
  s.body.append(row, status, note);
  pcapOptions(sel); // listed when the drawer opens
  b.addEventListener('click', () => {
    const w = windowFor(sinceOf());
    downloadEvidence({ ...scopeOf(), from: w.from.toFixed(3), to: w.to.toFixed(3), pcap: sel.value }, b, status, { snapshot: snap.checked });
  });
  return s;
}
