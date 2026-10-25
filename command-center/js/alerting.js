// Alert notifications on the screens: per firing alert its notification state (通知済 / 抑止中 / 確認済 ...) and the next
// repeat; ACK / silence controls (alert drawer); the silence list with create / extend / expire (alerts modal).
// Sources: Alertmanager's alerts and silences (masked, mask-api /am/), notify-relay's records (Loki {job="notify"}),
// and /am/ops (are writes allowed: only while the screens are on 127.0.0.1, until an authentication layer exists).
import { el, has, jstFull, jstHm, fmtDur, maskText } from './util.js';
import { amAlerts, amSilences, amOps, notifyLog, createSilence, expireSilence } from './api.js';
import { section, putIn, tiles, alertKey } from './views-common.js';

// the longest repeat interval allowed (7 d) + 1 h: the last notification of any firing alert is in the window.
// ponytail: the newest 5000 records only (mask-api's cap), read at most once a minute; a per-alert index if that is short
const LOG_HOURS = 7 * 24 + 1;
const LOG_LIMIT = 5000;
const LOG_EVERY_MS = 60000;
const ACK_HOURS = 24; // an ACK ends when its alert resolves (notify-relay expires it); this is the cap
const MAX_S = 7 * 86400 - 120; // mask-api accepts at most 7 days; a little under for clock differences
export const DURATIONS = [['1 h', 3600], ['4 h', 4 * 3600], ['24 h', 86400], ['7 d', MAX_S]];

export const AM = { ok: null, err: '', silences: [], byKey: new Map(), last: new Map(), logOk: false, logAt: 0, forceLog: false, logTruncated: false,
  ops: { writable: false, reason: '操作の可否を確認中…' } };
let changed = () => Promise.resolve();
export const setOnChange = (fn) => { changed = fn; };

const iso = (ms) => new Date(ms).toISOString();
// made here: createdBy "command-center (<operator>)" (mask-api sets it; plain "command-center" from before)
const ours = (s) => { const by = String(s?.createdBy || ''); return by === 'command-center' || by.startsWith('command-center ('); };
const ACK_RE = /^ACK\b/; // the same rule as mask-api (ack_comment) and notify-relay (ACK_RE)
export const isAck = (s) => ours(s) && ACK_RE.test(String(s.comment || ''));

// notification records per alert fingerprint, newest first (test notifications ignored)
export function lastNotified(entries) {
  const by = new Map();
  for (const e of entries) {
    let r;
    try { r = JSON.parse(e.line); } catch { continue; }
    if (!r || r.test || !r.fingerprint || !has(r.t)) continue;
    if (!by.has(r.fingerprint)) by.set(r.fingerprint, []);
    by.get(r.fingerprint).push(r);
  }
  for (const rs of by.values()) rs.sort((a, b) => b.t - a.t);
  return by;
}
// The records of THIS activation (a fingerprint fires again after resolving): matched by the alert's startsAt that the
// relay records; older records (without it) count only if sent after this activation began.
const sameActivation = (r, startsMs) => (r.starts ? Math.abs(Date.parse(r.starts) - startsMs) < 2000 : r.t * 1000 >= startsMs - 1000);
// latest firing record per receiver -> [{ receiver, result, detail, t, repeat_s, message }]
function perReceiver(recs, startsMs) {
  const out = new Map();
  for (const r of recs) if (r.status === 'firing' && sameActivation(r, startsMs) && !out.has(r.receiver)) out.set(r.receiver, r);
  return [...out.values()];
}
const shortDetail = (d) => maskText(String(d || '')).split(' ').slice(0, 2).join(' ');

// never throws: a failing source makes the state "unknown", it does not break the Prometheus panels
export async function pollAlerting() {
  const logDue = AM.forceLog || !AM.logOk || Date.now() - AM.logAt >= LOG_EVERY_MS;
  AM.forceLog = false;
  const [al, si, log, ops] = await Promise.allSettled([amAlerts(), amSilences(), logDue ? notifyLog(LOG_HOURS, LOG_LIMIT) : null, amOps()]);
  AM.ok = al.status === 'fulfilled' && si.status === 'fulfilled' && Array.isArray(al.value) && Array.isArray(si.value);
  AM.err = AM.ok ? '' : String(al.reason || si.reason || 'unexpected answer');
  if (AM.ok) {
    AM.silences = si.value;
    AM.byKey = new Map(al.value.map((a) => [alertKey(a.labels || {}), a]));
  }
  if (logDue) {
    AM.logOk = log.status === 'fulfilled' && !!log.value;
    if (AM.logOk) {
      AM.last = lastNotified(log.value.entries);
      AM.logAt = Date.now();
      AM.logTruncated = log.value.entries.length >= LOG_LIMIT; // older records exist but were not loaded
    } else AM.last = new Map(); // never stale "sent"
  }
  AM.ops = ops.status === 'fulfilled' && ops.value ? ops.value : { writable: false, reason: '操作の可否を確認できません (mask-api に接続できない)' };
}

// badge class per state (status is always text too, never colour alone)
export const NT_KIND = { sent: 'ok', partial: 'warn', acked: 'info', silenced: 'unknown', failed: 'warn', pending: 'none', none: 'none', unknown: 'unknown' };
// -> { kind, label (fixed slot, <= 4 chars), text, at, next, receivers, until, silence }
export function notifyState(a, now = Date.now()) {
  if (AM.ok === null) return { kind: 'none', label: '—', text: 'checking notifications' };
  if (!AM.ok) return { kind: 'unknown', label: '不明', text: 'Alertmanager unavailable: notification state unknown' };
  const am = AM.byKey.get(alertKey(a.labels));
  if (!am) return { kind: 'pending', label: '未通知', text: 'not in Alertmanager yet' };
  const results = AM.logOk ? perReceiver(AM.last.get(am.fingerprint) || [], Date.parse(am.startsAt)) : [];
  const failed = results.filter((r) => r.result !== 'ok'); // "partial" (some recipients refused) is a failure too
  const latest = results.reduce((m, r) => (m && m.t >= r.t ? m : r), null);
  const summary = results.map((r) => `${r.receiver} ${r.result === 'ok' ? 'OK' : shortDetail(r.detail) || 'NG'}`).join(' / ');
  const sent = latest ? { at: latest.t * 1000, receivers: results.filter((r) => r.result === 'ok').map((r) => r.receiver), message: latest.message } : {};
  const sil = (am.status?.silencedBy || []).map((id) => AM.silences.find((s) => s.id === id)).filter(Boolean);
  const s = sil.find(isAck) || sil[0];
  if (s) { // muted: the last notification is still shown, there is no next one
    const ack = isAck(s);
    return { kind: ack ? 'acked' : 'silenced', label: ack ? '確認済' : '抑止中', silence: s, until: Date.parse(s.endsAt), ...sent,
      text: `${ack ? 'acknowledged' : 'silenced'} · no notifications${ack ? ' until resolved' : ' until the end'}` };
  }
  // without the notification records (Loki failing) nothing is known about delivery: never "sent", "next" or "waiting"
  if (!AM.logOk) return { kind: 'unknown', label: '不明', text: 'notification records unavailable (Loki): delivery unknown' };
  // next repeat from the CURRENT routing: the receivers Alertmanager sends this alert to now, from their last success
  const routed = (am.receivers || []).map((r) => r.name).filter((n) => n !== 'none');
  const due = results.filter((r) => r.result === 'ok' && routed.includes(r.receiver) && has(r.repeat_s)).map((r) => (r.t + r.repeat_s) * 1000);
  const next = due.length ? Math.min(...due) : undefined;
  if (results.length) {
    // 通知済 only when every receiver it is routed to now has a success for this activation
    const missing = routed.filter((n) => !results.some((r) => r.receiver === n));
    const kind = failed.length ? 'failed' : missing.length ? 'partial' : 'sent';
    const head = { failed: `${failed.length} of ${results.length} receivers failed`, partial: `no record yet from ${missing.join(', ')}`, sent: 'sent' }[kind];
    return { kind, label: { failed: '通知失敗', partial: '一部未確認', sent: '通知済' }[kind], next, missing, ...sent,
      text: `${head}: ${summary}${routed.length ? '' : ' · not routed any more (no repeat)'}` };
  }
  if (AM.logTruncated) return { kind: 'unknown', label: '履歴上限', text: `older notification records not loaded (newest ${LOG_LIMIT} only)` };
  if (!routed.length) return { kind: 'none', label: '通知なし', text: 'no receiver for this severity (by configuration)' };
  return { kind: 'pending', label: '未通知', text: 'waiting for the first notification (grouping)' };
}
export const nextText = (st, now = Date.now()) => (!has(st.next) ? '' : st.next > now ? `next ${jstHm.format(new Date(st.next))}` : 'next: due');

const M = (name, value) => ({ name, value, isRegex: false, isEqual: true });
// scope: 'alert' (this alert: alertname + instance + ifName), 'device' (everything of the instance), 'name' (alertname)
export function alertMatchers(labels, scope) {
  if (scope === 'device') return [M('instance', labels.instance)];
  if (scope === 'name') return [M('alertname', labels.alertname)];
  return ['alertname', 'instance', 'ifName'].filter((k) => labels[k]).map((k) => M(k, labels[k]));
}
const matcherText = (ms) => (ms || []).map((m) => `${m.name}${m.isEqual === false ? '!=' : '='}${m.isRegex ? '~' : ''}${m.value}`).join(' · ');

// a control row action: disables its buttons while running, says what happened, then refreshes everything
async function act(status, buttons, fn, done) {
  for (const b of buttons) b.disabled = true;
  status.textContent = '送信中…';
  try {
    await fn();
    status.textContent = done;
    AM.forceLog = true;
    await changed(); // the views' next update sets every control's state again
  } catch (e) {
    status.textContent = `失敗: ${maskText(String(e.message || e))}`;
    for (const b of buttons) b.disabled = !AM.ops.writable;
  } finally {
    // the used button may now be disabled (ACK done) or gone (expired row): keep keyboard focus on the result line
    if (!document.activeElement || document.activeElement === document.body) {
      status.tabIndex = -1;
      status.focus({ preventScroll: true });
    }
  }
}
function button(text, label) {
  const b = el('button', 'link-btn ops-btn', text);
  b.type = 'button';
  if (label) b.setAttribute('aria-label', label);
  return b;
}
function select(label, opts, value) {
  const l = el('label', 'fld', label);
  const s = el('select');
  for (const [t, v] of opts) { const o = el('option', '', t); o.value = String(v); s.append(o); }
  s.value = String(value);
  l.append(s);
  return { wrap: l, sel: s };
}

// ---- alert drawer: state tiles + ACK / silence / expire ------------------------------------------------------
export function alertOpsSection() {
  const s = section('Notification & actions', '通知と操作 · via Alertmanager');
  const sum = el('div');
  const form = el('div', 'filters ops');
  const ack = button('確認 (ACK)', 'Acknowledge: stop repeat notifications of this alert until it resolves');
  const dur = select('抑止の期間', DURATIONS, 3600);
  const scope = select('対象', [['この警報', 'alert'], ['この機器のすべて', 'device'], ['この警報名のすべて', 'name']], 'alert');
  const mute = button('抑止する', 'Silence for the chosen period');
  const unmute = button('抑止を解除', 'Expire the silence / ACK');
  form.append(ack, dur.wrap, scope.wrap, mute, unmute);
  const note = el('p', 'ops-note');
  const status = el('p', 'ops-note ops-status');
  status.setAttribute('role', 'status');
  // the last notification's text as rendered (kept by the demo sink: what a real receiver would have got)
  const msgWrap = el('div', 'nt-msg-wrap');
  const msg = el('pre', 'nt-msg');
  msgWrap.append(el('div', 'v-meta-line', 'Notification text (as sent, IP/MAC masked)'), msg);
  s.body.append(sum, form, note, status, msgWrap);
  const all = [ack, mute, unmute, dur.sel, scope.sel];
  let cur = null;
  ack.addEventListener('click', () => act(status, all, () => createSilence({ matchers: alertMatchers(cur.labels, 'alert'),
    endsAt: iso(Date.now() + ACK_HOURS * 3600e3), comment: 'ACK: repeats stopped until resolved' }), '確認済みにしました (解消まで再通知しません)'));
  mute.addEventListener('click', () => act(status, all, () => createSilence({ matchers: alertMatchers(cur.labels, scope.sel.value),
    endsAt: iso(Date.now() + Number(dur.sel.value) * 1000), comment: 'silenced from the command-center' }), '抑止しました'));
  unmute.addEventListener('click', () => act(status, all, () => expireSilence(cur.st.silence.id), '解除しました'));
  return {
    wrap: s.wrap,
    update(a, firing) {
      const st = notifyState(a);
      cur = { labels: a.labels, st };
      const now = Date.now();
      putIn(sum, tiles([
        { label: 'Notification', value: st.label, kind: NT_KIND[st.kind], status: st.text },
        { label: 'Last sent (JST)', value: has(st.at) ? jstHm.format(new Date(st.at)) : undefined, sub: st.receivers?.join(', ') },
        { label: 'Next repeat (JST)', value: has(st.next) ? (st.next > now ? jstHm.format(new Date(st.next)) : 'due') : undefined,
          sub: has(st.next) && st.next > now ? `in ${fmtDur((st.next - now) / 1000)} · until resolved` : st.silence ? 'muted' : undefined },
        { label: st.kind === 'acked' ? 'ACK until (JST)' : 'Silenced until (JST)', value: has(st.until) ? jstFull.format(new Date(st.until)).slice(0, -3) : undefined,
          sub: st.silence ? maskText(String(st.silence.comment || '')) : undefined },
      ]));
      const w = AM.ops.writable && AM.ok && firing;
      for (const n of [dur.sel, scope.sel, mute]) n.disabled = !w;
      ack.disabled = !w || st.kind === 'acked';
      unmute.hidden = !st.silence;
      unmute.disabled = !w || !ours(st.silence);
      scope.sel.querySelector('option[value="device"]').disabled = !a.labels.instance;
      note.textContent = !AM.ok ? 'Alertmanager に接続できないため操作できません'
        : !firing ? '発報中ではないため操作できません (解消済み)'
          : !AM.ops.writable ? `操作できません: ${AM.ops.reason}`
            : st.silence && !ours(st.silence) ? 'この抑止は command-center 以外で作られたため、ここでは解除できません' : '';
      note.hidden = !note.textContent;
      msgWrap.hidden = !st.message;
      if (st.message && msg.textContent !== st.message) msg.textContent = maskText(String(st.message));
    },
  };
}

// ---- alerts modal: silence list + new silence ---------------------------------------------------------------
export function silenceSection({ devices, alertNames }) {
  const s = section('Silences & ACK', '抑止・確認の一覧 · Alertmanager');
  const form = el('form', 'filters ops');
  const dev = select('機器', [['すべて', ''], ...devices().map((d) => [d, d])], '');
  const name = select('警報名', [['すべて', '']], '');
  const dur = select('期間', DURATIONS, 3600);
  const cl = el('label', 'fld', 'コメント');
  const comment = el('input');
  comment.type = 'text';
  comment.maxLength = 200;
  comment.placeholder = '例 メンテナンス';
  cl.append(comment);
  const create = button('抑止を作成', 'Create a silence for the chosen device / alert name');
  create.type = 'submit';
  form.append(dev.wrap, name.wrap, dur.wrap, cl, create);
  const note = el('p', 'ops-note');
  const status = el('p', 'ops-note ops-status');
  status.setAttribute('role', 'status');
  const list = el('div', 'sil-list');
  s.body.append(form, note, status, list);
  alertNames().then((names) => {
    for (const n of names) { const o = el('option', '', n); o.value = n; name.sel.append(o); }
  }).catch(() => {});
  const controls = [dev.sel, name.sel, dur.sel, comment, create];
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const ms = [...(name.sel.value ? [M('alertname', name.sel.value)] : []), ...(dev.sel.value ? [M('instance', dev.sel.value)] : [])];
    if (!ms.length) { status.textContent = '機器か警報名のどちらかを選んでください (すべてを抑止することはできません)'; return; }
    act(status, controls, () => createSilence({ matchers: ms, endsAt: iso(Date.now() + Number(dur.sel.value) * 1000),
      comment: comment.value.trim() || 'silenced from the command-center' }), '抑止を作成しました');
  });
  return {
    wrap: s.wrap,
    update() {
      const w = AM.ops.writable && AM.ok;
      for (const c of controls) c.disabled = !w;
      note.textContent = !AM.ok ? 'Alertmanager に接続できません: 一覧と操作は使えません' : !w ? `操作できません: ${AM.ops.reason}` : '';
      note.hidden = !note.textContent;
      const now = Date.now();
      const shown = AM.silences.filter((x) => ['active', 'pending'].includes(x.status?.state)).sort((a, b) => Date.parse(a.endsAt) - Date.parse(b.endsAt));
      const rows = shown.map((x) => silenceRow(x, now, w, status));
      if (!rows.length) rows.push(el('p', 'na', AM.ok ? '抑止・確認はありません' : '—'));
      putIn(list, ...rows);
    },
  };
}
function silenceRow(x, now, writable, status) {
  const end = Date.parse(x.endsAt);
  const r = el('div', 'sil-row');
  const kind = isAck(x) ? ['info', 'ACK'] : ['unknown', x.status.state === 'pending' ? '予定' : '抑止'];
  const b = el('span', `st st-${kind[0]}`, kind[1]);
  const what = el('div', 'sil-what');
  what.append(el('div', 'sil-m', maskText(matcherText(x.matchers))),
    el('div', 'sil-sub', `until ${jstFull.format(new Date(end))} JST (${end > now ? `in ${fmtDur((end - now) / 1000)}` : 'ending'}) · ${maskText(String(x.comment || ''))} · by ${x.createdBy}`));
  const btns = el('div', 'sil-btns');
  if (ours(x)) {
    const extend = (h) => {
      const t = button(`+${h} h`, `Extend by ${h} hours`);
      t.dataset.fkey = `sil ${x.id} +${h}`;
      const cap = Math.min(now, Date.parse(x.startsAt)) + MAX_S * 1000; // 7 d from its start
      t.disabled = !writable || end >= cap - 60e3;
      t.title = t.disabled && writable ? 'already at 7 days from its start: make a new silence' : '';
      t.addEventListener('click', () => act(status, [t], () => createSilence({ id: x.id, endsAt: iso(Math.min(Math.max(end, now) + h * 3600e3, cap)) }), '延長しました'));
      return t;
    };
    const ex = button('解除', 'Expire this silence');
    ex.dataset.fkey = `sil ${x.id} expire`;
    ex.disabled = !writable;
    ex.addEventListener('click', () => act(status, [ex], () => expireSilence(x.id), '解除しました'));
    btns.append(extend(1), extend(24), ex);
  } else btns.append(el('span', 'sil-sub', 'managed outside the command-center'));
  r.append(b, what, btns);
  return r;
}
