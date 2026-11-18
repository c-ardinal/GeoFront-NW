// PLAYBACK mode: a time window, a cursor in it (slider, play at 0.5-8x, pause, one step), and the fetch pacing.
// The cursor is the screen's data time: main.js sets it as util.now() for every query builder (setTime hook) and
// re-renders everything through its normal poll (fetch hook). Live polling is off meanwhile (main.js).
// Fetch batches never overlap. While playing they start at least max(1 s, one scrape interval / speed) apart (real
// time), so the server is asked about as often as new data exists at that speed (1x: every 15 s, 8x: every ~2 s), never
// more than live polling at 8x; each batch advances the cursor by speed x the real time since the last one, so a slow
// server makes the steps coarser, never more frequent. A seek / step waits at least 1 s after the previous batch.
import { $, el, isPlayback, jstFull } from './util.js';
import { evidenceInfo } from './api.js';
import * as UI from './ui.js';

const STEP_S = 15; // the "1 ステップ" step, the slider resolution and the 1x pacing (kept at 15 s with the 30 s scrape interval)
const MIN_BATCH_MS = 1000;
const MAX_RANGE_S = 7 * 86400; // mask-api's evidence window cap, and the longest preset
const SPEEDS = [0.5, 1, 2, 4, 8];
const PRESETS = [['1h', 3600], ['6h', 6 * 3600], ['24h', 86400], ['7d', 7 * 86400]];
const DEFAULT_S = 3600;
const PB = { from: 0, to: 0, cursor: 0, shown: null, speed: 1, playing: false, lastReal: 0, busy: false, lastStart: -Infinity, want: false, timer: 0 };
let hooks = { setTime() {}, fetch: async () => {}, jump() {}, live() {}, exportWindow() {} };
let retention = { loaded: false, s: null, why: '' }; // the shorter of Prometheus' and Loki's retention

export const pbWindow = () => (isPlayback() ? { from: PB.from, to: PB.to, cursor: PB.cursor } : null);

const pad = (n) => String(n).padStart(2, '0');
// <input type="datetime-local"> values are read and written as JST, like every time on the screens
function toInput(ms) {
  const d = new Date(ms + 9 * 3600e3);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
const fromInput = (v) => (v ? Date.parse(`${v}:00+09:00`) : NaN);
const short = (ms) => jstFull.format(new Date(ms)).slice(0, -3); // MM/DD HH:MM
const durText = (s) => (s >= 86400 ? `${Math.round(s / 86400)}d` : s >= 3600 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 60)}m`);

async function loadRetention() {
  if (retention.loaded) return retention;
  try {
    const i = await evidenceInfo();
    const r = [i.retention_s?.prometheus, i.retention_s?.loki].filter((x) => Number.isFinite(x) && x > 0);
    retention = { loaded: true, s: r.length ? Math.min(...r) : null, why: r.length ? '' : '保持期間の確認不能 (範囲外の時刻は「—」表示)' };
  } catch {
    retention = { loaded: false, s: null, why: '保持期間の確認不能 (mask-api 接続不可)' };
  }
  return retention;
}
// -> '' when [from, to] can be played, else the reason it cannot
function rangeProblem(from, to) {
  const nowMs = Date.now();
  if (!Number.isFinite(from) || !Number.isFinite(to)) return '開始時刻と終了時刻を入力してください';
  if (to <= from) return '終了時刻は開始時刻以降に設定してください';
  if (to - from > MAX_RANGE_S * 1000) return '期間は 7 日以内に設定してください (証跡出力の上限と同一)';
  if (to > nowMs + 60e3) return '未来時刻の再生は不可';
  if (retention.s && from < nowMs - retention.s * 1000) return `保持期間外です (保存範囲は直近 ${durText(retention.s)}: Prometheus / Loki の保持期間)`;
  return '';
}

// ---- fetch pacing -----------------------------------------------------------------------------------------------
function request() { PB.want = true; pump(); }
async function pump() {
  if (PB.busy || !PB.want || !isPlayback()) return;
  const gap = PB.playing && !PB.seeked ? Math.max(MIN_BATCH_MS, (STEP_S * 1000) / PB.speed) : MIN_BATCH_MS;
  const wait = gap - (performance.now() - PB.lastStart);
  if (wait > 0) { clearTimeout(PB.timer); PB.timer = setTimeout(pump, wait); return; }
  PB.want = false;
  PB.seeked = false;
  const jumped = PB.jumped;
  PB.jumped = false;
  PB.busy = true;
  PB.lastStart = performance.now();
  if (PB.playing) {
    const real = performance.now();
    PB.cursor = Math.min(PB.to, PB.cursor + PB.speed * (real - PB.lastReal));
    PB.lastReal = real;
    if (PB.cursor >= PB.to) setPlaying(false);
  }
  // a slider move (either way) or going backwards: the syslog feed restarts at the new position (a step or playing on
  // only appends the newer lines)
  if (PB.shown !== null && (jumped || PB.cursor < PB.shown)) hooks.jump();
  PB.shown = PB.cursor;
  hooks.setTime(PB.cursor);
  renderBar();
  try { await hooks.fetch(); } finally {
    PB.busy = false;
    if (PB.playing) PB.want = true;
    pump();
  }
}

// ---- controls ---------------------------------------------------------------------------------------------------
function setPlaying(on) {
  PB.playing = on && PB.cursor < PB.to;
  PB.lastReal = performance.now();
  if (!PB.playing && !PB.seeked) { clearTimeout(PB.timer); PB.want = false; } // paused: no further batch for the same position
  const b = $('pb-play');
  b.replaceChildren(el('span', 'pb-ico', PB.playing ? '❚❚' : '▶'), PB.playing ? ' 一時停止' : ' 再生');
  b.dataset.on = String(PB.playing); // the label says the action (再生 / 一時停止), so no aria-pressed
  if (PB.playing) request();
}
function seek(ms, jump = true) {
  PB.cursor = Math.max(PB.from, Math.min(PB.to, ms));
  PB.lastReal = performance.now();
  PB.seeked = true; // a user move answers within 1 s, also while playing
  PB.jumped = PB.jumped || jump;
  request();
}
function renderBar() {
  const s = $('pb-slider');
  s.min = String(PB.from / 1000);
  s.max = String(PB.to / 1000);
  s.value = String(Math.round(PB.cursor / 1000));
  s.setAttribute('aria-valuetext', `${jstFull.format(new Date(PB.cursor))} JST`);
  s.title = `${jstFull.format(new Date(PB.cursor))} JST`;
  $('pb-range-btn').textContent = `${short(PB.from)} – ${short(PB.to)} (${durText((PB.to - PB.from) / 1000)})`;
  $('pb-step').disabled = PB.cursor >= PB.to;
}
function openRange(open) {
  const pop = $('pb-pop');
  pop.hidden = !open;
  $('pb-range-btn').setAttribute('aria-expanded', String(open));
  if (!open) return;
  $('pb-from').value = toInput(PB.from || Date.now() - DEFAULT_S * 1000);
  $('pb-to').value = toInput(PB.to || Date.now());
  loadRetention().then(validate);
  validate();
  $('pb-from').focus();
}
function validate() {
  for (const b of $('pb-presets').querySelectorAll('button')) {
    const s = Number(b.dataset.s);
    b.disabled = !!(retention.s && s > retention.s);
    b.title = b.disabled ? `保持期間外 (保存範囲は直近 ${durText(retention.s)})` : `直近 ${b.textContent} を再生`;
  }
  const why = rangeProblem(fromInput($('pb-from').value), fromInput($('pb-to').value));
  $('pb-apply').disabled = !!why;
  $('pb-why').textContent = why || retention.why;
}

// enter (or change the window): paused at its start
export function enter(fromMs, toMs) {
  PB.from = Math.floor(fromMs / 1000) * 1000;
  PB.to = Math.floor(toMs / 1000) * 1000;
  PB.cursor = PB.from;
  PB.shown = null;
  setPlaying(false);
  hooks.setTime(PB.cursor);
  $('playback').hidden = false;
  document.body.classList.add('pb-on');
  UI.refreshMode();
  hooks.jump(); // a new position: the syslog feed restarts there
  renderBar();
  request();
}
export function exit() {
  setPlaying(false);
  clearTimeout(PB.timer);
  PB.want = false;
  openRange(false);
  $('playback').hidden = true;
  document.body.classList.remove('pb-on');
  hooks.setTime(null);
  UI.refreshMode();
  hooks.live();
}
export const enterDefault = () => (isPlayback() ? openRange(true) : enter(Date.now() - DEFAULT_S * 1000, Date.now()));

export function initPlayback(h) {
  hooks = { ...hooks, ...h };
  const presets = $('pb-presets');
  for (const [text, s] of PRESETS) {
    const b = el('button', 'pb-btn', text);
    b.type = 'button';
    b.dataset.s = String(s);
    b.addEventListener('click', () => { openRange(false); enter(Date.now() - s * 1000, Date.now()); });
    presets.append(b);
  }
  for (const v of SPEEDS) { const o = el('option', '', `${v}×`); o.value = String(v); $('pb-speed').append(o); }
  $('pb-speed').value = '1';
  // a new speed changes the batch interval at once (the pending timer is re-armed by pump), not after the old one
  $('pb-speed').addEventListener('change', (e) => {
    if (PB.playing) { // the time played so far counts at the old speed
      const real = performance.now();
      PB.cursor = Math.min(PB.to, PB.cursor + PB.speed * (real - PB.lastReal));
      PB.lastReal = real;
    }
    PB.speed = Number(e.target.value);
    if (PB.playing) request();
  });
  $('pb-play').addEventListener('click', () => { if (PB.cursor >= PB.to) seek(PB.from); setPlaying(!PB.playing); });
  $('pb-step').addEventListener('click', () => { setPlaying(false); seek(PB.cursor + STEP_S * 1000, false); });
  $('pb-slider').step = String(STEP_S);
  $('pb-slider').addEventListener('input', (e) => seek(Number(e.target.value) * 1000));
  $('pb-live').addEventListener('click', exit);
  $('pb-export').addEventListener('click', () => hooks.exportWindow($('pb-export'), $('pb-status')));
  $('pb-range-btn').addEventListener('click', () => openRange($('pb-pop').hidden));
  $('pb-from').addEventListener('input', validate);
  $('pb-to').addEventListener('input', validate);
  $('pb-apply').addEventListener('click', () => { openRange(false); enter(fromInput($('pb-from').value), fromInput($('pb-to').value)); });
  $('pb-pop').addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); openRange(false); $('pb-range-btn').focus(); } });
  // the drawer / page padding make room for the bar (its height wraps on tablet and phone)
  new ResizeObserver(() => document.documentElement.style.setProperty('--pb-h', `${$('playback').offsetHeight}px`)).observe($('playback'));
  loadRetention();
}

// scripted-test hook (read-only): the window and the cursor
export const testState = () => ({ ...PB });
