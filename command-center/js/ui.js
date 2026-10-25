// View modes (WALLBOARD / INVESTIGATE), modal, detail drawer with breadcrumbs, idle auto-return.
// A view is { title, src: 'prom'|'loki'|'both', mount(body), update(ctx) }; update() runs on open and after every poll.
import { $, el } from './util.js';

const params = new URLSearchParams(location.search);
// Auto-return to WALLBOARD after this much idle time. `?idle=<seconds>` shortens it for scripted tests only.
export const IDLE_MS = (Number(params.get('idle')) || 300) * 1000;

const st = { modal: null, modalOpener: null, stack: [], drawerOpener: null, selection: false, touched: false, lastInput: Date.now(), ctx: null };
let hooks = { onClear: () => {}, onModeChange: () => {}, onView: () => {} };

export function initUi(h) {
  hooks = { ...hooks, ...h };
  $('modal-close').addEventListener('click', () => closeView(closeModal));
  $('modal-backdrop').addEventListener('click', () => closeView(closeModal));
  $('drawer-close').addEventListener('click', () => closeView(clearDrawer));
  $('drawer-back').addEventListener('click', drawerBack);
  $('back-live').addEventListener('click', clearAll);
  for (const ev of ['pointerdown', 'pointermove', 'keydown', 'wheel']) window.addEventListener(ev, () => { st.lastInput = Date.now(); }, { capture: true, passive: true });
  window.addEventListener('keydown', onKey);
  setInterval(() => { if (mode() === 'INVESTIGATE' && Date.now() - st.lastInput > IDLE_MS) clearAll(); }, 1000);
  updateMode();
}

export const mode = () => (st.modal || st.stack.length || st.selection || st.touched ? 'INVESTIGATE' : 'WALLBOARD');
function updateMode() {
  const m = mode();
  $('mode').textContent = m;
  $('mode').className = `mode mode-${m.toLowerCase()}`;
  $('back-live').hidden = m === 'WALLBOARD';
  document.body.dataset.mode = m.toLowerCase();
  hooks.onModeChange(m);
}
export function setSelected(on) { st.selection = on; updateMode(); }
export function touched() { st.touched = true; updateMode(); }

function onKey(e) {
  if (e.key === 'Escape') {
    e.preventDefault();
    if (st.modal) closeView(closeModal); else clearAll();
    return;
  }
  if (e.key === 'Tab' && st.modal) trapFocus(e, $('modal'));
}
function focusables(root) {
  return [...root.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
    .filter((n) => !n.disabled && !n.closest('[hidden]') && n.offsetParent !== null);
}
function trapFocus(e, root) {
  const f = focusables(root);
  if (!f.length) return;
  const first = f[0], lastEl = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); lastEl.focus(); }
  else if (!e.shiftKey && document.activeElement === lastEl) { e.preventDefault(); first.focus(); }
  else if (!root.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
}

// ---- focus restore -----------------------------------------------------------------------------
// Wallboard rows are rebuilt on every poll, so the opener is remembered by identity (data-fkey) and by its
// panel; on restore the live node is looked up again, falling back to the panel's title button.
function opener() {
  const n = document.activeElement;
  if (!n || n === document.body) return null;
  return { node: n, key: n.dataset?.fkey || null, panel: n.closest?.('.panel')?.id || null };
}
function restore(o) {
  if (!o) return;
  let t = o.node?.isConnected && !o.node.closest('[hidden]') ? o.node : null;
  if (!t && o.key) t = [...document.querySelectorAll('[data-fkey]')].find((x) => x.dataset.fkey === o.key && !x.closest('#modal, #drawer'));
  if (!t && o.panel) t = document.querySelector(`#${o.panel} .h-open`);
  t?.focus();
}

// ---- modal ------------------------------------------------------------------------------
export function openModal(view) {
  if (!st.modal) st.modalOpener = opener();
  st.modal = view;
  $('modal-title').textContent = view.title;
  const body = $('modal-body');
  body.replaceChildren();
  view.mount(body);
  $('modal-root').hidden = false;
  updateMode();
  runUpdate(view, $('modal'));
  $('modal-close').focus();
}
export function closeModal() {
  if (!st.modal) return;
  st.modal = null;
  $('modal-root').hidden = true;
  $('modal-body').replaceChildren();
  updateMode();
  const o = st.modalOpener;
  st.modalOpener = null;
  restore(o);
}

// ---- drawer (non-modal, right side) ----------------------------------------------------------
export function openDrawer(view, { reset = false } = {}) {
  if (st.modal) {
    // opened from a modal row: closing the drawer later returns focus to whatever opened the modal
    const o = st.modalOpener;
    st.modalOpener = null;
    closeModal();
    if (!st.stack.length) st.drawerOpener = o;
  } else if (!st.stack.length) st.drawerOpener = opener();
  if (reset) st.stack = [];
  st.stack.push(view);
  showTop();
}
function showTop() {
  const view = st.stack[st.stack.length - 1];
  const drawer = $('drawer');
  $('drawer-title').textContent = view.title;
  const crumbs = $('drawer-crumbs');
  crumbs.replaceChildren(...st.stack.map((v, i) => {
    if (i === st.stack.length - 1) return el('span', 'crumb cur', v.title);
    const b = el('button', 'crumb', v.title);
    b.type = 'button';
    b.addEventListener('click', () => { st.stack = st.stack.slice(0, i + 1); showTop(); });
    return b;
  }));
  $('drawer-back').hidden = st.stack.length < 2;
  crumbs.hidden = st.stack.length < 2; // a single crumb would only repeat the title
  hooks.onView(view); // re-apply this view's globe selection (also when returning via back/breadcrumb)
  const body = $('drawer-body');
  body.replaceChildren();
  view.mount(body);
  drawer.hidden = false;
  updateMode();
  runUpdate(view, drawer);
  $('drawer-title').focus();
}
function drawerBack() {
  if (st.stack.length > 1) { st.stack.pop(); showTop(); }
}
function clearDrawer() {
  if (!st.stack.length) return;
  st.stack = [];
  $('drawer').hidden = true;
  $('drawer-body').replaceChildren();
  updateMode();
  const o = st.drawerOpener;
  st.drawerOpener = null;
  restore(o);
}
// Closing the last open view (drawer or modal) returns to WALLBOARD, same as Esc / BACK TO LIVE.
function closeView(fn) {
  fn();
  if (!st.modal && !st.stack.length) clearAll();
}

// Return to WALLBOARD: close everything, clear selection, resume globe auto-rotate.
export function clearAll() {
  closeModal();
  clearDrawer();
  st.selection = false;
  st.touched = false;
  hooks.onClear();
  updateMode();
}

// ---- live refresh ----------------------------------------------------------------------------
export function refreshViews(ctx) {
  st.ctx = ctx;
  if (st.modal) runUpdate(st.modal, $('modal'));
  if (st.stack.length) runUpdate(st.stack[st.stack.length - 1], $('drawer'));
}
async function runUpdate(view, container) {
  const ctx = st.ctx;
  if (!ctx) return;
  const srcStale = (view.src === 'loki' ? ctx.lokiStale : view.src === 'both' ? ctx.promStale || ctx.lokiStale : ctx.promStale);
  try {
    await view.update(ctx);
    view.err = null;
  } catch (e) {
    view.err = String(e); // keep last rendered content; mark stale below
  }
  if (!container.contains(document.activeElement) && container.hidden) return;
  const stale = srcStale || !!view.err;
  container.classList.toggle('stale', stale);
  const tag = container.querySelector('.view-stale');
  if (tag) {
    tag.hidden = !stale;
    tag.title = view.err || 'data source stale';
  }
}
