// View modes (WALLBOARD / INVESTIGATE), modal, detail drawer with breadcrumbs, idle auto-return.
// A view is { title, src: 'prom'|'loki'|'both', mount(body), update(ctx) }; update() runs on open and after every poll.
import { $, el, REDUCED_MOTION, uiZoom } from './util.js';

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
    if (menuOpen()) { closeMenu(); $('bar-more').focus(); return; } // the "⋯" menu closes first
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

// ---- top bar: priority fit ---------------------------------------------------------------------------
// When the bar does not fit on one row (title + banner at its min width + status), steps are applied in order until it
// does: low-priority items move into the "⋯" menu (still readable / usable there), labels get shorter. Never applied:
// DEMO, LIVE/STALE badge, alert count, BACK TO LIVE (only shortened to its icon, with label + tooltip).
const BAR_STEPS = [['move', 'k-clock'], ['move', 'k-age'], ['move', 'k-targets'], ['cls', 'bar-s-demo'], ['move', 'k-mode'], ['cls', 'bar-s-lead'],
  ['cls', 'bar-s-title'], ['move', 'theme-toggle'], ['cls', 'bar-s-notitle'], ['cls', 'bar-s-back'], ['cls', 'bar-s-tight']];
export function initTopbar() {
  const bar = document.querySelector('.bar-main');
  const status = document.querySelector('.status');
  const title = document.querySelector('.title');
  const wrap = document.querySelector('.bar-more');
  const menu = $('bar-menu');
  const btn = $('bar-more');
  const homes = new Map(); // id -> placeholder comment at the item's place in the bar
  for (const [kind, id] of BAR_STEPS) if (kind === 'move') { const c = document.createComment(id); $(id).before(c); homes.set(id, c); }
  // one row = every box starts above the bottom of the shortest one (items of different heights still share a row)
  const oneRow = (nodes) => {
    const rs = nodes.filter((k) => k.offsetParent && k.getBoundingClientRect().height).map((k) => k.getBoundingClientRect());
    const minBottom = Math.min(...rs.map((r) => r.bottom));
    return rs.every((r) => r.top < minBottom - 1);
  };
  const banner = $('alert-banner');
  // ... and the banner keeps room for its counts plus a readable part of the first alert name
  const fits = () => bar.scrollWidth <= bar.clientWidth + 1 && oneRow([title, status]) && oneRow([...status.children])
    && (banner.hidden || banner.scrollWidth <= banner.clientWidth + 1);
  const top = $('topbar');
  const isOn = ([kind, id]) => (kind === 'cls' ? top.classList.contains(id) : $(id).parentElement === menu);
  // apply exactly the first n steps; only items whose placement changes are moved (in step order, so the menu keeps it)
  const setTo = (n) => {
    for (let i = BAR_STEPS.length - 1; i >= n; i--) {
      const [kind, id] = BAR_STEPS[i];
      if (!isOn(BAR_STEPS[i])) continue;
      if (kind === 'cls') top.classList.remove(id); else homes.get(id).after($(id));
    }
    for (let i = 0; i < n; i++) {
      const [kind, id] = BAR_STEPS[i];
      if (isOn(BAR_STEPS[i])) continue;
      if (kind === 'cls') top.classList.add(id); else menu.appendChild($(id));
    }
    wrap.hidden = n === 0;
  };
  let queued = false;
  let applied = 0;
  let dirty = true; // content may need less room (new banner text, an item hidden); width growth is detected below
  let lastW = 0;
  const fit = () => {
    queued = false;
    const focused = document.activeElement;
    let n = applied;
    if (!fits()) { while (n < BAR_STEPS.length && !fits()) setTo(++n); }
    else if (dirty || bar.clientWidth > lastW) { // room may have grown: drop steps while it still fits
      while (n > 0) { setTo(n - 1); if (fits()) n--; else { setTo(n); break; } }
    }
    dirty = false;
    lastW = bar.clientWidth;
    if (n !== applied) closeMenu(); // the button moved / the menu content changed
    applied = n;
    // a moved element loses focus: give it back (e.g. THEME focused inside the menu)
    if (focused && focused !== document.activeElement && focused.isConnected) {
      // still visible: focus it again; it now sits in the closed menu: the "⋯" button that reopens it takes the focus
      (focused.closest('#bar-menu[hidden]') ? btn : focused).focus({ preventScroll: true });
    }
  };
  const schedule = () => { if (!queued) { queued = true; requestAnimationFrame(fit); } };
  const scheduleDirty = () => { dirty = true; schedule(); };
  const ro = new ResizeObserver(schedule);
  for (const n of [bar, status, $('alert-banner')]) ro.observe(n);
  new MutationObserver(scheduleDirty).observe(banner, { childList: true, attributes: true, attributeFilter: ['hidden'] }); // new alert text, same box size
  new MutationObserver(scheduleDirty).observe($('back-live'), { attributes: true, attributeFilter: ['hidden'] });
  window.addEventListener('resize', () => { schedule(); closeMenu(); });
  btn.addEventListener('click', () => (menu.hidden ? openMenu() : closeMenu()));
  document.addEventListener('click', (e) => { if (!menu.hidden && !wrap.contains(e.target) && !menu.contains(e.target)) closeMenu(); });
  schedule();
}
function openMenu() {
  const r = $('bar-more').getBoundingClientRect();
  const z = uiZoom(); // fixed offsets are in the (zoomed) page's own px
  const m = $('bar-menu');
  m.style.top = `${(r.bottom + 4) / z}px`;
  m.style.right = `${Math.max(8, (innerWidth - r.right) / z)}px`;
  m.style.maxHeight = `${Math.max(120, (innerHeight - r.bottom - 12) / z)}px`; // scrolls inside when taller
  m.hidden = false;
  // keep it on screen: CSS caps its size to the viewport; if it is still wider than the room left of the anchor, pin it
  // to the right edge margin instead
  const mr = m.getBoundingClientRect();
  if (mr.left < 8) m.style.right = '8px';
  $('bar-more').setAttribute('aria-expanded', 'true');
}
function closeMenu() {
  if ($('bar-menu').contains(document.activeElement)) $('bar-more').focus({ preventScroll: true }); // focus never falls into a hidden menu
  $('bar-menu').hidden = true;
  $('bar-more').setAttribute('aria-expanded', 'false');
}
export const menuOpen = () => !$('bar-menu').hidden;

// ---- panel groups as tabs (tablet landscape side column, phone bottom bar; CSS hides .tab-off only there) ----------
// Buttons carrying data-tab (tab bar, phone summary cards, status-bar alert chip) select a group.
export function initTabs(onChange) {
  const tabsShown = () => getComputedStyle($('tabs')).display !== 'none';
  const select = (name, scroll) => {
    for (const p of document.querySelectorAll('.panel[data-group]')) p.classList.toggle('tab-off', p.dataset.group !== name);
    for (const b of $('tabs').querySelectorAll('button')) b.setAttribute('aria-current', String(b.dataset.tab === name));
    onChange();
    if (!scroll) return;
    const behavior = REDUCED_MOTION ? 'auto' : 'smooth';
    if (tabsShown()) { // the group is now the only one shown: bring it to the top, focus stays on the tab
      if (name === 'sum') window.scrollTo({ top: 0, behavior }); // summary cards + globe on top
      else document.querySelector('.panel[data-group]:not(.tab-off)')?.scrollIntoView({ block: 'start', behavior });
      return;
    }
    // no tab strip (tablet portrait: every group shown): go to the group's topmost panel and focus its heading
    const panels = [...document.querySelectorAll(`.panel[data-group="${name}"]`)].filter((p) => p.offsetParent);
    const target = panels.sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top)[0];
    if (!target) return;
    target.scrollIntoView({ block: 'start', behavior });
    const h = target.querySelector('h2');
    h.tabIndex = -1;
    h.focus({ preventScroll: true });
  };
  document.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-tab]');
    if (b) select(b.dataset.tab, true);
  });
  select('sum', false);
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
