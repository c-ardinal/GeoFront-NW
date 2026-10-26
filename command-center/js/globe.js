// Globe: rendering (default photo style / eva-film tactical style), selection highlight, zoom, click & hover,
// drawing mode (GPU: animated, at most 30 fps / LITE: static, drawn on change; render-mode.js) and frame pacing.
import { $, el, esc, fmtBps, maskIp, distKm, REDUCED_MOTION, uiZoom, refitTickers } from './util.js';
import { probeGpu, storedChoice, storeChoice, nextChoice, resolveMode, choiceLabel } from './render-mode.js';
import { pulseLayer, labelLayer } from './globe-layers.js';

export const ORIGIN = { lat: 35.68, lng: 139.77, label: 'HOME' }; // logical origin: coarse home region, NOT an address
const TEXTURE = 'https://cdn.jsdelivr.net/npm/three-globe@2.45.6/example/img/';
const MAX_ARCS = 30;
const LABEL_MIN_KM = 500;
const DEFAULT_POV = { lat: 25, lng: 150, altitude: 1.9 };
const FLY_MS = 900;
const ARC_DASH_MS = 2200;

// Per-theme palette. The default entries are exactly the original constants.
const STYLES = {
  default: { out: ['rgba(255,176,0,0.25)', '#ffb000'], in: ['rgba(0,229,255,0.25)', '#00e5ff'], dim: 'rgba(150,170,180,0.10)', ring: '0,229,255', atmo: '#33d6ff', atmoAlt: 0.22 },
  // film: green graticule, solid orange hex land, green range rings around HOME plus two slow radar sweeps
  'eva-film': { out: ['rgba(255,140,0,0.3)', '#ff8c00'], in: ['rgba(61,242,154,0.3)', '#3df29a'], dim: 'rgba(140,80,0,0.14)', ring: '255,140,0', atmo: '#ff8c00', atmoAlt: 0.07,
    hex: 'rgba(255,140,0,0.75)', grid: { step: 15, color: 'rgba(61,242,154,0.2)' },
    ranges: [
      ...[4, 8, 12].map((deg) => ({ deg, color: 'rgba(61,242,154,0.55)', dash: 0.01, gap: 0.01 })),
      { deg: 16, color: 'rgba(61,242,154,0.8)', dash: 1, gap: 0 },
      ...[8, 16].map((deg) => ({ deg, color: 'rgba(255,212,0,0.95)', dash: 0.08, gap: 0.92, anim: 5000 })),
    ] },
};
const theme = () => document.documentElement.dataset.theme;
const isEva = () => theme() === 'eva-film'; // tactical (non-photo) globe
const style = () => STYLES[theme()] || STYLES.default;

// Country outlines for the eva globe (Natural Earth 110m, fetched with SRI).
const COUNTRIES_URL = 'https://cdn.jsdelivr.net/npm/globe.gl@2.46.2/example/datasets/ne_110m_admin_0_countries.geojson';
const COUNTRIES_SRI = 'sha384-hAVr+/g2HDlVDeHrAVqTIQV3tH1JE5AbtuvCSCcoeG+ZDteCU2XGaE5yLDiLP9m5';
const geo = { land: null, failed: false, loading: false };

let globe = null;
let hooks = { onDest: () => {}, onInteract: () => {} };
let last = { arcs: [], cities: [] };
let selection = null; // { type: 'dest', key } | { type: 'src', host }
let pulses = null, labels = null;
let hidePoints = 0; // frames left to look for new point meshes to hide (see onBeforeRender)

// ---- drawing mode ---------------------------------------------------------------------------------------------------
const draw = { probe: null, choice: 'auto', mode: 'gpu' };
const animated = () => draw.mode === 'gpu' && !REDUCED_MOTION;
export const renderInfo = () => ({ ...draw, animated: animated(), label: choiceLabel(draw.choice, draw.mode), frames: globe?.renderer().info.render.frame ?? 0 });
export function cycleRender() {
  draw.choice = nextChoice(draw.choice);
  storeChoice(draw.choice);
  draw.mode = resolveMode(draw.choice, draw.probe);
  applyMotion();
  return renderInfo();
}

// ---- frame pacing -----------------------------------------------------------------------------------------------------
// globe.gl renders on every animation frame. Animated: at most FPS, IDLE_FPS after IDLE_AFTER_MS without any input.
// Static (LITE / reduced motion): the loop runs only while something changes (wake), otherwise it is paused.
// Hidden tab: paused. globe.gl's loop schedules its next frame through the instance property _animationCycle, so the
// wrapper below decides per frame whether to render.
const FPS = 30;
const IDLE_FPS = 15;
const IDLE_AFTER_MS = 60000;
const loop = { running: true, paced: false, skip: 0, last: 0, until: 0, timer: 0, dragging: false, stopped: false, input: performance.now() };
function initPacing() {
  const cycle = globe._animationCycle;
  if (typeof cycle !== 'function') return; // another globe.gl build: its own loop, unpaced
  loop.paced = true;
  globe._animationCycle = () => {
    loop.skip = 0;
    if (!loop.running) return;
    const t = performance.now();
    const fps = t - loop.input > IDLE_AFTER_MS ? IDLE_FPS : FPS;
    if (t - loop.last >= 1000 / fps - 4) { loop.last = t; cycle(); } else loop.skip = requestAnimationFrame(globe._animationCycle);
  };
  for (const ev of ['pointerdown', 'pointermove', 'keydown', 'wheel']) window.addEventListener(ev, () => { loop.input = performance.now(); }, { capture: true, passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) setRunning(false);
    else if (animated()) setRunning(true);
    else wake(400);
  });
}
function setRunning(on) {
  if (!globe || on === loop.running) return;
  loop.running = on;
  if (on) { globe.resumeAnimation(); return; }
  globe.pauseAnimation();
  cancelAnimationFrame(loop.skip);
  loop.skip = 0;
}
// static mode: keep drawing for ms (a data update needs a few frames, a camera move its duration)
function wake(ms) {
  if (!globe || animated() || document.hidden) return;
  loop.until = Math.max(loop.until, performance.now() + ms);
  setRunning(true);
  clearTimeout(loop.timer);
  loop.timer = setTimeout(sleepCheck, loop.until - performance.now() + 20);
}
function sleepCheck() {
  if (animated() || loop.dragging) return;
  if (performance.now() >= loop.until) setRunning(false); else loop.timer = setTimeout(sleepCheck, loop.until - performance.now() + 20);
}
// mode switch / start: motion on or off everywhere
function applyMotion() {
  if (!globe) return;
  const on = animated();
  // LITE: the whole page is static, as with reduced motion (style.css; tickers wrap instead of scrolling)
  if (document.documentElement.dataset.render !== draw.mode) {
    document.documentElement.dataset.render = draw.mode;
    refitTickers();
  }
  const ms = on ? undefined : 0; // static: no grow-in transitions (only a few frames are drawn per change)
  globe.arcDashAnimateTime(on ? ARC_DASH_MS : 0)
    .arcsTransitionDuration(ms ?? 1000).pointsTransitionDuration(ms ?? 1000).labelsTransitionDuration(ms ?? 1000);
  globe.controls().autoRotate = on && !loop.stopped;
  pulses?.setStatic(!on);
  if (isEva()) globe.pathsData(evaPaths(style()));
  applyData();
  if (on) setRunning(true); else wake(600);
}

export function initGlobe(h) {
  hooks = { ...hooks, ...h };
  const host = $('globe');
  if (typeof Globe !== 'function') {
    host.appendChild(el('div', 'globe-error', 'GLOBE LIBRARY UNAVAILABLE (CDN unreachable)'));
    return;
  }
  draw.probe = probeGpu();
  draw.choice = storedChoice();
  draw.mode = resolveMode(draw.choice, draw.probe);
  globe = Globe()(host)
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true).atmosphereColor('#33d6ff').atmosphereAltitude(0.22)
    .arcStartLat((d) => d.from.lat).arcStartLng((d) => d.from.lng)
    .arcEndLat((d) => d.to.lat).arcEndLng((d) => d.to.lng)
    .arcAltitudeAutoScale((d) => (d.dir === 'outbound' ? 0.55 : 0.4))
    // accessors are set once and read per-datum properties, so a selection change only updates colours
    // (re-assigning accessor functions makes three-globe rebuild every arc's geometry)
    .arcColor((d) => d.color).arcStroke((d) => d.stroke)
    .ringColor((d) => d.ringFn)
    .arcDashLength(0.35).arcDashGap(0.15)
    .arcDashInitialGap((d) => d.phase)
    .arcLabel((d) => { const c = cityUnderPointer(); return c ? cityTip(c) : tooltip(d.city, d.cc, d.asn, `${d.dir} ${fmtBps(d.bps)}`, d.srcs.size, d.ip); })
    // a click on an arc that lies over another destination's point selects that destination (points win)
    .onArcClick((d, ev, c) => pick(pointAt(c) || d.key))
    .onArcHover((d) => { host.style.cursor = d ? 'pointer' : ''; })
    // library ring layer: only until the shader pulses (globe-layers.js) can be built
    .ringMaxRadius((d) => d.r).ringPropagationSpeed(2.2).ringRepeatPeriod(() => (animated() ? 1400 : 0))
    .labelText((d) => d.text).labelSize((d) => d.size).labelDotRadius((d) => d.dot)
    .labelColor((d) => d.color).labelResolution(2).labelAltitude(0.006)
    // city labels are 3D text that sits over the destination point; route their hover/click to the destination
    .labelLabel((d) => { const c = cityUnderPointer() || (d.key ? d : null); return c ? cityTip(c) : ''; })
    .onLabelClick((d, ev, c) => { const u = cityUnderPointer(); const k = u?.key || pointAt(c) || d.key; if (k) pick(k); }) // a label may overlap a neighbouring point: the point wins
    .onLabelHover((d) => { host.style.cursor = d?.key ? 'pointer' : ''; })
    // invisible hit targets at each destination for hover tooltip + click (their meshes are not drawn: see hidePoints)
    .pointLat((d) => d.lat).pointLng((d) => d.lng).pointAltitude(0.004).pointRadius(2)
    .pointColor(() => 'rgba(255,255,255,0.01)').pointsMerge(false)
    .pointLabel(cityTip)
    .onPointClick((d) => pick(d.key))
    .onGlobeClick((c) => { const k = pointAt(c); if (k) pick(k); else hideCard(); }) // near-miss on a small point still selects it
    .onPointHover((d) => { host.style.cursor = d ? 'pointer' : ''; })
    .pointOfView(DEFAULT_POV, 0)
    // eva-only layers (empty in the default theme)
    .pathPoints((d) => d.pts).pathPointLat((p) => p[0]).pathPointLng((p) => p[1]).pathPointAlt(0.002)
    .pathColor((d) => d.color).pathDashLength((d) => d.dash).pathDashGap((d) => d.gap).pathDashAnimateTime((d) => d.anim)
    .pathTransitionDuration(0)
    .hexPolygonResolution(3).hexPolygonMargin(0.35).hexPolygonAltitude(0.004)
    .hexPolygonColor(() => style().hex).hexPolygonsTransitionDuration(0)
    .onGlobeReady(() => wake(800));
  host.addEventListener('pointermove', (e) => { const r = host.getBoundingClientRect(); pointer = { x: e.clientX - r.left, y: e.clientY - r.top }; wake(400); }, { passive: true });
  pulses = pulseLayer(globe);
  labels = labelLayer(globe, host);
  // per rendered frame: hide the hit-target point meshes once they exist; redraw the eva labels if the camera moved
  globe.scene().onBeforeRender = () => {
    if (hidePoints > 0) {
      let n = 0;
      globe.scene().traverse((o) => { if (o.__globeObjType === 'point' && o.material) { o.material.visible = false; n++; } });
      hidePoints = n ? 0 : hidePoints - 1;
    }
  };
  globe.scene().onAfterRender = () => labels.draw();
  const controls = globe.controls();
  controls.autoRotate = animated();
  controls.autoRotateSpeed = 0.35;
  controls.enableZoom = true;
  controls.addEventListener('start', () => { controls.autoRotate = false; loop.stopped = true; loop.dragging = true; setRunning(true); hooks.onInteract(); });
  controls.addEventListener('end', () => { loop.dragging = false; wake(800); });
  new ResizeObserver(fit).observe(host);
  initPacing();
  fit();
  styleGlobe();
  initZoomButtons();
  applyMotion();
}

// Arcs leaving HOME pass over nearby destinations; when the pointer is over a destination point, that point wins
// for both the tooltip and the click.
let pointer = null;
function cityUnderPointer() {
  if (!pointer || !globe) return null;
  const key = pointAt(globe.toGlobeCoords(pointer.x, pointer.y));
  return key ? (last.cities || []).find((c) => c.key === key) : null;
}
function cityTip(d, hint) {
  return tooltip(d.city, d.cc, d.asn, `in ${fmtBps(d.inBps)} / out ${fmtBps(d.outBps)}`, d.srcs.size, d.ips[0], hint);
}
function tooltip(city, cc, asn, traffic, srcCount, ip, hint = 'click for details') {
  return `<div class="gtip"><b>${esc(city || 'Unknown')}</b> · ${esc(cc)}<br>ASN ${esc(asn || '—')} · ${esc(maskIp(ip))}<br>`
    + `${esc(traffic)}<br>${srcCount} source host${srcCount === 1 ? '' : 's'} · GeoIP estimate<br><i>${esc(hint)}</i></div>`;
}

// Touch screens have no hover, so the tooltip never shows: the first tap on a destination shows the same summary as
// a card; a second tap on it (or the card's button) opens the detail drawer. With a mouse a click opens it directly.
const NO_HOVER = window.matchMedia('(hover: none)');
let armed = null;
function pick(key) {
  const c = (last.cities || []).find((x) => x.key === key);
  if (!NO_HOVER.matches || armed === key || !c) { hideCard(); hooks.onDest(key); return; }
  armed = key;
  const card = $('gcard');
  card.innerHTML = cityTip(c, 'tap again or OPEN for details'); // all values escaped in tooltip()
  const open = el('button', 'gcard-open', 'OPEN DETAILS');
  open.type = 'button';
  open.addEventListener('click', () => pick(key));
  const close = el('button', 'gcard-close', '✕');
  close.type = 'button';
  close.setAttribute('aria-label', 'Close summary');
  close.addEventListener('click', hideCard);
  card.append(open, close);
  card.hidden = false;
}
export function hideCard() {
  armed = null;
  const card = $('gcard');
  card.hidden = true;
  card.replaceChildren();
}

export function fit() {
  const host = $('globe');
  if (globe && (globe.width() !== host.clientWidth || globe.height() !== host.clientHeight)) {
    globe.width(host.clientWidth).height(host.clientHeight);
    wake(300);
  }
}

function initZoomButtons() {
  const zoom = (f) => {
    const p = globe.pointOfView();
    globe.controls().autoRotate = false;
    loop.stopped = true;
    moveCamera({ ...p, altitude: Math.min(4, Math.max(0.4, p.altitude * f)) }, REDUCED_MOTION ? 0 : 400);
    hooks.onInteract();
  };
  $('g-zoom-in').addEventListener('click', () => zoom(0.75));
  $('g-zoom-out').addEventListener('click', () => zoom(1.33));
  $('g-reset').addEventListener('click', () => resetView());
}

export function resetView() {
  hideCard();
  if (!globe) return;
  moveCamera(DEFAULT_POV, REDUCED_MOTION ? 0 : 800);
  loop.stopped = false;
  globe.controls().autoRotate = animated();
}

export function flyTo(lat, lng) {
  if (!globe) return;
  globe.controls().autoRotate = false;
  loop.stopped = true;
  moveCamera({ lat, lng, altitude: 1.5 }, REDUCED_MOTION ? 0 : FLY_MS);
}
function moveCamera(pov, ms) {
  globe.pointOfView(pov, ms);
  wake(ms + 300);
}

const POINT_HIT_KM = 250;
function pointAt(c) {
  if (!c || !Number.isFinite(c.lat)) return null;
  let best = null, bestKm = POINT_HIT_KM;
  for (const city of last.cities || []) {
    const km = distKm(c, city);
    if (km < bestKm) { best = city.key; bestKm = km; }
  }
  return best;
}

export function setSelection(sel) {
  selection = sel;
  if (globe) applyData();
}

// eva graticule as two paths (one draw call each instead of one per line): every meridian but 180° in one path (they
// meet at the poles), and every parallel in one path joined along the 180° meridian, which that path draws exactly once
function evaPaths({ grid, ranges }) {
  const g = { color: grid.color, dash: 1, gap: 0, anim: 0 };
  const meridians = [];
  for (let lng = -180 + grid.step, up = true; lng < 180; lng += grid.step, up = !up) {
    for (let i = 0; i <= 36; i++) meridians.push([up ? -90 + i * 5 : 90 - i * 5, lng]);
  }
  const parallels = [[-90, -180]];
  for (let lat = -90 + grid.step; lat < 90; lat += grid.step) {
    for (let i = 0; i <= 72; i++) parallels.push([lat, -180 + i * 5]);
  }
  parallels.push([90, -180]);
  const paths = [{ ...g, pts: meridians }, { ...g, pts: parallels }];
  for (const r of ranges) {
    paths.push({ ...r, anim: animated() ? r.anim || 0 : 0, pts: Array.from({ length: 73 }, (_, i) => {
      const a = (i * 5 * Math.PI) / 180;
      return [ORIGIN.lat + r.deg * Math.sin(a), ORIGIN.lng + (r.deg * Math.cos(a)) / Math.cos((ORIGIN.lat * Math.PI) / 180)];
    }) });
  }
  return paths;
}
function loadCountries() {
  if (geo.loading || geo.land || geo.failed) return;
  geo.loading = true;
  fetch(COUNTRIES_URL, { integrity: COUNTRIES_SRI })
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((j) => { geo.land = landFeature(j.features.filter((f) => f.properties.ISO_A2 !== 'AQ')); styleGlobe(); })
    .catch(() => { geo.failed = true; styleGlobe(); }) // graticule-only fallback, noted in the panel header
    .finally(() => { geo.loading = false; });
}
export const geoOutlineFailed = () => isEva() && geo.failed;
// All countries as ONE MultiPolygon: three-globe builds one mesh + material per hex-polygon datum, and ~170
// separate country meshes cost ~170 draw calls and program look-ups every frame (most of the eva CPU time).
function landFeature(features) {
  const coordinates = features.flatMap((f) => (f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates));
  return { type: 'Feature', properties: {}, geometry: { type: 'MultiPolygon', coordinates } };
}

// Theme switch never reloads textures: the default-theme textures are loaded once (on first default use, so a
// page opened in a tactical theme never flashes the photo globe when they land late) and kept; the eva looks
// detach them from the material (kept for reuse, not disposed) and hide the sky sphere.
const saved = { map: null, bump: null };
let texturesRequested = false;
export function styleGlobe() {
  if (!globe) return;
  const s = style();
  globe.atmosphereColor(s.atmo).atmosphereAltitude(s.atmoAlt);
  labels?.restyle();
  if (isEva()) {
    globe.pathsData(evaPaths(s)).hexPolygonsData(geo.land ? [geo.land] : []);
    darken();
    loadCountries();
  } else {
    if (!texturesRequested) {
      // first default-theme use: request the photo textures (three-globe sets map + clears the colour on load)
      texturesRequested = true;
      globe.globeImageUrl(`${TEXTURE}earth-night.jpg`).bumpImageUrl(`${TEXTURE}earth-topology.png`).backgroundImageUrl(`${TEXTURE}night-sky.png`);
    }
    const mat = globe.globeMaterial();
    if (saved.map) { mat.map = saved.map; mat.color = null; }
    if (saved.bump) mat.bumpMap = saved.bump;
    mat.needsUpdate = true;
    setSky(true);
    globe.pathsData([]).hexPolygonsData([]);
  }
  applyData();
  wake(1500); // texture / outline changes land over the next frames
}
// Plain dark sphere for eva; re-asserted on each render in case a texture load lands late.
const DARK = '080808';
function darken() {
  const mat = globe.globeMaterial();
  let changed = false;
  if (mat.map) { saved.map = mat.map; mat.map = null; changed = true; }
  if (mat.bumpMap) { saved.bump = mat.bumpMap; mat.bumpMap = null; changed = true; }
  if (!mat.color || mat.color.getHexString() !== DARK) {
    const c = mat.emissive.clone();
    c.set(`#${DARK}`);
    mat.color = c;
    changed = true;
  }
  if (changed) mat.needsUpdate = true;
  setSky(false);
}
function setSky(visible) {
  globe.scene().traverse((o) => {
    if (o.isMesh && o.material?.side === 1 /* THREE.BackSide: the background sky sphere */ && o.material.map) o.visible = visible;
  });
}

// flows: normalized flow records [{ src, ip, cc, city, lat, lon, asn, dir, bps }]
export function renderGlobe(flows) {
  if (!globe) return;
  fit();
  const arcMap = new Map();
  const cityMap = new Map();
  for (const f of flows) {
    if (f.lat === null) continue;
    const key = `${f.cc}|${f.city}`;
    const ak = `${f.ip}|${f.dir}`;
    const to = { lat: f.lat, lng: f.lon };
    const a = arcMap.get(ak) || { key, ip: f.ip, cc: f.cc, city: f.city, asn: f.asn, dir: f.dir, bps: 0, srcs: new Set(),
      from: f.dir === 'outbound' ? ORIGIN : to, to: f.dir === 'outbound' ? to : ORIGIN };
    a.bps += f.bps;
    if (f.bps > 0) a.srcs.add(f.src);
    arcMap.set(ak, a);
    const c = cityMap.get(key) || { key, lat: f.lat, lng: f.lon, city: f.city, cc: f.cc, asn: f.asn, text: f.city.toUpperCase(), bps: 0, inBps: 0, outBps: 0, srcs: new Set(), ips: [] };
    c.bps += f.bps;
    if (f.dir === 'outbound') c.outBps += f.bps; else c.inBps += f.bps;
    if (f.bps > 0) c.srcs.add(f.src);
    if (!c.ips.includes(f.ip)) c.ips.push(f.ip);
    cityMap.set(key, c);
  }
  const arcsAll = [...arcMap.values()].sort((a, b) => b.bps - a.bps);
  arcsAll.forEach((a, i) => { a.phase = (i * 0.37) % 1; });
  last = { arcsAll, cities: [...cityMap.values()] };
  $('arc-note').textContent = (arcsAll.length > MAX_ARCS ? `top ${MAX_ARCS} of ${arcsAll.length} arcs shown` : `${arcsAll.length} arcs`)
    + (geoOutlineFailed() ? ' · geo outline unavailable' : '');
  applyData();
}

// selection: { type: 'dest', key: 'CC|City' } | { type: 'country', cc } | { type: 'src', host } | null
function selHit(x) {
  if (!selection) return true;
  if (selection.type === 'dest') return x.key === selection.key;
  if (selection.type === 'country') return x.cc === selection.cc;
  return x.srcs.has(selection.host);
}
const matches = selHit;

const rgb = (csv) => csv.split(',').map((v) => Number(v) / 255);
function applyData() {
  if (!globe) return;
  const s = style();
  const arcs = (last.arcsAll?.slice(0, MAX_ARCS) || []).map((a) => ({ ...a }));
  const maxBps = arcs.length ? arcs[0].bps : 1;
  for (const a of arcs) {
    const hit = matches(a);
    a.stroke = (0.15 + 1.1 * Math.sqrt(a.bps / maxBps)) * (selection && hit ? 1.8 : 1);
    a.color = hit ? (a.dir === 'outbound' ? s.out : s.in) : s.dim;
  }
  const cities = last.cities || [];
  const cmax = Math.max(1, ...cities.map((c) => c.bps));
  globe.arcsData(arcs);
  const rings = cities.map((c) => ({ ...c, r: 1.5 + 3 * Math.sqrt(c.bps / cmax), alpha: selection && !matchesCity(c) ? 0.15 : 1 }));
  if (pulses.set(rings.map((c) => ({ lat: c.lat, lng: c.lng, r: c.r, rgb: rgb(s.ring), alpha: c.alpha })))) globe.ringsData([]);
  else globe.ringsData(rings.map((c) => ({ ...c, ringFn: (t) => `rgba(${s.ring},${c.alpha * (1 - t)})` })));
  globe.pointsData(cities);
  hidePoints = 30;
  // Label priority by bps: skip a city label within LABEL_MIN_KM of the origin or of a label already placed;
  // a selected destination is always labelled.
  const placed = [ORIGIN];
  const ordered = [...cities].sort((a, b) => (isSelCity(b) - isSelCity(a)) || b.bps - a.bps);
  const labelled = ordered.filter((c) => {
    if (!isSelCity(c) && placed.some((p) => distKm(p, c) < LABEL_MIN_KM)) return false;
    placed.push(c);
    return true;
  });
  if (isEva()) {
    darken();
    globe.labelsData([]);
    // drawing order = priority for the screen-space thinning: selected destination, then HOME, then by bps
    const sel = labelled.filter((c) => isSelCity(c));
    const rest = labelled.filter((c) => !isSelCity(c));
    labels.set([...sel, { ...ORIGIN, text: ORIGIN.label, home: true }, ...rest].map((c) => ({ lat: c.lat, lng: c.lng, text: c.text, home: !!c.home })));
  } else {
    labels.set([]);
    globe.labelsData([
      ...labelled.map((c) => ({ ...c, size: isSelCity(c) ? 1.6 : 1.3, dot: 0.35, color: isSelCity(c) ? '#ffffff' : 'rgba(160,240,255,0.9)' })),
      { ...ORIGIN, text: ORIGIN.label, size: 1.5, dot: 0.6, color: '#ffb000' },
    ]);
  }
  wake(200); // static mode: the library applies the new data on its next frames
}
const isSelCity = (c) => (selection && selection.type !== 'src' && selHit(c) ? 1 : 0);
const matchesCity = selHit;

// test hook for scripted checks (screen position of a destination)
export function screenOf(lat, lng) {
  return globe ? globe.getScreenCoords(lat, lng, 0.004) : null;
}
export const testSelection = () => selection;
export const testInfo = () => ({ pov: globe?.pointOfView(), cities: (last.cities || []).map((c) => ({ key: c.key, lat: c.lat, lng: c.lng })),
  gl: globe && { ...globe.renderer().info.memory, programs: globe.renderer().info.programs.length, w: globe.width(), h: globe.height() },
  render: renderInfo(), paced: loop.paced, running: loop.running, labels: labels?.count() ?? 0, uiZoom: uiZoom() });
