// Globe: rendering (default photo style / eva tactical style), selection highlight, zoom, click & hover.
import { $, el, esc, fmtBps, maskIp, distKm, REDUCED_MOTION } from './util.js';

export const ORIGIN = { lat: 35.68, lng: 139.77, label: 'HOME' }; // logical origin: coarse home region, NOT an address
const TEXTURE = 'https://cdn.jsdelivr.net/npm/three-globe@2.45.6/example/img/';
const MAX_ARCS = 30;
const LABEL_MIN_KM = 500;
const DEFAULT_POV = { lat: 25, lng: 150, altitude: 1.9 };
const FLY_MS = 900;

// Per-theme palette. The default entries are exactly the original constants.
const STYLES = {
  default: { out: ['rgba(255,176,0,0.25)', '#ffb000'], in: ['rgba(0,229,255,0.25)', '#00e5ff'], dim: 'rgba(150,170,180,0.10)', ring: '0,229,255', atmo: '#33d6ff', atmoAlt: 0.22 },
  eva: { out: ['rgba(255,154,31,0.25)', '#ff9a1f'], in: ['rgba(79,224,176,0.25)', '#4fe0b0'], dim: 'rgba(140,100,40,0.12)', ring: '255,154,31', atmo: '#ff9a1f', atmoAlt: 0.12 },
};
const isEva = () => document.documentElement.dataset.theme === 'eva';
const style = () => (isEva() ? STYLES.eva : STYLES.default);

// Country outlines for the eva globe (Natural Earth 110m, fetched with SRI).
const COUNTRIES_URL = 'https://cdn.jsdelivr.net/npm/globe.gl@2.46.2/example/datasets/ne_110m_admin_0_countries.geojson';
const COUNTRIES_SRI = 'sha384-hAVr+/g2HDlVDeHrAVqTIQV3tH1JE5AbtuvCSCcoeG+ZDteCU2XGaE5yLDiLP9m5';
const geo = { countries: null, failed: false, loading: false };

let globe = null;
let hooks = { onDest: () => {}, onInteract: () => {} };
let last = { arcs: [], cities: [] };
let selection = null; // { type: 'dest', key } | { type: 'src', host }

export function initGlobe(h) {
  hooks = { ...hooks, ...h };
  const host = $('globe');
  if (typeof Globe !== 'function') {
    host.appendChild(el('div', 'globe-error', 'GLOBE LIBRARY UNAVAILABLE (CDN unreachable)'));
    return;
  }
  globe = Globe()(host)
    .backgroundColor('rgba(0,0,0,0)')
    .globeImageUrl(`${TEXTURE}earth-night.jpg`)
    .bumpImageUrl(`${TEXTURE}earth-topology.png`)
    .backgroundImageUrl(`${TEXTURE}night-sky.png`)
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
    .arcDashAnimateTime(REDUCED_MOTION ? 0 : 2200)
    .arcLabel((d) => { const c = cityUnderPointer(); return c ? cityTip(c) : tooltip(d.city, d.cc, d.asn, `${d.dir} ${fmtBps(d.bps)}`, d.srcs.size, d.ip); })
    // a click on an arc that lies over another destination's point selects that destination (points win)
    .onArcClick((d, ev, c) => hooks.onDest(pointAt(c) || d.key))
    .onArcHover((d) => { host.style.cursor = d ? 'pointer' : ''; })
    .ringMaxRadius((d) => d.r).ringPropagationSpeed(2.2)
    .ringRepeatPeriod(REDUCED_MOTION ? 0 : 1400)
    .labelText((d) => d.text).labelSize((d) => d.size).labelDotRadius((d) => d.dot)
    .labelColor((d) => d.color).labelResolution(2).labelAltitude(0.006)
    // city labels are 3D text that sits over the destination point; route their hover/click to the destination
    .labelLabel((d) => { const c = cityUnderPointer() || (d.key ? d : null); return c ? cityTip(c) : ''; })
    .onLabelClick((d, ev, c) => { const u = cityUnderPointer(); const k = u?.key || pointAt(c) || d.key; if (k) hooks.onDest(k); }) // a label may overlap a neighbouring point: the point wins
    .onLabelHover((d) => { host.style.cursor = d?.key ? 'pointer' : ''; })
    // invisible hit targets at each destination for hover tooltip + click
    .pointLat((d) => d.lat).pointLng((d) => d.lng).pointAltitude(0.004).pointRadius(2)
    .pointColor(() => 'rgba(255,255,255,0.01)').pointsMerge(false)
    .pointLabel(cityTip)
    .onPointClick((d) => hooks.onDest(d.key))
    .onGlobeClick((c) => { const k = pointAt(c); if (k) hooks.onDest(k); }) // near-miss on a small point still selects it
    .onPointHover((d) => { host.style.cursor = d ? 'pointer' : ''; })
    .pointOfView(DEFAULT_POV, 0)
    // eva-only layers (empty in the default theme)
    .pathPoints((d) => d.pts).pathPointLat((p) => p[0]).pathPointLng((p) => p[1]).pathPointAlt(0.002)
    .pathColor((d) => (d.kind === 'range' ? 'rgba(255,194,46,0.6)' : 'rgba(255,154,31,0.22)'))
    .pathDashLength((d) => (d.kind === 'range' ? 0.02 : 1)).pathDashGap((d) => (d.kind === 'range' ? 0.015 : 0))
    .pathTransitionDuration(0)
    .hexPolygonResolution(3).hexPolygonMargin(0.35).hexPolygonAltitude(0.004)
    .hexPolygonColor(() => 'rgba(255,154,31,0.5)').hexPolygonsTransitionDuration(0)
    .htmlElement((d) => {
      const outer = el('div', `glabel${d.home ? ' glabel-home' : ''}${d.sel ? ' glabel-sel' : ''}`);
      outer.appendChild(el('span', '', d.text));
      return outer;
    })
    .htmlAltitude(0.01)
    .htmlElementVisibilityModifier((e, visible) => { e.style.opacity = visible ? '' : '0'; });
  host.addEventListener('pointermove', (e) => { const r = host.getBoundingClientRect(); pointer = { x: e.clientX - r.left, y: e.clientY - r.top }; }, { passive: true });
  const controls = globe.controls();
  controls.autoRotate = !REDUCED_MOTION;
  controls.autoRotateSpeed = 0.35;
  controls.enableZoom = true;
  controls.addEventListener('start', () => { controls.autoRotate = false; hooks.onInteract(); });
  new ResizeObserver(fit).observe(host);
  fit();
  styleGlobe();
  initZoomButtons();
}

// Arcs leaving HOME pass over nearby destinations; when the pointer is over a destination point, that point wins
// for both the tooltip and the click.
let pointer = null;
function cityUnderPointer() {
  if (!pointer || !globe) return null;
  const key = pointAt(globe.toGlobeCoords(pointer.x, pointer.y));
  return key ? (last.cities || []).find((c) => c.key === key) : null;
}
function cityTip(d) {
  return tooltip(d.city, d.cc, d.asn, `in ${fmtBps(d.inBps)} / out ${fmtBps(d.outBps)}`, d.srcs.size, d.ips[0]);
}
function tooltip(city, cc, asn, traffic, srcCount, ip) {
  return `<div class="gtip"><b>${esc(city || 'Unknown')}</b> · ${esc(cc)}<br>ASN ${esc(asn || '—')} · ${esc(maskIp(ip))}<br>`
    + `${esc(traffic)}<br>${srcCount} source host${srcCount === 1 ? '' : 's'} · GeoIP estimate<br><i>click for details</i></div>`;
}

function fit() {
  const host = $('globe');
  if (globe && (globe.width() !== host.clientWidth || globe.height() !== host.clientHeight)) {
    globe.width(host.clientWidth).height(host.clientHeight);
  }
}

function initZoomButtons() {
  const zoom = (f) => {
    const p = globe.pointOfView();
    globe.controls().autoRotate = false;
    globe.pointOfView({ ...p, altitude: Math.min(4, Math.max(0.4, p.altitude * f)) }, REDUCED_MOTION ? 0 : 400);
    hooks.onInteract();
  };
  $('g-zoom-in').addEventListener('click', () => zoom(0.75));
  $('g-zoom-out').addEventListener('click', () => zoom(1.33));
  $('g-reset').addEventListener('click', () => resetView());
}

export function resetView() {
  if (!globe) return;
  globe.pointOfView(DEFAULT_POV, REDUCED_MOTION ? 0 : 800);
  globe.controls().autoRotate = !REDUCED_MOTION;
}

export function flyTo(lat, lng) {
  if (!globe) return;
  globe.controls().autoRotate = false;
  globe.pointOfView({ lat, lng, altitude: 1.5 }, REDUCED_MOTION ? 0 : FLY_MS);
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

function evaPaths() {
  const paths = [];
  for (let lng = -180; lng < 180; lng += 30) paths.push({ pts: Array.from({ length: 37 }, (_, i) => [-90 + i * 5, lng]), kind: 'grid' });
  for (let lat = -60; lat <= 60; lat += 30) paths.push({ pts: Array.from({ length: 73 }, (_, i) => [lat, -180 + i * 5]), kind: 'grid' });
  for (const deg of [5, 10]) {
    paths.push({ kind: 'range', pts: Array.from({ length: 73 }, (_, i) => {
      const a = (i * 5 * Math.PI) / 180;
      return [ORIGIN.lat + deg * Math.sin(a), ORIGIN.lng + (deg * Math.cos(a)) / Math.cos((ORIGIN.lat * Math.PI) / 180)];
    }) });
  }
  return paths;
}
function loadCountries() {
  if (geo.loading || geo.countries || geo.failed) return;
  geo.loading = true;
  fetch(COUNTRIES_URL, { integrity: COUNTRIES_SRI })
    .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then((j) => { geo.countries = j.features.filter((f) => f.properties.ISO_A2 !== 'AQ'); styleGlobe(); })
    .catch(() => { geo.failed = true; styleGlobe(); }) // graticule-only fallback, noted in the panel header
    .finally(() => { geo.loading = false; });
}
export const geoOutlineFailed = () => isEva() && geo.failed;

// Theme switch never reloads textures: the default-theme textures are loaded once and kept; the eva look
// detaches them from the material (kept for reuse, not disposed) and hides the sky sphere.
const saved = { map: null, bump: null };
export function styleGlobe() {
  if (!globe) return;
  const s = style();
  globe.atmosphereColor(s.atmo).atmosphereAltitude(s.atmoAlt);
  if (isEva()) {
    globe.pathsData(evaPaths()).hexPolygonsData(geo.countries || []);
    darken();
    loadCountries();
  } else {
    const mat = globe.globeMaterial();
    if (saved.map) { mat.map = saved.map; mat.color = null; }
    if (saved.bump) mat.bumpMap = saved.bump;
    mat.needsUpdate = true;
    setSky(true);
    globe.pathsData([]).hexPolygonsData([]).htmlElementsData([]);
  }
  applyData();
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
  globe.ringsData(cities.map((c) => {
    const alpha = selection && !matchesCity(c) ? 0.15 : 1;
    return { ...c, r: 1.5 + 3 * Math.sqrt(c.bps / cmax), ringFn: (t) => `rgba(${s.ring},${alpha * (1 - t)})` };
  }));
  globe.pointsData(cities);
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
    globe.htmlElementsData([...labelled.map((c) => ({ ...c, sel: isSelCity(c) })), { ...ORIGIN, text: ORIGIN.label, home: true }]);
    return;
  }
  globe.labelsData([
    ...labelled.map((c) => ({ ...c, size: isSelCity(c) ? 1.6 : 1.3, dot: 0.35, color: isSelCity(c) ? '#ffffff' : 'rgba(160,240,255,0.9)' })),
    { ...ORIGIN, text: ORIGIN.label, size: 1.5, dot: 0.6, color: '#ffb000' },
  ]);
}
const isSelCity = (c) => (selection && selection.type !== 'src' && selHit(c) ? 1 : 0);
const matchesCity = selHit;

// test hook for scripted checks (screen position of a destination)
export function screenOf(lat, lng) {
  return globe ? globe.getScreenCoords(lat, lng, 0.004) : null;
}
export const testSelection = () => selection;
export const testInfo = () => ({ pov: globe?.pointOfView(), cities: (last.cities || []).map((c) => ({ key: c.key, lat: c.lat, lng: c.lng })) });
