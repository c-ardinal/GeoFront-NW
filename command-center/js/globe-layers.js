// Globe layers that cost one draw call and no per-frame JS work:
//   pulses: the rings expanding from each destination, computed in a fragment shader from one time uniform (three-globe's
//     ring layer creates a Line per ring and recolours / rescales every ring from JS on every frame)
//   labels: the film label chips, drawn into one 2D canvas over the globe and redrawn only when the camera, the size
//     or the labels changed (an HTML label layer repositions every label element on every frame)
// globe.gl bundles three.js without exporting it: the few classes needed are taken from its own scene objects.
import { uiZoom } from './util.js';

// ---- three.js classes from the live scene ---------------------------------------------------------------------------
// the class in obj's prototype chain that itself defines `method` (subclasses such as SphereGeometry do not)
function owner(obj, method) {
  for (let p = Object.getPrototypeOf(obj); p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
    if (Object.prototype.hasOwnProperty.call(p, method)) return p.constructor;
  }
  return null;
}
function threeKit(scene) {
  let mesh = null, shader = null;
  scene.traverse((o) => {
    if (!mesh && o.isMesh && o.geometry?.isBufferGeometry && o.geometry.getAttribute('position')) mesh = o;
    if (!shader && o.material?.isShaderMaterial) shader = o.material;
  });
  if (!mesh || !shader) return null; // the globe (and its atmosphere shader) not built yet: try again on the next update
  const Geometry = owner(mesh.geometry, 'setIndex');
  const Mesh = owner(mesh, 'getVertexPosition');
  // ShaderMaterial: the class right below Material (which defines setValues) in the shader material's chain
  let Shader = null;
  for (let p = Object.getPrototypeOf(shader); p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
    const parent = Object.getPrototypeOf(p);
    if (parent && Object.prototype.hasOwnProperty.call(parent, 'setValues')) { Shader = p.constructor; break; }
  }
  const Attribute = mesh.geometry.getAttribute('position').constructor;
  return Geometry && Mesh && Shader ? { Geometry, Mesh, Shader, Attribute } : null;
}

// ---- pulses ---------------------------------------------------------------------------------------------------------
// Same motion as the ring layer it replaces: a ring leaves the centre every PERIOD s, grows at SPEED deg/s up to the
// destination's radius and fades as it grows (alpha x (1 - r / rMax)); one pixel wide. Static (LITE / reduced motion):
// one ring at the full radius.
const SPEED = 2.2; // deg / s (ringPropagationSpeed)
const PERIOD = 1.4; // s (ringRepeatPeriod)
const ALT = 0.0015; // globe radii above the surface (three-globe's ring altitude)
const VERT = `
attribute vec2 aUv;
attribute vec4 aColor;
attribute float aMax;
varying vec2 vUv;
varying vec4 vColor;
varying float vMax;
void main() {
  vUv = aUv; vColor = aColor; vMax = aMax;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`;
const FRAG = `
uniform float uTime;
uniform float uStatic;
varying vec2 vUv;
varying vec4 vColor;
varying float vMax;
void main() {
  float d = length(vUv);
  if (d > vMax) discard;
  float w = fwidth(d);
  float a;
  if (uStatic > 0.5) {
    a = 0.6 * (1.0 - smoothstep(0.0, w, abs(d - vMax + w)));
  } else {
    float gap = ${(SPEED * PERIOD).toFixed(4)};
    float x = mod(uTime * ${SPEED.toFixed(4)} - d, gap);
    a = (1.0 - smoothstep(0.0, w, min(x, gap - x))) * (1.0 - d / vMax);
  }
  if (a <= 0.0) discard;
  gl_FragColor = vec4(vColor.rgb, vColor.a * a);
}`;

// rings: [{ lat, lng, r (deg), rgb: [r, g, b] 0..1, alpha }]
export function pulseLayer(globe) {
  let kit = null, mesh = null, isStatic = false;
  const uniforms = { uTime: { value: 0 }, uStatic: { value: 0 } };
  const t0 = performance.now();
  function build(rings) {
    const R = globe.getGlobeRadius();
    const n = rings.length * 6;
    const pos = new Float32Array(n * 3), uv = new Float32Array(n * 2), col = new Float32Array(n * 4), max = new Float32Array(n);
    let v = 0;
    for (const g of rings) {
      const c = globe.getCoords(g.lat, g.lng, ALT);
      const len = Math.hypot(c.x, c.y, c.z);
      const nx = c.x / len, ny = c.y / len, nz = c.z / len;
      // east = y-axis x normal, north = normal x east (three-globe: +y is the north pole)
      let ex = nz, ez = -nx;
      const el = Math.hypot(ex, ez) || 1;
      ex /= el; ez /= el;
      const north = [ny * ez, nz * ex - nx * ez, -ny * ex];
      const k = (g.r * Math.PI / 180) * R; // world units per ring radius (tangent plane, small angles)
      for (const [su, sv] of [[-1, -1], [1, -1], [1, 1], [-1, -1], [1, 1], [-1, 1]]) {
        pos.set([c.x + (su * ex + sv * north[0]) * k, c.y + sv * north[1] * k, c.z + (su * ez + sv * north[2]) * k], v * 3);
        uv.set([su * g.r, sv * g.r], v * 2);
        col.set([...g.rgb, g.alpha], v * 4);
        max[v] = g.r;
        v++;
      }
    }
    const geo = new kit.Geometry();
    geo.setAttribute('position', new kit.Attribute(pos, 3));
    geo.setAttribute('aUv', new kit.Attribute(uv, 2));
    geo.setAttribute('aColor', new kit.Attribute(col, 4));
    geo.setAttribute('aMax', new kit.Attribute(max, 1));
    return geo;
  }
  return {
    // false: the classes are not available yet (the caller keeps the library's ring layer meanwhile)
    set(rings) {
      kit ||= threeKit(globe.scene());
      if (!kit) return false;
      if (!mesh) {
        const material = new kit.Shader({ uniforms, vertexShader: VERT, fragmentShader: FRAG, transparent: true, depthWrite: false });
        mesh = new kit.Mesh(new kit.Geometry(), material);
        mesh.frustumCulled = false;
        // the pattern repeats every PERIOD: wrapped, the uniform keeps full float precision on a kiosk running for weeks
        mesh.onBeforeRender = () => { uniforms.uTime.value = isStatic ? 0 : ((performance.now() - t0) / 1000) % PERIOD; };
        globe.scene().add(mesh);
      }
      mesh.geometry.dispose();
      mesh.geometry = build(rings);
      return true;
    },
    setStatic(on) { isStatic = on; uniforms.uStatic.value = on ? 1 : 0; },
  };
}

// ---- film labels --------------------------------------------------------------------------------------------------
// Drawn exactly where the former HTML labels were: the .glabel box (marker ::before + chip span, styled in the
// stylesheets) centred on the point. Geometry and colours are read from one hidden sample element per kind (a layout read
// only for a label text not seen before). Labels on the far side of the globe are not drawn; a lower-priority label whose
// box would overlap an already drawn one is skipped (LABEL_PAD px apart).
const LABEL_PAD = 3;

function sampleOf(host, cls) {
  const outer = document.createElement('div');
  outer.className = cls;
  outer.setAttribute('aria-hidden', 'true');
  outer.style.cssText = 'position:absolute;visibility:hidden;left:0;top:0';
  const span = document.createElement('span');
  outer.appendChild(span);
  host.appendChild(outer);
  const s = getComputedStyle(span);
  const dot = getComputedStyle(outer, '::before');
  return {
    outer, span, cache: new Map(),
    font: `${s.fontWeight} ${s.fontSize} ${s.fontFamily}`, letterSpacing: s.letterSpacing, color: s.color, bg: s.backgroundColor,
    bar: parseFloat(s.borderLeftWidth) || 0, barColor: s.borderLeftColor, padL: parseFloat(s.paddingLeft) || 0,
    dot: { x: parseFloat(dot.left) || 0, y: parseFloat(dot.top) || 0, w: parseFloat(dot.width) || 0, h: parseFloat(dot.height) || 0, color: dot.backgroundColor },
  };
}
// -> box of the whole label and of its chip, relative to the label's centre (screen px, page zoom included)
function measure(sample, text) {
  const key = `${uiZoom()}|${text}`;
  let m = sample.cache.get(key);
  if (m) return m;
  sample.span.textContent = text;
  const o = sample.outer.getBoundingClientRect(), c = sample.span.getBoundingClientRect();
  m = { w: o.width, h: o.height, cx: c.left - o.left - o.width / 2, cy: c.top - o.top - o.height / 2, cw: c.width, ch: c.height };
  sample.cache.set(key, m);
  return m;
}

export function labelLayer(globe, host) {
  const canvas = document.createElement('canvas');
  canvas.className = 'glabel-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  // right above the WebGL canvas: the library's tooltip and controls stay on top of the labels
  globe.renderer().domElement.after(canvas);
  const ctx = canvas.getContext('2d');
  let labels = [], samples = null, lastKey = '';
  const dropSamples = () => { if (samples) { samples.plain.outer.remove(); samples.home.outer.remove(); } samples = null; };
  document.fonts?.addEventListener('loadingdone', () => { dropSamples(); lastKey = ''; }); // widths change with the web font
  function draw() {
    if (!labels.length) { // default theme: nothing to draw, clear once
      if (lastKey !== 'empty') ctx.clearRect(0, 0, canvas.width, canvas.height);
      lastKey = 'empty';
      return;
    }
    const cam = globe.camera();
    const w = host.clientWidth, h = host.clientHeight, dpr = window.devicePixelRatio || 1;
    const key = [w, h, dpr, uiZoom(), ...cam.matrixWorld.elements.map((x) => x.toFixed(4)), cam.zoom].join(',');
    if (key === lastKey) return; // nothing moved
    lastKey = key;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    samples ||= { plain: sampleOf(host, 'glabel'), home: sampleOf(host, 'glabel glabel-home') };
    const cp = cam.position;
    const z = uiZoom(); // the chip follows the page zoom (.glabel span), the marker does not
    const shown = [];
    ctx.textBaseline = 'middle';
    for (const d of labels) {
      const p = globe.getCoords(d.lat, d.lng, 0.01);
      if (p.x * cp.x + p.y * cp.y + p.z * cp.z <= p.x * p.x + p.y * p.y + p.z * p.z) continue; // far side
      const s = d.home ? samples.home : samples.plain;
      const m = measure(s, d.text);
      const { x, y } = globe.getScreenCoords(d.lat, d.lng, 0.01);
      const left = x - m.w / 2, top = y - m.h / 2;
      const box = { l: Math.min(left + s.dot.x, x + m.cx), t: top, r: x + m.cx + m.cw, b: top + m.h };
      if (shown.some((o) => box.l - LABEL_PAD < o.r && box.r + LABEL_PAD > o.l && box.t - LABEL_PAD < o.b && box.b + LABEL_PAD > o.t)) continue;
      shown.push(box);
      ctx.fillStyle = s.dot.color;
      ctx.fillRect(left + s.dot.x, top + s.dot.y, s.dot.w, s.dot.h);
      const cx = x + m.cx, cy = y + m.cy;
      ctx.fillStyle = s.bg;
      ctx.fillRect(cx, cy, m.cw, m.ch);
      ctx.fillStyle = s.barColor;
      ctx.fillRect(cx, cy, s.bar * z, m.ch);
      ctx.save();
      ctx.translate(cx + (s.bar + s.padL) * z, cy + m.ch / 2);
      ctx.scale(z, z);
      ctx.font = s.font;
      ctx.letterSpacing = s.letterSpacing;
      ctx.fillStyle = s.color;
      ctx.fillText(d.text, 0, 0.5);
      ctx.restore();
    }
  }
  return {
    // labels in priority order: [{ lat, lng, text, home }]
    set(list) { labels = list; lastKey = ''; },
    restyle() { dropSamples(); lastKey = ''; }, // theme / zoom change: read the stylesheets again
    draw,
    count: () => labels.length,
  };
}
