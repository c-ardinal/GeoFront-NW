// Drawing mode of the globe. GPU: the animated WebGL globe (arcs flowing, pulses, rotation), capped at 30 fps.
// LITE: the same globe and the same information, static (no animation, no rotation) and drawn only when something
// changed (data, a pointer / camera move). AUTO picks LITE when there is no WebGL or the browser renders it in
// software (SwiftShader / llvmpipe / ...): animating a CPU-rendered globe takes several cores. The choice (auto / gpu
// / lite) is kept in localStorage (settings menu); ?render=auto|gpu|lite overrides it for one page view.
const KEY = 'cc-render';
const CHOICES = ['auto', 'gpu', 'lite'];
const SOFTWARE = /swiftshader|llvmpipe|softpipe|software|basic render|mesa offscreen|subzero/i;

function context(type, attrs) {
  try { return document.createElement('canvas').getContext(type, attrs); } catch { return null; }
}
const release = (gl) => gl?.getExtension('WEBGL_lose_context')?.loseContext();

// -> { gpu, renderer }: hardware WebGL or not, and the renderer string (shown in the menu's tooltip)
export function probeGpu() {
  const gl = context('webgl2') || context('webgl');
  if (!gl) return { gpu: false, renderer: 'no WebGL' };
  const info = gl.getExtension('WEBGL_debug_renderer_info');
  const renderer = String(gl.getParameter(info ? info.UNMASKED_RENDERER_WEBGL : gl.RENDERER) || 'unknown');
  release(gl);
  // a browser that would fall back to software (blocklisted driver, no GPU process) refuses this context
  const fast = context('webgl2', { failIfMajorPerformanceCaveat: true }) || context('webgl', { failIfMajorPerformanceCaveat: true });
  release(fast);
  return { gpu: !!fast && !SOFTWARE.test(renderer), renderer };
}

export function storedChoice() {
  const q = new URLSearchParams(location.search).get('render');
  if (CHOICES.includes(q)) return q;
  try {
    const v = localStorage.getItem(KEY);
    return CHOICES.includes(v) ? v : 'auto';
  } catch { return 'auto'; }
}
export function storeChoice(v) {
  try { localStorage.setItem(KEY, v); } catch { /* storage unavailable: the choice lasts for this page view */ }
}
export const nextChoice = (c) => CHOICES[(CHOICES.indexOf(c) + 1) % CHOICES.length];
export const resolveMode = (choice, probe) => (choice === 'auto' ? (probe.gpu ? 'gpu' : 'lite') : choice);
// menu label: the mode in use, and whether it was picked automatically
export const choiceLabel = (choice, mode) => `RENDER: ${mode === 'gpu' ? 'GPU' : 'LITE'}${choice === 'auto' ? ' (AUTO)' : ''}`;
