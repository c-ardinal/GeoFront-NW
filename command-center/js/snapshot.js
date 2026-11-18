// Screen snapshot for the evidence zip (P6): a PNG of the screen as shown, made in this browser without a library.
// The page is cloned; in the clone every text is masked once more (IPv4 / MAC, as util.maskText) and address tokens are
// removed, typed form text is emptied, scripts and external style links are dropped, and every visible canvas (the
// WebGL globe, drawn right before, its 2D label layer, charts) becomes its own picture. The clone is drawn through an SVG
// <foreignObject> image onto a canvas -> PNG. Only what the screen already shows (masked by mask-api) can be in it.
// Throws an Error with the reason when it cannot (a browser that taints such a canvas, an unreadable canvas, ...).
// ponytail: only vertical scroll positions are kept; web fonts from the font CDN are not embedded (system fonts in the
// picture).
import { maskText } from './util.js';
import { redrawNow } from './globe.js';

const MAX_SIDE = 4096; // px of the PNG (mask-api accepts up to 8192)
const TOKEN = /~[0-9a-f]{12}(?![0-9a-f])/g;
const XHTML = 'http://www.w3.org/1999/xhtml';
const TYPED = new Set(['text', 'search', 'email', 'url', 'tel', 'number', 'password', '']);

function sameOriginCss() {
  let out = '';
  for (const sheet of document.styleSheets) {
    try { for (const r of sheet.cssRules) out += `${r.cssText}\n`; } catch { /* a cross-origin sheet (web fonts): left out */ }
  }
  return out;
}

function canvasPictures() {
  redrawNow(); // the WebGL drawing buffer is only readable in the task that drew it
  return [...document.querySelectorAll('canvas')].map((c) => {
    const r = c.getBoundingClientRect();
    if (!r.width || !r.height || !c.width || !c.height) return null;
    try { return c.toDataURL('image/png'); } catch (e) { throw new Error(`画面の一部 (canvas) の読取不可: ${e.name || e}`); }
  });
}

function maskClone(root) {
  const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walk.nextNode(); n; n = walk.nextNode()) {
    if (n.parentNode?.nodeName === 'STYLE') continue;
    const t = maskText(n.data).replace(TOKEN, '');
    if (t !== n.data) n.data = t;
  }
}

function copyFormState(live, clone) {
  const a = live.querySelectorAll('input, textarea, select');
  const b = clone.querySelectorAll('input, textarea, select');
  a.forEach((x, i) => {
    const y = b[i];
    if (x.tagName === 'SELECT') [...y.options].forEach((o, j) => o.toggleAttribute('selected', j === x.selectedIndex));
    else if (x.tagName === 'TEXTAREA') y.textContent = '';
    else if (x.type === 'checkbox' || x.type === 'radio') y.toggleAttribute('checked', x.checked);
    else if (TYPED.has(x.type)) y.setAttribute('value', ''); // typed text is not part of the snapshot
  });
}

// a scrolled area starts at the item on screen: in the clone, the items above it are left out (vertical scroll only;
// by items, not pixels: the picture's fonts and line heights differ from the screen's)
function keepScroll(live, clone) {
  const a = [...live.querySelectorAll('*')];
  const b = clone.querySelectorAll('*');
  const twin = new Map(a.map((x, i) => [x, b[i]]));
  for (const x of a) {
    if (x.scrollTop <= 0) continue;
    const top = x.getBoundingClientRect().top;
    for (let el = x; el && el.children.length;) {
      const kids = [...el.children];
      const i = kids.findIndex((k) => k.getBoundingClientRect().bottom > top + 1);
      if (i < 0) break;
      kids.slice(0, i).forEach((k) => twin.get(k)?.style.setProperty('display', 'none'));
      el = kids[i].getBoundingClientRect().top < top - 1 ? kids[i] : null; // straddles the edge: go one level in
    }
  }
}

function svgOf(w, h) {
  const live = document.documentElement;
  const pics = canvasPictures();
  const clone = live.cloneNode(true);
  copyFormState(live, clone);
  keepScroll(live, clone);
  clone.querySelectorAll('canvas').forEach((c, i) => {
    if (pics[i]) c.style.background = `url("${pics[i]}") 0 0 / 100% 100% no-repeat`;
  });
  clone.querySelectorAll('script, noscript, link, iframe, template').forEach((e) => e.remove());
  maskClone(clone);
  const style = document.createElementNS(XHTML, 'style');
  // a picture starts every animation at its first frame (fade-ins at opacity 0): drawn as LITE draws it, static
  style.textContent = `${sameOriginCss()}\n*, *::before, *::after { animation: none !important; transition: none !important; }`;
  (clone.querySelector('head') || clone).append(style);
  clone.style.setProperty('margin-top', `${-window.scrollY}px`);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const at of live.attributes) if (!/^xmlns/.test(at.name)) svg.setAttribute(at.name, at.value); // :root[data-theme] etc.
  svg.setAttribute('width', w);
  svg.setAttribute('height', h);
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  const fo = document.createElementNS('http://www.w3.org/2000/svg', 'foreignObject');
  fo.setAttribute('width', '100%');
  fo.setAttribute('height', '100%');
  fo.append(clone);
  svg.append(fo);
  return new XMLSerializer().serializeToString(svg);
}

// -> Promise<Blob> (image/png) of the viewport
export async function snapshotPng() {
  const w = window.innerWidth;
  const h = window.innerHeight;
  const img = new Image();
  img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgOf(w, h))}`;
  try { await img.decode(); } catch { throw new Error('画面の画像化に失敗 (本ブラウザは画面の描画出力に非対応)'); }
  const scale = Math.min(window.devicePixelRatio || 1, 2, MAX_SIDE / w, MAX_SIDE / h);
  const out = document.createElement('canvas');
  out.width = Math.max(1, Math.round(w * scale));
  out.height = Math.max(1, Math.round(h * scale));
  const g = out.getContext('2d');
  g.fillStyle = getComputedStyle(document.body).backgroundColor || '#000';
  g.fillRect(0, 0, out.width, out.height);
  g.drawImage(img, 0, 0, out.width, out.height);
  return new Promise((resolve, reject) => {
    try {
      out.toBlob((b) => (b ? resolve(b) : reject(new Error('PNG の生成に失敗'))), 'image/png');
    } catch (e) { // a tainted canvas (browsers that treat <foreignObject> pictures as cross-origin)
      reject(new Error(`本ブラウザでは画面の PNG 化が不可 (${e.name || e})`));
    }
  });
}
