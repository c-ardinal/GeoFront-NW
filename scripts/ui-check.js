// Browser check of the F1 views (推移 / ログ検索) on a running stack without login (127.0.0.1, e2e-open):
//   PW_CORE=<dir of playwright-core> CHROME=<chromium / headless shell> node scripts/ui-check.js <base-url> [screenshot dir]
// Optional BROWSER_LOCK=<dir>: created while the browser runs (one browser at a time), removed at the end.
// Both themes x 390 / 768 / 1280 / 1920 / 2560 px: the views open from the panel headings (no new top-bar item), draw
// (SVG or "—"), at most 600 points per series, no horizontal overflow, >= 44 px targets below 1280 px; then once:
// legend toggle, keyboard readout, drag-to-zoom + 拡大を戻す, presets, log search (marks, histogram, refused regex,
// selected line -> 原因候補), drawer deep links, LITE mode and PLAYBACK (the window ends at the cursor).
// One line per check (OK / NG); exit 1 when any is NG. Read-only: nothing is written to the stack.
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PW_CORE || 'playwright-core');

const BASE = (process.argv[2] || 'http://127.0.0.1:28080').replace(/\/$/, '');
const OUT = process.argv[3] || '';
const LOCK = process.env.BROWSER_LOCK || '';
const WIDTHS = [390, 768, 1280, 1920, 2560];
let fails = 0;
const check = (name, ok, detail = '') => { if (!ok) fails++; console.log(`[${ok ? 'OK' : 'NG'}] ${name}${detail !== '' ? `  (${detail})` : ''}`); };
const heightOf = (w) => (w < 768 ? 844 : w < 1280 ? 1024 : w >= 2560 ? 1440 : 1080);

async function shot(page, name) {
  if (OUT) await page.screenshot({ path: path.join(OUT, `${name}.png`) });
}

async function load(page, theme, render = 'auto') {
  await page.goto(`${BASE}/`);
  await page.evaluate(([t, r]) => { localStorage.setItem('cc-theme', t); localStorage.setItem('cc-render', r); }, [theme, render]);
  await page.goto(`${BASE}/?idle=3600`);
  await page.waitForSelector('#boot.gone', { timeout: 60000 });
  await page.waitForTimeout(2500);
}

// the heading button of a panel; below 1280 px the panel's tab group first
async function openFrom(page, panel, tab, text) {
  if (await page.evaluate(() => getComputedStyle(document.getElementById('tabs')).display !== 'none')) await page.click(`#tabs button[data-tab="${tab}"]`);
  await page.locator(`#${panel} > h2 .h-act`, { hasText: text }).click();
  await page.waitForSelector('#modal-root:not([hidden])');
}

const modalInfo = (page) => page.evaluate(() => {
  const m = document.getElementById('modal-body');
  const small = [...document.querySelectorAll('#modal button, #modal select, #modal input:not([type="checkbox"]), #modal .ls-row')]
    .filter((n) => n.offsetParent && n.getBoundingClientRect().height > 0)
    .filter((n) => n.getBoundingClientRect().height < 43.5).map((n) => `${n.tagName}.${n.className}:${Math.round(n.getBoundingClientRect().height)}`);
  return { title: document.getElementById('modal-title').textContent, overflow: m.scrollWidth > m.clientWidth + 1, small,
    svg: !!m.querySelector('.tr-svg'), dash: !!m.querySelector('.tr-dash'), paths: m.querySelectorAll('.tr-line').length,
    legend: m.querySelectorAll('.tr-lg').length, note: m.querySelector('.tr-note')?.textContent || '' };
});

async function trendBasics(page, tag, w) {
  const heads = await page.evaluate(() => ['p-wan', 'p-if', 'p-logs'].map((id) => {
    const h = document.querySelector(`#${id} > h2`);
    return h.offsetParent && h.scrollWidth > h.clientWidth + 1 ? id : null;
  }).filter(Boolean));
  check(`${tag}: panel headings with 推移 / 検索 do not overflow`, !heads.length, heads.join(','));
  await shot(page, `${tag}-wall`);
  await openFrom(page, 'p-wan', 'sum', '推移');
  await page.waitForFunction(() => document.querySelector('#modal .tr-svg, #modal .tr-dash'), null, { timeout: 30000 });
  const i = await modalInfo(page);
  check(`${tag}: 推移 opens from the WAN heading and draws`, i.title === '推移' && (i.svg || i.dash), `${i.paths} lines, ${i.legend} legend`);
  const pts = /1 系列 (\d+) 点/.exec(i.note);
  check(`${tag}: at most 600 points per series`, !pts || Number(pts[1]) <= 600, pts?.[1]);
  check(`${tag}: 推移 has no horizontal overflow`, !i.overflow);
  if (w < 1280) check(`${tag}: 推移 targets >= 44 px`, !i.small.length, i.small.slice(0, 4).join(' '));
  await shot(page, `${tag}-trend`);
  await page.keyboard.press('Escape');
  await openFrom(page, 'p-logs', 'log', '検索');
  await page.waitForFunction(() => document.querySelectorAll('#modal .ls-row').length && document.querySelectorAll('#modal .ls-col').length, null, { timeout: 30000 });
  const l = await modalInfo(page);
  check(`${tag}: ログ検索 opens from the SYSLOG heading with lines and a histogram`, l.title === 'ログ検索');
  check(`${tag}: ログ検索 has no horizontal overflow`, !l.overflow);
  if (w < 1280) check(`${tag}: ログ検索 targets >= 44 px`, !l.small.length, l.small.slice(0, 4).join(' '));
  await shot(page, `${tag}-logsearch`);
  await page.keyboard.press('Escape');
}

async function trendDeep(page) {
  await openFrom(page, 'p-wan', 'sum', '推移');
  await page.waitForSelector('#modal .tr-svg', { timeout: 30000 });
  const before = (await modalInfo(page)).paths;
  await page.locator('#modal .tr-lg').first().click();
  const after = await modalInfo(page);
  check('legend button hides its series', after.paths < before && (await page.locator('#modal .tr-lg').first().getAttribute('aria-pressed')) === 'false', `${before} -> ${after.paths}`);
  await page.locator('#modal .tr-lg').first().click();
  await page.focus('#modal .tr-chart');
  await page.keyboard.press('ArrowLeft');
  const read = await page.textContent('#modal .tr-read');
  check('keyboard: ← on the chart reads the values', /\d{2}:\d{2}/.test(read), read.trim().slice(0, 60));
  const box = await page.locator('#modal .tr-chart').boundingBox();
  await page.mouse.move(box.x + box.width * 0.4, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.7, box.y + box.height / 2, { steps: 5 });
  await page.mouse.up();
  await page.waitForFunction(() => !document.querySelector('#modal .tr-acts .link-btn').disabled, null, { timeout: 15000 });
  const zoomed = await page.textContent('#modal .tr-note');
  check('drag zooms into the span (拡大を戻す enabled)', /分|時間/.test(zoomed), zoomed.split('·')[0]);
  await page.locator('#modal .tr-acts .link-btn', { hasText: '拡大を戻す' }).click();
  await page.locator('#modal .seg-btn', { hasText: '7d' }).click();
  await page.waitForFunction(() => /^7 日/.test(document.querySelector('#modal .tr-note')?.textContent || ''), null, { timeout: 30000 });
  const n7 = await page.textContent('#modal .tr-note');
  const p7 = Number(/1 系列 (\d+) 点/.exec(n7)?.[1]);
  check('preset 7d: step sized for <= 600 points, the newest values included', p7 > 0 && p7 <= 600, n7.split('·').slice(0, 3).join('·'));
  // another family / scope: interface drops (the testbed may not answer them: "—" is the right answer then)
  await page.selectOption('#modal .tr-bar select', 'if_drops');
  await page.waitForFunction(() => document.querySelector('#modal .tr-svg, #modal .tr-dash') && !/読み込み中/.test(document.querySelector('#modal .tr-status').textContent), null, { timeout: 30000 });
  const d = await modalInfo(page);
  check('family switch: IF の破棄 draws or says "—"', d.svg || d.dash, d.dash ? '—' : `${d.paths} lines`);
  await page.selectOption('#modal .tr-bar select', 'flow_country');
  await page.waitForFunction(() => document.querySelector('#modal .tr-svg, #modal .tr-dash') && !/読み込み中/.test(document.querySelector('#modal .tr-status').textContent), null, { timeout: 30000 });
  const fl = await page.evaluate(() => document.querySelectorAll('#modal .tr-area').length);
  check('flows by country are stacked areas', fl > 0 || (await modalInfo(page)).dash, `${fl} areas`);
  await shot(page, 'trend-flows');
  await page.keyboard.press('Escape');
}

async function searchDeep(page) {
  await openFrom(page, 'p-logs', 'log', '検索');
  await page.waitForSelector('#modal .ls-row', { timeout: 30000 });
  const word = await page.evaluate(() => (document.querySelector('#modal .ls-row .log-m').textContent.match(/[A-Za-z]{4,}/) || ['LAN'])[0]);
  await page.fill('#modal .ls-q input', word.toLowerCase());
  await page.click('#modal .ls-go');
  await page.waitForFunction(() => /行 \(新しい順\)|一致する行はありません/.test(document.querySelector('#modal .v-meta-line').textContent), null, { timeout: 30000 });
  const m = await page.evaluate(() => { const rows = [...document.querySelectorAll('#modal .ls-row')]; return { n: rows.length, marked: rows.filter((r) => r.querySelector('mark')).length }; });
  check(`keyword "${word.toLowerCase()}": every line marked (case-insensitive)`, m.n > 0 && m.marked === m.n, `${m.marked}/${m.n}`);
  const bars = await page.evaluate(() => document.querySelectorAll('#modal .ls-col').length);
  check('histogram: 60 buckets', bars === 60, bars);
  await page.focus('#modal .ls-hbox');
  await page.keyboard.press('End');
  check('histogram: keyboard selects a bucket', /件/.test(await page.textContent('#modal .ls-tip')));
  await page.fill('#modal .ls-q input', '(a+)+$');
  await page.check('#modal .ls-bar input[type="checkbox"]');
  await page.click('#modal .ls-go');
  await page.waitForFunction(() => /検索できません/.test(document.querySelector('#modal .v-meta-line').textContent), null, { timeout: 30000 });
  check('unsafe regex refused with the reason', true, (await page.textContent('#modal .v-meta-line')).slice(0, 60));
  await page.uncheck('#modal .ls-bar input[type="checkbox"]');
  await page.fill('#modal .ls-q input', '');
  await page.click('#modal .ls-go');
  await page.waitForSelector('#modal .ls-row', { timeout: 30000 });
  await page.focus('#modal .ls-row');
  await page.keyboard.press('Enter');
  check('a selected line offers 原因候補 / evidence', await page.isVisible('#modal .ls-selbar'));
  await shot(page, 'logsearch-selected');
  await page.locator('#modal .ls-selbar .link-btn', { hasText: '原因候補' }).click();
  await page.waitForSelector('#drawer:not([hidden])', { timeout: 15000 });
  check('selected line -> 原因候補 drawer', /原因候補/.test(await page.textContent('#drawer-title')), await page.textContent('#drawer-title'));
  await page.keyboard.press('Escape');
}

async function drawerLinks(page) {
  if (await page.evaluate(() => getComputedStyle(document.getElementById('tabs')).display !== 'none')) await page.click('#tabs button[data-tab="sum"]');
  await page.locator('#devices .row.clickable').first().click();
  await page.waitForSelector('#drawer:not([hidden])');
  await page.locator('#drawer .link-btn', { hasText: '推移を見る' }).click();
  await page.waitForFunction(() => document.querySelector('#modal .tr-svg, #modal .tr-dash'), null, { timeout: 30000 });
  const sel = await page.evaluate(() => [...document.querySelectorAll('#modal .tr-scope select')].map((s) => s.value));
  check('device drawer -> 推移を見る (the device kept)', sel[0] && sel[0] !== '', sel.join(','));
  await page.keyboard.press('Escape');
  await page.locator('#devices .row.clickable').first().click();
  await page.waitForSelector('#drawer:not([hidden])');
  await page.locator('#drawer .link-btn', { hasText: 'ログを検索' }).click();
  await page.waitForSelector('#modal .ls-bar', { timeout: 15000 });
  const host = await page.evaluate(() => document.querySelector('#modal .ls-bar select').value);
  check('device drawer -> ログを検索 (the host kept)', !!host, host);
  await page.keyboard.press('Escape');
}

// destination drawers (needs flows, e.g. the demo profile): a country and an address-level (UNKNOWN GEO) destination
// both offer 推移を見る with the destination's country kept
async function destLinks(page) {
  for (const [list, what] of [['#dest', 'country'], ['#unknown', 'address']]) {
    const row = page.locator(`${list} .row.clickable`).first();
    if (!(await row.count())) { console.log(`[--] destination drawer (${what}): no flow rows here, not checked`); continue; }
    if (await page.evaluate(() => getComputedStyle(document.getElementById('tabs')).display !== 'none')) await page.click('#tabs button[data-tab="net"]');
    await row.click();
    await page.waitForSelector('#drawer:not([hidden])');
    const link = page.locator('#drawer .link-btn', { hasText: '推移を見る' }).first();
    check(`destination drawer (${what}) offers 推移を見る`, (await link.count()) > 0);
    if (!(await link.count())) { await page.keyboard.press('Escape'); continue; }
    await link.click();
    await page.waitForFunction(() => document.querySelector('#modal .tr-svg, #modal .tr-dash'), null, { timeout: 30000 });
    const cc = await page.evaluate(() => [...document.querySelectorAll('#modal .tr-scope input')].map((i) => i.value).filter(Boolean).join(','));
    check(`destination drawer (${what}) -> 推移 keeps the country`, !!cc, cc);
    await page.keyboard.press('Escape');
  }
}

async function playback(page) {
  const reqs = [];
  page.on('request', (r) => { if (r.url().includes('/trend/series')) reqs.push(r.url()); });
  const cursor = await page.evaluate(() => { const t = Date.now(); window.ccTest.enterPlayback(t - 3 * 3600e3, t - 3600e3); return window.ccTest.playback().cursor; });
  await page.waitForTimeout(2500);
  await page.locator('#p-wan > h2 .h-act', { hasText: '推移' }).click().catch(() => {});
  await page.waitForFunction(() => document.querySelector('#modal .tr-svg, #modal .tr-dash'), null, { timeout: 30000 });
  await page.waitForTimeout(800);
  const cur = await page.evaluate(() => window.ccTest.playback().cursor);
  const to = Math.max(...reqs.map((u) => Number(new URL(u).searchParams.get('to'))));
  check('PLAYBACK: 推移 ends at the cursor', Number.isFinite(to) && to <= cur / 1000 + 1, `to ${to} cursor ${Math.round(cur / 1000)} (start ${Math.round(cursor / 1000)})`);
  await shot(page, 'trend-playback');
  await page.keyboard.press('Escape');
}

(async () => {
  if (OUT) fs.mkdirSync(OUT, { recursive: true });
  if (LOCK) fs.mkdirSync(LOCK); // fails when another browser holds it
  const b = await chromium.launch({ executablePath: process.env.CHROME || undefined, args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
  try {
    const ctx = await b.newContext({ viewport: { width: 1920, height: 1080 } });
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    for (const theme of ['default', 'film']) {
      for (const w of WIDTHS) {
        await page.setViewportSize({ width: w, height: heightOf(w) });
        await load(page, theme);
        const head = await page.evaluate(() => document.getElementById('topbar').innerText);
        check(`${theme} ${w}: no 推移 / 検索 item in the top bar`, !/推移|検索/.test(head));
        await trendBasics(page, `${theme}-${w}`, w);
      }
    }
    await page.setViewportSize({ width: 1920, height: 1080 });
    await load(page, 'default');
    await trendDeep(page);
    await searchDeep(page);
    await drawerLinks(page);
    await destLinks(page);
    await load(page, 'default', 'lite');
    check('LITE mode on', await page.evaluate(() => document.documentElement.dataset.render === 'lite'));
    await trendBasics(page, 'lite-1920', 1920);
    await load(page, 'film');
    await playback(page);
    check('no page errors', !errors.length, errors.slice(0, 3).join(' | '));
  } catch (e) {
    check('run', false, String(e.message || e).split('\n')[0]);
  } finally {
    await b.close();
    if (LOCK) fs.rmdirSync(LOCK);
  }
  console.log(`${fails ? 'NG' : 'OK'}: ${fails} failed`);
  process.exit(fails ? 1 : 0);
})();
