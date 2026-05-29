const { chromium } = require('playwright');
const readline = require('readline');
const fs = require('fs');
const path = require('path');

let browser = null;
let context = null;
let page = null;

async function ensurePage(headless = false) {
  if (!browser) {
    browser = await chromium.launch({
      headless,
      args: ['--disable-dev-shm-usage']
    });
    context = await browser.newContext({
      viewport: { width: 1280, height: 800 },
      acceptDownloads: true
    });
    page = await context.newPage();
  }
  if (!page || page.isClosed()) {
    page = await context.newPage();
  }
  return page;
}

async function handle(cmd) {
  const action = cmd.action;
  const args = cmd.args || {};
  const p = await ensurePage(!!args.headless);

  if (action === 'open') {
    await p.goto(args.url, { waitUntil: args.waitUntil || 'domcontentloaded', timeout: args.timeout || 45000 });
    return { ok: true, url: p.url(), title: await p.title() };
  }
  if (action === 'click') {
    if (args.selector) {
      await p.click(args.selector, { button: args.button || 'left', timeout: args.timeout || 15000 });
    } else {
      await p.mouse.click(Number(args.x), Number(args.y), { button: args.button || 'left' });
    }
    await p.waitForTimeout(args.wait || 300);
    return { ok: true, url: p.url(), title: await p.title() };
  }
  if (action === 'type') {
    if (args.selector) {
      if (args.clear !== false) {
        await p.fill(args.selector, args.text || '', { timeout: args.timeout || 15000 });
      } else {
        await p.click(args.selector, { timeout: args.timeout || 15000 });
        await p.keyboard.type(args.text || '', { delay: args.delay || 0 });
      }
    } else {
      await p.keyboard.type(args.text || '', { delay: args.delay || 0 });
    }
    return { ok: true, url: p.url(), title: await p.title() };
  }
  if (action === 'press') {
    await p.keyboard.press(args.key);
    await p.waitForTimeout(args.wait || 300);
    return { ok: true, url: p.url(), title: await p.title() };
  }
  if (action === 'screenshot') {
    const out = path.resolve(args.path || 'browser-screenshot.png');
    fs.mkdirSync(path.dirname(out), { recursive: true });
    await p.screenshot({ path: out, fullPage: args.fullPage !== false });
    return { ok: true, path: out, url: p.url(), title: await p.title() };
  }
  if (action === 'eval') {
    const result = await p.evaluate(args.script || 'document.documentElement.innerText');
    return { ok: true, result, url: p.url(), title: await p.title() };
  }
  if (action === 'text') {
    const text = await p.locator(args.selector || 'body').innerText({ timeout: args.timeout || 15000 });
    return { ok: true, text: text.slice(0, args.limit || 30000), url: p.url(), title: await p.title() };
  }
  if (action === 'state') {
    return { ok: true, url: p.url(), title: await p.title() };
  }
  if (action === 'close') {
    if (browser) await browser.close();
    browser = context = page = null;
    return { ok: true, closed: true };
  }
  throw new Error('unknown browser action: ' + action);
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', async (line) => {
  try {
    const cmd = JSON.parse(line);
    const result = await handle(cmd);
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: e.stack || String(e) }) + '\n');
  }
});

process.on('SIGTERM', async () => {
  try { if (browser) await browser.close(); } catch {}
  process.exit(0);
});
