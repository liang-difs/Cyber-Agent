import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';

const baseUrl = process.env.VISUAL_BASE_URL || 'http://127.0.0.1:3000';
const chromePath = process.env.CHROME_PATH || '/usr/bin/google-chrome';
const outDir = path.resolve(process.env.VISUAL_OUT_DIR || 'artifacts/frontend-visual-check');
const strictConsole = process.env.VISUAL_STRICT_CONSOLE === 'true';

const routes = ['/chat', '/pcap', '/reports', '/alerts', '/analysis', '/audit', '/monitor', '/cve'];
const viewports = [
  { name: 'desktop', width: 1440, height: 1000 },
  { name: 'mobile', width: 390, height: 844 },
];

function b64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function makeVisualCheckToken() {
  const header = b64url({ alg: 'none', typ: 'JWT' });
  const payload = b64url({
    sub: 'visual-check',
    role: 'admin',
    tenant_id: 'default',
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  return `${header}.${payload}.`;
}

async function collectLayoutMetrics(page) {
  return page.evaluate(() => {
    const root = document.documentElement;
    const overflowNodes = [...document.querySelectorAll('body *')]
      .filter((el) => {
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        if (style.position === 'fixed') return false;
        return rect.width > 0 && rect.height > 0 && (rect.right > window.innerWidth + 2 || rect.left < -2);
      })
      .slice(0, 8)
      .map((el) => {
        const rect = el.getBoundingClientRect();
        return {
          tag: el.tagName,
          className: String(el.className || '').slice(0, 120),
          text: (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 100),
          left: Math.round(rect.left),
          right: Math.round(rect.right),
        };
      });

    return {
      scrollWidth: root.scrollWidth,
      clientWidth: root.clientWidth,
      hasHorizontalOverflow: root.scrollWidth > root.clientWidth + 2,
      overflowNodes,
      text: document.body.innerText.slice(0, 240),
    };
  });
}

fs.mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch({
  headless: true,
  executablePath: fs.existsSync(chromePath) ? chromePath : undefined,
});

const results = [];
const token = makeVisualCheckToken();

for (const viewport of viewports) {
  const context = await browser.newContext({ viewport: { width: viewport.width, height: viewport.height } });
  await context.addInitScript((jwt) => localStorage.setItem('token', jwt), token);
  const page = await context.newPage();

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      results.push({ type: 'console-error', viewport: viewport.name, route: page.url(), message: msg.text() });
    }
  });
  page.on('pageerror', (err) => {
    results.push({ type: 'page-error', viewport: viewport.name, route: page.url(), message: err.message });
  });

  for (const route of routes) {
    await page.goto(`${baseUrl}${route}`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(500);
    const screenshot = path.join(outDir, `${viewport.name}-${route.slice(1)}.png`);
    await page.screenshot({ path: screenshot, fullPage: true });
    results.push({
      type: 'route-check',
      viewport: viewport.name,
      route,
      screenshot,
      ...(await collectLayoutMetrics(page)),
    });
  }

  await context.close();
}

await browser.close();

const reportPath = path.join(outDir, 'report.json');
fs.writeFileSync(reportPath, `${JSON.stringify(results, null, 2)}\n`);

const routeChecks = results.filter((item) => item.type === 'route-check');
const failed = results.filter((item) => {
  if (item.type === 'route-check') return item.hasHorizontalOverflow;
  if (item.type === 'page-error') return true;
  if (item.type === 'console-error') return strictConsole;
  return true;
});

console.log(`Visual check completed: ${routeChecks.length} route snapshots`);
console.log(`Report: ${reportPath}`);
if (failed.length > 0) {
  console.log(JSON.stringify(failed, null, 2));
  process.exitCode = 1;
}
