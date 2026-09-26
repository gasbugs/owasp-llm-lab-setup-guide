/* Publisher-only UI replay: actual saved P18 evidence, not a live grading E2E. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

async function main() {
  const [passedPath, failedPath, screenshot] = process.argv.slice(2);
  assert(passedPath && failedPath && screenshot, 'pass.json fail.json screenshot.png required');
  const passed = JSON.parse(fs.readFileSync(passedPath)).verification;
  const failed = JSON.parse(fs.readFileSync(failedPath)).verification;
  assert.equal(passed.task_completed, true);
  assert.equal(failed.task_completed, false);
  const root = path.resolve(__dirname, '../../llm-security-control-plane/guided-control-center');
  let calls = 0;
  const server = http.createServer((req, res) => {
    if (req.url === '/api/bootstrap') {
      res.setHeader('content-type', 'application/json');
      return res.end(JSON.stringify({ csrf_token: 'replay-only', official_uis: [] }));
    }
    if (req.url === '/api/practice/P18/verify') {
      assert.equal(req.method, 'POST');
      assert.equal(req.headers['x-csrf-token'], 'replay-only');
      res.setHeader('content-type', 'application/json');
      return res.end(JSON.stringify(calls++ === 0 ? passed : failed));
    }
    const files = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'],
                    '/app.css': ['app.css', 'text/css'] };
    if (!files[req.url]) { res.writeHead(404); return res.end(); }
    const [name, type] = files[req.url];
    res.setHeader('content-type', type);
    res.end(fs.readFileSync(path.join(root, name)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' });
    await context.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.goto(origin, { waitUntil: 'networkidle' });
    await page.locator('.tab[data-tab-index="10"]').click();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
    const problem = await page.locator('#h18-work').innerText();
    assert(problem.includes('P18') && problem.includes('queries.yaml'));
    const examples = (await page.locator('#h18-work pre').allTextContents()).join('\n');
    assert(!examples.includes('logql:') && !examples.includes('sum by ('));
    await page.locator('#h18-verify').click();
    await page.waitForFunction(() => document.querySelector('#task-completion').textContent === 'P18 과제: 완료');
    assert.deepEqual(JSON.parse(await page.locator('#raw').innerText()), passed);
    await page.locator('#h18-verify').click();
    await page.waitForFunction(() => document.querySelector('#task-completion').textContent === 'P18 과제: 미완료');
    assert.equal(await page.locator('#verdict strong').innerText(), 'ERR');
    assert.deepEqual(JSON.parse(await page.locator('#raw').innerText()), failed);
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.locator('#h18-verify').focus();
      await page.locator('#h18-help').waitFor({ state: 'visible' });
      const fits = await page.evaluate(() => {
        const tip = document.querySelector('#h18-help').getBoundingClientRect();
        const work = document.querySelector('.workbench').getBoundingClientRect();
        return tip.left >= Math.max(0, work.left) - 1 && tip.right <= Math.min(innerWidth, work.right) + 1
          && document.documentElement.scrollWidth <= innerWidth;
      });
      assert(fits, `tooltip or page overflows at ${width}px`);
      await page.locator('[aria-describedby="h18-help"]').focus();
      assert.equal(await page.locator('[aria-describedby="h18-help"]').evaluate(el => el.closest(".action-control").classList.contains("tip-dismissed")), false);
      await page.locator('[aria-describedby="h18-help"]').press('Escape');
      assert.equal(await page.locator('[aria-describedby="h18-help"]').evaluate(el => el.closest(".action-control").classList.contains("tip-dismissed")), true);
      await page.locator('[aria-describedby="h18-help"]').evaluate(el => el.blur());
    }
    await page.locator('[data-theme-choice="light"]').click();
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
    await page.locator('[data-theme-choice="dark"]').click();
    await page.locator('#h18-work').scrollIntoViewIfNeeded();
    await page.screenshot({ path: screenshot });
    assert.deepEqual(errors, []);
    assert.equal(calls, 2);
    console.log(JSON.stringify({ scope: 'UI replay only', cases: ['problem-only', 'complete-to-incomplete',
      'raw-evidence-preserved', 'dark-system-and-manual', '1440px', '390px', 'keyboard-tooltip', 'mobile-tooltip'], screenshot }));
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
}
main().catch(err => { console.error(err); process.exitCode = 1; });
