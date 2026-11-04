/* Optional Playwright integration smoke test; no production JS dependency.
 *   node scripts/test_rls_weight_dashboard_browser.js /absolute/path/dashboard.html
 *   node scripts/test_rls_weight_dashboard_browser.js http://127.0.0.1:8764/dashboard.html
 * Requires an installed Playwright module (or PLAYWRIGHT_MODULE=/absolute/module/path).
 * Alternatively load this file into browser_run_code's async(page) function,
 * then call `return await testDashboard(page)` against an already-open dashboard.
 * Works with both empty and populated v1 payloads. Fixtures are not real-data evidence.
 */
async function testDashboard(page) {
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const failures = [];
  const onError = error => failures.push(error.message);
  const onConsole = message => { if (message.type() === 'error') failures.push(message.text()); };
  page.on('pageerror', onError);
  page.on('console', onConsole);
  const result = {};
  const context = page.context();
  try {
    await page.reload({waitUntil: 'load'});
    const payload = await page.locator('#dashboard-data').textContent().then(JSON.parse);
    const tabs = page.getByRole('tab');
    assert(await tabs.count() === 4, 'Four accessible tabs are required');
    assert(await page.locator('script[src],link[rel=stylesheet],iframe,img').count() === 0,
      'Dashboard must not fetch external UI resources or interpret payload markup');
    // Once loaded, every interaction must work without network connectivity.
    await context.setOffline(true);
    result.offlineInteractions = true;
    const selectTab = name => page.getByRole('tab', {name, exact: true}).click();
    await selectTab('Overview');
    const conditions = await page.locator('#conditions').innerText();
    assert(!conditions.includes('run_manifest_sha256'), 'Overview must show run names, not provenance JSON');
    for (const mode of ['packet', 'byte', 'flow']) {
      const col = ['packet', 'byte', 'flow'].indexOf(mode) + 1;
      for (const [label, key] of [['Flow count', 'flow_count'], ['Packet total', 'packet_total'],
                                ['Byte total (Ethernet)', 'byte_total']]) {
        const value = payload.modes?.[mode]?.stats?.[key];
        const row = page.locator('#overview-stats tbody tr').filter({
          has: page.locator('td:first-child', {hasText: new RegExp('^' + label.replace(/[()]/g, '\\$&') + '$')})
        });
        const cell = row.locator('td').nth(col);
        assert(await cell.getAttribute('title') === String(value ?? '—'), `Exact ${mode} ${key} lost`);
        assert((await cell.innerText()).replaceAll(',', '') === String(value ?? '—'),
          `Displayed ${mode} ${key} differs from its saved value`);
      }
    }
    result.exactStatDisplay = true;
    await selectTab('Flow Size Distribution');
    const available = ['overall_ipv4', 'packet', 'byte', 'flow'].filter(k => payload.ecdf?.[k]?.points?.length);
    assert(await page.locator('[data-curve]').count() === available.length, 'Available curve count differs');
    for (const key of ['overall_ipv4', 'packet', 'byte', 'flow']) {
      const button = page.locator(`[data-series=${key}]`);
      await button.click();
      assert(await button.getAttribute('aria-pressed') === 'false', `${key} toggle state failed`);
      assert(await page.locator(`[data-curve=${key}]`).count() === 0, `${key} curve did not hide`);
      await button.click();
      assert(await page.locator(`[data-curve=${key}]`).count() === Number(available.includes(key)),
        `${key} curve did not restore`);
    }
    for (const key of available) {
      assert(await page.locator(`[data-envelope=${key}]`).count() === Number(!!payload.ecdf[key].simplified),
        `${key} bound envelope visibility differs from simplification flag`);
    }
    result.curveToggles = true;
    const svg = page.locator('#ecdf-svg');
    const original = [await svg.getAttribute('data-x-min'), await svg.getAttribute('data-x-max')];
    const box = await svg.boundingBox();
    if (available.length) {
      const key = available[0], point = payload.ecdf[key].points[0];
      const lx = Math.log10(Number(point.packet_count));
      const px = 78 + (lx - Number(original[0])) / (Number(original[1]) - Number(original[0])) * 892;
      await page.mouse.move(box.x + (px + 0.1) / 1000 * box.width, box.y + box.height * 0.5);
      const text = await page.locator('#tooltip').innerText();
      assert(text.includes('packet_count ' + point.packet_count) &&
        text.includes('F(x) ' + point.cumulative_fraction) && text.includes(String(point.cumulative_count)),
        'ECDF hover does not show a true saved point');
      result.ecdfHover = true;
    }
    await page.locator('#zoom-in').click();
    const zoomed = Number(await svg.getAttribute('data-x-max')) - Number(await svg.getAttribute('data-x-min'));
    assert(zoomed < Number(original[1]) - Number(original[0]), 'ECDF button zoom failed');
    await page.locator('#zoom-reset').click();
    assert(await svg.getAttribute('data-x-max') === original[1], 'ECDF reset failed');
    await page.mouse.move(box.x + box.width * 0.3, box.y + box.height * 0.5);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.6, box.y + box.height * 0.5, {steps: 5});
    await page.mouse.up();
    assert(Number(await svg.getAttribute('data-x-max')) < Number(original[1]), 'Drag zoom failed');
    await page.locator('#zoom-reset').click();
    await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.5);
    await page.mouse.wheel(0, -100);
    await page.waitForFunction(max => Number(document.querySelector('#ecdf-svg').dataset.xMax) < max,
      Number(original[1]));
    await page.locator('#zoom-reset').click();
    result.zoomResetAndDrag = true;
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#ecdf-download').click();
    const download = await downloadPromise;
    assert(download.suggestedFilename() === 'rls-weight-ecdf.svg', 'SVG export failed');
    result.svgDownload = true;
    await selectTab('Prefix Analysis');
    const prefixes = payload.prefixes || [];
    if (prefixes.length) {
      const target = prefixes[0].prefix_24;
      await page.locator('#prefix-search').fill(target);
      const rows = await page.locator('#prefix-body tr').allTextContents();
      assert(rows.length && rows.every(text => text.includes(target)), 'Prefix search failed');
      await page.locator('#prefix-search').fill('__no_matching_prefix__');
      assert((await page.locator('#prefix-body').innerText()).includes('該当する/24がありません'),
        'Empty search state failed');
      await page.locator('#prefix-search').fill('');
      for (const mode of ['packet', 'byte', 'flow', 'overlap']) {
        await page.locator('#prefix-mode').selectOption(mode);
        const keys = await page.locator('#prefix-body tr[data-prefix]').evaluateAll(rows => rows.map(r => r.dataset.prefix));
        assert(keys.every(key => prefixes.some(p => p.prefix_24 === key &&
          (mode === 'overlap' ? p.modes.length > 1 : p.modes.includes(mode)))), 'Mode filter failed: ' + mode);
      }
      await page.locator('#prefix-mode').selectOption('all');
      if (prefixes.length > 25) {
        await page.locator('#prefix-next').click();
        assert((await page.locator('#prefix-page-status').innerText()).includes('ページ 2 /'), 'Pagination failed');
        await page.locator('#prefix-prev').click();
      }
      const headers = page.locator('#prefix-head th');
      for (let index = 0; index < await headers.count(); index++) {
        const th = headers.nth(index), button = th.locator('button');
        if (await th.getAttribute('aria-sort') === 'ascending') await button.click();
        await button.click();
        assert(await th.getAttribute('aria-sort') === 'ascending', 'Ascending sort failed');
        await button.click();
        assert(await th.getAttribute('aria-sort') === 'descending', 'Descending sort failed');
      }
      // Sorting by adjacent integers above 2^53 must retain the source values.
      const numeric = prefixes.filter(p => /^\d+$/.test(String(p.stats?.flow_count)));
      if (numeric.length === prefixes.length) {
        const expected = numeric.reduce((a, b) => BigInt(a.stats.flow_count) > BigInt(b.stats.flow_count) ? a : b);
        const header = headers.nth(3);
        if (await header.getAttribute('aria-sort') !== 'descending') {
          await header.locator('button').click();
          await header.locator('button').click();
        }
        const raw = await page.locator('#prefix-body tr').first().locator('td').nth(3).getAttribute('title');
        assert(raw === String(expected.stats.flow_count), 'Exact integer ordering failed');
      }
      const scatterTarget = prefixes.find(p => Number(p.stats?.flow_count) > 0 && Number(p.stats?.mean_packet_count) > 0);
      if (scatterTarget) {
        await page.locator('#prefix-search').fill(scatterTarget.prefix_24);
        await page.locator('#scatter-canvas').scrollIntoViewIfNeeded();
        const canvas = await page.locator('#scatter-canvas').boundingBox();
        await page.mouse.move(canvas.x + 524 / 1000 * canvas.width, canvas.y + 208.5 / 460 * canvas.height);
        const hover = await page.locator('#tooltip').innerText();
        assert(hover.includes(scatterTarget.prefix_24) &&
          hover.includes('flow_count: ' + scatterTarget.stats.flow_count) &&
          hover.includes('mean_packet_count: ' + scatterTarget.stats.mean_packet_count) &&
          hover.includes('packet_total: ' + scatterTarget.stats.packet_total) &&
          hover.includes('byte_total: ' + scatterTarget.stats.byte_total), 'Scatter hover differs from saved stats');
        result.scatterHover = true;
        await page.locator('#prefix-search').fill('');
      }
      result.tableSearchFilterSortPaging = true;
    } else {
      assert((await page.locator('#prefix-body').innerText()).includes('該当する/24がありません'),
        'Empty prefix state failed');
      result.emptyPrefixes = true;
    }
    await selectTab('Experiment Details');
    assert((await page.locator('#provenance').innerText()).includes('保存済み記録'), 'Provenance panel failed');
    assert(failures.length === 0, 'Browser errors: ' + failures.join('; '));
    result.pageErrors = failures;
    return result;
  } finally {
    await context.setOffline(false);
    page.off('pageerror', onError);
    page.off('console', onConsole);
  }
}

if (typeof module !== 'undefined') module.exports = {testDashboard};
if (typeof require === 'function' && require.main === module) {
  (async () => {
    const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
    const {pathToFileURL} = require('node:url');
    const {resolve} = require('node:path');
    const target = process.argv[2];
    if (!target) throw new Error('Pass a dashboard.html path or URL');
    const browser = await chromium.launch({headless: true});
    try {
      const page = await browser.newPage({viewport: {width: 1440, height: 1000}, acceptDownloads: true});
      await page.goto(/^(?:https?|file):/.test(target) ? target : pathToFileURL(resolve(target)).href);
      console.log(JSON.stringify(await testDashboard(page), null, 2));
    } finally { await browser.close(); }
  })().catch(error => {console.error(error); process.exitCode = 1;});
}
