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
    assert(await tabs.count() === 5, 'Five accessible tabs are required');
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
    result.perPrefix = await testPerPrefix(page, payload, assert);
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

async function testPerPrefix(page, payload, assert) {
  await page.getByRole('tab', {name:'Per-Prefix Flow Size Distribution', exact:true}).click();
  const prefixes=payload.prefixes||[],curves=payload.per_prefix_ecdf?.curves||{};
  const mode=['packet','byte','flow'].reduce((a,b)=>prefixes.filter(p=>p.modes.includes(a)).length>=prefixes.filter(p=>p.modes.includes(b)).length?a:b,'packet');
  await page.locator('#pp-mode').selectOption(mode);
  await page.locator('#pp-search').fill('__absent__');
  assert((await page.locator('#pp-options').innerText()).includes('該当する/24がありません'),'Per-prefix empty search failed');
  await page.locator('#pp-search').fill('');
  const eligible=prefixes.filter(p=>p.modes.includes(mode));
  if(eligible.length>20){
    await page.locator('#pp-next').click();
    assert((await page.locator('#pp-page-status').innerText()).includes('ページ 2 /'),'Per-prefix paging failed');
    await page.locator('#pp-prev').click();
  }
  for(const p of eligible.slice(0,5)){
    await page.locator('#pp-search').fill(p.prefix_24);
    await page.locator('#pp-options input[type=checkbox]').check();
  }
  const selected=eligible.slice(0,5);
  const paths=page.locator('#pp-svg [data-prefix-curve]');
  assert(await paths.count()===selected.filter(p=>JSON.parse(curves[p.prefix_24]?.encoded_points||'[]').length).length,'Individual curves must stay separate');
  for(const p of selected){
    const row=page.locator('#pp-stats tr[data-prefix]').filter({has:page.locator('td:first-child',{hasText:p.prefix_24})});
    for(const [i,key] of ['flow_count','packet_total','byte_total','median','p95','mean_packet_count','one_packet_rate'].entries()){
      assert(await row.locator('td').nth(i+1).getAttribute('title')===String(p.stats?.[key]??'—'),'Individual exact statistics lost: '+key);
    }
  }
  if(eligible.length>5){
    await page.locator('#pp-search').fill(eligible[5].prefix_24);
    assert(await page.locator('#pp-options input[type=checkbox]').isDisabled(),'Sixth prefix must be disabled');
  }
  for(const id of ['pp-overall','pp-union']){
    await page.locator('#'+id).uncheck();
    assert(await page.locator('#pp-svg [data-reference='+id.slice(3)+']').count()===0,'Reference toggle failed');
    await page.locator('#'+id).check();
  }
  const svg=page.locator('#pp-svg'),min=await svg.getAttribute('data-x-min'),max=await svg.getAttribute('data-x-max');
  await page.locator('#pp-zoom-in').click();
  assert(Number(await svg.getAttribute('data-x-max'))-Number(await svg.getAttribute('data-x-min'))<Number(max)-Number(min),'Prefix zoom failed');
  await page.locator('#pp-reset').click();
  assert(await svg.getAttribute('data-x-max')===max,'Prefix reset failed');
  const withPoints=selected.filter(p=>JSON.parse(curves[p.prefix_24]?.encoded_points||'[]').length);
  for(const visible of withPoints){
    await svg.scrollIntoViewIfNeeded();
    const point=JSON.parse(curves[visible.prefix_24].encoded_points)[0],box=await svg.boundingBox();
    const px=78+(Math.log10(Number(point.packet_count))-Number(min))/(Number(max)-Number(min))*892;
    await page.mouse.move(box.x+Math.max(78.1,Math.min(969.9,px))/1000*box.width,box.y+box.height*.5);
    const hover=await page.locator('#tooltip').innerText();
    assert(hover.includes(visible.prefix_24+': packet_count '+point.packet_count+' · F(x) '+point.cumulative_fraction),'Each prefix must show its OWN saved point, not a mixed or averaged distribution');
  }
  await svg.scrollIntoViewIfNeeded();
  const box=await svg.boundingBox();
  await page.mouse.move(box.x+box.width*.3,box.y+box.height*.5);
  await page.mouse.down();await page.mouse.move(box.x+box.width*.6,box.y+box.height*.5,{steps:4});await page.mouse.up();
  assert(Number(await svg.getAttribute('data-x-max'))<Number(max),'Per-prefix drag zoom failed');
  await page.locator('#pp-reset').click();await svg.scrollIntoViewIfNeeded();
  const wheelBox=await svg.boundingBox();await page.mouse.move(wheelBox.x+wheelBox.width*.5,wheelBox.y+wheelBox.height*.5);
  await page.mouse.wheel(0,-100);
  await page.waitForFunction(max=>Number(document.querySelector('#pp-svg').dataset.xMax)<max,Number(max));
  await page.locator('#pp-reset').click();
  const downloadPromise=page.waitForEvent('download');
  await page.locator('#pp-download').click();
  assert((await downloadPromise).suggestedFilename()==='rls-per-prefix-ecdf.svg','Prefix SVG save failed');
  if(selected.length){
    await page.locator('#pp-search').fill(selected[0].prefix_24);
    await page.locator('#pp-options input[type=checkbox]').uncheck();
    assert(await page.locator('#pp-stats tr[data-prefix]').count()===selected.length-1,'Prefix deselection failed');
  }
  await page.locator('#pp-mode').selectOption(mode==='packet'?'flow':'packet');
  assert(await page.locator('#pp-stats tr[data-prefix]').count()===0,'Mode switch must clear previous selections');
  await page.locator('#pp-clear').click();
  await page.locator('#pp-search').fill('');
  return {search:true,separateCurves:true,exactStats:true,maxFive:eligible.length>5,toggles:true,zoom:true,svg:true,deselection:true,modeSwitch:true};
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
