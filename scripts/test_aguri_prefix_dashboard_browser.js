/* Optional offline Playwright check for an Aguri individual-prefix HTML. */
const assert = require('node:assert/strict');
const {readFile} = require('node:fs/promises');
const {resolve} = require('node:path');
const {pathToFileURL} = require('node:url');

async function testOverlapFilters(page, data, keys) {
 await page.reload();
 const group = page.locator('#prefix-overlap-filters');
 const buttons = group.getByRole('button');
 const filter = key => group.locator('[data-prefix-filter="'+key+'"]');
 const tab = key => page.getByRole('tab',{name:key,exact:true});
 const cards = page.locator('.prefix-card');
 const search = page.locator('#prefix-search');
 const next = page.locator('#prefix-next');
 const status = page.locator('#prefix-status');
 const selected = Object.fromEntries(keys.map(key=>[key,new Set(data.conditions[key].prefixes)]));
 const saved = new Map();
 const pairs = new Set();
 let zeroPair = false;
 let searchIntersection = false;
 let pageReset = false;

 for (const key of keys) {
  await tab(key).click();
  assert.equal(await buttons.count(),5);
  assert.equal(await filter('all').getAttribute('aria-pressed'),'true');
  assert.equal(await filter(key).count(),0);
  const peers = keys.filter(other=>other!==key);
  const sort = page.locator('#prefix-sort');
  await sort.selectOption('prefix');
  for (const choice of ['all','only',...peers]) {
   const expected = [...selected[key]].filter(cidr=>choice==='all' ||
    (choice==='only' ? peers.every(peer=>!selected[peer].has(cidr)) : selected[choice].has(cidr)));
   const name = choice==='all' ? 'すべて' : choice==='only' ? 'この条件のみ' : choice+'と共通（'+expected.length.toLocaleString('en-US')+'件）';
   assert.equal(await filter(choice).textContent(),name);
   if (peers.includes(choice)) pairs.add([key,choice].sort().join('/'));
   await filter(choice).click();
   assert.equal(await group.locator('[aria-pressed=true]').count(),1);
   assert.equal(await filter(choice).getAttribute('aria-pressed'),'true');
   assert.match(await status.textContent(),/ページ 1 \/ /);
   assert.equal(await sort.inputValue(),'prefix');
   const seen=[];
   while (true) {
    const pageCards=await cards.evaluateAll(nodes=>nodes.map(node=>[
     node.dataset.prefix,[...node.querySelectorAll('.prefix-common-label')].map(label=>label.textContent),
    ]));
    for(const [cidr,labels] of pageCards){
     seen.push(cidr);
     assert.deepEqual(labels,peers.filter(peer=>selected[peer].has(cidr)));
    }
    if(await next.isDisabled())break;
    await next.click();
   }
   assert.deepEqual(seen.sort(),expected.sort());
   if (peers.includes(choice) && expected.length===0) {
    zeroPair=true;
    assert.match(await page.locator('#prefix-cards').innerText(),new RegExp(choice+'と共通'));
   }
  }

  const multiPagePeer = peers.find(other=>[...selected[key]].filter(cidr=>selected[other].has(cidr)).length>12);
  if (multiPagePeer) {
   await filter('all').click();
   await next.click();
   assert.match(await status.textContent(),/ページ 2 \/ /);
   await filter(multiPagePeer).click();
   assert.match(await status.textContent(),/ページ 1 \/ /);
   pageReset=true;
  }
  const peer = peers.find(other=>[...selected[key]].some(cidr=>selected[other].has(cidr)));
  const choice = peer ?? 'only';
  await filter(choice).click();
  let query = '';
  if (peer) {
   const match=[...selected[key]].find(cidr=>selected[peer].has(cidr));
   const mismatch=[...selected[key]].find(cidr=>!selected[peer].has(cidr));
   if (mismatch) {
    await search.fill(mismatch);
    assert.equal(await cards.count(),0);
    assert.match(await page.locator('#prefix-cards').innerText(),/該当する選定Prefix/);
    searchIntersection=true;
   }
   query=match;
   await search.fill(query);
   assert.deepEqual(await cards.evaluateAll(nodes=>nodes.map(node=>node.dataset.prefix)),[match]);
   assert.equal(await filter(choice).textContent(),choice+'と共通（'+[...selected[key]].filter(cidr=>selected[peer].has(cidr)).length.toLocaleString('en-US')+'件）');
  }
  saved.set(key,{choice,query});
 }
 for(const [key,{choice,query}] of saved){
  await tab(key).click();
  assert.equal(await filter(choice).getAttribute('aria-pressed'),'true');
  assert.equal(await search.inputValue(),query);
  assert.equal(await page.locator('#prefix-sort').inputValue(),'prefix');
 }
 assert.equal(pairs.size,6);
 return {pairs:pairs.size,zeroPair,searchIntersection,pageReset};
}

async function testPrefixDashboard(page) {
 const errors = [];
 const requests = [];
 page.on('pageerror', error => errors.push(error.message));
 page.on('console', message => { if (message.type()==='error') errors.push(message.text()); });
 page.on('request', request => { if (/^https?:/.test(request.url())) requests.push(request.url()); });
 await page.context().setOffline(true);
 await page.reload();
 const data = JSON.parse(await page.locator('#dashboard-data').textContent());
 const cards = page.locator('.prefix-card');
 const detail = page.locator('#prefix-detail');
 const displayed = () => cards.evaluateAll(nodes => nodes.map(node => node.dataset.prefix));
 const next = page.locator('#prefix-next');
 const status = page.locator('#prefix-status');
 const keys = ['A','B','C-packet','C-flow'];
 const tab = key => page.getByRole('tab',{name:key,exact:true});

 assert.deepEqual(await page.getByRole('tab').allTextContents(),keys);
 assert.equal(await tab('A').getAttribute('aria-selected'),'true');
 assert(await detail.isHidden());
 assert.equal(await page.locator('#prefix-chart svg').count(),0);
 let paging = false;
 let emptyTab = false;
 let zeroFlow = false;
 for (const key of keys) {
  await tab(key).click();
  const expected = data.conditions[key].prefixes;
  const seen = [];
  while (true) {
   const batch = await displayed();
   assert(batch.length<=12);
   seen.push(...batch);
   if (await next.isDisabled()) break;
   paging = true;
   await next.click();
  }
  assert.deepEqual(seen.sort(),[...expected].sort());
  if (!expected.length) {
   emptyTab = true;
   assert.match(await page.locator('#prefix-cards').innerText(),/該当する選定Prefix/);
  }
 }

 const many = keys.find(key=>data.conditions[key].prefixes.length>12);
 if (many) {
  await tab(many).click();
  const sorted = [...data.conditions[many].prefixes].sort((a,b)=>a.localeCompare(b,'en',{numeric:true}));
  await page.locator('#prefix-sort').selectOption('prefix');
  assert.deepEqual(await displayed(),[...sorted].reverse().slice(0,12));
  await page.locator('#prefix-direction').click();
  assert.deepEqual(await displayed(),sorted.slice(0,12));
  await next.click();
  const pageTwo = await displayed();
  assert.deepEqual(pageTwo,sorted.slice(12,24));
  await tab(many).press('ArrowRight');
  assert.equal(await tab(many).getAttribute('aria-selected'),'false');
  await tab(many).click();
  assert.deepEqual(await displayed(),pageTwo);
  await page.locator('#prefix-direction').click();
 }

 const condition = keys.find(key => data.conditions[key].prefixes.some(cidr => data.curves[cidr].displayed_point_count>0));
 if (condition) {
  await tab(condition).click();
  const cidr = data.conditions[condition].prefixes.find(cidr => data.curves[cidr].displayed_point_count>0);
  const search = page.locator('#prefix-search');
  const sort = page.locator('#prefix-sort');
  await search.fill(cidr);
  await sort.selectOption('p95');
  await page.locator('#prefix-direction').click();
  assert.deepEqual(await displayed(),[cidr]);
  const card = cards.first();
  await card.focus();
  const scroll = await page.evaluate(()=>window.scrollY);
  await card.press('Enter');
  assert(await detail.isVisible());
  assert.equal(await page.locator('#prefix-detail-title').textContent(),condition+' · '+cidr);
  assert.equal(await page.locator(':focus').getAttribute('id'),'prefix-close');
  for (const field of ['flow_count','packet_total','byte_total','median','p95','one_packet_rate']) {
   assert.equal(await detail.locator('[data-stat='+field+']').getAttribute('title'),String(data.prefixes[cidr].stats[field]??'—'));
  }
  const chart = page.locator('#prefix-chart');
  const svg = chart.locator('svg');
  const span = async () => Number(await svg.getAttribute('data-x-max'))-Number(await svg.getAttribute('data-x-min'));
  const original = await span();
  const zoom = name => chart.getByRole('button',{name,exact:true}).click();
  const reset = () => zoom('表示範囲をリセット');
  await zoom('拡大 ＋');
  assert(await span()<original);
  await zoom('縮小 −');
  assert(Math.abs(await span()-original)<1e-12);
  await svg.scrollIntoViewIfNeeded();
  const point = JSON.parse(data.curves[cidr].encoded_points)[0];
  const box = await svg.boundingBox();
  const position = Math.max(78.3,Math.min(969.7,78+Math.log10(Number(point.packet_count))/original*892));
  await page.mouse.move(box.x+box.width*position/1000,box.y+box.height/2);
  const tip = await page.locator('#tooltip').innerText();
  assert(tip.includes('packet_count '+point.packet_count));
  assert(tip.includes('累積 '+point.cumulative_count+' / '+data.curves[cidr].total_flow_count));
  await page.mouse.move(box.x+box.width*.25,box.y+box.height/2);
  await page.mouse.down();
  await page.mouse.move(box.x+box.width*.65,box.y+box.height/2,{steps:4});
  await page.mouse.up();
  assert(await span()<original);
  await reset();
  assert.equal(await span(),original);
  await svg.scrollIntoViewIfNeeded();
  const wheelBox = await svg.boundingBox();
  await page.mouse.move(wheelBox.x+wheelBox.width/2,wheelBox.y+wheelBox.height/2);
  await page.mouse.wheel(0,-100);
  await page.waitForFunction(max=>Number(document.querySelector('#prefix-chart svg').dataset.xMax)<max,original);
  await reset();
  const pending = page.waitForEvent('download');
  await chart.getByRole('button',{name:'SVGを保存',exact:true}).click();
  const download = await pending;
  assert.match(download.suggestedFilename(),/\.svg$/);
  const xml = await readFile(await download.path(),'utf8');
  assert(await page.evaluate(source=>{
   const doc=new DOMParser().parseFromString(source,'image/svg+xml');
   return !doc.querySelector('parsererror') && doc.querySelector('[data-curve=prefix]')!==null;
  },xml));
  await page.keyboard.press('Escape');
  assert(await detail.isHidden());
  assert.equal(await page.locator(':focus').getAttribute('data-prefix'),cidr);
  assert.equal(await page.evaluate(()=>window.scrollY),scroll);
  await card.click();
  await page.getByRole('button',{name:'詳細を閉じる'}).click();
  assert(await detail.isHidden());
  await tab(keys.find(key=>key!==condition)).click();
  await tab(condition).click();
  assert.equal(await search.inputValue(),cidr);
  assert.equal(await sort.inputValue(),'p95');
  assert.equal(await page.locator('#prefix-direction').textContent(),'昇順');
  assert.match(await status.textContent(),/^1件/);
  await search.fill('missing-cidr');
  assert.deepEqual(await displayed(),[]);
  await search.fill('');
 }

 const zeroKey = keys.find(key=>data.conditions[key].prefixes.some(cidr=>data.prefixes[cidr].stats.flow_count===0));
 if (zeroKey) {
  zeroFlow = true;
  await tab(zeroKey).click();
  const cidr = data.conditions[zeroKey].prefixes.find(cidr=>data.prefixes[cidr].stats.flow_count===0);
  await page.locator('#prefix-search').fill(cidr);
  await cards.first().click();
  assert.match(await detail.innerText(),/空分布/);
  assert.equal(await detail.locator('[data-curve]').count(),0);
  await page.getByRole('button',{name:'詳細を閉じる'}).click();
 }

 await page.setViewportSize({width:390,height:844});
 const populated = keys.find(key=>data.conditions[key].prefixes.length);
 if (populated) {
  await tab(populated).click();
  await page.locator('#prefix-search').fill('');
  await cards.first().click();
  assert(await detail.isVisible());
 }
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 const overlap=await testOverlapFilters(page,data,keys);
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 assert.deepEqual(errors,[]);
 assert.deepEqual(requests,[]);
 return {tabs:4,detail:!!condition,paging,emptyTab,zeroFlow,offline:true,narrowViewport:true,overlap};
}

module.exports = {testPrefixDashboard};
if (require.main === module) {
 (async()=>{
  const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
  const path=process.argv[2];
  if(!path)throw new Error('Pass prefix_dashboard.html path');
  const browser=await chromium.launch({headless:true,channel:process.env.PLAYWRIGHT_CHANNEL||undefined});
  try{
   const page=await browser.newPage({viewport:{width:1440,height:1000},offline:true,acceptDownloads:true});
   await page.goto(pathToFileURL(resolve(path)).href);
   console.log(JSON.stringify(await testPrefixDashboard(page),null,2));
  }finally{await browser.close();}
 })().catch(error=>{console.error(error);process.exitCode=1;});
}
