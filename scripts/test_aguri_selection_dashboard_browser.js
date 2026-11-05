/* Optional Playwright smoke test. HTML itself has no Playwright dependency. */
async function testABC(page){
 const assert=(ok,message)=>{if(!ok)throw new Error(message);},errors=[];
 const onerror=e=>errors.push(e.message),onconsole=m=>{if(m.type()==='error')errors.push(m.text());};
 page.on('pageerror',onerror);page.on('console',onconsole);
 await page.reload({waitUntil:'load'});const data=JSON.parse(await page.locator('#dashboard-data').textContent());
 await page.context().setOffline(true);
 try{
  assert(await page.getByRole('tab').count()===5,'Five tabs required');
  assert(await page.locator('script[src],link[rel=stylesheet],iframe,img').count()===0,'External resources forbidden');
  await page.getByRole('tab',{name:'Overview',exact:true}).click();
  for(const [i,key] of ['A','B','C'].entries()){
   const row=page.locator('#summary tbody tr').filter({has:page.locator('td:first-child',{hasText:'Flow count'})});
   assert(await row.locator('td').nth(i+1).getAttribute('title')===String(data.conditions[key].stats.flow_count),'Exact overview count lost');
  }
  await page.getByRole('tab',{name:'Flow Size Distribution',exact:true}).click();
  const mount=page.locator('#main-chart'),svg=mount.locator('svg');
  for(const key of ['overall_ipv4','A','B','C']){
   const b=mount.locator('[data-series='+key+']');await b.click();assert(await mount.locator('[data-curve='+key+']').count()===0,'Curve did not hide');await b.click();
   assert(await mount.locator('[data-curve='+key+']').count()===Number(!!data.all_curves[key].points.length),'Curve not restored');
  }
  const first=data.all_curves.overall_ipv4.points[0];await svg.scrollIntoViewIfNeeded();let box=await svg.boundingBox();
  const min=Number(await svg.getAttribute('data-x-min')),max=Number(await svg.getAttribute('data-x-max'));
  if(first){const x=Math.max(78.1,Math.min(969.9,78+(Math.log10(Number(first.packet_count))-min)/(max-min)*892));await page.mouse.move(box.x+x/1000*box.width,box.y+box.height*.5);const text=await page.locator('#tooltip').innerText();assert(text.includes('Overall: packet_count '+first.packet_count+' · F(x) '+first.cumulative_fraction),'Hover not a genuine saved point');}
  await mount.getByRole('button',{name:'拡大 ＋',exact:true}).click();assert(Number(await svg.getAttribute('data-x-max'))<max,'Zoom failed');await mount.getByRole('button',{name:'表示範囲をリセット'}).click();
  await svg.scrollIntoViewIfNeeded();box=await svg.boundingBox();await page.mouse.move(box.x+box.width*.3,box.y+box.height*.5);await page.mouse.down();await page.mouse.move(box.x+box.width*.6,box.y+box.height*.5,{steps:4});await page.mouse.up();assert(Number(await svg.getAttribute('data-x-max'))<max,'Drag failed');await mount.getByRole('button',{name:'表示範囲をリセット'}).click();
  await svg.scrollIntoViewIfNeeded();box=await svg.boundingBox();await page.mouse.move(box.x+box.width*.5,box.y+box.height*.5);await page.mouse.wheel(0,-100);await page.waitForFunction(m=>Number(document.querySelector('#main-chart svg').dataset.xMax)<m,max);await mount.getByRole('button',{name:'表示範囲をリセット'}).click();
  let pending=page.waitForEvent('download');await mount.locator('[data-download]').click();assert((await pending).suggestedFilename()==='aguri-abc-ecdf.svg','SVG failed');
  await page.getByRole('tab',{name:'Selection Changes',exact:true}).click();
  await page.locator('#selection-search').fill('__missing__');assert((await page.locator('#selection-table').innerText()).includes('該当するprefixがありません'),'Empty search failed');await page.locator('#selection-search').fill('');
  for(const key of ['A','B','C','new-B','lost-A','common-AB'])await page.locator('#selection-filter').selectOption(key);
  if(data.prefixes.length){const target=data.prefixes[0].prefix;await page.locator('#selection-filter').selectOption('all');await page.locator('#selection-search').fill(target);assert((await page.locator('#selection-table').innerText()).includes(target),'CIDR search failed');}
  await page.getByRole('tab',{name:'Prefix Contribution',exact:true}).click();
  for(const key of ['B','C']){
   await page.locator('#sensitivity-condition').selectOption(key);const s=data.sensitivities[key];
   const row=page.locator('#sensitivity-stats tbody tr').filter({has:page.locator('td:first-child',{hasText:'Flow count'})});
   assert(await row.locator('td').nth(1).getAttribute('title')===String(s.before.flow_count),'Sensitivity before differs');
   assert(await row.locator('td').nth(2).getAttribute('title')===String(s.after.flow_count),'Sensitivity after differs');
   assert(await page.locator('#sensitivity-chart [data-curve='+key+'_without_target]').count()===Number(s.after.flow_count>0),'Empty exclusion curve handling failed');
  }
  pending=page.waitForEvent('download');await page.locator('#sensitivity-chart [data-download]').click();assert((await pending).suggestedFilename()==='aguri-target-exclusion.svg','Sensitivity SVG failed');
  await page.locator('#rank-search').fill('__missing__');assert((await page.locator('#rank').innerText()).includes('該当するprefixがありません'),'Contribution empty filter failed');
  await page.getByRole('tab',{name:'Experiment Details',exact:true}).click();assert((await page.locator('#provenance').innerText()).includes('BPF'),'Details missing');
  assert(!errors.length,'Browser errors: '+errors.join(';'));
  return {offline:true,exactOverview:true,curveToggles:true,hover:!!first,zoomDragWheel:true,svg:true,searchFilters:true,exclusionStats:true,emptyHandling:true,errors};
 }finally{await page.context().setOffline(false);page.off('pageerror',onerror);page.off('console',onconsole);}
}
if(typeof module!=='undefined')module.exports={testABC};
if(typeof require==='function'&&require.main===module){(async()=>{const{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');const{pathToFileURL}=require('node:url');const{resolve}=require('node:path');const b=await chromium.launch({headless:true});try{const page=await b.newPage({viewport:{width:1440,height:1000},acceptDownloads:true});const p=process.argv[2];if(!p)throw new Error('Pass dashboard.html path or URL');await page.goto(/^(https?|file):/.test(p)?p:pathToFileURL(resolve(p)).href);console.log(JSON.stringify(await testABC(page),null,2));}finally{await b.close();}})().catch(e=>{console.error(e);process.exitCode=1;});}
