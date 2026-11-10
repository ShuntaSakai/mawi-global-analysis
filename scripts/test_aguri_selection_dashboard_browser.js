/* Optional Playwright smoke test. HTML itself has no Playwright dependency. */
async function testComparison(page,v2){
 const assert=(ok,message)=>{if(!ok)throw new Error(message);},errors=[];
 const onerror=e=>errors.push(e.message),onconsole=m=>{if(m.type()==='error')errors.push(m.text());};
 page.on('pageerror',onerror);page.on('console',onconsole);
 const remoteRequests=[];
 const onRequest=request=>{if(/^https?:/.test(request.url()))remoteRequests.push(request.url());};
 page.on('request',onRequest);
 try{
  if(page.url().startsWith('file:')){
   await page.context().setOffline(true);
   await page.reload({waitUntil:'load'});
  }else{
   await page.context().setOffline(true);
  }
  const data=JSON.parse(await page.locator('#dashboard-data').textContent());
  const keys=v2?['A','B','C-packet','C-flow']:['A','B','C'];
  const series=['overall_ipv4',...keys];
  assert(data.schema_version===(v2?'aguri-selection-analysis-v2':'aguri-selection-analysis-v1'),'Wrong dashboard version');
  assert(await page.getByRole('tab').count()===(v2?4:5),'Incorrect tab count');
  if(v2){
   assert(await page.locator('#tab-contribution,#contribution,#sensitivity-chart,#rank').count()===0,'v2 must omit Contribution UI');
   assert(await page.locator('#jaccard tbody tr').count()===18,'Expected six pairs with three Jaccard kinds each');
  }
  assert(await page.locator('script[src],link[rel=stylesheet],iframe,img').count()===0,'External resources forbidden');
  await page.getByRole('tab',{name:'Overview',exact:true}).click();
  for(const [i,key] of keys.entries()){
   const row=page.locator('#summary tbody tr').filter({has:page.locator('td:first-child',{hasText:'Flow count'})});
   assert(await row.locator('td').nth(i+1).getAttribute('title')===String(data.conditions[key].stats.flow_count),'Exact overview count lost');
  }
  await page.getByRole('tab',{name:'Flow Size Distribution',exact:true}).click();
  const mount=page.locator('#main-chart'),svg=mount.locator('svg');
  assert(await mount.locator('[data-series]').count()===series.length,'Missing series toggles');
  for(const key of series){
   const b=mount.locator('[data-series='+key+']');
   await b.click();assert(await mount.locator('[data-curve='+key+']').count()===0,'Curve did not hide');
   for(const other of series.filter(k=>k!==key)){
    assert(await mount.locator('[data-curve='+other+']').count()===Number(!!data.all_curves[other].points.length),'Another series was toggled');
   }
   await b.click();
   assert(await mount.locator('[data-curve='+key+']').count()===Number(!!data.all_curves[key].points.length),'Curve not restored');
  }
  const first=data.all_curves.overall_ipv4.points[0];await svg.scrollIntoViewIfNeeded();let box=await svg.boundingBox();
  const min=Number(await svg.getAttribute('data-x-min')),max=Number(await svg.getAttribute('data-x-max'));
  for(const key of series){
   const point=data.all_curves[key].points[0];
   if(!point)continue;
   const x=Math.max(78.2,Math.min(969.8,78+(Math.log10(Number(point.packet_count))-min)/(max-min)*892));
   await page.mouse.move(box.x+x/1000*box.width,box.y+box.height*.5);
   const label=key==='overall_ipv4'?'Overall':key;
   const text=await page.locator('#tooltip').innerText();
   assert(text.includes(label+': packet_count '+point.packet_count+' · F(x) '+point.cumulative_fraction),'Hover mismatch for '+key);
   assert(text.includes('累積 '+point.cumulative_count+' / '+data.all_curves[key].total_flow_count+' · 度数 '+point.frequency),'Exact counts missing for '+key);
  }
  await mount.getByRole('button',{name:'拡大 ＋',exact:true}).click();assert(Number(await svg.getAttribute('data-x-max'))<max,'Zoom failed');await mount.getByRole('button',{name:'表示範囲をリセット'}).click();
  await svg.scrollIntoViewIfNeeded();box=await svg.boundingBox();await page.mouse.move(box.x+box.width*.3,box.y+box.height*.5);await page.mouse.down();await page.mouse.move(box.x+box.width*.6,box.y+box.height*.5,{steps:4});await page.mouse.up();assert(Number(await svg.getAttribute('data-x-max'))<max,'Drag failed');await mount.getByRole('button',{name:'表示範囲をリセット'}).click();
  await svg.scrollIntoViewIfNeeded();box=await svg.boundingBox();await page.mouse.move(box.x+box.width*.5,box.y+box.height*.5);await page.mouse.wheel(0,-100);await page.waitForFunction(m=>Number(document.querySelector('#main-chart svg').dataset.xMax)<m,max);await mount.getByRole('button',{name:'表示範囲をリセット'}).click();
  const saved=page.waitForEvent('download');
  await mount.locator('[data-download]').click();
  const download=await saved;
  assert(download.suggestedFilename()===(v2?'aguri-ab-c-packet-flow-ecdf.svg':'aguri-abc-ecdf.svg'),'SVG failed');
  const xml=await require('node:fs/promises').readFile(await download.path(),'utf8');
  assert(await page.evaluate(svg=>{
   const doc=new DOMParser().parseFromString(svg,'image/svg+xml');
   return !doc.querySelector('parsererror')&&doc.documentElement.localName==='svg';
  },xml),'Downloaded SVG is not valid XML');
  await page.getByRole('tab',{name:'Selection Changes',exact:true}).click();
  await page.locator('#selection-search').fill('__missing__');assert((await page.locator('#selection-table').innerText()).includes('該当するprefixがありません'),'Empty search failed');await page.locator('#selection-search').fill('');
  for(const key of [...keys,'new-B','lost-A','common-AB'])await page.locator('#selection-filter').selectOption(key);
  if(data.prefixes.length){const target=data.prefixes[0].prefix;await page.locator('#selection-filter').selectOption('all');await page.locator('#selection-search').fill(target);assert((await page.locator('#selection-table').innerText()).includes(target),'CIDR search failed');}
  if(v2){
   await page.locator('#selection-search').fill('');
   for(const key of ['C-packet','C-flow']){
    await page.locator('#selection-filter').selectOption(key);
    const expected=data.prefix_contribution.filter(row=>row.condition===key).map(row=>row.prefix).sort();
    const shown=[];
    do{
     shown.push(...await page.locator('#selection-table tbody tr').evaluateAll(rows=>rows.map(row=>[row.cells[0].textContent,row.cells[1].textContent])));
     if(await page.locator('#selection-next').isDisabled())break;
     await page.locator('#selection-next').click();
    }while(true);
    assert(shown.every(([condition])=>condition===key),'Filter leaked another condition');
    assert(JSON.stringify(shown.map(([,prefix])=>prefix).sort())===JSON.stringify(expected),'Filtered CIDRs differ for '+key);
   }
  }else{
   await page.getByRole('tab',{name:'Prefix Contribution',exact:true}).click();
   for(const key of ['B','C']){
    await page.locator('#sensitivity-condition').selectOption(key);const s=data.sensitivities[key];
    const row=page.locator('#sensitivity-stats tbody tr').filter({has:page.locator('td:first-child',{hasText:'Flow count'})});
    assert(await row.locator('td').nth(1).getAttribute('title')===String(s.before.flow_count),'Sensitivity before differs');
    assert(await row.locator('td').nth(2).getAttribute('title')===String(s.after.flow_count),'Sensitivity after differs');
    assert(await page.locator('#sensitivity-chart [data-curve='+key+'_without_target]').count()===Number(s.after.flow_count>0),'Empty exclusion curve handling failed');
   }
   const pending=page.waitForEvent('download');await page.locator('#sensitivity-chart [data-download]').click();assert((await pending).suggestedFilename()==='aguri-target-exclusion.svg','Sensitivity SVG failed');
   await page.locator('#rank-search').fill('__missing__');assert((await page.locator('#rank').innerText()).includes('該当するprefixがありません'),'Contribution empty filter failed');
  }
  await page.getByRole('tab',{name:'Experiment Details',exact:true}).click();assert((await page.locator('#provenance').innerText()).includes('BPF'),'Details missing');
  if(v2){
   const details=await page.locator('#provenance').textContent();
   for(const key of keys)assert(details.includes(data.provenance.validation.runs[key].run_name),'Missing run in Details');
   assert(details.includes(data.dataset_id)&&details.includes('comparison_manifest.json'),'Missing dataset or manifest in Details');
   const oldViewport=page.viewportSize();
   await page.setViewportSize({width:390,height:844});
   try{
    await page.getByRole('tab',{name:'Flow Size Distribution',exact:true}).click();
    assert(await svg.isVisible(),'Chart hidden at narrow viewport');
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'Page overflows at narrow viewport');
   }finally{if(oldViewport)await page.setViewportSize(oldViewport);}
  }
  assert(!errors.length,'Browser errors: '+errors.join(';'));
  assert(!remoteRequests.length,'External requests: '+remoteRequests.join(', '));
  return {version:v2?2:1,offline:true,exactOverview:true,curveToggles:true,hover:!!first,zoomDragWheel:true,svg:true,searchFilters:true,exclusionStats:!v2,narrowViewport:v2,errors};
 }finally{await page.context().setOffline(false);page.off('request',onRequest);page.off('pageerror',onerror);page.off('console',onconsole);}
}

const testABC=page=>testComparison(page,false);
const testV2=page=>testComparison(page,true);
if(typeof module!=='undefined')module.exports={testABC,testV2};
if(typeof require==='function'&&require.main===module){
 (async()=>{
  const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
  const {pathToFileURL}=require('node:url');
  const {resolve}=require('node:path');
  const [, , path, version]=process.argv;
  if(!path)throw new Error('Pass dashboard.html path or URL [--v2]');
  const browser=await chromium.launch({headless:true,channel:process.env.PLAYWRIGHT_CHANNEL||undefined});
  try{
   const page=await browser.newPage({viewport:{width:1440,height:1000},acceptDownloads:true});
   await page.goto(/^(https?|file):/.test(path)?path:pathToFileURL(resolve(path)).href);
   console.log(JSON.stringify(await (version==='--v2'?testV2:testABC)(page),null,2));
  }finally{await browser.close();}
 })().catch(error=>{console.error(error);process.exitCode=1;});
}
