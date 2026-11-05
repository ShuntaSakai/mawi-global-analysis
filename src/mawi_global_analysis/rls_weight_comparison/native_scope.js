// Independent scope comparison; the selected native sets are never recomputed.
const scopeCurves=object(data.scope_ecdf),scopeRows=object(data.scope_comparison);
let scopeRange=[0,1],scopeFull=[0,1],scopeTraces=[],scopeDrag=null;
const scopeVisible=new Set(['overall','native','normalized24']);
function prepareScope(){
  const mode=$('scope-mode').value;
  scopeTraces=[['overall','Overall','overall_ipv4',COLOR.overall_ipv4,'6 3'],
    ['native',mode+' native',mode,COLOR[mode],''],
    ['normalized24',mode+' normalized /24','normalized_'+mode,'#8c4b9e','3 3']].map(([key,label,name,color,dash])=>{
      const curve=object(scopeCurves[name]);return {key,label,color,dash,curve,points:ppPoints(curve)};
    });
  let max=1;for(const t of scopeTraces)if(t.points.length)max=Math.max(max,t.points.at(-1).lx);
  scopeFull=[0,max];scopeRange=[...scopeFull];$('scope-legend').replaceChildren();$('scope-reduction').replaceChildren();
  for(const t of scopeTraces){
    const button=node('button',t.label,'legend-button');button.style.color=t.color;button.dataset.scopeSeries=t.key;
    button.setAttribute('aria-pressed',String(scopeVisible.has(t.key)));
    button.addEventListener('click',()=>{if(scopeVisible.has(t.key))scopeVisible.delete(t.key);else scopeVisible.add(t.key);button.setAttribute('aria-pressed',String(scopeVisible.has(t.key)));renderScope();});
    $('scope-legend').append(button);
    $('scope-reduction').append(node('p',t.label+': '+(!t.points.length?'空分布':`表示 ${int(t.curve.displayed_point_count)} / 正確な異なる値 ${int(t.curve.exact_point_count)} · `+(t.curve.simplified?'縮約（下界/上界）・最大帯幅 '+display(t.curve.error_bound):'全ECDF点')),'caption'));
  }
  const record=object(scopeRows[mode]),table=node('table'),head=node('tr');head.append(node('th','指標'),node('th',mode+' native'),node('th',mode+' normalized /24'));table.append(head);
  for(const [key,label,format] of [...STAT_ROWS,['flow_coverage','Flow coverage',percent]]){
    const row=node('tr');row.dataset.stat=key;row.append(node('td',label));
    for(const prefix of ['native_','normalized24_']){const value=record[prefix+key],cell=node('td',format(value));cell.title=display(value);row.append(cell);}table.append(row);
  }
  $('scope-stats').replaceChildren(table);$('scope-ks').textContent='KS native vs normalized24: '+number(record.ks_distance)+' · exact '+display(record.ks_numerator)+' / '+display(record.ks_denominator);
  hideTooltip();renderScope();
}
function renderScope(){
  const svg=$('scope-svg'),{x,y}=axes(svg,scopeRange,[0,1],'packet_count per flow · log scale','Cumulative fraction');
  svg.dataset.xMin=scopeRange[0];svg.dataset.xMax=scopeRange[1];
  const defs=svgNode('defs'),clip=svgNode('clipPath',{id:'scope-clip'});clip.append(svgNode('rect',{x:LEFT,y:TOP,width:PW,height:PH}));defs.append(clip);svg.append(defs);
  const group=svgNode('g',{'clip-path':'url(#scope-clip)'});let count=0;
  for(const t of scopeTraces){
    if(!scopeVisible.has(t.key)||!t.points.length)continue;count++;
    const lower=[[scopeRange[0],0]],upper=[[scopeRange[0],0]];
    t.points.forEach((p,i)=>{const prev=i?t.points[i-1].fy:0;lower.push([p.lx,prev],[p.lx,p.fy]);upper.push([p.lx,prev],[p.lx,p.fy]);if(t.curve.simplified&&i+1<t.points.length)upper.push([p.lx,t.points[i+1].fy],[t.points[i+1].lx,t.points[i+1].fy]);});
    lower.push([Math.max(scopeRange[1],t.points.at(-1).lx),t.points.at(-1).fy]);upper.push([Math.max(scopeRange[1],t.points.at(-1).lx),t.points.at(-1).fy]);
    const path=points=>points.map((p,i)=>(i?'L':'M')+x(p[0])+','+y(p[1])).join('');
    if(t.curve.simplified)group.append(svgNode('path',{'data-scope-envelope':t.key,d:path(lower)+path([...upper].reverse()).replace(/^M/,'L')+'Z',fill:t.color,'fill-opacity':.12}));
    group.append(svgNode('path',{'data-scope-curve':t.key,d:path(lower),fill:'none',stroke:t.color,'stroke-width':2.4,'stroke-dasharray':t.dash}));
  }
  svg.append(group);$('scope-status').textContent=`${count}曲線 · 同じ選定native prefix集合を固定 · log10(x): ${number(scopeRange[0])} — ${number(scopeRange[1])}`;
}
function scopeZoom(factor,anchor=.5){
  const span=Math.min(scopeFull[1]-scopeFull[0],Math.max(.01,(scopeRange[1]-scopeRange[0])*factor));
  const center=scopeRange[0]+(scopeRange[1]-scopeRange[0])*anchor,start=Math.min(scopeFull[1]-span,Math.max(scopeFull[0],center-span*anchor));scopeRange=[start,start+span];hideTooltip();renderScope();
}
safePanel('scope-stats',prepareScope);
$('scope-mode').addEventListener('change',prepareScope);$('scope-zoom-in').addEventListener('click',()=>scopeZoom(.5));$('scope-zoom-out').addEventListener('click',()=>scopeZoom(2));
$('scope-reset').addEventListener('click',()=>{scopeRange=[...scopeFull];hideTooltip();renderScope();});
$('scope-svg').addEventListener('pointermove',event=>{
  const px=svgX(event,$('scope-svg'));if(px<LEFT||px>W-RIGHT){hideTooltip();return;}
  const lx=scopeRange[0]+(px-LEFT)/PW*(scopeRange[1]-scopeRange[0]),lines=['実際のECDF選択点（最も近い点）'];
  for(const t of scopeTraces){if(!scopeVisible.has(t.key)||!t.points.length)continue;let lo=0,hi=t.points.length;while(lo<hi){const mid=(lo+hi)>>1;if(t.points[mid].lx<lx)lo=mid+1;else hi=mid;}let p=t.points[Math.min(lo,t.points.length-1)];if(lo&&Math.abs(t.points[lo-1].lx-lx)<Math.abs(p.lx-lx))p=t.points[lo-1];lines.push(t.label+': packet_count '+display(p.raw.packet_count)+' · F(x) '+display(p.raw.cumulative_fraction)+'\n累積 '+display(p.raw.cumulative_count)+' / '+display(t.curve.total_flow_count));if(t.curve.simplified)lines.push('縮約: 点は真値。点間は下界/上界。');}tooltip(event,lines);
});
$('scope-svg').addEventListener('pointerleave',hideTooltip);
$('scope-svg').addEventListener('wheel',event=>{const px=svgX(event,$('scope-svg'));if(px<LEFT||px>W-RIGHT)return;event.preventDefault();scopeZoom(event.deltaY>0?1.3:1/1.3,(px-LEFT)/PW);},{passive:false});
$('scope-download').addEventListener('click',()=>{
  const copy=$('scope-svg').cloneNode(true);copy.setAttribute('xmlns',NS);copy.setAttribute('width',W);copy.setAttribute('height',H+140);copy.setAttribute('viewBox',`0 0 ${W} ${H+140}`);
  copy.querySelectorAll('text').forEach(t=>{t.setAttribute('font-family','sans-serif');t.setAttribute('font-size','12');t.setAttribute('fill','#294459');});
  let row=0;for(const t of scopeTraces)if(scopeVisible.has(t.key))copy.append(svgNode('text',{x:LEFT,y:H+20+row++*20,fill:t.color,'font-size':12,'font-family':'sans-serif'},t.label));
  copy.append(svgNode('text',{x:LEFT,y:H+100,'font-size':11,'font-family':'sans-serif'},'Fixed native selection; only evaluation scope differs. Simplified: lower steps / upper bands.'),svgNode('text',{x:LEFT,y:H+120,'font-size':11,'font-family':'sans-serif'},'Dataset: '+display(data.dataset_id)));
  const url=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(copy)],{type:'image/svg+xml'})),a=node('a');a.href=url;a.download='rls-native-normalized24-ecdf.svg';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
// A prefix-table row leads directly to its individual native ECDF.
$('prefix-body').addEventListener('click',event=>{
  const row=event.target.closest('tr[data-prefix]');if(!row)return;
  const card=allPrefixes.find(p=>p.prefix===row.dataset.prefix);if(!card)return;
  $('pp-mode').value=card.modes[0];ppSelected.clear();ppDecoded.clear();ppSelected.set(card.prefix,PP_COLORS[0]);
  $('pp-search').value=card.prefix;ppPage=0;ppUpdateOptions();ppRefresh(true);selectTab($('tab-per-prefix'));
});
