'use strict';
const AguriEcdf = (()=>{
const $=id=>document.getElementById(id),NS='http://www.w3.org/2000/svg';
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x)?x:{},arr=x=>Array.isArray(x)?x:[],show=x=>x==null?'—':String(x);
const integer=x=>x==null?'—':String(x).replace(/\B(?=(\d{3})+(?!\d))/g,','),num=x=>x==null||!Number.isFinite(Number(x))?'—':Number(x).toLocaleString('en-US',{maximumFractionDigits:6}),pct=x=>x==null?'—':num(Number(x)*100)+'%';
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const svgEl=(tag,attrs={},text)=>{const n=document.createElementNS(NS,tag);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,v);if(text!==undefined)n.textContent=text;return n;};
function tooltip(event,lines){const t=$('tooltip');t.replaceChildren(...lines.map((line,i)=>el(i?'p':'strong',line)));t.hidden=false;const box=t.getBoundingClientRect();t.style.left=Math.max(5,Math.min(event.clientX+14,innerWidth-box.width-8))+'px';t.style.top=Math.max(5,Math.min(event.clientY+10,innerHeight-box.height-8))+'px';}
function hideTooltip(){$('tooltip').hidden=true;}
// Generic right-continuous ECDF controller: only genuine saved points are used.
function logInt(value){const s=String(value??'').replace(/^0+/,'');if(!/^\d+$/.test(s))return NaN;const n=s.slice(0,15);return s.length-1+Math.log10(Number(n)/10**(n.length-1));}
function projectPoints(curve){
 return arr(curve.points).filter(p=>p&&Number.isFinite(logInt(p.packet_count))&&Number.isFinite(p.cumulative_fraction))
  .map(p=>({raw:p,lx:logInt(p.packet_count),fy:p.cumulative_fraction}));
}
function ecdfPaths(points,simplified,left,right,x,y){
 const low=[[left,0]],high=[[left,0]];
 points.forEach((p,i)=>{
  const prev=i?points[i-1].fy:0;
  low.push([p.lx,prev],[p.lx,p.fy]);
  high.push([p.lx,prev],[p.lx,p.fy]);
  if(simplified&&i+1<points.length)high.push([p.lx,points[i+1].fy],[points[i+1].lx,points[i+1].fy]);
 });
 const last=points.at(-1),end=[Math.max(right,last.lx),last.fy];
 low.push(end);high.push(end);
 const path=ps=>ps.map((p,i)=>(i?'L':'M')+x(p[0])+','+y(p[1])).join('');
 const line=path(low);
 return {line,band:simplified?line+path(high.reverse()).replace(/^M/,'L')+'Z':null};
}

function chart(mount,series,filename,{curves,datasetId,exactSource='ecdf_counts.csv',maxLog=1}){
 const W=1000,H=460,L=78,R=30,T=22,B=65,PW=W-L-R,PH=H-T-B,frame=$(mount);frame.replaceChildren();
 const legend=el('div',undefined,'toolbar'),controls=el('div',undefined,'toolbar'),notes=el('div'),status=el('p',undefined,'caption');status.setAttribute('role','status');const svg=svgEl('svg',{viewBox:`0 0 ${W} ${H}`,class:'chart',role:'img','aria-label':'Exact-frequency ECDF'});svg.dataset.chart=mount;
 const state=series.map(s=>({...s,visible:true,curve:obj(curves[s.key]),points:projectPoints(obj(curves[s.key]))}));
 let full=[0,maxLog],range=[0,1],drag=null;for(const s of state)if(s.points.length)full[1]=Math.max(full[1],s.points.at(-1).lx);range=[...full];
 function position(event){const box=svg.getBoundingClientRect();return(event.clientX-box.left)*W/box.width;}
 function render(){svg.replaceChildren();svg.dataset.xMin=range[0];svg.dataset.xMax=range[1];const x=v=>L+(v-range[0])/(range[1]-range[0])*PW,y=v=>T+(1-v)*PH;
  for(let i=0;i<=5;i++){const value=i/5;svg.append(svgEl('line',{x1:L,y1:y(value),x2:W-R,y2:y(value),stroke:'#e2e9ef'}),svgEl('text',{x:L-12,y:y(value)+4,'text-anchor':'end'},value.toFixed(1)));}
  const step=Math.max(1,Math.ceil((range[1]-range[0])/8));let ticks=0;for(let v=Math.ceil(range[0]/step)*step;v<=range[1];v+=step){svg.append(svgEl('text',{x:x(v),y:H-B+23,'text-anchor':'middle'},v<=5&&v>=0?integer(10**v):'10^'+v.toFixed(2)));ticks++;}
  if(!ticks||range[1]-range[0]<1)for(const v of [range[0],range[1]])svg.append(svgEl('text',{x:x(v),y:H-B+23,'text-anchor':'middle'},'10^'+v.toFixed(2)));
  svg.append(svgEl('path',{d:`M${L},${T}V${H-B}H${W-R}`,fill:'none',stroke:'#869bab'}),svgEl('text',{x:L+PW/2,y:H-15,'text-anchor':'middle'},'packet_count per flow · log scale'),svgEl('text',{transform:`translate(20 ${T+PH/2}) rotate(-90)`,'text-anchor':'middle'},'Cumulative fraction'));
  const clip=svgEl('clipPath',{id:mount+'-clip'});clip.append(svgEl('rect',{x:L,y:T,width:PW,height:PH}));const defs=svgEl('defs');defs.append(clip);svg.append(defs);const g=svgEl('g',{'clip-path':`url(#${mount}-clip)`});let count=0;
  for(const s of state){
   if(!s.visible||!s.points.length)continue;
   count++;
   const {line,band}=ecdfPaths(s.points,s.curve.simplified,range[0],range[1],x,y);
   if(band)g.append(svgEl('path',{'data-envelope':s.key,d:band,fill:s.color,'fill-opacity':.12}));
   g.append(svgEl('path',{'data-curve':s.key,d:line,fill:'none',stroke:s.color,'stroke-width':2.4,'stroke-dasharray':s.dash||''}));
  }
  svg.append(g);status.textContent=`表示 ${count}曲線 · log10(x): ${num(range[0])} — ${num(range[1])}`;}
 function zoom(factor,anchor=.5){const span=Math.min(full[1]-full[0],Math.max(.01,(range[1]-range[0])*factor)),center=range[0]+(range[1]-range[0])*anchor,start=Math.min(full[1]-span,Math.max(full[0],center-span*anchor));range=[start,start+span];hideTooltip();render();}
 for(const s of state){const button=el('button',s.label,'legend-button');button.style.color=s.color;button.dataset.series=s.key;button.setAttribute('aria-pressed','true');button.addEventListener('click',()=>{s.visible=!s.visible;button.setAttribute('aria-pressed',String(s.visible));hideTooltip();render();});legend.append(button);notes.append(el('p',s.label+': '+(s.points.length?`表示 ${integer(s.curve.displayed_point_count)} / 正確な異なる値 ${integer(s.curve.exact_point_count)} · `+(s.curve.simplified?'縮約: 階段は下界、帯は上界、最大帯幅 '+show(s.curve.error_bound):'全ECDF点'):'空分布 / データなし'),'caption'));}
 for(const [label,action] of [['拡大 ＋',()=>zoom(.5)],['縮小 −',()=>zoom(2)],['表示範囲をリセット',()=>{range=[...full];hideTooltip();render();}]]){const b=el('button',label);b.addEventListener('click',action);controls.append(b);}
 const download=el('button','SVGを保存');download.dataset.download=mount;download.addEventListener('click',()=>{const copy=svg.cloneNode(true);copy.querySelector('[data-selection]')?.remove();copy.setAttribute('xmlns',NS);copy.setAttribute('width',W);copy.setAttribute('height',H+160);copy.setAttribute('viewBox',`0 0 ${W} ${H+160}`);copy.querySelectorAll('text').forEach(t=>{t.setAttribute('font-family','sans-serif');t.setAttribute('font-size','12');t.setAttribute('fill','#294459');});let row=0;for(const s of state)if(s.visible)copy.append(svgEl('text',{x:L,y:H+20+20*row++,fill:s.color,'font-size':12,'font-family':'sans-serif'},s.label));copy.append(svgEl('text',{x:L,y:H+125,'font-size':11},'Dataset: '+show(datasetId)+' · Fixed native selection; simplified steps/bands are bounds.'),svgEl('text',{x:L,y:H+145,'font-size':11},'Saved-run descriptive comparison; exact counts are in '+exactSource+'.'));const url=URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(copy)],{type:'image/svg+xml'})),a=el('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});controls.append(download);
 svg.addEventListener('pointermove',event=>{const px=position(event);if(px<L||px>W-R){hideTooltip();return;}const lx=range[0]+(px-L)/PW*(range[1]-range[0]),lines=['最も近い保存済みECDF選択点（点間の真値ではありません）'];for(const s of state){if(!s.visible||!s.points.length)continue;let lo=0,hi=s.points.length;while(lo<hi){const mid=(lo+hi)>>1;if(s.points[mid].lx<lx)lo=mid+1;else hi=mid;}let p=s.points[Math.min(lo,s.points.length-1)];if(lo&&Math.abs(s.points[lo-1].lx-lx)<Math.abs(p.lx-lx))p=s.points[lo-1];lines.push(s.label+': packet_count '+p.raw.packet_count+' · F(x) '+p.raw.cumulative_fraction+'\n累積 '+p.raw.cumulative_count+' / '+s.curve.total_flow_count+' · 度数 '+p.raw.frequency);}tooltip(event,lines);if(drag!=null){let r=svg.querySelector('[data-selection]');if(!r){r=svgEl('rect',{'data-selection':'true',y:T,height:PH,fill:'#126ea6','fill-opacity':.16});svg.append(r);}r.setAttribute('x',Math.min(drag,px));r.setAttribute('width',Math.abs(drag-px));}});
 svg.addEventListener('pointerleave',hideTooltip);svg.addEventListener('pointerdown',e=>{const px=position(e);if(e.button===0&&px>=L&&px<=W-R){drag=px;svg.setPointerCapture(e.pointerId);}});svg.addEventListener('pointerup',e=>{if(drag==null)return;const end=Math.max(L,Math.min(W-R,position(e))),start=drag;drag=null;if(Math.abs(start-end)>8){const old=[...range];range=[old[0]+(Math.min(start,end)-L)/PW*(old[1]-old[0]),old[0]+(Math.max(start,end)-L)/PW*(old[1]-old[0])];}hideTooltip();render();});svg.addEventListener('pointercancel',()=>{drag=null;render();});svg.addEventListener('wheel',e=>{const px=position(e);if(px<L||px>W-R)return;e.preventDefault();zoom(e.deltaY>0?1.3:1/1.3,(px-L)/PW);},{passive:false});
 frame.append(legend,controls,svg,status,notes);render();return {state};
}
return {$,obj,arr,show,integer,num,pct,el,svgEl,logInt,projectPoints,ecdfPaths,chart,hideTooltip};
})();
