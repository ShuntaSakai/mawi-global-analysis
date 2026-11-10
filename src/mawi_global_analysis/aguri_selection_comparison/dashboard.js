'use strict';
(()=>{
const {$,obj,arr,show,integer,num,pct,el,hideTooltip}=AguriEcdf;
let data={};try{data=JSON.parse($('dashboard-data').textContent)||{};}catch(error){}
const v2=data.schema_version==='aguri-selection-analysis-v2';
const KEYS=v2?['A','B','C-packet','C-flow']:['A','B','C'];
const COLORS={overall_ipv4:'#364455',A:'#126ea6',B:'#ae580d',C:'#227343','C-packet':'#227343','C-flow':'#873fa3'};
const DASH={overall_ipv4:'',A:'8 3',B:'3 3',C:'10 3 2 3','C-packet':'10 3 2 3','C-flow':'2 3 8 3'};
const conditions=obj(data.conditions),curves=obj(data.all_curves),provenance=obj(data.provenance),validation=obj(provenance.validation),runs=obj(validation.runs);
function table(headers,rows,id){const t=el('table'),h=el('tr');for(const text of headers)h.append(el('th',text));const th=el('thead');th.append(h);t.append(th);const body=el('tbody');for(const cells of rows){const r=el('tr');for(const value of cells){const pair=Array.isArray(value)?value:[value,value],c=el('td',show(pair[0]));c.title=show(pair[1]);r.append(c);}body.append(r);}t.append(body);if(id)$(id).replaceChildren(t);return t;}
const tabs=[...document.querySelectorAll('[role=tab]')];function selectTab(tab){for(const b of tabs){const active=b===tab;b.setAttribute('aria-selected',String(active));b.tabIndex=active?0:-1;$(b.getAttribute('aria-controls')).hidden=!active;}hideTooltip();}
tabs.forEach((b,i)=>{b.addEventListener('click',()=>selectTab(b));b.addEventListener('keydown',e=>{const next=e.key==='ArrowRight'?(i+1)%tabs.length:e.key==='ArrowLeft'?(i+tabs.length-1)%tabs.length:null;if(next!=null){e.preventDefault();selectTab(tabs[next]);tabs[next].focus();}});});
const synthetic=KEYS.some(k=>{
 const evidence=String(obj(runs[k]).source_evidence||'');
 return evidence.includes('synthetic')&&!evidence.startsWith('synthetic_or_manual_execution');
});
$('evidence').textContent=synthetic?'合成データ · 実MAWIの結果ではありません':'保存済みrunの記述比較 · 実MAWIでの検証状況は入力来歴を確認してください';
$('dataset').textContent='Dataset · '+show(data.dataset_id);
$('ab-verification').textContent='検証範囲: '+show(validation.ab_contrast_verification)+'。';
const selection=k=>obj(obj(runs[k]).selection_details).description??obj(runs[k]).selection_input;
const canonicalKeys=KEYS.slice(2),interpretation=obj(validation.interpretation);
$('selection-description').textContent='A：旧Aguri unfiltered · B：旧Aguri IPv4 TCP/UDP · '+canonicalKeys.map(k=>k+'：'+show(selection(k))).join(' · ');
const contrasts=canonicalKeys.map(k=>'B→'+k+': '+show(interpretation['B_to_'+k])+'。');
if(v2)contrasts.push('C-packet→C-flow: '+show(interpretation['C-packet_to_C-flow'])+'。両曲線とも横軸は1フロー当たりのpacket_countです。');
$('bc-interpretation').textContent=contrasts.join(' ')+' ';
table(['条件','run','選定入力','BPF'],KEYS.map(k=>[k,obj(runs[k]).run_name,selection(k),obj(runs[k]).bpf??(canonicalKeys.includes(k)?'canonical入力（PCAP BPFなし）':'なし')]),'conditions');
const FIELDS=[['flow_count','Flow count',integer],['packet_total','Packet total',integer],['byte_total','Byte total',integer],['median','Median',num],['p95','P95',num],['mean_packet_count','Mean packets',num],['one_packet_rate','One-packet rate',pct]];
const summary=[['選定native prefix数',...KEYS.map(k=>[integer(obj(conditions[k]).selected_native_prefix_count),obj(conditions[k]).selected_native_prefix_count])]];
for(const [key,label,format] of FIELDS)summary.push([label,...KEYS.map(k=>{const v=obj(obj(conditions[k]).stats)[key];return[format(v),v];})]);
for(const key of ['flow','packet','byte'])summary.push([key+' coverage',...KEYS.map(k=>{const v=obj(obj(conditions[k]).coverage)[key];return[pct(v),v];})]);
summary.push(['KS vs Overall',...KEYS.map(k=>[num(obj(conditions[k]).ks_distance),obj(conditions[k]).ks_distance])],['KS exact numerator / denominator',...KEYS.map(k=>show(obj(conditions[k]).ks_numerator)+' / '+show(obj(conditions[k]).ks_denominator))]);table(['指標',...KEYS],summary,'summary');
table(['条件ペア','集合','交差','和','Jaccard'],arr(data.jaccard).map(r=>[r.condition_a+' / '+r.condition_b,r.set_kind,[integer(r.intersection_count),r.intersection_count],[integer(r.union_count),r.union_count],[num(r.jaccard),r.jaccard]]),'jaccard');
const chart=(mount,series,filename)=>AguriEcdf.chart(mount,series,filename,{curves,datasetId:data.dataset_id});
chart('main-chart',['overall_ipv4',...KEYS].map(key=>({key,label:key==='overall_ipv4'?'Overall':key,color:COLORS[key],dash:DASH[key]})),v2?'aguri-ab-c-packet-flow-ecdf.svg':'aguri-abc-ecdf.svg');
const legacy=obj(data.legacy);$('legacy').append(el('p','Status: '+show(legacy.status)),el('p',legacy.supplied_reference_matches?'提供された参照exportとのID・整数度数・提供統計の一致を確認しました。旧大会の実行・公表値そのものの独立認証ではありません。':'旧大会のhistorical再現は未確認です。現行アーカイブのunion規約との一致だけでは当時の入力・実行結果の再現を証明できません。'),el('pre',JSON.stringify(legacy,null,2)));
const prefixes=arr(data.prefixes),records=arr(data.prefix_contribution),prefixMap=new Map(prefixes.map(p=>[p.prefix,p]));
const added=prefixes.filter(p=>arr(p.conditions).includes('B')&&!arr(p.conditions).includes('A')),removed=prefixes.filter(p=>arr(p.conditions).includes('A')&&!arr(p.conditions).includes('B')),common=prefixes.filter(p=>arr(p.conditions).includes('A')&&arr(p.conditions).includes('B'));
$('ab-change').textContent=`A/B共通 ${integer(common.length)} · Bで新規 ${integer(added.length)} · Aのみ ${integer(removed.length)}（完全一致CIDR）`;
table(['flow component','Flow count','Median','One-packet rate'],Object.entries(obj(data.components)).map(([name,s])=>[name,[integer(s.flow_count),s.flow_count],[num(s.median),s.median],[pct(s.one_packet_rate),s.one_packet_rate]]),'components');
function prefixTable(mount,search,filter,prev,next,status,ranking=false){let page=0;function update(reset=false){if(reset)page=0;const q=$(search).value.trim().toLowerCase(),mode=$(filter).value;const rows=records.filter(r=>{if(!show(r.prefix).toLowerCase().includes(q))return false;const selected=arr(obj(prefixMap.get(r.prefix)).conditions);return ranking?r.condition===mode:mode==='all'||(mode==='new-B'?r.condition==='B'&&!selected.includes('A'):mode==='lost-A'?r.condition==='A'&&!selected.includes('B'):mode==='common-AB'?selected.includes('A')&&selected.includes('B'):r.condition===mode);}).sort((a,b)=>{const aa=BigInt(a.flow_count??0),bb=BigInt(b.flow_count??0);return aa===bb?show(a.prefix).localeCompare(show(b.prefix)):aa>bb?-1:1;});const pages=Math.max(1,Math.ceil(rows.length/25));page=Math.max(0,Math.min(page,pages-1));table(['条件','Native prefix','Flow count','Packet total','Byte total','Mean packets','One-packet rate','Union share','Exclusive union IDs'],rows.slice(page*25,(page+1)*25).map(r=>[r.condition,r.prefix,[integer(r.flow_count),r.flow_count],[integer(r.packet_total),r.packet_total],[integer(r.byte_total),r.byte_total],[num(r.mean_packet_count),r.mean_packet_count],[pct(r.one_packet_rate),r.one_packet_rate],[pct(r.union_share),r.union_share],[integer(r.exclusive_union_flow_count),r.exclusive_union_flow_count]]),mount);if(!rows.length)$(mount).append(el('p','該当するprefixがありません。','empty'));$(status).textContent=`${integer(rows.length)}件 · ページ ${page+1} / ${pages}`;$(prev).disabled=page===0;$(next).disabled=page+1>=pages;}
 $(search).addEventListener('input',()=>update(true));$(filter).addEventListener('change',()=>update(true));$(prev).addEventListener('click',()=>{page--;update();});$(next).addEventListener('click',()=>{page++;update();});update();}
prefixTable('selection-table','selection-search','selection-filter','selection-prev','selection-next','selection-status');
if($('contribution')){
prefixTable('rank','rank-search','rank-condition','rank-prev','rank-next','rank-status',true);
$('focus-title').textContent='対象: '+show(data.target)+' · 固定選定の事後的な寄与分析';
table(['条件','選定','候補exact','具体的な包含候補','所属flows','1packet flows','1packet率','所属∩union','Union share'],KEYS.map(k=>{const f=obj(obj(data.focus)[k]);return[k,show(f.selected),show(f.candidate_exact),arr(f.candidate_covering).join(', ')||'なし',[integer(f.flow_count),f.flow_count],[integer(f.one_packet_count),f.one_packet_count],[pct(f.one_packet_rate),f.one_packet_rate],[integer(f.in_union_flow_count),f.in_union_flow_count],[pct(f.union_share),f.union_share]];}),'focus');
function sensitivity(){const k=$('sensitivity-condition').value,r=obj(obj(data.sensitivities)[k]);chart('sensitivity-chart',[{key:'overall_ipv4',label:'Overall',color:COLORS.overall_ipv4},{key:k,label:k+' before',color:COLORS[k]},{key:k+'_without_target',label:k+' without '+show(data.target),color:'#8c4b9e',dash:'5 3'}],'aguri-target-exclusion.svg');const rows=FIELDS.map(([key,label,f])=>[label,[f(obj(r.before)[key]),obj(r.before)[key]],[f(obj(r.after)[key]),obj(r.after)[key]]]);rows.push(['KS vs Overall',[num(obj(r.before_ks).ks_distance),obj(r.before_ks).ks_distance],[num(r.ks_distance),r.ks_distance]],['KS exact',show(obj(r.before_ks).ks_numerator)+' / '+show(obj(r.before_ks).ks_denominator),show(r.ks_numerator)+' / '+show(r.ks_denominator)]);table(['指標',k+' before',k+' after'],rows,'sensitivity-stats');$('sensitivity-status').textContent='対象CIDRが選定されていた: '+show(r.selected_before)+' · unionから失われたflow数: '+integer(r.removed_flow_count)+'。残るprefixのunionを再構築しています。';}
$('sensitivity-condition').addEventListener('change',sensitivity);sensitivity();
}
for(const [label,value] of [['Dataset / completion manifest',{dataset_id:data.dataset_id,manifest:'comparison_manifest.json',bundle_kind:data.bundle_kind??'dashboard (v1)',dashboard_hash:'recorded in the completion manifest after rendering'}],['Source validation / PCAP・canonical・executables・BPF',provenance.validation],['統計・所属定義',obj(validation.common).evaluation],['実装hash',provenance.implementation_sha256],['表示の簡略化と正確値',provenance.display],['成果物hash・件数',provenance.artifacts],['歴史的再現の照合',data.legacy]]){const d=el('details'),s=el('summary',label);d.append(s,el('pre',JSON.stringify(value??null,null,2)));$('provenance').append(d);}
})();
