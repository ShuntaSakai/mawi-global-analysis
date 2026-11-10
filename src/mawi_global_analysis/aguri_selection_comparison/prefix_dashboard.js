'use strict';
(() => {
 const { $, el, svgEl, integer, num, pct, logInt, projectPoints, ecdfPaths, chart, hideTooltip } = AguriEcdf;
 const data = JSON.parse($('dashboard-data').textContent);
 const pageSize = 12;
 const tabs = Array.from(document.querySelectorAll('[role=tab]'));
 const keys = tabs.map(tab => tab.dataset.condition);
 const states = new Map(tabs.map(tab => [tab.dataset.condition, {
  query: '', overlap: 'all', overlapCounts: null, sort: 'flow_count', ascending: false, page: 0, scroll: 0, results: null,
 }]));
 const decoded = new Map();
 const maxLog = Math.max(1, logInt(data.axis_max_packet_count));
 const cardFields = [['flow_count', 'Flow count', integer], ['median', 'Median', num],
  ['p95', 'P95', num], ['one_packet_rate', '1パケット率', pct]];
 const detailFields = [...cardFields.slice(0, 1), ['packet_total', 'Packet total', integer],
  ['byte_total', 'Byte total', integer], ...cardFields.slice(1)];
 let active = 'A';
 let opened = null;

 function metrics(cidr, fields) {
  const grid = el('span', undefined, 'prefix-metrics');
  for (const [key, label, format] of fields) {
   const field = el('span', label);
   const value = data.prefixes[cidr].stats[key];
   const number = el('b', format(value));
   number.dataset.stat = key;
   number.title = value == null ? '—' : String(value);
   field.append(number);
   grid.append(field);
  }
  return grid;
 }

 function curveFor(cidr) {
  if (!decoded.has(cidr)) {
   const curve = data.curves[cidr];
   decoded.set(cidr, {...curve, points: JSON.parse(curve.encoded_points)});
  }
  return decoded.get(cidr);
 }

 function thumbnail(curve) {
  const svg = svgEl('svg', {viewBox:'0 0 240 94', 'aria-hidden':'true'});
  const x = value => 25 + value/maxLog*202;
  const y = value => 8 + (1-value)*65;
  svg.append(svgEl('path', {d:'M25,8V73H227', fill:'none', stroke:'#869bab'}));
  for (const value of [0, 1]) svg.append(svgEl('text', {x:17,y:y(value)+4,'text-anchor':'end'}, value));
  svg.append(svgEl('text', {x:25,y:89,'text-anchor':'middle'}, '1'),
             svgEl('text', {x:227,y:89,'text-anchor':'end'}, '10^'+num(maxLog)));
  const points = projectPoints(curve);
  if (points.length) {
   const {line, band} = ecdfPaths(points, curve.simplified, 0, maxLog, x, y);
   if (curve.simplified) svg.append(svgEl('path', {d:band, fill:'#126ea6','fill-opacity':.15}));
   svg.append(svgEl('path', {d:line, fill:'none', stroke:'#126ea6','stroke-width':2}));
  }
  return svg;
 }

 function showDetail(cidr, card) {
  if (opened) opened.card.setAttribute('aria-expanded', 'false');
  opened = {card, scroll: window.scrollY};
  card.setAttribute('aria-expanded', 'true');
  const condition = data.conditions[active];
  $('prefix-detail-title').textContent = active+' · '+cidr;
  $('prefix-detail-stats').replaceChildren(metrics(cidr, detailFields));
  $('prefix-source').textContent = '完全度数 · '+condition.frequencies;
  $('prefix-detail').hidden = false;
  $('prefix-layout').classList.add('detail-open');
  const curve = curveFor(cidr);
  chart('prefix-chart', [{key:'prefix', label:active+' · '+cidr, color:'#126ea6'}],
        'aguri-'+active+'-'+cidr.replace('/', '-')+'-ecdf.svg',
        {curves:{prefix:curve}, datasetId:data.dataset_id, exactSource:condition.frequencies, maxLog});
  $('prefix-close').focus();
 }

 function closeDetail(restore = false) {
  if (!opened) return;
  const {card, scroll} = opened;
  opened = null;
  card.setAttribute('aria-expanded', 'false');
  hideTooltip();
  $('prefix-detail').hidden = true;
  $('prefix-layout').classList.remove('detail-open');
  $('prefix-chart').replaceChildren();
  if (restore) {
   card.focus({preventScroll:true});
   window.scrollTo(0, scroll);
  }
 }

 function makeCard(cidr) {
  const card = el('button', undefined, 'prefix-card');
  card.type = 'button';
  card.dataset.prefix = cidr;
  card.setAttribute('aria-label', cidr+' の詳細');
  card.setAttribute('aria-controls', 'prefix-detail');
  card.setAttribute('aria-expanded', 'false');
  const curve = curveFor(cidr);
  const note = !curve.displayed_point_count ? '0フロー · 空分布' : curve.simplified ?
   '縮約 · 階段は下界、帯は上界 · 最大幅 '+num(curve.error_bound) : '全ECDF点';
  const peers = keys.filter(key => key !== active && data.prefixes[cidr].conditions.includes(key));
  const common = el('span', peers.length ? '共通' : 'この条件のみ', 'prefix-common');
  for (const key of peers) common.append(el('span', key, 'prefix-common-label'));
  card.setAttribute('aria-description', peers.length ? peers.join('、')+'と共通' : 'この条件のみ');
  card.append(el('strong', cidr), common, metrics(cidr, cardFields), thumbnail(curve), el('span', note, 'caption'));
  card.addEventListener('click', () => showDetail(cidr, card));
  return card;
 }

 function filtered(state) {
  const query = state.query.trim().toLowerCase();
  const order = state.ascending ? 1 : -1;
  const stat = state.sort;
  return data.conditions[active].prefixes.filter(cidr => {
   if (!cidr.includes(query)) return false;
   const selected = data.prefixes[cidr].conditions;
   return state.overlap === 'all' ||
    (state.overlap === 'only' ? selected.length === 1 : selected.includes(state.overlap));
  }).sort((a, b) => {
   const byPrefix = a.localeCompare(b, 'en', {numeric:true});
   if (stat === 'prefix') return order*byPrefix;
   const av = data.prefixes[a].stats[stat], bv = data.prefixes[b].stats[stat];
   if (av == null || bv == null) return av == null && bv == null ? byPrefix : av == null ? 1 : -1;
   const [x, y] = stat === 'flow_count' ? [BigInt(av), BigInt(bv)] : [Number(av), Number(bv)];
   return x === y ? byPrefix : order*(x > y ? 1 : -1);
  });
 }

 function overlapCounts() {
  const counts = Object.fromEntries(keys.map(key => [key, 0]));
  counts.only = 0;
  for (const cidr of data.conditions[active].prefixes) {
   const selected = data.prefixes[cidr].conditions;
   if (selected.length === 1) counts.only++;
   for (const key of selected) counts[key]++;
  }
  return counts;
 }

 function renderOverlapFilters(state) {
  const group = $('prefix-overlap-filters');
  const counts = state.overlapCounts ??= overlapCounts();
  const options = [['all', 'すべて'], ['only', 'この条件のみ'],
   ...keys.filter(key => key !== active).map(key => [key, key+'と共通（'+integer(counts[key])+'件）'])];
  group.replaceChildren(...options.map(([key, label]) => {
   const button = el('button', label);
   button.type = 'button';
   button.dataset.prefixFilter = key;
   button.setAttribute('aria-pressed', String(state.overlap === key));
   button.addEventListener('click', () => {
    if (state.overlap === key) return;
    group.querySelector('[aria-pressed=true]').setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-pressed', 'true');
    updateSettings({overlap:key});
   });
   return button;
  }));
 }

 function renderPage() {
  closeDetail();
  decoded.clear();
  const state = states.get(active);
  const results = state.results ??= filtered(state);
  const pages = Math.max(1, Math.ceil(results.length/pageSize));
  state.page = Math.min(state.page, pages-1);
  const cards = results.slice(state.page*pageSize, (state.page+1)*pageSize).map(makeCard);
  let emptyMessage = '該当する選定Prefixがありません。';
  if (state.overlapCounts[state.overlap] === 0) {
   emptyMessage = state.overlap === 'only' ? 'この条件のみで選定されたPrefixはありません。' :
    state.overlap+'と共通の選定Prefixはありません。';
  }
  $('prefix-cards').replaceChildren(...(cards.length ? cards : [el('p', emptyMessage)]));
  $('prefix-status').textContent = integer(results.length)+'件 · ページ '+(state.page+1)+' / '+pages;
  $('prefix-prev').disabled = state.page === 0;
  $('prefix-next').disabled = state.page+1 >= pages;
 }

 function selectTab(tab) {
  if (active !== tab.dataset.condition) {
   states.get(active).scroll = opened?.scroll ?? window.scrollY;
   active = tab.dataset.condition;
  }
  for (const button of tabs) {
   const selected = button === tab;
   button.tabIndex = selected ? 0 : -1;
   button.setAttribute('aria-selected', String(selected));
  }
  $('prefix-panel').setAttribute('aria-labelledby', tab.id);
  const state = states.get(active);
  $('prefix-search').value = state.query;
  $('prefix-sort').value = state.sort;
  $('prefix-direction').textContent = state.ascending ? '昇順' : '降順';
  const condition = data.conditions[active];
  $('prefix-run').textContent = active+' · '+condition.run_name+' · '+(condition.details?.description ?? condition.selection_input ?? '—');
  renderOverlapFilters(state);
  renderPage();
  window.scrollTo(0, state.scroll);
 }

 function updateSettings(changes) {
  Object.assign(states.get(active), changes, {page:0, results:null});
  renderPage();
 }

 $('prefix-dataset').textContent = 'Dataset · '+data.dataset_id;
 $('prefix-axis').textContent = 'カード共通軸 · packet_count 1〜10^'+num(maxLog)+'（対数） · 累積フロー割合 0〜1';
 $('prefix-search').addEventListener('input', event => updateSettings({query:event.target.value}));
 $('prefix-sort').addEventListener('change', event => updateSettings({sort:event.target.value}));
 $('prefix-direction').addEventListener('click', event => {
  const ascending = !states.get(active).ascending;
  event.target.textContent = ascending ? '昇順' : '降順';
  updateSettings({ascending});
 });
 for (const [id, delta] of [['prefix-prev', -1], ['prefix-next', 1]]) {
  $(id).addEventListener('click', () => {
   states.get(active).page += delta;
   renderPage();
   if ($(id).disabled) $(delta<0 ? 'prefix-next' : 'prefix-prev').focus({preventScroll:true});
  });
 }
 $('prefix-close').addEventListener('click', () => closeDetail(true));
 document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && opened) { event.preventDefault(); closeDetail(true); }
 });
 tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', event => {
   const next = {ArrowRight:(index+1)%tabs.length, ArrowLeft:(index+tabs.length-1)%tabs.length,
                 Home:0, End:tabs.length-1}[event.key];
   if (next === undefined) return;
   event.preventDefault();
   selectTab(tabs[next]);
   tabs[next].focus({preventScroll:true});
  });
 });
 selectTab(tabs[0]);
})();
