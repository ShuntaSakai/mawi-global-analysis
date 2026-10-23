"""Execute the embedded offline UI against a minimal DOM; no browser dependencies."""
import shutil
import subprocess
from pathlib import Path


def test_embedded_notes_behavior():
    node = shutil.which('node')
    assert node, 'Node.js is required for dashboard JavaScript behavioral tests'
    template = Path(__file__).parents[1] / 'src/mawi_global_analysis/prefix_dashboard.html'
    script = template.read_text().split('<script>')[1].split('</script>')[0]
    harness = r'''
const assert=require('node:assert/strict');
class El {
 constructor(){this.value='';this.listeners={};this.style={};this.dataset={};this.classList={toggle(){}};this.files=[];}
 addEventListener(k,f){this.listeners[k]=f;} append(){} replaceChildren(){} setAttribute(){} remove(){} click(){this.listeners.click?.();} getBoundingClientRect(){return {left:0,bottom:0,top:0};}
}
const els=new Map(); const get=id=>{if(!els.has(id))els.set(id,new El());return els.get(id);};
const stat={flow_count:1,median:1,p95:1,one_packet_rate:1,removal_rate:0};
const target=prefix=>({prefix,notes:{observation:'initial',interpretation:'',next_check:''},stats:{Raw:stat,removed:stat,retained:stat},thumbnail:{},detail_image:''});
const payload={dataset_id:'dataset',run_name:'run',prefixes:[target('a'),target('b')],references:[target('reference')]};
get('dashboard-data').textContent=JSON.stringify(payload);get('sort').value='flow_count';
class Template { cloneNode(){return new Template();} querySelector(){return this.data||(this.data={textContent:''});} get outerHTML(){return '<html><script id="dashboard-data" type="application/json">'+this.data.textContent+'</script></html>';}}
global.document={documentElement:new Template(),getElementById:get,createElement:()=>new El(),createTextNode:x=>x,querySelectorAll:()=>[],body:new El(),addEventListener(){}};
let confirmResult=true,confirmCount=0;const windowEvents={};
global.window={innerWidth:1200,addEventListener:(k,f)=>windowEvents[k]=f,confirm:()=>{confirmCount++;return confirmResult;}};
'''
    checks = r'''
(async()=>{
const special='<script>alert("x")</script>\n\' & 日本語';
get('observation').value=special;get('observation').listeners.input();
assert.equal(byPrefix.get('a').notes.observation,special);assert(isDirty());
selected='b';renderDetail();selected='a';renderDetail();assert.equal(get('observation').value,special);
renderCards();group='removed';renderCards();assert.equal(get('observation').value,special);
let warned=false;windowEvents.beforeunload({preventDefault(){warned=true;}});assert(warned);
const exported=notesDocument();assert.equal(exported.schema_version,1);assert.equal(exported.dataset_id,'dataset');assert.equal(exported.run_name,'run');assert.equal(Object.keys(exported.notes).length,3);
const file=value=>({size:100,text:async()=>typeof value==='string'?value:JSON.stringify(value)});
const before=notesSnapshot();await importNotes(file('{'));assert.equal(notesSnapshot(),before);
for(const patch of [{dataset_id:'other'},{run_name:'other'},{schema_version:2},{notes:{unknown:{}}}]){await importNotes(file({...exported,...patch}));assert.equal(notesSnapshot(),before);}
for(const bad of [5,'x'.repeat(10001)]){const doc=structuredClone(exported);doc.notes.a.observation=bad;await importNotes(file(doc));assert.equal(notesSnapshot(),before);}
await importNotes({size:MAX_FILE_BYTES+1,text:async()=>{throw Error('must not read');}});assert.equal(notesSnapshot(),before);
byPrefix.get('a').notes.observation='changed';confirmResult=false;const changed=notesSnapshot();await importNotes(file(exported));assert.equal(notesSnapshot(),changed);
confirmResult=true;await importNotes(file(exported));assert.equal(byPrefix.get('a').notes.observation,special);assert(!isDirty());
// An edit while File.text is pending must still trigger conflict confirmation.
let finish;const pending=importNotes({size:100,text:()=>new Promise(resolve=>finish=resolve)});
byPrefix.get('a').notes.observation='late edit';confirmResult=false;const count=confirmCount;finish(JSON.stringify(exported));await pending;assert.equal(confirmCount,count+1);assert.equal(byPrefix.get('a').notes.observation,'late edit');
// Export uses the actual Blob/download path and preserves plain text.
let blob;URL.createObjectURL=b=>{blob=b;return 'blob:test';};URL.revokeObjectURL=()=>{};
get('export-notes').click();assert.equal(JSON.parse(await blob.text()).notes.a.observation,'late edit');assert(!isDirty());
// HTML exports contain every target, preserve analysis, and escape HTML delimiters.
const hostile='</script><script>alert(1)</script><img src=x onerror=alert(1)> & > " \\\n日本語\u2028\u2029';
for(const t of all)t.notes.observation=hostile+t.prefix;
const analysis=JSON.parse(JSON.stringify(data));
const first=notedHTML();
const embedded=first.split('type="application/json">')[1].split('</script>')[0];
assert(!embedded.includes('<'));assert(!embedded.includes('>'));assert(!embedded.includes('&'));
const restored=JSON.parse(embedded);assert.deepEqual(restored,data);
assert.equal(restored.references[0].notes.observation,hostile+'reference');
get('export-html').click();assert.equal(await blob.text(),first);assert(!isDirty());
assert.deepEqual(data,analysis);assert.equal(notedHTML(),first);
// Reopened data starts clean, remains editable, and supports another export.
const vm=require('node:vm');
const reopen=scriptSource=>{const context={require,console,Blob,URL,setTimeout,document,window};get('dashboard-data').textContent=embedded;vm.runInNewContext(scriptSource+`;assert.equal(isDirty(),false);byPrefix.get('a').notes.next_check='again';assert(isDirty());assert(JSON.parse(notedHTML().split('type="application/json">')[1].split('</script>')[0]).prefixes[0].notes.next_check==='again');`,{...context,assert});};
reopen(SOURCE);
byPrefix.get('a').notes.next_check='unsaved';URL.createObjectURL=()=>{throw Error('download failed');};get('export-html').click();assert(isDirty());
console.log('notes behavioral checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    result = subprocess.run([node, '-'], input=harness + '\nconst SOURCE='+__import__('json').dumps(script)+';\n' + script + checks, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
