"""Synthetic saved A/B/C provenance; no selector or PCAP execution in this fixture."""
import csv
import hashlib
import importlib
import json
import ipaddress
import struct
from pathlib import Path
import shutil

import pandas as pd
import pytest
import yaml

from mawi_global_analysis.aguri import AGURI_CANDIDATE_COLUMNS, PINNED_AGURIM_SHA, parse_aguri_output
from mawi_global_analysis.agurim_prime.stage import _parse_control, METHODS
from mawi_global_analysis.agurim_prime.input import CONVERTER_VERSION
from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_stage import FLOW_COLUMNS, FLOW_SCHEMA_VERSION
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config, sha256_file, stable_json_hash
from mawi_global_analysis.membership import build_membership
from mawi_global_analysis.prefix import build_corrected_prefix_ledger

ROOT=Path(__file__).parents[1]
TARGET='93.139.29.123/32'


def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(obj,indent=2)+'\n')


def state(root):
    return {str(p.relative_to(root)):(p.stat().st_mtime_ns,sha256_file(p)) for p in root.rglob('*') if p.is_file()}


def api(name):return importlib.import_module('mawi_global_analysis.aguri_selection_comparison.'+name)


def fixture_root(root,empty=False):
    """Seven manual flows; A includes shared f1/f2/f3, B also selects TARGET."""
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    cfg=load_config(ROOT/'configs/baseline.yaml');capture=hashlib.sha256(b'synthetic capture identity, never a real PCAP').hexdigest()
    rows=[]
    values=[('192.0.2.1','198.51.100.1',4,400),('93.139.29.123','192.0.2.2',1,100),
            ('93.139.29.123','203.0.113.1',1,120),('192.0.2.3','192.0.2.4',10,1000),
            ('203.0.113.2','203.0.113.3',2,200),('93.139.29.123','93.139.29.123',1,140),
            ('2001:db8::1','2001:db8::2',7,700)]
    for i,(src,dst,n,b) in enumerate([] if empty else values):
        row=dict.fromkeys(FLOW_COLUMNS,0);row.update(flow_id=f'f{i}',ip_version=6 if ':' in src else 4,src_ip=src,dst_ip=dst,
            protocol=6,packet_count=n,byte_count=b,frame_byte_count=b,packets_from_src=n,packets_from_dst=0,
            bytes_from_src=b,bytes_from_dst=0)
        rows.append(row)
    flows=root/'data/fixture/processed/flows/flows.csv';flows.parent.mkdir(parents=True)
    pd.DataFrame(rows,columns=FLOW_COLUMNS).to_csv(flows,index=False)
    fm=flows.with_name('flow_manifest.json');fp=flow_fingerprint(capture,cfg,FLOW_SCHEMA_VERSION)
    save(fm,dict(schema_version=FLOW_SCHEMA_VERSION,input_sha256=capture,fingerprint=fp,row_count=len(rows),flow_config=flow_generation_config(cfg)))
    def entry(path,frame,producer=None):return dict(path=str(path),row_count=len(frame),sha256=sha256_file(path),producer=producer or {})
    for condition,run in [('A','baseline'),('B','agurim-ipv4-tcp-udp'),('C','canonical-packet-t1-h2')]:
        run_dir=root/'results/fixture'/run;run_dir.mkdir(parents=True)
        c=cfg.model_dump();c['experiment']['name']=run
        options=[] if condition!='B' else ['-f','ip and (tcp or udp)'];c['aguri']['options']=options
        text=yaml.safe_dump(c);local=cfg.model_copy(update={'aguri':cfg.aguri.model_copy(update={'options':options})})
        prefixes=[] if empty else (['192.0.2.0/24'] if condition=='A' else ['192.0.2.0/24',TARGET] if condition=='B' else [TARGET])
        raw=''.join(f'[{i}] {p} *: 100 (10.00%) 10 (10.00%)\n' for i,p in enumerate(prefixes,1))
        cache=root/'data/fixture/processed'/('aguri/'+condition if condition!='C' else 'prime/C');cache.mkdir(parents=True)
        rendered=cache/'raw.txt';rendered.write_text(raw)
        if condition!='C':
            candidates=pd.DataFrame(parse_aguri_output(raw),columns=AGURI_CANDIDATE_COLUMNS);cp=cache/'aguri_candidates.csv';candidates.to_csv(cp,index=False)
            exes={}
            for name in ('aguri3','agurim'):
                exe=root/'bin'/name;exe.parent.mkdir(exist_ok=True);exe.write_text('synthetic '+name+'; must never execute')
                exes[name]={'path':str(exe),'sha256':sha256_file(exe),'version':'synthetic; not executed'}
            identity=dict(schema_version='aguri-v1',input_sha256=capture,agurim_submodule_sha=PINNED_AGURIM_SHA,
                          executable_sha256={k:v['sha256'] for k,v in exes.items()},options=options)
            fingerprint=stable_json_hash(identity);agr=cache/'raw.agr';agr.write_text('synthetic intermediate')
            cm=cache/'aguri_manifest.json'
            save(cm,dict(schema_version='aguri-v1',status='success',input_sha256=capture,agurim_submodule_sha=PINNED_AGURIM_SHA,
                fingerprint=fingerprint,options=options,executables=exes,candidate_count=len(candidates),
                artifacts={'candidates_csv':str(cp),'rendered_text':str(rendered),'raw_agr':str(agr)},
                commands=[{'argv':[exes['aguri3']['path'],*options,'-r','synthetic.pcap','-w',str(agr)],'returncode':0},
                          {'argv':[exes['agurim']['path'],'-w',str(rendered),str(agr)],'returncode':0}]))
            producer=dict(aguri_fingerprint=fingerprint,aguri_candidates_sha256=sha256_file(cp),cache_manifest_sha256=sha256_file(cm))
            cache_record={'aguri':{'manifest_path':str(cm),'fingerprint':fingerprint}}
            candidate_name='aguri_candidates';selection=None
        else:
            candidates=_parse_control(raw);cp=cache/'prime_candidates.csv';candidates.to_csv(cp,index=False)
            binary=cache/'canonical.bin'
            with binary.open('wb') as stream:
                for row in rows:
                    if row['ip_version']==4:
                        stream.write(struct.pack('!16s16sHHBBHIIII',ipaddress.ip_address(row['src_ip']).packed.ljust(16,b'\0'),ipaddress.ip_address(row['dst_ip']).packed.ljust(16,b'\0'),0,0,4,6,0,row['packet_count'],row['byte_count'],0,0))
            exe=root/'bin/agurim-prime';exe.write_text('synthetic prime; must never execute')
            source=dict(path=str(flows),csv_sha256=sha256_file(flows),manifest_path=str(fm),manifest_sha256=sha256_file(fm),flow_fingerprint=fp,row_count=len(rows),capture_sha256=capture)
            fork={'schema_version':'agurim-prime-build-v1','status':'success','upstream_commit':PINNED_AGURIM_SHA,
                  'patch_sha256':sha256_file(ROOT/'vendor/agurim-prime/flow-mode.patch'),'executable_sha256':sha256_file(exe),
                  'fork_commit':None,'compiler':'synthetic fixture; no compilation','compiler_argv':['synthetic-cc','not-executed'],
                  'source_sha256':{'agurim.c':hashlib.sha256(b'synthetic source').hexdigest()}}
            fork['fork_identity']=stable_json_hash({k:fork[k] for k in ('upstream_commit','patch_sha256')})
            build=exe.with_name('build_manifest.json');save(build,fork)
            identity={'schema_version':'agurim-prime-v1','basis':'packet','input':source,'executable_sha256':sha256_file(exe),
                      'threshold':1,'options':['-F','-m','packet','-t','1','-n','0','-D','-D'],
                      'fork':{**fork,'build_manifest_sha256':sha256_file(build)},
                      'converter_version':CONVERTER_VERSION,
                      'implementation_sha256':{n:sha256_file(ROOT/'src/mawi_global_analysis/agurim_prime'/n) for n in ('input.py','stage.py')}}
            fingerprint=stable_json_hash(identity);cm=cache/'prime_manifest.json'
            save(cm,dict(status='success',identity=identity,fingerprint=fingerprint,candidate_count=len(candidates),
                audit={'input_rows':len(rows),'included_flows':max(0,len(rows)-1),'excluded_ipv6':int(bool(rows)),'excluded_protocol':0,
                       'included_packets':sum(r['packet_count'] for r in rows if r['ip_version']==4),
                       'included_frame_bytes':sum(r['byte_count'] for r in rows if r['ip_version']==4),
                       'unit_packets':False,'scope':'IPv4 TCP/UDP','orientation':'first observed packet; not initiator/responder'},
                count_semantics='HHH discounted residuals',command={'argv':[str(exe),*identity['options']],'returncode':0},
                artifacts={k:{'name':p.name,'sha256':sha256_file(p)} for k,p in [('binary_input',binary),('rendered',rendered),('candidates',cp)]}))
            producer={'prime_fingerprint':fingerprint,'prime_candidates_sha256':sha256_file(cp),'cache_manifest_sha256':sha256_file(cm)}
            cache_record={'agurim_prime':{'manifest_path':str(cm),'fingerprint':fingerprint}}
            candidate_name='agurim_prime_candidates';selection={'method':METHODS['packet'],'basis':'packet','prime_fingerprint':fingerprint,'additional_filters':[],'top_k':None,'endpoint_orientation':'first_observed'}
        ledger=build_corrected_prefix_ledger(candidates,local);pp=run_dir/'prefixes.csv';ledger.to_csv(pp,index=False)
        members=build_membership(pd.DataFrame(rows,columns=FLOW_COLUMNS),ledger);mp=run_dir/'flow_prefix_membership.csv';members.to_csv(mp,index=False)
        manifest=dict(status='success',dataset_id='fixture',run_name=run,input={'sha256':capture,'path':str(root/'synthetic.pcap')},config={'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()},
            artifacts={'flows':entry(flows,rows),candidate_name:entry(cp,candidates,producer),'prefixes':entry(pp,ledger,producer),
                       'flow_prefix_membership':entry(mp,members,{**producer,'prefixes_sha256':sha256_file(pp)})},
            cache={'flows':{'fingerprint':fp,'manifest_path':str(fm)},**cache_record},evidence_level='synthetic_fixture_only')
        if selection:manifest.update(schema_version='agurim-prime-run-v1',selection=selection,implementation_sha256={n:sha256_file(ROOT/'src/mawi_global_analysis'/n) for n in ('agurim_prime/stage.py','prefix.py','membership.py')})
        save(run_dir/'run_manifest.json',manifest)
    return root


@pytest.fixture
def abc(tmp_path):return fixture_root(tmp_path/'inputs')


def validate(root):return api('validation').validate_inputs(root,'fixture',chunksize=2)


def test_accepts_dedicated_abc_contract_readonly(abc):
    before=state(abc);data=validate(abc)
    assert data['status']=='valid' and data['ab_bpf_only'] is True
    assert data['common']['canonical']['row_count']==7
    assert data['runs']['B']['bpf']=='ip and (tcp or udp)'
    assert data['runs']['C']['selection_input']=='canonical flows'
    assert state(abc)==before


def test_rejects_bpf_mismatch(abc):
    p=abc/'results/fixture/agurim-ipv4-tcp-udp/run_manifest.json';d=json.loads(p.read_text())
    c=yaml.safe_load(d['config']['text']);c['aguri']['options']=['-f','tcp'];s=yaml.safe_dump(c)
    d['config']={'text':s,'hash':hashlib.sha256(s.encode()).hexdigest()};save(p,d)
    with pytest.raises(ValueError,match='BPF|options|filter'):validate(abc)


def test_rejects_other_canonical_hash(abc):
    p=abc/'results/fixture/baseline/run_manifest.json';d=json.loads(p.read_text());d['input']['sha256']='a'*64;save(p,d)
    with pytest.raises(ValueError):validate(abc)


def test_rejects_stale_corrected_ledger(abc):
    p=abc/'results/fixture/baseline/prefixes.csv';p.write_text(p.read_text().replace('192.0.2.0/24','192.0.2.0/25'))
    with pytest.raises(ValueError):validate(abc)


def analyze(root,output,**kwargs):
    return api('analysis').analyze_inputs(root,'fixture',output,chunksize=kwargs.pop('chunksize',2),**kwargs)


def test_exact_sets_counts_ecdf_and_shared_flow_exclusion(abc,tmp_path):
    before=state(abc);got=analyze(abc,tmp_path/'out');assert state(abc)==before
    assert got['overall']['flow_count']==6 and got['overall']['packet_total']==19
    assert got['overall']['byte_total']==1960
    assert [got['conditions'][m]['stats']['flow_count'] for m in 'ABC']==[3,5,3]
    assert [got['conditions'][m]['stats']['median'] for m in 'ABC']==[4,1,1]
    assert got['conditions']['A']['coverage']['packet']==pytest.approx(15/19)
    assert got['conditions']['B']['ks_numerator']=='1' and got['conditions']['B']['ks_denominator']=='10'
    assert got['conditions']['C']['ks_distance']==.5
    assert got['curves']['B']['points'][-1]['cumulative_fraction']==1
    pair={(r['condition_a'],r['condition_b'],r['set_kind']):r for r in got['jaccard']}
    assert pair['A','B','native_prefix']['jaccard']==.5
    assert pair['A','B','flow_id']['jaccard']==.6
    assert pair['A','C','flow_id']['jaccard']==.2
    b=got['sensitivities']['B'];c=got['sensitivities']['C']
    assert b['after']['flow_count']==3 and b['after']['median']==4 and b['removed_flow_count']==2
    assert c['after']['flow_count']==0 and c['after']['median'] is None
    target=got['focus']['A'];assert not target['selected'] and not target['candidate_covering']
    assert target['flow_count']==3 and target['one_packet_count']==3 and target['in_union_flow_count']==1
    assert got['focus']['B']['union_share']==.6
    rows=list(csv.DictReader((tmp_path/'out/modes/B/frequencies.csv').open()))
    assert [(r['packet_count'],r['frequency']) for r in rows if r['distribution']==TARGET]==[('1','3')]
    assert got['components']['B_only_union']['flow_count']==2
    assert got['components']['B_added_prefix_union']['flow_count']==3


def test_empty_and_zero_denominators(tmp_path):
    root=fixture_root(tmp_path/'empty',empty=True);got=analyze(root,tmp_path/'out')
    assert got['overall']['flow_count']==0
    assert all(r['coverage']['flow'] is None and r['ks_distance'] is None for r in got['conditions'].values())
    assert all(r['jaccard'] is None for r in got['jaccard'])
    assert got['focus']['A']['union_share'] is None


def test_chunk_and_display_limit_preserve_exact_outputs(abc,tmp_path):
    a=analyze(abc,tmp_path/'a',chunksize=1,max_ecdf_points=2)
    b=analyze(abc,tmp_path/'b',chunksize=99,max_ecdf_points=2000)
    assert a['conditions']==b['conditions'] and a['sensitivities']==b['sensitivities']
    for path in (tmp_path/'a').rglob('*.csv'):assert path.read_bytes()==(tmp_path/'b'/path.relative_to(tmp_path/'a')).read_bytes()


def test_rehashed_corrupt_native_edges_are_rejected(abc,tmp_path):
    p=abc/'results/fixture/agurim-ipv4-tcp-udp/flow_prefix_membership.csv'
    frame=pd.read_csv(p);frame=frame.drop(frame.index[frame.analysis_scope=='native'][0]);frame.to_csv(p,index=False)
    mp=p.with_name('run_manifest.json');m=json.loads(mp.read_text());m['artifacts']['flow_prefix_membership'].update(row_count=len(frame),sha256=sha256_file(p));save(mp,m)
    with pytest.raises(ValueError,match='membership'):analyze(abc,tmp_path/'out')


def test_generation_and_hash_verification_are_readonly(abc,tmp_path):
    before=state(abc);mod=api('generation');path=mod.generate(abc,'fixture',tmp_path/'bundle',chunksize=1)
    assert state(abc)==before and mod.verify_manifest(path)['status']=='success'
    assert (path.parent/'dashboard.html').is_file()
    with (path.parent/'ecdf_counts.csv').open('a') as stream:stream.write('bad\n')
    with pytest.raises(ValueError,match='SHA-256'):mod.verify_manifest(path)
    with pytest.raises(FileExistsError):mod.generate(abc,'fixture',tmp_path/'bundle')


def test_validation_failure_and_publication_failure_leave_no_success(abc,tmp_path,monkeypatch):
    import os
    mod=api('generation');link=os.link
    def fail(source,target,*a,**k):
        if Path(target).name=='comparison_manifest.json':raise OSError('simulated publication failure')
        return link(source,target,*a,**k)
    monkeypatch.setattr(os,'link',fail)
    with pytest.raises(OSError,match='publication failure'):mod.generate(abc,'fixture',tmp_path/'failed')
    assert not (tmp_path/'failed').exists()


def test_historical_reference_compares_exact_ids_and_frequencies(abc,tmp_path):
    ref=tmp_path/'reference';ref.mkdir()
    with (ref/'union_flow_ids.csv').open('w') as s:s.write('flow_id\nf0\nf1\nf3\n')
    with (ref/'frequencies.csv').open('w') as s:s.write('packet_count,frequency\n1,1\n4,1\n10,1\n')
    validation=validate(abc);c=validation['common']['canonical']
    save(ref/'legacy_manifest.json',{'schema_version':'society-union-reference-v1',
        'canonical_csv_sha256':c['csv_sha256'],'input_capture_sha256':c['capture_sha256'],
        'selected_native_prefixes':['192.0.2.0/24'],'quantile_rule':'pandas default linear',
        'statistics':{'flow_count':3,'median':4},'artifacts':{k:{'path':p,'sha256':sha256_file(ref/p)} for k,p in [('flow_ids','union_flow_ids.csv'),('frequencies','frequencies.csv')]}})
    got=api('generation').generate(abc,'fixture',tmp_path/'out',legacy_reference=ref/'legacy_manifest.json')
    result=json.loads((got.parent/'legacy_comparison.json').read_text())
    assert result['supplied_reference_matches'] and result['flow_ids_equal'] and result['frequencies_equal']
    assert not result['historical_reproduction_verified']


def test_offline_renderer_escapes_payload():
    from test_rls_weight_comparison_dashboard import Document
    html=api('dashboard').render({'dataset_id':'</script><img src=x onerror=alert(1)>','conditions':{},'prefixes':[]})
    doc=Document(html);assert len(doc.scripts)==2 and not doc.external
    assert "connect-src 'none'" in doc.csp
    assert '\\u003c/script\\u003e' in html


def reseal_old(root,edit):
    mp=root/'results/fixture/baseline/run_manifest.json';m=json.loads(mp.read_text())
    cp=Path(m['cache']['aguri']['manifest_path']);cache=json.loads(cp.read_text());edit(cache);save(cp,cache)
    for r in m['artifacts'].values():
        if 'cache_manifest_sha256' in r.get('producer',{}):r['producer']['cache_manifest_sha256']=sha256_file(cp)
    save(mp,m)


def test_manifest_command_must_bind_the_recorded_pcap(abc):
    reseal_old(abc,lambda c:c['commands'][0]['argv'].__setitem__(-3,'other-capture.pcap'))
    with pytest.raises(ValueError,match='input|PCAP'):validate(abc)


def test_cli_validate_only_never_writes_or_executes_or_reads_pcap(abc,tmp_path,monkeypatch):
    import subprocess
    def forbidden(*a,**k):pytest.fail('PCAP/selector execution is forbidden')
    monkeypatch.setattr(subprocess,'run',forbidden)
    original=Path.open
    def guarded(path,*a,**k):
        if path.suffix=='.pcap':pytest.fail('PCAP was opened')
        return original(path,*a,**k)
    monkeypatch.setattr(Path,'open',guarded)
    before=state(abc)
    assert api('cli').main(['--root',str(abc),'--dataset','fixture','--validate-only'])==0
    assert state(abc)==before
    assert api('cli').main(['--root',str(abc),'--dataset','fixture','--output-dir',str(tmp_path/'out')])==0


def test_readonly_validation_rejects_other_agurim_options(abc):
    reseal_old(abc,lambda c:c['commands'][1]['argv'].insert(1,'-D'))
    with pytest.raises(ValueError,match='Agurim argv'):validate(abc)


@pytest.mark.parametrize('target',['data/new-comparison','results/new-comparison'])
def test_protected_output_is_refused(abc,target):
    with pytest.raises(ValueError):api('generation').generate(abc,'fixture',abc/target)
    assert not (abc/target).exists()


def test_source_change_after_aggregation_prevents_publication(abc,tmp_path,monkeypatch):
    mod=api('generation');real=mod.analyze_inputs
    def change(*a,**k):
        result=real(*a,**k)
        with (abc/'data/fixture/processed/flows/flows.csv').open('a') as stream:stream.write('\n')
        return result
    monkeypatch.setattr(mod,'analyze_inputs',change)
    with pytest.raises(ValueError):mod.generate(abc,'fixture',tmp_path/'failed')
    assert not (tmp_path/'failed').exists()
