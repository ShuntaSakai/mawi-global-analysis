"""Canonical-input Aguri3→Agurim, immutable caches and corrected membership."""
from __future__ import annotations
import csv
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import pandas as pd
import yaml

from mawi_global_analysis.agurim_prime.input import CONVERTER_VERSION,convert_flows
from mawi_global_analysis.agurim_prime.stage import REPO,_source,_verify_source,_json,_entry
from mawi_global_analysis.config import ExperimentConfig
from mawi_global_analysis.hashing import sha256_file,stable_json_hash
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS,build_membership
from mawi_global_analysis.prefix import build_corrected_prefix_ledger
from .wire import read_wire

MODES=('packet','byte','flow')
ALL_MODES=(*MODES,'combination')
PATCHES=('vendor/agurim-prime/flow-mode.patch','vendor/agurim-two-stage/two-stage.patch')
PIN='ab5c5cc80e9e1229bb66ec83bb25f186898d5e49'
FILES={'binary_input':'canonical.bin','intermediate':'stage1.agw','rendered':'stage2.agw','candidates':'candidates.csv'}
COLUMNS=('aggregate_id','src_prefix','dst_prefix','discounted_packets','discounted_bytes','discounted_flow_count')

def save(path,value):
    with Path(path).open('w',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n');stream.flush();os.fsync(stream.fileno())

def publish(work: Path,output: Path,completion: str):
    output.mkdir();files=[]
    try:
        for p in sorted(work.iterdir(),key=lambda p:p.name==completion):
            if not p.is_file():raise ValueError('unexpected staged directory')
            os.link(p,output/p.name);files.append(output/p.name)
    except BaseException:
        for p in files:
            if p.exists() and p.samefile(work/p.name):p.unlink()
        try:output.rmdir()
        except OSError:pass
        raise

def settings(mode,threshold=1,heuristics=0,max_hashentries=1000000):
    if mode not in ALL_MODES:raise ValueError('unknown aggregation basis')
    for k,v,lo,hi in [('threshold',threshold,1,100),('heuristics',heuristics,0,2),('max_hashentries',max_hashentries,1,2**31-1)]:
        if type(v) is not int or not lo<=v<=hi:raise ValueError(f'{k}: integer in [{lo},{hi}] required')
    return dict(threshold=threshold,heuristics=heuristics,max_hashentries=max_hashentries,interval=0,output_interval=0,
                top_k=None,quickmerge='upstream-packet-fixed',protocol_deficit='audit only; preserve old no-label fallback')

def options(mode,s,stage):
    result=['-W','-m',mode,'-t',str(s['threshold']),*(['-D']*s['heuristics'])]
    return [*result,'-H',str(s['max_hashentries'])] if stage==1 else [*result,'-n','0']

def implementation():
    package=Path(__file__).resolve().parents[1]
    names=('aguri_two_stage/stage.py','aguri_two_stage/wire.py','agurim_prime/input.py','prefix.py','membership.py')
    return {n:sha256_file(package/n) for n in names}

def build_identity(folder):
    folder=Path(folder).resolve();path=folder/'build_manifest.json';build=_json(path)
    chain=[{'path':n,'sha256':sha256_file(REPO/n)} for n in PATCHES]
    if (build.get('schema_version')!='aguri-two-stage-build-v1' or build.get('status')!='success'
            or build.get('upstream_commit')!=PIN or build.get('patches')!=chain
            or build.get('fork_identity')!=stable_json_hash(dict(upstream_commit=PIN,patches=chain))
            or 'fork_commit' not in build or not isinstance(build.get('compiler'),str)
            or set(build.get('compiler_argv',{}))!={'aguri3','agurim'}):raise ValueError('two-stage build lineage mismatch; rebuild fork')
    commit=build['fork_commit']
    if commit is not None and (not isinstance(commit,str) or re.fullmatch('[0-9a-f]{40}',commit) is None):raise ValueError('invalid build fork_commit')
    if not build['compiler'].strip() or any(not isinstance(v,list) or not v or any(not isinstance(x,str) or not x for x in v) for v in build['compiler_argv'].values()):raise ValueError('invalid compiler metadata')
    required={'aguri3.c','agurim.c','weights.c','agurim.h','hhh.c','odflow.c','agurim_plot.c','agurim_subr.c','aguri_flow.h','ip_parse.c','ip_parse.h','pcap_parse.c','Makefile'}
    sources=build.get('source_sha256',{})
    if set(sources)!=required:raise ValueError('two-stage build source inventory mismatch')
    for name,checksum in sources.items():
        if sha256_file(folder/'src'/name)!=checksum:raise ValueError('build source checksum mismatch: '+name)
    binaries=build.get('executable_sha256',{})
    if set(binaries)!={'aguri3','agurim'}:raise ValueError('both stage executables required')
    for name,checksum in binaries.items():
        if sha256_file(folder/name)!=checksum:raise ValueError('build executable checksum mismatch: '+name)
    return {**build,'build_manifest_path':str(path),'build_manifest_sha256':sha256_file(path)}

def _candidate(row,index):
    return dict(aggregate_id=str(index),src_prefix=row['src_prefix'],dst_prefix=row['dst_prefix'],
                discounted_packets=str(row['packets']),discounted_bytes=str(row['bytes']),discounted_flow_count=str(row['flows']))

def cache_verify(path,identity,fingerprint):
    m=_json(path/'two_stage_manifest.json')
    if m.get('status')!='success' or m.get('identity')!=identity or m.get('fingerprint')!=fingerprint or stable_json_hash(identity)!=fingerprint:
        raise ValueError('two-stage cache identity mismatch')
    if set(m.get('artifacts',{}))!=set(FILES):raise ValueError('two-stage cache missing artifacts')
    for key,name in FILES.items():
        if m['artifacts'][key].get('name')!=name or sha256_file(path/name)!=m['artifacts'][key].get('sha256'):raise ValueError('cache checksum mismatch: '+key)
    from mawi_global_analysis.aguri_selection_comparison.binary import verify_canonical_binary
    binary=verify_canonical_binary(Path(identity['input']['path']),path/'canonical.bin')
    audit=m['audits']['input']
    for k,v in binary['audit'].items():
        if audit.get(k)!=v:raise ValueError('canonical binary audit mismatch: '+k)
    if audit['input_rows']!=identity['input']['row_count']:raise ValueError('canonical row count mismatch')
    expected={'mode':identity['basis'],**{k:identity['settings'][k] for k in ('threshold','heuristics','max_hashentries')}}
    stage1=read_wire(path/'stage1.agw',expected={**expected,'stage':1})
    index=0
    with (path/'candidates.csv').open(newline='') as stream:
        rows=csv.DictReader(stream,strict=True)
        if rows.fieldnames!=list(COLUMNS):raise ValueError('candidate schema mismatch')
        def check(row):
            nonlocal index
            index+=1
            if next(rows,None)!=_candidate(row,index):raise ValueError('candidate differs from stage2 residual')
        stage2=read_wire(path/'stage2.agw',expected={**expected,'stage':2},on_address=check)
        if next(rows,None) is not None:raise ValueError('candidate has extra rows')
    if index!=m.get('candidate_count'):raise ValueError('candidate count mismatch')
    totals=dict(packet=audit['included_packets'],byte=audit['included_frame_bytes'],flow=audit['included_flows'])
    if stage1['totals']!=totals or stage2['totals']!=totals:raise ValueError('two-stage input/residual counter mismatch')
    if m['audits'].get('stage1')!=stage1 or m['audits'].get('stage2')!=stage2:raise ValueError('wire audit mismatch')
    commands=m.get('commands')
    if not isinstance(commands,list) or len(commands)!=2:raise ValueError('both stage commands required')
    for i,(program,src,dst) in enumerate([('aguri3','binary_input','intermediate'),('agurim','intermediate','rendered')],1):
        c=commands[i-1];exe=Path(identity['build']['build_manifest_path']).parent/program
        if (c.get('argv')!=[str(exe),*options(identity['basis'],identity['settings'],i)] or type(c.get('returncode')) is not int or c['returncode']!=0
                or c.get('stdin')!=m['artifacts'][src] or c.get('stdout')!=m['artifacts'][dst]):raise ValueError(f'stage{i} command/input/output binding mismatch')
    return m

def _cache(root,dataset,source,cfg,build,mode,s):
    identity=dict(schema_version='aguri-two-stage-cache-v1',basis=mode,input=source,build=build,settings=s,
        converter_version=CONVERTER_VERSION,wire_version='aguri-weight-wire-v1',implementation_sha256=implementation())
    fp=stable_json_hash(identity);parent=root/'data'/dataset/'processed/aguri-two-stage';path=parent/fp
    if path.is_symlink():raise ValueError('cache symlink not accepted')
    if path.exists():return path,cache_verify(path,identity,fp),'reused'
    parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.two-stage-',dir=parent) as temp:
        work=Path(temp);audit=convert_flows(Path(source['path']),work/'canonical.bin')
        if audit['input_rows']!=source['row_count']:raise ValueError('canonical row count mismatch')
        commands=[]
        for i,(program,src,dst) in enumerate([('aguri3','canonical.bin','stage1.agw'),('agurim','stage1.agw','stage2.agw')],1):
            argv=[str(Path(build['build_manifest_path']).parent/program),*options(mode,s,i)]
            with (work/src).open('rb') as inp,(work/dst).open('wb') as out:
                r=subprocess.run(argv,stdin=inp,stdout=out,stderr=subprocess.PIPE,check=False)
            if r.returncode:raise ValueError(f'{program} failed ({r.returncode}): {r.stderr.decode(errors="replace")}')
            commands.append(dict(argv=argv,returncode=r.returncode,stderr=r.stderr.decode(errors='replace')))
        expected={'mode':mode,**{k:s[k] for k in ('threshold','heuristics','max_hashentries')}}
        one=read_wire(work/'stage1.agw',expected={**expected,'stage':1});count=0
        with (work/'candidates.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=COLUMNS,lineterminator='\n');writer.writeheader()
            def write(row):
                nonlocal count
                count+=1;writer.writerow(_candidate(row,count))
            two=read_wire(work/'stage2.agw',expected={**expected,'stage':2},on_address=write)
        artifacts={k:{'name':n,'sha256':sha256_file(work/n)} for k,n in FILES.items()}
        for c,(src,dst) in zip(commands,[('binary_input','intermediate'),('intermediate','rendered')]):c.update(stdin=artifacts[src],stdout=artifacts[dst])
        m=dict(schema_version='aguri-two-stage-cache-v1',status='success',identity=identity,fingerprint=fp,commands=commands,
               artifacts=artifacts,audits=dict(input=audit,stage1=one,stage2=two),candidate_count=count)
        save(work/'two_stage_manifest.json',m);cache_verify(work,identity,fp);_verify_source(source)
        if build_identity(Path(build['build_manifest_path']).parent)!=build:raise ValueError('build changed during processing')
        publish(work,path,'two_stage_manifest.json')
    return path,m,'completed'

def run_two_stage(root: Path,dataset_id: str,run_name: str,flows: Path,build_dir: Path,*,mode='flow',threshold=1,heuristics=0,max_hashentries=1000000,chunksize=100000)->Path:
    root,flows,build_dir=(Path(p).expanduser().resolve() for p in (root,flows,build_dir))
    for value in (dataset_id,run_name):
        if not value or Path(value).name!=value or value in ('.','..'):raise ValueError('dataset/run must be single names')
    if type(chunksize) is not int or chunksize<1:raise ValueError('chunksize must be positive')
    s=settings(mode,threshold,heuristics,max_hashentries);run=root/'results'/dataset_id/run_name
    if run.is_symlink() or run.exists():raise FileExistsError(run)
    source,fm,cfg=_source(flows)
    if cfg.flow.inactive_timeout_seconds is not None or sorted(cfg.flow.protocols)!=['tcp','udp']:raise ValueError('two-stage canonical input requires TCP/UDP and timeout=null')
    build=build_identity(build_dir);cache,cm,status=_cache(root,dataset_id,source,cfg,build,mode,s)
    cfgdata=cfg.model_dump();cfgdata['experiment']={'name':'aguri-two-stage-'+mode,'description':'Canonical Aguri3→Agurim; fixed settings; Raw'}
    cfg=ExperimentConfig.model_validate(cfgdata);text=yaml.safe_dump(cfg.model_dump(),sort_keys=False)
    candidate=cache/'candidates.csv';producer=dict(flow_fingerprint=fm['fingerprint'],two_stage_fingerprint=cm['fingerprint'],
        two_stage_candidates_sha256=sha256_file(candidate),cache_manifest_sha256=sha256_file(cache/'two_stage_manifest.json'))
    ledger=build_corrected_prefix_ledger(pd.read_csv(candidate),cfg);run.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.two-stage-run-',dir=run.parent) as temp:
        work=Path(temp);ledger.to_csv(work/'prefixes.csv',index=False);count=0
        with (work/'flow_prefix_membership.csv').open('w',newline='') as stream:
            csv.writer(stream).writerow(MEMBERSHIP_COLUMNS)
            for chunk in pd.read_csv(flows,chunksize=chunksize,dtype={'flow_id':str}):
                edges=build_membership(chunk,ledger);edges.to_csv(stream,index=False,header=False);count+=len(edges)
        artifacts={'flows':_entry(flows,source['row_count'],dict(flow_fingerprint=fm['fingerprint'],cache_manifest_path=source['manifest_path'],cache_manifest_sha256=source['manifest_sha256'])),
            'aguri_two_stage_candidates':_entry(candidate,cm['candidate_count'],producer),
            'prefixes':_entry(work/'prefixes.csv',len(ledger),producer),
            'flow_prefix_membership':_entry(work/'flow_prefix_membership.csv',count,{**producer,'prefixes_sha256':sha256_file(work/'prefixes.csv')})}
        for key in ('prefixes','flow_prefix_membership'):artifacts[key]['path']=str(run/Path(artifacts[key]['path']).name)
        m=dict(schema_version='aguri-two-stage-run-v1',status='success',dataset_id=dataset_id,run_name=run_name,input={'sha256':source['capture_sha256']},
            config={'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()},
            selection=dict(method='aguri-two-stage-'+mode,basis=mode,two_stage_fingerprint=cm['fingerprint'],top_k=None,additional_filters=[],endpoint_orientation='first_observed'),
            cache=dict(flows={'fingerprint':fm['fingerprint'],'manifest_path':source['manifest_path']},aguri_two_stage={'fingerprint':cm['fingerprint'],'manifest_path':str(cache/'two_stage_manifest.json')}),
            stages=[{'name':'flows','status':'reused'},{'name':'aguri3','status':status},{'name':'agurim','status':status},{'name':'membership','status':'completed'}],
            artifacts=artifacts,implementation_sha256=implementation(),evidence_level='synthetic_or_manual_execution; real MAWI validation not asserted')
        save(work/'run_manifest.json',m);_verify_source(source)
        if cache_verify(cache,cm['identity'],cm['fingerprint'])!=cm:raise ValueError('cache changed during run')
        publish(work,run,'run_manifest.json')
    return run/'run_manifest.json'
