"""Immutable canonical-input Agurim prime runs and provenance."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile

import pandas as pd
import yaml

from mawi_global_analysis.aguri import PINNED_AGURIM_SHA, _AGGREGATE_RE
from mawi_global_analysis.config import ExperimentConfig, load_config
from mawi_global_analysis.flow_stage import FLOW_SCHEMA_VERSION, _validate_cache_manifest, _validate_cached_flows
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config, sha256_file, stable_json_hash
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS, build_membership
from mawi_global_analysis.prefix import build_corrected_prefix_ledger
from .input import CONVERTER_VERSION, convert_flows

REPO = Path(__file__).resolve().parents[3]
METHODS = {'flow':'agurim-prime','byte':'agurim-canonical-byte',
           'packet':'agurim-canonical-packet','unit-packet':'agurim-unit-packet-probe'}


def _json(path: Path) -> dict:
    value=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value,dict):
        raise ValueError(f'manifest must be an object: {path}')
    return value


def _save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def _entry(path: Path, count: int, producer: dict | None = None) -> dict:
    return {'path':str(path.resolve()),'row_count':count,'sha256':sha256_file(path),
            'producer':producer or {}}


def _source(flows: Path) -> tuple[dict, dict, ExperimentConfig]:
    manifest_path=flows.parent/'flow_manifest.json'
    fm=_json(manifest_path)
    cfg=load_config(REPO/'configs/baseline.yaml')
    data=cfg.model_dump()
    data['flow']=fm.get('flow_config')
    cfg=ExperimentConfig.model_validate(data)
    capture=fm.get('input_sha256')
    if (not isinstance(capture,str) or len(capture)!=64
            or any(c not in '0123456789abcdef' for c in capture)):
        raise ValueError('invalid canonical input capture checksum')
    count=_validate_cache_manifest(manifest_path,input_sha256=capture,
        fingerprint=flow_fingerprint(capture,cfg,FLOW_SCHEMA_VERSION),flow_config=flow_generation_config(cfg))
    _validate_cached_flows(flows,count)
    source={'path':str(flows),'csv_sha256':sha256_file(flows),
            'manifest_path':str(manifest_path),'manifest_sha256':sha256_file(manifest_path),
            'flow_fingerprint':fm['fingerprint'],'row_count':count,'capture_sha256':capture}
    if fm.get('flows_sha256',source['csv_sha256'])!=source['csv_sha256']:
        raise ValueError('canonical flow checksum mismatch')
    return source,fm,cfg


def _fork(executable: Path) -> tuple[dict, str]:
    build=_json(executable.parent/'build_manifest.json')
    digest=sha256_file(executable)
    if build.get('executable_sha256')!=digest:
        raise ValueError('fork executable checksum differs from build manifest')
    if build.get('upstream_commit')!=PINNED_AGURIM_SHA:
        raise ValueError('unexpected fork upstream commit')
    patch=sha256_file(REPO/'vendor/agurim-prime/flow-mode.patch')
    if build.get('patch_sha256')!=patch:
        raise ValueError('fork build uses a different source patch; rebuild it')
    return {**build,'build_manifest_sha256':sha256_file(executable.parent/'build_manifest.json')},digest


def _parse_control(text: str) -> pd.DataFrame:
    """Read upstream weighted aggregates, accepting its protocol wildcard syntax."""
    rows=[]
    protocol=re.compile(r'(?:\[(?:\*|\d+):[^:\]]+:[^\]]+\]\s+\d+(?:\.\d+)?%\s+\d+(?:\.\d+)?%\s*)+')
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith('%'):
            continue
        match=_AGGREGATE_RE.fullmatch(line)
        if match:
            rows.append({'aggregate_id':match['id'],'src_prefix':match['src'],'dst_prefix':match['dst'],
                         'discounted_bytes':match['bytes'].replace(',',''),
                         'discounted_packets':match['packets'].replace(',',''),
                         'byte_ratio':match['byte_ratio'],'packet_ratio':match['packet_ratio']})
        elif not rows or not raw[:1].isspace() or not protocol.fullmatch(line):
            raise ValueError(f'unparsed canonical control output: {line}')
    return pd.DataFrame(rows,columns=['aggregate_id','src_prefix','dst_prefix','discounted_bytes',
                                     'discounted_packets','byte_ratio','packet_ratio'])


def _options(mode: str, threshold: int, heuristics: int) -> list[str]:
    if mode not in METHODS:
        raise ValueError('unknown aggregation basis')
    if type(threshold) is not int or not 1<=threshold<=100:
        raise ValueError('threshold must be an integer percentage in [1,100]')
    if type(heuristics) is not int or not 0<=heuristics<=2:
        raise ValueError('disable-heuristics must be 0, 1 or 2')
    return ['-F','-m','packet' if mode=='unit-packet' else mode,'-t',str(threshold),'-n','0',*(['-D']*heuristics)]


def _verify_source(source: dict) -> None:
    if (sha256_file(Path(source['path']))!=source['csv_sha256']
            or sha256_file(Path(source['manifest_path']))!=source['manifest_sha256']):
        raise ValueError('canonical inputs changed during prime processing')


def _verify_cache(path: Path, identity: dict, fingerprint: str) -> dict:
    manifest=_json(path/'prime_manifest.json')
    if (manifest.get('status')!='success' or manifest.get('identity')!=identity
            or manifest.get('fingerprint')!=fingerprint):
        raise ValueError('prime cache identity mismatch or incomplete cache')
    artifacts=manifest.get('artifacts',{})
    if set(artifacts)!={'binary_input','rendered','candidates'}:
        raise ValueError('prime cache missing artifacts')
    for name,entry in artifacts.items():
        # Resolve relative names only inside this exact immutable cache.
        expected={'binary_input':'canonical.bin','rendered':'raw.txt','candidates':'prime_candidates.csv'}[name]
        if entry.get('name')!=expected or sha256_file(path/expected)!=entry.get('sha256'):
            raise ValueError(f'prime cache checksum mismatch: {name}')
    with (path/'prime_candidates.csv').open(newline='') as stream:
        count=sum(1 for _ in csv.DictReader(stream))
    if count!=manifest.get('candidate_count'):
        raise ValueError('prime cache candidate row count mismatch')
    return manifest


def _cache(root: Path, dataset: str, source: dict, fm: dict, executable: Path,
           mode: str, threshold: int, heuristics: int) -> tuple[Path,dict,str]:
    fork,executable_sha=_fork(executable)
    options=_options(mode,threshold,heuristics)
    identity={'schema_version':'agurim-prime-v1','basis':mode,'input':source,
        'fork':fork,'executable_sha256':executable_sha,'threshold':threshold,'options':options,
        'converter_version':CONVERTER_VERSION,
        'implementation_sha256':{name:sha256_file(Path(__file__).with_name(name)) for name in ('input.py','stage.py')}}
    fingerprint=stable_json_hash(identity)
    parent=root/'data'/dataset/'processed/agurim-prime'
    path=parent/fingerprint
    if path.exists():
        return path,_verify_cache(path,identity,fingerprint),'reused'
    parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.prime-',dir=parent) as temp:
        work=Path(temp)
        audit=convert_flows(Path(source['path']),work/'canonical.bin',unit_packets=mode=='unit-packet',
                            allow_segments=fm['flow_config']['inactive_timeout_seconds'] is not None)
        if audit['input_rows']!=source['row_count']:
            raise ValueError('canonical flow row count differs from manifest')
        with (work/'canonical.bin').open('rb') as stream, (work/'raw.txt').open('w') as output:
            result=subprocess.run([str(executable),*options],stdin=stream,stdout=output,
                                  stderr=subprocess.PIPE,text=True,check=False)
        if result.returncode!=0:
            raise RuntimeError(f'Agurim prime failed ({result.returncode}): {result.stderr}')
        if mode=='flow':
            candidates=pd.read_csv(work/'raw.txt',dtype={'src_prefix':str,'dst_prefix':str})
            expected=['aggregate_id','src_prefix','dst_prefix','discounted_flow_count','flow_ratio',
                      'discounted_bytes','discounted_packets']
            if candidates.columns.tolist()!=expected:
                raise ValueError('fork flow output has unexpected columns')
            if int(candidates.discounted_flow_count.sum())!=audit['included_flows']:
                raise ValueError('fork discounted flow count is not conserved')
        else:
            candidates=_parse_control((work/'raw.txt').read_text())
        candidates.to_csv(work/'prime_candidates.csv',index=False)
        _verify_source(source)
        if sha256_file(executable)!=executable_sha:
            raise ValueError('fork executable changed during processing')
        manifest={'status':'success','fingerprint':fingerprint,'identity':identity,
            'candidate_count':len(candidates),'audit':audit,
            'command':{'argv':[str(executable),*options],'returncode':result.returncode,'stderr':result.stderr},
            'count_semantics':'HHH discounted residuals; recompute full /24 counts from canonical membership',
            'artifacts':{name:{'name':filename,'sha256':sha256_file(work/filename)} for name,filename in
                         [('binary_input','canonical.bin'),('rendered','raw.txt'),('candidates','prime_candidates.csv')]}}
        _save(work/'prime_manifest.json',manifest)
        # mkdir claims a new name without replacing even an empty existing folder.
        path.mkdir()
        for item in work.iterdir():
            item.rename(path/item.name)
    return path,manifest,'completed'


def run_prime(root: Path, dataset_id: str, run_name: str, flows: Path, executable: Path, *,
              mode: str = 'flow', threshold: int = 1, heuristics: int = 0,
              chunksize: int = 100_000) -> Path:
    """Select with RLS, then reevaluate exact Raw membership from canonical CSV.

    A run name is single-use, even with identical inputs. Valid immutable caches
    may be reused by a new run. No force/overwrite path is provided.
    """
    root,flows,executable=(Path(p).expanduser().resolve() for p in (root,flows,executable))
    for name in (dataset_id,run_name):
        if not name or Path(name).name!=name or name in ('.','..'):
            raise ValueError('dataset and run must be single path components')
    if type(chunksize) is not int or chunksize<1:
        raise ValueError('chunksize must be positive')
    _options(mode,threshold,heuristics)
    run=root/'results'/dataset_id/run_name
    if run.exists():
        raise FileExistsError(f'existing run will not be overwritten: {run}')
    source,fm,cfg=_source(flows)
    cache,cache_manifest,cache_status=_cache(root,dataset_id,source,fm,executable,mode,threshold,heuristics)
    fingerprint=cache_manifest['fingerprint']
    candidate=cache/'prime_candidates.csv'
    cfg_data=cfg.model_dump()
    cfg_data['experiment']={'name':METHODS[mode],'description':f'Canonical IPv4 TCP/UDP {mode} RLS; Raw; threshold {threshold}%'}
    cfg=ExperimentConfig.model_validate(cfg_data)
    text=yaml.safe_dump(cfg.model_dump(),sort_keys=False)
    producer={'flow_fingerprint':fm['fingerprint'],'prime_fingerprint':fingerprint,
              'prime_candidates_sha256':sha256_file(candidate),'cache_manifest_sha256':sha256_file(cache/'prime_manifest.json')}
    ledger=build_corrected_prefix_ledger(pd.read_csv(candidate),cfg)
    run.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.prime-run-',dir=run.parent) as temp:
        work=Path(temp)
        ledger.to_csv(work/'prefixes.csv',index=False)
        edge_count=0
        with (work/'flow_prefix_membership.csv').open('w',newline='') as output:
            writer=csv.writer(output);writer.writerow(MEMBERSHIP_COLUMNS)
            for chunk in pd.read_csv(flows,chunksize=chunksize,dtype={'flow_id':str}):
                membership=build_membership(chunk,ledger)
                membership.to_csv(output,index=False,header=False)
                edge_count+=len(membership)
        _verify_source(source)
        artifacts={
            'flows':_entry(flows,source['row_count'],{'flow_fingerprint':fm['fingerprint'],
                'cache_manifest_path':source['manifest_path'],'cache_manifest_sha256':source['manifest_sha256']}),
            'agurim_prime_candidates':_entry(candidate,cache_manifest['candidate_count'],producer),
            'prefixes':_entry(work/'prefixes.csv',len(ledger),producer),
            'flow_prefix_membership':_entry(work/'flow_prefix_membership.csv',edge_count,
                {**producer,'prefixes_sha256':sha256_file(work/'prefixes.csv')})}
        for name in ('prefixes','flow_prefix_membership'):
            artifacts[name]['path']=str(run/Path(artifacts[name]['path']).name)
        manifest={'schema_version':'agurim-prime-run-v1','status':'success','dataset_id':dataset_id,'run_name':run_name,
            'stages':[{'name':'flows','status':'reused'},
                      {'name':'agurim_prime','status':cache_status},
                      {'name':'prefixes','status':'completed'},
                      {'name':'membership','status':'completed'}],
            'input':{'sha256':source['capture_sha256']},'config':{'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()},
            'selection':{'method':METHODS[mode],'basis':mode,'prime_fingerprint':fingerprint,
                         'additional_filters':[],'top_k':None,'endpoint_orientation':'first_observed'},
            'artifacts':artifacts,'cache':{
                'flows':{'fingerprint':fm['fingerprint'],'manifest_path':source['manifest_path']},
                'agurim_prime':{'fingerprint':fingerprint,'manifest_path':str(cache/'prime_manifest.json')}},
            'implementation_sha256':{name:sha256_file(REPO/'src/mawi_global_analysis'/name)
                for name in ('agurim_prime/stage.py','prefix.py','membership.py')},
            'evidence_level':'implementation_output; real MAWI validation not asserted'}
        git=subprocess.run(['git','-C',str(REPO),'rev-parse','HEAD'],capture_output=True,text=True,check=False)
        manifest['git_commit']=git.stdout.strip() if git.returncode==0 else None
        _save(work/'run_manifest.json',manifest)
        run.mkdir()
        for item in work.iterdir():
            item.rename(run/item.name)
    return run/'run_manifest.json'

def inspect_prime_lineage(info, root: Path, input_hashes: dict) -> dict:
    """Bind method, canonical observations, cache and candidate producer exactly."""
    m=info.manifest
    selection=m.get('selection',{})
    mode=selection.get('basis')
    if mode not in METHODS or selection.get('method')!=METHODS[mode]:
        raise ValueError('prime selection method/basis mismatch')
    if selection.get('additional_filters')!=[] or selection.get('top_k') is not None:
        raise ValueError('prime selection must retain all normalized /24s')
    cache=m.get('cache',{}).get('agurim_prime',{})
    manifest_path=Path(cache.get('manifest_path',''))
    if not manifest_path.is_absolute():
        manifest_path=root/manifest_path
    recorded=_json(manifest_path)
    identity=recorded.get('identity',{})
    fingerprint=stable_json_hash(identity)
    if (identity.get('basis')!=mode or fingerprint!=cache.get('fingerprint')
            or selection.get('prime_fingerprint')!=fingerprint):
        raise ValueError('prime cache fingerprint/basis mismatch')
    actual=_verify_cache(manifest_path.parent,identity,fingerprint)
    source=identity.get('input',{})
    expected={'csv_sha256':input_hashes['flows']['sha256'],
              'manifest_sha256':input_hashes['flow_manifest']['sha256'],
              'flow_fingerprint':info.flow_manifest['fingerprint'],
              'capture_sha256':m['input']['sha256'],'row_count':info.entries['flows']['row_count']}
    if any(source.get(key)!=value for key,value in expected.items()):
        raise ValueError('prime cache canonical input identity mismatch')
    candidate=m['artifacts'].get('agurim_prime_candidates',{})
    candidate_path=manifest_path.parent/'prime_candidates.csv'
    recorded_path=Path(candidate.get('path',''))
    if not recorded_path.is_absolute():
        recorded_path=root/recorded_path
    candidate_sha=sha256_file(candidate_path)
    manifest_sha=sha256_file(manifest_path)
    if (recorded_path.resolve()!=candidate_path.resolve() or candidate.get('sha256')!=candidate_sha
            or candidate.get('row_count')!=actual['candidate_count']):
        raise ValueError('prime candidate artifact identity mismatch')
    for entry in (candidate,info.entries['prefixes'],info.entries['flow_prefix_membership']):
        producer=entry.get('producer',{})
        if (producer.get('prime_fingerprint')!=fingerprint
                or producer.get('prime_candidates_sha256')!=candidate_sha
                or producer.get('cache_manifest_sha256')!=manifest_sha):
            raise ValueError('prime producer identity mismatch')
    return {'fingerprint':fingerprint,'cache_manifest_sha256':manifest_sha,
            'candidate_sha256':candidate_sha,'identity':identity,'audit':actual['audit'],
            'count_semantics':actual['count_semantics']}
