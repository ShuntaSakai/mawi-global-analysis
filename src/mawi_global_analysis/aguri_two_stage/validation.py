"""Read-only dedicated two-stage lineage and three-weight comparison validation."""
from __future__ import annotations
from pathlib import Path
import pandas as pd
import yaml
import re
from mawi_global_analysis.config import ExperimentConfig
from mawi_global_analysis.agurim_prime.input import CONVERTER_VERSION
from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.hashing import sha256_file,stable_json_hash
from mawi_global_analysis.normalized24.analysis import _input_hashes
from mawi_global_analysis.prefix import build_corrected_prefix_ledger
from .stage import MODES,ALL_MODES,cache_verify,build_identity,implementation,settings
from mawi_global_analysis.agurim_prime.stage import _json,_source

SCHEMA='aguri-two-stage-validation-v1'
def equal(key,a,b):
    if type(a) is not type(b) or a!=b:raise ValueError(f'{key}: expected {b!r}; got {a!r}')

def inspect_lineage(info,root,inputs):
    m=info.manifest;s=m.get('selection',{});mode=s.get('basis')
    if m.get('schema_version')!='aguri-two-stage-run-v1' or mode not in ALL_MODES or s.get('method')!='aguri-two-stage-'+mode:raise ValueError('two-stage selection method/schema mismatch')
    for k,v in {'additional_filters':[],'top_k':None,'endpoint_orientation':'first_observed'}.items():equal('selection.'+k,s.get(k),v)
    ref=m.get('cache',{}).get('aguri_two_stage',{});path=Path(ref.get('manifest_path',''))
    if not path.is_absolute():path=Path(root)/path
    cm=_json(path);identity=cm['identity'];fp=stable_json_hash(identity)
    equal('cache fingerprint',ref.get('fingerprint'),fp);equal('selection fingerprint',s.get('two_stage_fingerprint'),fp)
    equal('cache schema',identity.get('schema_version'),'aguri-two-stage-cache-v1');equal('basis',identity.get('basis'),mode)
    expected=settings(mode,**{k:identity['settings'][k] for k in ('threshold','heuristics','max_hashentries')});equal('settings',identity.get('settings'),expected)
    equal('implementation',identity.get('implementation_sha256'),implementation());equal('run implementation',m.get('implementation_sha256'),implementation())
    source,_,cfg=_source(info.paths['flows']);equal('canonical input',identity.get('input'),source)
    equal('run name',m.get('run_name'),info.manifest_path.parent.name)
    equal('converter version',identity.get('converter_version'),CONVERTER_VERSION)
    equal('wire version',identity.get('wire_version'),'aguri-weight-wire-v1')
    equal('canonical manifest hash',inputs['flow_manifest']['sha256'],source['manifest_sha256'])
    saved=ExperimentConfig.model_validate(yaml.safe_load(m['config']['text']))
    for section in ('flow','prefix','scan','analysis','aguri'):
        equal('config.'+section,getattr(saved,section).model_dump(),getattr(cfg,section).model_dump())
    if cfg.flow.inactive_timeout_seconds is not None or sorted(cfg.flow.protocols)!=['tcp','udp']:raise ValueError('canonical timeout/protocol mismatch')
    build=build_identity(Path(identity['build']['build_manifest_path']).parent);equal('build',identity['build'],build)
    actual=cache_verify(path.parent,identity,fp)
    equal('run input capture',m['input']['sha256'],source['capture_sha256'])
    candidate=m['artifacts'].get('aguri_two_stage_candidates',{});candidate_path=path.parent/'candidates.csv'
    equal('candidate path',str(Path(candidate.get('path','')).resolve()),str(candidate_path.resolve()))
    equal('candidate hash',candidate.get('sha256'),sha256_file(candidate_path));equal('candidate rows',candidate.get('row_count'),actual['candidate_count'])
    for e in (candidate,info.entries['prefixes'],info.entries['flow_prefix_membership']):
        p=e.get('producer',{})
        for k,v in {'two_stage_fingerprint':fp,'two_stage_candidates_sha256':sha256_file(candidate_path),'cache_manifest_sha256':sha256_file(path)}.items():equal('producer.'+k,p.get(k),v)
    expected=build_corrected_prefix_ledger(pd.read_csv(candidate_path),cfg)
    try:pd.testing.assert_frame_equal(expected,pd.read_csv(info.paths['prefixes'],keep_default_na=False),check_dtype=False)
    except AssertionError as e:raise ValueError('corrected prefix ledger differs from stage2 candidates') from e
    return dict(fingerprint=fp,identity=identity,audits=actual['audits'],cache_manifest_path=str(path),cache_manifest_sha256=sha256_file(path),candidate_sha256=sha256_file(candidate_path))

def validate_runs(root: Path,dataset_id: str,*,packet_run: str,byte_run: str,flow_run: str,chunksize=100000):
    if type(chunksize) is not int or chunksize<1:raise ValueError('chunksize must be positive')
    root=Path(root).expanduser().resolve();runs={};common=None;tracked={}
    for mode,run in zip(MODES,(packet_run,byte_run,flow_run)):
        try:
            info=inspect_run(root,dataset_id,run,raw_only=True);inputs=_input_hashes(info,root);lineage=inspect_lineage(info,root,inputs)
            equal('mode',info.manifest['selection']['basis'],mode);identity=lineage['identity']
            equal('threshold',identity['settings']['threshold'],1)
            contract={k:identity[k] for k in ('input','build','settings','converter_version','wire_version','implementation_sha256')}
            if common is None:common=contract
            else:equal(mode+'.common',contract,common)
            for e in inputs.values():tracked[e['path']]=e['sha256']
            runs[mode]=dict(run_name=run,run_manifest_sha256=inputs['run_manifest']['sha256'],config_sha256=info.manifest['config']['hash'],inputs=inputs,lineage=lineage)
        except (ValueError,OSError,KeyError) as e:raise ValueError(f'{mode}/{run}: {e}') from e
    for name,checksum in tracked.items():equal('input changed',sha256_file(Path(name)),checksum)
    return dict(schema_version=SCHEMA,status='valid',dataset_id=dataset_id,common=common,runs=runs,
        interpretation='same canonical, both Aguri3 and Agurim, fixed settings; only basis varies. HHH residuals are not membership counts.',
        validation_scope='hashes/lineage/records/wire/ledger; complete native and normalized membership checked by aggregation')
