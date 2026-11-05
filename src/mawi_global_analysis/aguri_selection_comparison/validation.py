"""Read-only A/B/C selection contracts; never use the three-weight validator."""
from __future__ import annotations

import csv
import io
import getopt
from pathlib import Path
import re

import pandas as pd
import yaml

from mawi_global_analysis.aguri import AGURI_CANDIDATE_COLUMNS, PINNED_AGURIM_SHA, parse_aguri_output
from mawi_global_analysis.agurim_prime.input import CONVERTER_VERSION
from mawi_global_analysis.agurim_prime.stage import METHODS, _options, _parse_control, inspect_prime_lineage
from mawi_global_analysis.config import ExperimentConfig
from mawi_global_analysis.flow_length import _chunks, inspect_run
from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.normalized24.analysis import _input_hashes
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS, build_corrected_prefix_ledger
from mawi_global_analysis.rls_weight_comparison.generation import _json
from mawi_global_analysis.rls_weight_comparison.validation import _validate_scope

CONDITIONS=('A','B','C')
DEFAULT_RUNS={'A':'baseline','B':'agurim-ipv4-tcp-udp','C':'canonical-packet-t1-h2'}
BPF='ip and (tcp or udp)'
SCHEMA='aguri-selection-validation-v1'


def resolve(root: Path,value) -> Path:
    if not isinstance(value,str) or not value:raise ValueError('provenance: nonempty path required')
    p=Path(value).expanduser();return (p if p.is_absolute() else root/p).resolve()


def equal(field,actual,expected):
    if type(actual) is not type(expected) or actual!=expected:
        raise ValueError(f'{field}: expected {expected!r}; got {actual!r}')


def digest(value,field):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:raise ValueError(f'{field}: missing/invalid SHA-256')
    return value


def track(path,tracked):
    path=Path(path).resolve();actual=sha256_file(path)
    if str(path) in tracked:equal(f'{path}: changed during validation',actual,tracked[str(path)])
    tracked[str(path)]=actual;return actual


def executable(record,root,tracked,label):
    checksum=digest(record.get('sha256'),label+'.sha256');path=resolve(root,record.get('path'))
    if path.is_file():
        equal(label+'.actual_sha256',track(path,tracked),checksum);status='actual_file_verified_without_execution'
    else:status='recorded_hash_only; executable absent, historical binary not independently verified'
    return dict(path=str(path),sha256=checksum,verification=status)


def _strip_filter(options,label):
    if not isinstance(options,list) or not all(isinstance(x,str) for x in options):raise ValueError(label+'.options: string list required')
    if '--' in options:raise ValueError(label+'.options: end-of-options marker would hide pipeline input arguments')
    try:parsed,arguments=getopt.getopt(options,'c:df:hi:m:p:r:s:t:vw:DE:H:I:P:S:T:')
    except getopt.GetoptError as exc:raise ValueError(label+'.options: '+str(exc)) from exc
    if arguments:raise ValueError(label+'.options: positional arguments are not supported')
    filters=[value for flag,value in parsed if flag=='-f'];expected=1 if label=='B' else 0
    equal(label+'.BPF option count',len(filters),expected)
    if expected:equal(label+'.BPF filter',filters[0],BPF)
    canonical=[]
    for flag,value in parsed:
        if flag!='-f':canonical.extend([flag,value] if value else [flag])
    return canonical,BPF if expected else None


def _old(root,info,cfg,label,inputs,tracked):
    m=info.manifest;ref=m.get('cache',{}).get('aguri',{})
    path=resolve(root,ref.get('manifest_path'));track(path,tracked);cache=_json(path)
    for key,val in {'schema_version':'aguri-v1','status':'success','input_sha256':m['input']['sha256'],
                    'agurim_submodule_sha':PINNED_AGURIM_SHA,'options':cfg.aguri.options}.items():equal(label+'.aguri.'+key,cache.get(key),val)
    exes={name:executable(cache.get('executables',{}).get(name,{}),root,tracked,label+'.'+name) for name in ('aguri3','agurim')}
    identity=dict(schema_version='aguri-v1',input_sha256=m['input']['sha256'],agurim_submodule_sha=PINNED_AGURIM_SHA,
                  executable_sha256={k:v['sha256'] for k,v in exes.items()},options=cfg.aguri.options)
    fingerprint=stable_json_hash(identity)
    equal(label+'.aguri.fingerprint',cache.get('fingerprint'),fingerprint);equal(label+'.run.aguri.fingerprint',ref.get('fingerprint'),fingerprint)
    artifacts=cache.get('artifacts',{});paths={k:resolve(root,artifacts.get(k)) for k in ('candidates_csv','rendered_text','raw_agr')}
    for p in paths.values():track(p,tracked)
    entry=m['artifacts'].get('aguri_candidates',{})
    equal(label+'.candidate.path',str(resolve(root,entry.get('path'))),str(paths['candidates_csv']))
    expected_producer={'aguri_fingerprint':fingerprint,'aguri_candidates_sha256':tracked[str(paths['candidates_csv'])]}
    for name,item in (('candidate',entry),('prefixes',info.entries['prefixes'])):
        for key,val in expected_producer.items():equal(label+'.'+name+'.producer.'+key,item.get('producer',{}).get(key),val)
    # The cache manifest checksum, when recorded, must match; older prefix
    # producers legitimately record only fingerprint/candidate bindings.
    for item in (entry,ref,info.entries['prefixes'],info.entries['flow_prefix_membership']):
        producer=item.get('producer',{})
        for key,val in expected_producer.items():
            if producer.get(key) is not None:equal(label+'.producer.'+key,producer[key],val)
        if producer.get('cache_manifest_path') is not None:equal(label+'.producer.cache_manifest_path',str(resolve(root,producer['cache_manifest_path'])),str(path))
        recorded=producer.get('cache_manifest_sha256')
        if recorded is not None:equal(label+'.cache_manifest_sha256',recorded,tracked[str(path)])
    if entry.get('sha256') is not None:equal(label+'.candidate.sha256',entry['sha256'],tracked[str(paths['candidates_csv'])])
    candidates=pd.read_csv(paths['candidates_csv'],dtype=str,keep_default_na=False)
    equal(label+'.candidate_count',len(candidates),cache.get('candidate_count'));equal(label+'.run.candidate_count',len(candidates),entry.get('row_count'))
    parsed=pd.DataFrame(parse_aguri_output(paths['rendered_text'].read_text()),columns=AGURI_CANDIDATE_COLUMNS)
    _frames(label+'.rendered/candidate',parsed,candidates,list(AGURI_CANDIDATE_COLUMNS))
    options,bpf=_strip_filter(cfg.aguri.options,label)
    commands=cache.get('commands',[])
    if len(commands)!=2:raise ValueError(label+'.commands: expected Aguri3 then Agurim')
    for cmd in commands:equal(label+'.command.returncode',cmd.get('returncode'),0)
    first=commands[0].get('argv',[]);second=commands[1].get('argv',[])
    if len(first)!=len(cfg.aguri.options)+5:raise ValueError(label+'.Aguri3 argv: unexpected options/input/output shape')
    equal(label+'.Aguri3 options',first[1:1+len(cfg.aguri.options)],cfg.aguri.options)
    equal(label+'.Aguri3 -r',first[-4],'-r');equal(label+'.Aguri3 -w',first[-2],'-w')
    equal(label+'.Aguri3 executable',str(resolve(root,first[0])),exes['aguri3']['path'])
    equal(label+'.Aguri3 output',str(resolve(root,first[-1])),str(paths['raw_agr']))
    if not first[-3]:raise ValueError(label+'.Aguri3 input path missing')
    capture_path=resolve(root,m['input'].get('path'))
    command_capture=resolve(root,first[-3])
    if capture_path.suffix!='.gz':
        equal(label+'.Aguri3 input PCAP binding',str(command_capture),str(capture_path))
    elif command_capture.suffix!='.pcap':
        raise ValueError(label+'.Aguri3 decompressed input must be recorded as a PCAP path')
    if len(second)<4 or second[-1]!=str(paths['raw_agr']):
        # Resolve relative raw-input paths without rewriting the manifest.
        if len(second)<4 or resolve(root,second[-1])!=paths['raw_agr']:raise ValueError(label+'.Agurim input does not bind raw AGR')
    equal(label+'.Agurim executable',str(resolve(root,second[0])),exes['agurim']['path'])
    try:i=second.index('-w')
    except ValueError as exc:raise ValueError(label+'.Agurim output option missing') from exc
    equal(label+'.Agurim output',str(resolve(root,second[i+1])),str(paths['rendered_text']))
    normalized=[]
    for token in second[1:]:
        normalized.append('<AGR>' if token==second[-1] else '<RENDERED>' if token==second[i+1] else token)
    return dict(run_name=info.manifest_path.parent.name,selection_input='PCAP → Aguri3 → Agurim',bpf=bpf,
        executable=exes,cache_manifest=str(path),cache_manifest_sha256=tracked[str(path)],fingerprint=fingerprint,
        aguri3_non_bpf_options=options,agurim_normalized_argv=normalized,commands=commands,
        capture_input={'declared_path':str(capture_path),'command_path':str(command_capture),
            'verification':'recorded_gzip_temporary_input_only' if capture_path.suffix=='.gz' else 'command_bound_to_declared_pcap_path',
            'decoded_content_verified':False if capture_path.suffix=='.gz' else None},
        candidate_path=str(paths['candidates_csv']),rendered_path=str(paths['rendered_text']),
        raw_historical_hash='not recorded in aguri-v1; current raw/rendered hashes saved, parsed candidate binding verified'),candidates


def _frames(label,left,right,columns):
    # Roundtrip writer representations; do not round numerical strings or merge rows.
    left=pd.read_csv(io.StringIO(left.to_csv(index=False)),dtype=str,keep_default_na=False)
    if list(right.columns)!=columns or not left[columns].equals(right[columns].reset_index(drop=True)):
        raise ValueError(label+': table differs')


def _prime(root,info,label,inputs,tracked):
    lineage=inspect_prime_lineage(info,root,inputs)
    ref=info.manifest['cache']['agurim_prime'];path=resolve(root,ref['manifest_path']);track(path,tracked);cache=_json(path)
    identity=lineage['identity'];equal('C.run.schema',info.manifest.get('schema_version'),'agurim-prime-run-v1');equal('C.identity.schema',identity.get('schema_version'),'agurim-prime-v1')
    equal('C.endpoint_orientation',info.manifest['selection'].get('endpoint_orientation'),'first_observed')
    equal('C.basis',identity.get('basis'),'packet');equal('C.selection.method',info.manifest['selection']['method'],METHODS['packet'])
    equal('C.threshold',identity.get('threshold'),1);equal('C.options',identity.get('options'),_options('packet',1,2))
    equal('C.converter_version',identity.get('converter_version'),CONVERTER_VERSION)
    for key in ('input.py','stage.py'):digest(identity.get('implementation_sha256',{}).get(key),'C.converter.'+key)
    fork=identity.get('fork',{});equal('C.fork.upstream',fork.get('upstream_commit'),PINNED_AGURIM_SHA)
    equal('C.fork.patch_sha256',fork.get('patch_sha256'),sha256_file(Path(__file__).resolve().parents[3]/'vendor/agurim-prime/flow-mode.patch'))
    recorded_impl=info.manifest.get('implementation_sha256',{})
    for name in ('agurim_prime/stage.py','prefix.py','membership.py'):digest(recorded_impl.get(name),'C.implementation.'+name)
    equal('C.converter/stage identity',recorded_impl['agurim_prime/stage.py'],identity['implementation_sha256']['stage.py'])
    equal('C.fork.executable',fork.get('executable_sha256'),identity.get('executable_sha256'))
    equal('C.fork.schema',fork.get('schema_version'),'agurim-prime-build-v1');equal('C.fork.status',fork.get('status'),'success')
    equal('C.fork.fork_identity',fork.get('fork_identity'),stable_json_hash({k:fork[k] for k in ('upstream_commit','patch_sha256')}))
    if 'fork_commit' not in fork or (fork['fork_commit'] is not None and (not isinstance(fork['fork_commit'],str) or re.fullmatch('[0-9a-f]{40}',fork['fork_commit']) is None)):
        raise ValueError('C.fork.fork_commit: explicit null or commit SHA required')
    if not isinstance(fork.get('compiler'),str) or not fork['compiler'].strip():raise ValueError('C.fork.compiler missing')
    if not isinstance(fork.get('compiler_argv'),list) or not fork['compiler_argv'] or not all(isinstance(v,str) and v for v in fork['compiler_argv']):raise ValueError('C.fork.compiler_argv missing')
    if not isinstance(fork.get('source_sha256'),dict) or not fork['source_sha256']:raise ValueError('C.fork.source_sha256 missing')
    for name,value in fork['source_sha256'].items():digest(value,'C.fork.source.'+name)
    digest(fork.get('build_manifest_sha256'),'C.fork.build_manifest_sha256')
    argv=cache.get('command',{}).get('argv',[])
    if not argv:raise ValueError('C.command.argv missing')
    equal('C.command.options',argv[1:],identity['options']);equal('C.command.returncode',cache['command'].get('returncode'),0)
    exe=executable({'path':argv[0],'sha256':identity['executable_sha256']},root,tracked,'C.agurim-prime')
    build_path=Path(exe['path']).with_name('build_manifest.json')
    if build_path.is_file():
        build_sha=track(build_path,tracked);build=_json(build_path)
        equal('C.fork/build_manifest',fork,{**build,'build_manifest_sha256':build_sha})
        build_verification='available build manifest and recorded fork agree'
    else:build_verification='recorded build hash/metadata only; build manifest unavailable'
    for artifact in cache['artifacts'].values():track(path.parent/artifact['name'],tracked)
    cp=path.parent/'prime_candidates.csv';rp=path.parent/'raw.txt'
    candidates=pd.read_csv(cp,dtype=str,keep_default_na=False);parsed=_parse_control(rp.read_text())
    _frames('C.rendered/candidate',parsed,candidates,list(parsed.columns))
    for field,expected in (('unit_packets',False),('scope','IPv4 TCP/UDP'),('orientation','first observed packet; not initiator/responder')):
        equal('C.audit.'+field,lineage['audit'].get(field),expected)
    from .binary import verify_canonical_binary
    binary_check=verify_canonical_binary(info.paths['flows'],path.parent/'canonical.bin')
    for field,value in binary_check['audit'].items():equal('C.binary.audit.'+field,lineage['audit'].get(field),value)
    equal('C.binary expected SHA-256',binary_check['expected_sha256'],cache['artifacts']['binary_input']['sha256'])
    return dict(binary_verification=binary_check,build_manifest_verification=build_verification,
                run_name=info.manifest_path.parent.name,selection_input='canonical flows',bpf=None,
                executable={'agurim-prime':exe},candidate_path=str(cp),rendered_path=str(rp),lineage=lineage),candidates


def validate_inputs(root: Path,dataset_id: str,*,run_a: str=DEFAULT_RUNS['A'],run_b: str=DEFAULT_RUNS['B'],
                    run_c: str=DEFAULT_RUNS['C'],chunksize: int=100_000) -> dict:
    """Dedicated A/B/C validation; no PCAP read, subprocess or output mutation."""
    if type(chunksize) is not int or chunksize<1:raise ValueError('chunksize must be positive')
    root=Path(root).expanduser().resolve();tracked={};runs={};configs={};canonical=None;infos={}
    for label,run in zip(CONDITIONS,(run_a,run_b,run_c)):
        try:
            info=inspect_run(root,dataset_id,run,raw_only=True);infos[label]=info
            inputs=_input_hashes(info,root)
            for entry in inputs.values():track(entry['path'],tracked)
            for name,entry in info.entries.items():
                if entry.get('sha256') is not None:equal(label+'.'+name+'.sha256',inputs[name]['sha256'],entry['sha256'])
            cfg=ExperimentConfig.model_validate(yaml.safe_load(info.manifest['config']['text']));configs[label]=cfg
            equal(label+'.flow.protocols',sorted(cfg.flow.protocols),['tcp','udp'])
            common={'csv_sha256':inputs['flows']['sha256'],'flow_manifest_sha256':inputs['flow_manifest']['sha256'],
                    'capture_sha256':info.manifest['input']['sha256'],'flow_fingerprint':info.flow_manifest['fingerprint'],
                    'row_count':info.entries['flows']['row_count'],'flow_config':info.flow_manifest['flow_config']}
            if canonical is None:canonical=common
            else:equal(label+'.canonical',common,canonical)
            record,candidates=_prime(root,info,label,inputs,tracked) if label=='C' else _old(root,info,cfg,label,inputs,tracked)
            expected=build_corrected_prefix_ledger(candidates,cfg)
            actual=pd.read_csv(info.paths['prefixes'],dtype=str,keep_default_na=False)
            expected=expected.sort_values('prefix').reset_index(drop=True);actual=actual.sort_values('prefix').reset_index(drop=True)
            _frames(label+'.corrected_selection',expected,actual,list(CORRECTED_LEDGER_COLUMNS))
            equal(label+'.membership.prefixes_sha256',info.entries['flow_prefix_membership'].get('producer',{}).get('prefixes_sha256'),inputs['prefixes']['sha256'])
            for _ in _chunks(info,'flow_prefix_membership',('flow_id','analysis_scope','analysis_prefix','src_match','dst_match'),chunksize):pass
            record.update(inputs=inputs,selected_native_prefixes=info.selected_prefixes,config=info.manifest['config'],
                          source_evidence=info.manifest.get('evidence_level','saved_artifact_analysis; independent real-data evidence not recorded'),
                          historical_artifact_hashes={k:bool(v.get('sha256')) for k,v in info.entries.items()})
            runs[label]=record
        except (ValueError,OSError,KeyError,TypeError,AttributeError) as exc:
            raise ValueError(f'{label} run {run!r}: {exc}') from exc
    for section in ('flow','prefix','analysis','scan','legacy'):
        equal('A/B.config.'+section,getattr(configs['A'],section).model_dump() if getattr(configs['A'],section) else None,
              getattr(configs['B'],section).model_dump() if getattr(configs['B'],section) else None)
    equal('A/B.Aguri3 non-BPF options',runs['A']['aguri3_non_bpf_options'],runs['B']['aguri3_non_bpf_options'])
    equal('A/B.Agurim argv',runs['A']['agurim_normalized_argv'],runs['B']['agurim_normalized_argv'])
    equal('A/B.executables',{k:v['sha256'] for k,v in runs['A']['executable'].items()},{k:v['sha256'] for k,v in runs['B']['executable'].items()})
    for section in ('prefix','analysis'):equal('A/B/C.'+section,getattr(configs['A'],section).model_dump(),getattr(configs['C'],section).model_dump())
    audit=_validate_scope(infos['A'],chunksize)
    for field in ('input_rows','included_flows','excluded_ipv6','excluded_protocol'):
        equal('C.canonical.audit.'+field,runs['C']['lineage']['audit'].get(field),audit[field])
    for path,checksum in tracked.items():equal(path+': final hash',sha256_file(Path(path)),checksum)
    input_binding=all(runs[k]['capture_input']['verification']=='command_bound_to_declared_pcap_path' for k in ('A','B'))
    return dict(schema_version=SCHEMA,status='valid',dataset_id=dataset_id,ab_config_bpf_only=True,ab_bpf_only=input_binding,
        ab_input_binding_verified=input_binding,ab_contrast_verification='recorded_pipeline_input_binding' if input_binding else 'recorded_config_only; gzip temporary bytes not independently bound',runs=runs,
        common={'canonical':canonical,'evaluation':{'scope':'IPv4 TCP/UDP','group':'Raw','membership_scope':'native',
                'endpoint_rule':'src_ip OR dst_ip','union_deduplication':'flow_id','quantile':'linear: (n-1)*q'}},
        tracked_files=tracked,scope_audit=audit,
        interpretation={'A_to_B':('recorded PCAP/executable/options contrast isolates BPF' if input_binding else 'recorded selector configuration differs only by BPF; gzip temporary input bytes cannot independently be linked')+'; older raw-output history not independently hash-bound',
                        'B_to_C':'first aggregation and RLS input format also differ; not a pure RLS implementation effect'},
        validation_scope='contracts/current hashes/corrected selection; native edges checked during aggregation')
