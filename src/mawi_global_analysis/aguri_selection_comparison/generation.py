"""Immutable A/B/C result bundles; no PCAP or selector execution."""
import csv
import json
import ipaddress
from pathlib import Path
import tempfile

from mawi_global_analysis.hashing import sha256_file,stable_json_hash
from mawi_global_analysis.normalized24.statistics import _new_output
from mawi_global_analysis.rls_weight_comparison.generation import _entries,_publish,_write_text,_write_csv,_json,STATS
from mawi_global_analysis.rls_weight_comparison.refresh import _guard_locations
from .analysis import TARGET,analyze_inputs
from . import prefix_ecdf
from .validation import (
    CONDITIONS, CONDITIONS_V2, DEFAULT_RUNS, TWO_STAGE_BASES, _validate_inputs,
    SCHEMA as VALIDATION_SCHEMA, SCHEMA_V2 as VALIDATION_SCHEMA_V2,
)

SCHEMA='aguri-selection-comparison-v1'
SCHEMA_V2='aguri-selection-comparison-v2'
DATA_ARTIFACTS={'summary.json','selection_summary.csv','prefix_stats.csv','pairwise_prefixes.csv','jaccard.csv',
                'ecdf_counts.csv','focus_prefix.csv','sensitivity_summary.csv','component_stats.csv','legacy_comparison.json'}


def _required_artifacts(keys):
    return DATA_ARTIFACTS | {f'modes/{key}/{name}' for key in keys for name in ('summary.json','frequencies.csv')}


REQUIRED=_required_artifacts(CONDITIONS) | {'dashboard.html'}
REQUIRED_V2=_required_artifacts(CONDITIONS_V2)


def _selection_conditions(validation):
    conditions={key:dict(run_name=run['run_name'],selection_input=run['selection_input'],details=run.get('selection_details'))
                for key,run in validation['runs'].items()}
    if validation['schema_version']==VALIDATION_SCHEMA_V2:
        for condition in conditions.values():
            condition['basis']=(condition['details'] or {}).get('basis')
    return conditions


def verify_manifest(path: Path) -> dict:
    path=Path(path).expanduser().resolve();m=_json(path)
    schema=m.get('schema_version')
    if schema not in (SCHEMA,SCHEMA_V2) or m.get('status')!='success':
        raise ValueError('unsupported/incomplete comparison manifest')
    v2=schema==SCHEMA_V2
    keys=CONDITIONS_V2 if v2 else CONDITIONS
    bundle_kind=m.get('bundle_kind') if v2 else None
    if v2 and 'bundle_kind' in m and bundle_kind!='dashboard':
        raise ValueError('unsupported v2 bundle kind')
    required=(REQUIRED_V2 | {'dashboard.html'} if bundle_kind=='dashboard' else REQUIRED_V2) if v2 else REQUIRED
    prefix_data=m.get('prefix_ecdf') if v2 else None
    if v2 and 'prefix_ecdf' in m:
        if bundle_kind!='dashboard' or prefix_data!=prefix_ecdf.DESCRIPTOR:
            raise ValueError('unsupported prefix ECDF artifact descriptor')
        required=required | {prefix_ecdf.ARTIFACT}
    if not isinstance(m.get('artifacts'),dict) or not required.issubset(m['artifacts']):
        raise ValueError('comparison artifacts missing')
    if v2 and bundle_kind is None and 'dashboard.html' in m['artifacts']:
        raise ValueError('v2 comparison bundle is data-only')
    validation=m.get('validation')
    if (not isinstance(validation,dict) or validation!=m.get('final_validation')
            or validation.get('schema_version')!=(VALIDATION_SCHEMA_V2 if v2 else VALIDATION_SCHEMA) or validation.get('status')!='valid'
            or validation.get('dataset_id')!=m.get('dataset_id') or validation.get('ab_config_bpf_only') is not True
            or type(validation.get('ab_bpf_only')) is not bool
            or validation.get('ab_bpf_only')!=validation.get('ab_input_binding_verified')
            or not isinstance(validation.get('runs'),dict) or set(validation['runs'])!=set(keys)
            or not isinstance(validation.get('common'),dict) or not isinstance(validation['common'].get('canonical'),dict)):
        raise ValueError('comparison validation binding/structure mismatch')
    bindings=[]
    for condition in ('A','B'):
        run=validation['runs'][condition]
        if not isinstance(run,dict) or not isinstance(run.get('capture_input'),dict):raise ValueError('comparison validation input binding missing')
        level=run['capture_input'].get('verification')
        if level not in ('recorded_gzip_temporary_input_only','command_bound_to_declared_pcap_path'):raise ValueError('comparison validation input binding unsupported')
        bindings.append(level=='command_bound_to_declared_pcap_path')
    if validation['ab_bpf_only']!=all(bindings):raise ValueError('comparison validation BPF evidence level mismatch')
    for name,entry in m['artifacts'].items():
        rel=Path(name);file=(path.parent/rel).resolve()
        if not name or rel.is_absolute() or '..' in rel.parts or rel.as_posix()!=name or not file.is_relative_to(path.parent):raise ValueError('unsafe artifact path')
        if sha256_file(file)!=entry.get('sha256'):raise ValueError(name+': SHA-256 mismatch')
        if file.suffix=='.csv':
            with file.open(newline='',encoding='utf-8') as s:
                r=csv.reader(s,strict=True)
                if next(r,None)!=entry.get('columns') or sum(1 for _ in r)!=entry.get('row_count'):raise ValueError(name+': schema/count mismatch')
    summary=_json(path.parent/'summary.json')
    if any(m.get(key)!=summary.get(key) for key in ('dataset_id','target')):
        raise ValueError('comparison summary metadata binding mismatch')
    if v2:
        if (summary.get('prefix_ecdf')!=prefix_data
                or (prefix_ecdf.ARTIFACT in m['artifacts'])!=(prefix_data is not None)):
            raise ValueError('prefix ECDF artifact binding mismatch')
        if summary.get('bundle_kind')!=bundle_kind:
            raise ValueError('v2 bundle kind binding mismatch')
        if (summary.get('schema_version')!='aguri-selection-analysis-v2'
                or summary.get('validation_sha256')!=stable_json_hash(validation)
                or set(summary.get('conditions',{}))!=set(keys)):
            raise ValueError('v2 comparison analysis/validation binding mismatch')
        for key,basis in TWO_STAGE_BASES.items():
            details=validation['runs'][key].get('selection_details') or {}
            if details.get('basis')!=basis or details.get('method')!='aguri-two-stage-'+basis:
                raise ValueError(f'{key}: comparison basis binding mismatch')
        for key in keys:
            mode=_json(path.parent/'modes'/key/'summary.json')
            if (mode.get('schema_version')!='aguri-selection-statistics-v2'
                    or mode.get('condition')!=key or mode.get('inputs')!=validation['runs'][key]['inputs']):
                raise ValueError(f'{key}: comparison mode binding mismatch')
    if v2 or 'selection_conditions' in m or 'selection_conditions' in summary:
        expected=_selection_conditions(validation)
        if m.get('selection_conditions')!=expected or summary.get('selection_conditions')!=expected:
            raise ValueError('comparison selection conditions binding mismatch')
    if prefix_data is not None:
        prefix_ecdf.verify_prefix_ecdf_binding(_json(path.parent/prefix_ecdf.ARTIFACT),summary,validation)
    if m.get('legacy')!=_json(path.parent/'legacy_comparison.json') or m['legacy'].get('historical_reproduction_verified') is not False:
        raise ValueError('legacy evidence binding mismatch')
    return m


def generate(root: Path,dataset_id: str,output_dir: Path,*,run_a=DEFAULT_RUNS['A'],run_b=DEFAULT_RUNS['B'],run_c=None,run_c_packet=None,run_c_flow=None,
             chunksize=100_000,scratch_dir=None,max_ecdf_points=2000,target=TARGET,legacy_reference=None) -> Path:
    target=str(ipaddress.ip_network(target,strict=True))
    if ipaddress.ip_network(target).version!=4 or ipaddress.ip_network(target).prefixlen<24:raise ValueError('target must be IPv4 /24..32')
    root=Path(root).expanduser().resolve();output=Path(output_dir).expanduser()
    if output.is_symlink():raise FileExistsError('existing output symlink')
    output=output.resolve();_new_output(root,output)
    args=dict(run_a=run_a,run_b=run_b,run_c=run_c,run_c_packet=run_c_packet,run_c_flow=run_c_flow,chunksize=chunksize)
    validation=_validate_inputs(root,dataset_id,**args)
    v2=validation['schema_version']==VALIDATION_SCHEMA_V2
    protection={'source_runs':{k:{'inputs':r['inputs']} for k,r in validation['runs'].items()}}
    _guard_locations(root/'results'/dataset_id,protection,output,Path(scratch_dir).expanduser().resolve() if scratch_dir else None)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aguri-selection-',dir=output.parent) as temp:
        work=Path(temp)/'bundle'
        result=analyze_inputs(root,dataset_id,work,**args,scratch_dir=scratch_dir,max_ecdf_points=max_ecdf_points,
                              target=target,validation=validation,legacy_reference=legacy_reference)
        result['selection_conditions']=_selection_conditions(validation)
        if v2:
            result['validation_sha256']=stable_json_hash(validation)
            result['bundle_kind']='dashboard'
            result['prefix_ecdf']=prefix_ecdf.DESCRIPTOR
            individual=prefix_ecdf.build_prefix_ecdf_payload(work,result,scratch_dir=scratch_dir)
            _write_text(work/prefix_ecdf.ARTIFACT,
                        json.dumps(individual,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n')
            del individual
        _write_csv(work/'focus_prefix.csv',('condition','selected','candidate_exact','candidate_covering',*STATS,'one_packet_count','in_union_flow_count','union_share'),
            [{**r,'condition':k,'candidate_covering':json.dumps(r['candidate_covering'])} for k,r in result['focus'].items()])
        records=[]
        for key,r in result['sensitivities'].items():
            for variant in ('before','after'):
                metric=r['before_ks'] if variant=='before' else {k:r[k] for k in ('ks_distance','ks_numerator','ks_denominator')}
                records.append(dict(condition=key,variant=variant,excluded_prefix=target,selected_before=r['selected_before'],**r[variant],**metric))
        _write_csv(work/'sensitivity_summary.csv',('condition','variant','excluded_prefix','selected_before',*STATS,'ks_distance','ks_numerator','ks_denominator'),records)
        _write_csv(work/'component_stats.csv',('component',*STATS),[dict(component=k,**r) for k,r in result['components'].items()])
        _write_text(work/'legacy_comparison.json',json.dumps(result['legacy'],indent=2,allow_nan=False)+'\n')
        _write_text(work/'summary.json',json.dumps({k:v for k,v in result.items() if k not in ('curves','all_curves')},indent=2,allow_nan=False)+'\n')
        package=Path(__file__).resolve().parents[1]
        implementation={str(p.relative_to(package)):sha256_file(p) for p in Path(__file__).parent.iterdir() if p.is_file() and p.suffix in ('.py','.html','.js')}
        for name in ('normalized24/analysis.py','normalized24/statistics.py','rls_weight_comparison/native_analysis.py','rls_weight_comparison/metrics.py',
                     'rls_weight_comparison/dashboard.py','rls_weight_comparison/dashboard.html','flow_length.py','aguri.py','prefix.py','membership.py'):
            implementation[name]=sha256_file(package/name)
        if v2:
            name='rls_weight_comparison/prefix_ecdf.py'
            implementation[name]=sha256_file(package/name)
        else:
            implementation.pop('aguri_selection_comparison/prefix_ecdf.py',None)
        if v2 or validation['runs']['C']['selection_details']['method']=='aguri-two-stage-packet':
            for name in ('aguri_two_stage/validation.py','aguri_two_stage/stage.py','aguri_two_stage/wire.py',
                         'agurim_prime/input.py','agurim_prime/stage.py'):
                implementation[name]=sha256_file(package/name)
        display={'max_ecdf_points':max_ecdf_points,'statistics':'exact full frequencies; never sampled points',
                 'simplified':'retained true points; lower HV steps with next-point upper bounds'}
        payload={**result,'provenance':{'validation':validation,'implementation_sha256':implementation,
            'artifacts':_entries(work),'display':display,
            'evidence':'Saved-run comparison; synthetic fixtures are not MAWI findings. No historical reproduction without bound reference.'}}
        from .dashboard import render
        _write_text(work/'dashboard.html',render(payload))
        final=_validate_inputs(root,dataset_id,**args)
        if final!=validation:raise ValueError('input provenance changed during comparison')
        for name,checksum in result['legacy'].get('tracked_files',{}).items():
            if sha256_file(Path(name))!=checksum:raise ValueError('legacy reference changed during comparison')
        manifest=dict(schema_version=SCHEMA_V2 if v2 else SCHEMA,status='success',dataset_id=dataset_id,validation=validation,final_validation=final,
                      target=target,selection_conditions=result['selection_conditions'],implementation_sha256=implementation,artifacts=_entries(work),
                      display=display,interpretation=validation['interpretation'],legacy=result['legacy'])
        if v2:
            manifest['bundle_kind']=result['bundle_kind']
            manifest['prefix_ecdf']=result['prefix_ecdf']
        _write_text(work/'comparison_manifest.json',json.dumps(manifest,indent=2,sort_keys=True,allow_nan=False)+'\n')
        verify_manifest(work/'comparison_manifest.json');_new_output(root,output);_publish(work,output)
    return output/'comparison_manifest.json'
