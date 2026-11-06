"""Immutable A/B/C result bundles; no PCAP or selector execution."""
import csv
import json
import ipaddress
from pathlib import Path
import tempfile

from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24.statistics import _new_output
from mawi_global_analysis.rls_weight_comparison.generation import _entries,_publish,_write_text,_write_csv,_json,STATS
from mawi_global_analysis.rls_weight_comparison.refresh import _guard_locations
from .analysis import TARGET,analyze_inputs
from .validation import DEFAULT_RUNS,CONDITIONS,SCHEMA as VALIDATION_SCHEMA,validate_inputs

SCHEMA='aguri-selection-comparison-v1'
REQUIRED={'dashboard.html','summary.json','selection_summary.csv','prefix_stats.csv','pairwise_prefixes.csv','jaccard.csv',
          'ecdf_counts.csv','focus_prefix.csv','sensitivity_summary.csv','component_stats.csv','legacy_comparison.json',
          *(f'modes/{c}/{n}' for c in CONDITIONS for n in ('summary.json','frequencies.csv'))}


def _selection_conditions(validation):
    return {key:dict(run_name=run['run_name'],selection_input=run['selection_input'],details=run.get('selection_details'))
            for key,run in validation['runs'].items()}


def verify_manifest(path: Path) -> dict:
    path=Path(path).expanduser().resolve();m=_json(path)
    if m.get('schema_version')!=SCHEMA or m.get('status')!='success':raise ValueError('unsupported/incomplete comparison manifest')
    if not isinstance(m.get('artifacts'),dict) or not REQUIRED.issubset(m['artifacts']):raise ValueError('comparison artifacts missing')
    validation=m.get('validation')
    if (not isinstance(validation,dict) or validation!=m.get('final_validation')
            or validation.get('schema_version')!=VALIDATION_SCHEMA or validation.get('status')!='valid'
            or validation.get('dataset_id')!=m.get('dataset_id') or validation.get('ab_config_bpf_only') is not True
            or type(validation.get('ab_bpf_only')) is not bool
            or validation.get('ab_bpf_only')!=validation.get('ab_input_binding_verified')
            or not isinstance(validation.get('runs'),dict) or set(validation['runs'])!=set(CONDITIONS)
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
    if 'selection_conditions' in m or 'selection_conditions' in summary:
        expected=_selection_conditions(validation)
        if m.get('selection_conditions')!=expected or summary.get('selection_conditions')!=expected:
            raise ValueError('comparison selection conditions binding mismatch')
    if m.get('legacy')!=_json(path.parent/'legacy_comparison.json') or m['legacy'].get('historical_reproduction_verified') is not False:
        raise ValueError('legacy evidence binding mismatch')
    return m


def generate(root: Path,dataset_id: str,output_dir: Path,*,run_a=DEFAULT_RUNS['A'],run_b=DEFAULT_RUNS['B'],run_c=DEFAULT_RUNS['C'],
             chunksize=100_000,scratch_dir=None,max_ecdf_points=2000,target=TARGET,legacy_reference=None) -> Path:
    target=str(ipaddress.ip_network(target,strict=True))
    if ipaddress.ip_network(target).version!=4 or ipaddress.ip_network(target).prefixlen<24:raise ValueError('target must be IPv4 /24..32')
    root=Path(root).expanduser().resolve();output=Path(output_dir).expanduser()
    if output.is_symlink():raise FileExistsError('existing output symlink')
    output=output.resolve();_new_output(root,output)
    args=dict(run_a=run_a,run_b=run_b,run_c=run_c,chunksize=chunksize)
    validation=validate_inputs(root,dataset_id,**args)
    protection={'source_runs':{k:{'inputs':r['inputs']} for k,r in validation['runs'].items()}}
    _guard_locations(root/'results'/dataset_id,protection,output,Path(scratch_dir).expanduser().resolve() if scratch_dir else None)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aguri-selection-',dir=output.parent) as temp:
        work=Path(temp)/'bundle'
        result=analyze_inputs(root,dataset_id,work,**args,scratch_dir=scratch_dir,max_ecdf_points=max_ecdf_points,
                              target=target,validation=validation,legacy_reference=legacy_reference)
        result['selection_conditions']=_selection_conditions(validation)
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
        if validation['runs']['C']['selection_details']['method']=='aguri-two-stage-packet':
            for name in ('aguri_two_stage/validation.py','aguri_two_stage/stage.py','aguri_two_stage/wire.py',
                         'agurim_prime/input.py','agurim_prime/stage.py'):
                implementation[name]=sha256_file(package/name)
        payload={**result,'provenance':{'validation':validation,'implementation_sha256':implementation,'artifacts':_entries(work),
            'display':{'max_ecdf_points':max_ecdf_points,'statistics':'exact full frequencies; never sampled points',
                       'simplified':'retained true points; lower HV steps with next-point upper bounds'},
            'evidence':'Saved-run comparison; synthetic fixtures are not MAWI findings. No historical reproduction without bound reference.'}}
        from .dashboard import render
        _write_text(work/'dashboard.html',render(payload))
        final=validate_inputs(root,dataset_id,**args)
        if final!=validation:raise ValueError('input provenance changed during comparison')
        for name,checksum in result['legacy'].get('tracked_files',{}).items():
            if sha256_file(Path(name))!=checksum:raise ValueError('legacy reference changed during comparison')
        manifest=dict(schema_version=SCHEMA,status='success',dataset_id=dataset_id,validation=validation,final_validation=final,
                      target=target,selection_conditions=result['selection_conditions'],implementation_sha256=implementation,artifacts=_entries(work),
                      display=payload['provenance']['display'],interpretation=validation['interpretation'],legacy=result['legacy'])
        _write_text(work/'comparison_manifest.json',json.dumps(manifest,indent=2,sort_keys=True,allow_nan=False)+'\n')
        verify_manifest(work/'comparison_manifest.json');_new_output(root,output);_publish(work,output)
    return output/'comparison_manifest.json'
