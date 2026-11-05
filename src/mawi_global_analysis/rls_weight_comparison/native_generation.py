"""Publish native evaluation alongside an unchanged normalized comparison."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
import shutil
import tempfile

from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24.statistics import _new_output
from .generation import (STATS, _entries, _json, _publish, _verify_artifacts, _write_csv,
                         _write_text, generate_comparison, verify_comparison_manifest)
from .metrics import MODES
from .native_analysis import analyze_native_runs
from .refresh import _guard_locations
from .validation import validate_comparison

EXTENSION_SCHEMA='rls-native-comparison-v1'
NATIVE_REQUIRED={'dashboard_native.html','native_selection_summary.csv','native_prefix_stats.csv',
                 'native_ecdf_counts.csv','native_pairwise_jaccard.csv','scope_comparison.csv','scope_ecdf_counts.csv',
                 *(f'native/modes/{m}/{name}' for m in MODES for name in ('summary.json','frequencies.csv'))}


def verify_native_extension(manifest: dict) -> None:
    """Reject scope contradictions and metadata downgrade of reserved artifacts."""
    extension=manifest.get('native_extension')
    if extension is None:
        if NATIVE_REQUIRED.intersection(manifest['artifacts']):
            raise ValueError('native artifacts require native_extension metadata')
        return
    expected={'schema_version':EXTENSION_SCHEMA,'membership_scope':'native',
              'endpoint_rule':'src_ip OR dst_ip','prefix_expansion':False,
              'union_deduplication':'flow_id','selection_fixed':True}
    if not isinstance(extension,dict):raise ValueError('native_extension must be an object')
    for key,value in expected.items():
        if type(extension.get(key)) is not type(value) or extension[key]!=value:
            raise ValueError(f'native_extension.{key}: missing or contradictory value')
    if extension.get('required_artifacts')!=sorted(NATIVE_REQUIRED) or not NATIVE_REQUIRED.issubset(manifest['artifacts']):
        raise ValueError('native artifacts missing or required_artifacts inconsistent')
    invariants={'membership_unique_correct_complete','native_union_subset_normalized24_by_flow_id',
                'native_totals_lte_normalized24','same_prefix_distribution_across_modes','overall_identical'}
    recorded=extension.get('invariants')
    if not isinstance(recorded,dict) or set(recorded)!=invariants or any(v is not True for v in recorded.values()):
        raise ValueError('native_extension.invariants: incomplete or contradictory checks')
    validation=manifest.get('validation')
    if (not isinstance(validation,dict) or validation.get('status')!='valid'
            or validation.get('dataset_id')!=manifest.get('dataset_id')
            or extension.get('validation')!=validation or extension.get('final_validation')!=validation
            or manifest.get('final_validation')!=validation):
        raise ValueError('native_extension validation binding mismatch')
    if (not isinstance(validation.get('runs'),dict) or set(validation['runs'])!=set(MODES)
            or not isinstance(validation.get('common'),dict) or not isinstance(validation['common'].get('canonical'),dict)
            or any(not isinstance(validation['runs'][m],dict) or 'run_manifest_sha256' not in validation['runs'][m] for m in MODES)
            or 'csv_sha256' not in validation['common']['canonical']):
        raise ValueError('native_extension validation structure incomplete')
    schemas={'statistics':'rls-native-statistics-v1','dashboard':'rls-native-comparison-dashboard-v1',
             'frequency':'normalized24-exact-frequencies-v1','per_prefix_ecdf':'rls-native-prefix-ecdf-v1'}
    if extension.get('schemas')!=schemas:raise ValueError('native_extension.schemas mismatch')
    implementation=extension.get('implementation_sha256')
    if (not isinstance(implementation,dict) or not {'native_analysis.py','native_generation.py','normalized24/analysis.py'}.issubset(implementation)
            or any(not isinstance(v,str) or re.fullmatch('[0-9a-f]{64}',v) is None for v in implementation.values())):
        raise ValueError('native_extension implementation hashes missing or invalid')
    inputs=extension.get('native_inputs')
    if not isinstance(inputs,dict) or set(inputs)!=set(MODES):raise ValueError('native_extension.native_inputs missing')
    for mode,records in inputs.items():
        if not isinstance(records,dict) or not {'flows','run_manifest','flow_manifest','prefixes','flow_prefix_membership'}.issubset(records):
            raise ValueError(f'native_extension.{mode}.inputs incomplete')
        for name,record in records.items():
            if (not isinstance(record,dict) or not isinstance(record.get('path'),str)
                    or not isinstance(record.get('sha256'),str) or re.fullmatch('[0-9a-f]{64}',record['sha256']) is None):
                raise ValueError(f'native_extension.{mode}.{name}: invalid input binding')
        if (records['run_manifest']['sha256']!=validation['runs'][mode]['run_manifest_sha256']
                or records['flows']['sha256']!=validation['common']['canonical']['csv_sha256']):
            raise ValueError(f'native_extension.{mode}: canonical/run input mismatch')


def generate_native_comparison(root: Path, dataset_id: str, *, packet_run: str, byte_run: str,
                               flow_run: str, output_dir: Path, comparison_manifest: Path | None=None,
                               chunksize: int=100_000, scratch_dir: Path | None=None,
                               max_ecdf_points: int=2000) -> Path:
    """Fixed selections; only evaluation scopes differ. Source outputs are read-only.

    With comparison_manifest, copy every original artifact unchanged. Otherwise
    use the existing normalized generator privately. Neither path invokes RLS or
    reads PCAP. Publish a new bundle and its final manifest only on success.
    """
    root=Path(root).expanduser().resolve();output=Path(output_dir).expanduser()
    if output.is_symlink():raise FileExistsError(f'existing output symlink: {output}')
    output=output.resolve();_new_output(root,output)
    runs=dict(packet_run=packet_run,byte_run=byte_run,flow_run=flow_run)
    validation=validate_comparison(root,dataset_id,chunksize=chunksize,**runs)
    infos={m:inspect_run(root,dataset_id,r,raw_only=True,verify_content_hashes=False) for m,r in zip(MODES,(packet_run,byte_run,flow_run))}
    protection={'source_runs':{m:{'inputs':{'run_manifest':{'path':str(info.manifest_path.resolve())}}} for m,info in infos.items()}}
    _guard_locations(root/'results'/dataset_id,protection,output,Path(scratch_dir).expanduser().resolve() if scratch_dir else None)
    source=None;source_hash=None;manifest=None
    if comparison_manifest is not None:
        source=Path(comparison_manifest).expanduser().resolve()
        raw=source.read_bytes();source_hash=hashlib.sha256(raw).hexdigest();manifest=json.loads(raw)
        if verify_comparison_manifest(source)!=manifest:raise ValueError('source comparison changed during snapshot')
        if manifest.get('native_extension') is not None:raise ValueError('source comparison already has native extension; use its normalized source')
        if manifest.get('validation')!=validation or manifest.get('dataset_id')!=dataset_id:
            raise ValueError('source comparison does not match these fixed saved runs / canonical inputs')
        _guard_locations(source.parent,manifest,output,Path(scratch_dir).expanduser().resolve() if scratch_dir else None)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-bundle-',dir=output.parent) as temporary:
        staging=Path(temporary)
        if source:
            work=staging/'bundle';work.mkdir()
            for name in manifest['artifacts']:
                target=work/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source.parent/name,target)
            _verify_artifacts(work,manifest['artifacts'])
        else:
            generated=generate_comparison(root,dataset_id,**runs,output_dir=staging/'bundle',chunksize=chunksize,
                                          scratch_dir=scratch_dir,max_ecdf_points=max_ecdf_points)
            work=generated.parent;manifest=_json(generated);generated.unlink()
        result=analyze_native_runs(infos,work,work/'native',chunksize=chunksize,
                                   scratch_dir=scratch_dir,max_ecdf_points=max_ecdf_points)
        (work/'native/ecdf_counts.csv').rename(work/'native_ecdf_counts.csv')
        (work/'native/scope_ecdf_counts.csv').rename(work/'scope_ecdf_counts.csv')
        selection=[];prefix_stats=[]
        for mode in MODES:
            record=result['modes'][mode]
            selection.append(dict(mode=mode,selected_native_prefix_count=record['selected_native_prefix_count'],**record['stats'],
                **{k+'_coverage':v for k,v in record['coverage'].items()},
                **{k:record[k] for k in ('ks_distance','ks_numerator','ks_denominator')}))
            for p in result['prefixes']:
                if mode in p['modes']:prefix_stats.append(dict(mode=mode,prefix=p['prefix'],**p['stats']))
        _write_csv(work/'native_selection_summary.csv',('mode','selected_native_prefix_count',*STATS,'flow_coverage','packet_coverage','byte_coverage','ks_distance','ks_numerator','ks_denominator'),selection)
        _write_csv(work/'native_prefix_stats.csv',('mode','prefix',*STATS),prefix_stats)
        _write_csv(work/'native_pairwise_jaccard.csv',('mode_a','mode_b','set_kind','intersection_count','union_count','jaccard'),result['jaccard'])
        columns=('mode','selection_fixed','native_union_subset_normalized24',*('native_'+k for k in STATS),
            *('normalized24_'+k for k in STATS),'native_flow_coverage','normalized24_flow_coverage','ks_distance','ks_numerator','ks_denominator')
        _write_csv(work/'scope_comparison.csv',columns,result['scope_comparison'].values())
        implementation={name:sha256_file(Path(__file__).with_name(name)) for name in
            ('native_analysis.py','native_generation.py','native_dashboard.py','native_scope.html','native_scope.js',
             'generation.py','refresh.py','metrics.py','prefix_ecdf.py','dashboard.py','dashboard.html','validation.py','cli.py')}
        package=Path(__file__).resolve().parents[1]
        implementation.update({name:sha256_file(package/name) for name in ('normalized24/analysis.py','normalized24/statistics.py','flow_length.py','membership.py')})
        extension=dict(schema_version=EXTENSION_SCHEMA,membership_scope='native',endpoint_rule='src_ip OR dst_ip',
            prefix_expansion=False,union_deduplication='flow_id',selection_fixed=True,
            source_comparison_manifest={'path':str(source),'sha256':source_hash} if source else None,
            implementation_sha256=implementation,validation=validation,
            native_inputs={m:_json(work/'native/modes'/m/'summary.json')['provenance']['inputs'] for m in MODES},
            invariants={'membership_unique_correct_complete':True,'native_union_subset_normalized24_by_flow_id':True,
                        'native_totals_lte_normalized24':True,'same_prefix_distribution_across_modes':True,'overall_identical':True},
            display={'max_ecdf_points':max_ecdf_points,'individual':{k:v for k,v in result['per_prefix_ecdf'].items() if k!='curves'},
                     'sampling':'retained genuine points; simplified HV lower bound with next-point upper envelope'},
            schemas={'statistics':'rls-native-statistics-v1','dashboard':'rls-native-comparison-dashboard-v1',
                     'frequency':'normalized24-exact-frequencies-v1','per_prefix_ecdf':'rls-native-prefix-ecdf-v1'},
            required_artifacts=sorted(NATIVE_REQUIRED))
        result.update(dataset_id=dataset_id,runs=validation['runs'],conditions={'selection_run_contract':validation['common'],
                      'evaluation':{'scope':'native','parent_24_expansion':False,'endpoint_rule':'src_ip OR dst_ip','group':'Raw'}},
                      evidence='Saved-run descriptive native evaluation; synthetic fixtures are not real MAWI findings.',
                      provenance={'validation':validation,'inputs':extension['native_inputs'],
                                  'implementation':implementation,'schemas':extension['schemas'],'display':extension['display'],
                                  'native_extension':extension,'artifacts':_entries(work)})
        from .native_dashboard import render_native_dashboard
        _write_text(work/'dashboard_native.html',render_native_dashboard(result))
        final=validate_comparison(root,dataset_id,chunksize=chunksize,**runs)
        if final!=validation:raise ValueError('input runs changed during native evaluation')
        if source:
            verify_comparison_manifest(source)
            if sha256_file(source)!=source_hash:raise ValueError('source comparison manifest changed during native evaluation')
            for name,entry in manifest['artifacts'].items():
                if sha256_file(work/name)!=entry['sha256']:raise ValueError(f'{name}: normalized artifact changed')
        entries=_entries(work)
        manifest.update(artifacts=entries,native_extension={**extension,'final_validation':final})
        _write_text(work/'comparison_manifest.json',json.dumps(manifest,ensure_ascii=False,allow_nan=False,indent=2,sort_keys=True)+'\n')
        verify_comparison_manifest(work/'comparison_manifest.json');_new_output(root,output);_publish(work,output)
    return output/'comparison_manifest.json'
