"""Dedicated two-stage comparison; exact shared aggregators and immutable data exports."""
from __future__ import annotations
import csv
import json
from pathlib import Path
import sqlite3
import tempfile
from contextlib import closing
from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24 import export_raw_statistics
from mawi_global_analysis.normalized24.statistics import _new_output
from mawi_global_analysis.rls_weight_comparison.generation import (_entries,_publish,_write_text,_write_csv,_json,STATS,_load_frequencies,_same_overall)
from mawi_global_analysis.rls_weight_comparison.metrics import write_ecdf
from mawi_global_analysis.rls_weight_comparison.native_analysis import analyze_native_runs
from mawi_global_analysis.rls_weight_comparison.refresh import _guard_locations
from .validation import validate_runs,SCHEMA as VALIDATION_SCHEMA
from .stage import MODES

LEGACY_SCHEMA='aguri-two-stage-comparison-v1'
SCHEMA='aguri-two-stage-comparison-v2'
REQUIRED={'summary.json','ecdf_counts.csv','native_selection_summary.csv','native_prefix_stats.csv','native_pairwise_jaccard.csv',
          'native_ecdf_counts.csv','scope_comparison.csv','scope_ecdf_counts.csv',
          *(f'{prefix}modes/{mode}/{name}' for prefix in ('','native/') for mode in MODES for name in ('summary.json','frequencies.csv'))}

def verify_manifest(path):
    path=Path(path).expanduser().resolve();m=_json(path);entries=m.get('artifacts')
    schema=m.get('schema_version')
    required=REQUIRED | {'dashboard.html'} if schema==LEGACY_SCHEMA else REQUIRED
    if (schema not in (LEGACY_SCHEMA,SCHEMA) or m.get('status')!='success'
            or not isinstance(entries,dict) or not required.issubset(entries)):
        raise ValueError('incomplete two-stage comparison manifest')
    if schema==SCHEMA and any(Path(name).suffix not in ('.csv','.json') for name in entries):
        raise ValueError('two-stage comparison v2 is data-only')
    v=m.get('validation')
    if (not isinstance(v,dict) or v!=m.get('final_validation') or v.get('schema_version')!=VALIDATION_SCHEMA
            or v.get('status')!='valid' or v.get('dataset_id')!=m.get('dataset_id') or set(v.get('runs',{}))!=set(MODES)):
        raise ValueError('comparison validation binding mismatch')
    for name,e in entries.items():
        rel=Path(name);file=(path.parent/rel).resolve()
        if not name or rel.is_absolute() or '..' in rel.parts or '\\' in name or rel.as_posix()!=name or not file.is_relative_to(path.parent):raise ValueError('unsafe artifact path')
        if not isinstance(e,dict) or sha256_file(file)!=e.get('sha256'):raise ValueError(name+': SHA-256 mismatch')
        if rel.suffix=='.csv':
            with file.open(encoding='utf-8',newline='') as stream:
                r=csv.reader(stream,strict=True)
                if next(r,None)!=e.get('columns') or sum(1 for _ in r)!=e.get('row_count'):raise ValueError(name+': schema/count mismatch')
        elif schema==SCHEMA:
            if type(e.get('record_count')) is not int or e['record_count']!=1:
                raise ValueError(name+': JSON record_count mismatch')
            _json(file)
    summary=_json(path.parent/'summary.json')
    if (summary.get('dataset_id')!=m['dataset_id'] or summary.get('conditions')!=v.get('common')
            or summary.get('runs')!=v['runs']):raise ValueError('summary condition binding mismatch')
    return m

def generate_comparison(root,dataset_id,*,packet_run,byte_run,flow_run,output_dir,chunksize=100000,scratch_dir=None,max_ecdf_points=2000):
    root=Path(root).expanduser().resolve();output=Path(output_dir).expanduser()
    if output.is_symlink():raise FileExistsError(output)
    output=output.resolve();_new_output(root,output)
    runs=dict(packet_run=packet_run,byte_run=byte_run,flow_run=flow_run)
    validation=validate_runs(root,dataset_id,**runs,chunksize=chunksize)
    _guard_locations(root/'results'/dataset_id,{'source_runs':validation['runs']},output,Path(scratch_dir).expanduser().resolve() if scratch_dir else None)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.two-stage-comparison-',dir=output.parent) as tmp:
        work=Path(tmp)/'bundle';work.mkdir();data={}
        for mode,run in zip(MODES,(packet_run,byte_run,flow_run)):
            data[mode]=_json(export_raw_statistics(root,dataset_id,run,work/'modes'/mode,chunksize=chunksize,scratch_dir=scratch_dir))
        infos={mode:inspect_run(root,dataset_id,run,raw_only=True) for mode,run in zip(MODES,(packet_run,byte_run,flow_run))}
        result=analyze_native_runs(infos,work,work/'native',chunksize=chunksize,scratch_dir=scratch_dir,max_ecdf_points=max_ecdf_points)
        (work/'native/ecdf_counts.csv').rename(work/'native_ecdf_counts.csv');(work/'native/scope_ecdf_counts.csv').rename(work/'scope_ecdf_counts.csv')
        # Existing frequency helpers verify all three Overall distributions.
        with tempfile.TemporaryDirectory(prefix='two-stage-frequency-',dir=scratch_dir) as frequency_tmp, closing(sqlite3.connect(Path(frequency_tmp)/'working.sqlite')) as db:
            db.execute('PRAGMA cache_size=-32768');db.execute('PRAGMA temp_store=FILE')
            db.execute('CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(distribution,packets)) WITHOUT ROWID')
            for mode in MODES:_load_frequencies(db,mode,work/'modes'/mode/'frequencies.csv')
            overall=_same_overall(db,data)
            with (work/'ecdf_counts.csv').open('w',newline='') as stream:
                write_ecdf(db,{'overall_ipv4':overall['flow_count'],**{mode:data[mode]['references'][0]['stats']['flow_count'] for mode in MODES}},stream,max_points=max_ecdf_points)
        selection=[];prefixes=[]
        for mode in MODES:
            r=result['modes'][mode]
            selection.append(dict(mode=mode,selected_native_prefix_count=r['selected_native_prefix_count'],**r['stats'],**{k+'_coverage':v for k,v in r['coverage'].items()},**{k:r[k] for k in ('ks_distance','ks_numerator','ks_denominator')}))
            for p in result['prefixes']:
                if mode in p['modes']:prefixes.append(dict(mode=mode,prefix=p['prefix'],**p['stats']))
        _write_csv(work/'native_selection_summary.csv',('mode','selected_native_prefix_count',*STATS,'flow_coverage','packet_coverage','byte_coverage','ks_distance','ks_numerator','ks_denominator'),selection)
        _write_csv(work/'native_prefix_stats.csv',('mode','prefix',*STATS),prefixes)
        _write_csv(work/'native_pairwise_jaccard.csv',('mode_a','mode_b','set_kind','intersection_count','union_count','jaccard'),result['jaccard'])
        columns=('mode','selection_fixed','native_union_subset_normalized24',*('native_'+k for k in STATS),*('normalized24_'+k for k in STATS),'native_flow_coverage','normalized24_flow_coverage','ks_distance','ks_numerator','ks_denominator')
        _write_csv(work/'scope_comparison.csv',columns,result['scope_comparison'].values())
        result.update(dataset_id=dataset_id,conditions=validation['common'],runs=validation['runs'],evidence='Synthetic tests are not MAWI findings. Canonical Aguri3→Agurim; fixed settings, variable basis.')
        summary={k:v for k,v in result.items() if k not in ('ecdf','scope_ecdf','per_prefix_ecdf')}
        _write_text(work/'summary.json',json.dumps(summary,allow_nan=False,indent=2)+'\n')
        package=Path(__file__).resolve().parents[1]
        implementation={str(p.relative_to(package)):sha256_file(p) for p in Path(__file__).parent.iterdir() if p.is_file() and p.suffix=='.py'}
        for name in ('normalized24/analysis.py','normalized24/statistics.py','rls_weight_comparison/native_analysis.py','rls_weight_comparison/metrics.py',
                     'rls_weight_comparison/prefix_ecdf.py'):
            implementation[name]=sha256_file(package/name)
        final=validate_runs(root,dataset_id,**runs,chunksize=chunksize)
        if final!=validation:raise ValueError('two-stage inputs changed during comparison')
        m=dict(schema_version=SCHEMA,status='success',dataset_id=dataset_id,validation=validation,final_validation=final,implementation_sha256=implementation,artifacts=_entries(work))
        _write_text(work/'comparison_manifest.json',json.dumps(m,indent=2,sort_keys=True,allow_nan=False)+'\n');verify_manifest(work/'comparison_manifest.json')
        _new_output(root,output);_publish(work,output)
    return output/'comparison_manifest.json'
