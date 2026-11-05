"""Validated immutable comparison bundles; no flow extraction or RLS execution."""
from __future__ import annotations

import csv
from itertools import combinations
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile

from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24 import export_raw_statistics
from mawi_global_analysis.normalized24.statistics import _new_output
from .metrics import MODES, BITS, ratio, flow_jaccards, ks_distance, write_ecdf
from .validation import validate_comparison
from .prefix_ecdf import SCHEMA as PREFIX_ECDF_SCHEMA, build_prefix_ecdfs

SCHEMA = 'rls-weight-comparison-v1'
STATS = ('flow_count','packet_total','byte_total','mean_packet_count','median','p95','one_packet_rate')
CSV_NAMES = ('selected_native_prefixes.csv','selected_normalized24.csv','selection_summary.csv',
             'pairwise_jaccard.csv','prefix24_stats.csv','ecdf_counts.csv')
REQUIRED = {'dashboard.html',*CSV_NAMES,
            *(f'modes/{mode}/{name}' for mode in MODES for name in ('summary.json','frequencies.csv'))}


def _json(path: Path) -> dict:
    value=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value,dict):
        raise ValueError(f'{path}: expected a JSON object')
    return value


def _write_text(path: Path, text: str) -> None:
    with path.open('w',encoding='utf-8') as stream:
        stream.write(text);stream.flush();os.fsync(stream.fileno())


def _write_csv(path: Path, columns, rows) -> None:
    with path.open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,lineterminator='\n')
        writer.writeheader();writer.writerows(rows)
        stream.flush();os.fsync(stream.fileno())


def _entries(work: Path) -> dict:
    entries={}
    for path in sorted(work.rglob('*')):
        if not path.is_file() or path.name=='comparison_manifest.json':
            continue
        entry={'sha256':sha256_file(path)}
        if path.suffix=='.csv':
            with path.open(encoding='utf-8',newline='') as stream:
                reader=csv.reader(stream,strict=True)
                entry['columns']=next(reader)
                entry['row_count']=sum(1 for _ in reader)
        else:
            entry['record_count']=1
        entries[path.relative_to(work).as_posix()]=entry
    return entries


def _verify_artifacts(base: Path, entries: dict) -> None:
    if not REQUIRED.issubset(entries):
        raise ValueError(f'comparison artifacts missing: {sorted(REQUIRED-set(entries))}')
    for name,entry in entries.items():
        # Canonical artifact names only: resolving inside base is insufficient
        # for aliases such as ../<base-name>/file when copying to another base.
        relative=Path(name)
        if (not name or relative.is_absolute() or '..' in relative.parts
                or name!=relative.as_posix() or '\\' in name):
            raise ValueError(f'artifacts.{name}: unsafe relative path')
        path=(base/name).resolve()
        if not path.is_relative_to(base.resolve()) or Path(name).is_absolute():
            raise ValueError(f'artifacts.{name}: unsafe relative path')
        if sha256_file(path)!=entry.get('sha256'):
            raise ValueError(f'artifacts.{name}: SHA-256 mismatch')
        if path.suffix=='.csv':
            with path.open(encoding='utf-8',newline='') as stream:
                reader=csv.reader(stream,strict=True)
                if next(reader)!=entry.get('columns') or sum(1 for _ in reader)!=entry.get('row_count'):
                    raise ValueError(f'artifacts.{name}: schema or row_count mismatch')


def verify_comparison_manifest(path: Path) -> dict:
    """Rehash every recorded output without executing analysis or mutating files."""
    path=Path(path).expanduser().resolve()
    manifest=_json(path)
    if manifest.get('schema_version')!=SCHEMA or manifest.get('status')!='success':
        raise ValueError('comparison_manifest: unsupported schema or incomplete export')
    entries=manifest.get('artifacts')
    if not isinstance(entries,dict):
        raise ValueError('comparison_manifest.artifacts: expected an object')
    _verify_artifacts(path.parent,entries)
    from .native_generation import verify_native_extension
    verify_native_extension(manifest)
    return manifest


def _load_frequencies(db, mode: str, path: Path) -> None:
    with path.open(encoding='utf-8',newline='') as stream:
        for row in csv.DictReader(stream,strict=True):
            target=row['distribution']
            if target not in ('overall_ipv4','selected_union'):
                continue
            packets,n=int(row['packet_count']),int(row['frequency'])
            if packets<=0 or n<=0:
                raise ValueError(f'{mode}.frequencies: positive integers required')
            target=f'overall_{mode}' if target=='overall_ipv4' else mode
            db.execute('INSERT INTO frequencies VALUES (?,?,?)',(target,packets,n))


def _load_membership(db, root: Path, dataset: str, run: str, mode: str, chunksize: int) -> None:
    info=inspect_run(root,dataset,run,raw_only=True,verify_content_hashes=False)
    statement='INSERT INTO flow_sets VALUES (?,?) ON CONFLICT(id) DO UPDATE SET mask=mask | excluded.mask'
    with info.paths['flow_prefix_membership'].open(encoding='utf-8',newline='') as stream:
        batch=[]
        for row in csv.DictReader(stream,strict=True):
            if row['analysis_scope']=='normalized_24':
                if not row['flow_id']:
                    raise ValueError(f'{mode}.membership: empty flow_id')
                batch.append((row['flow_id'],BITS[mode]))
                if len(batch)>=chunksize:
                    db.executemany(statement,batch);batch=[]
        db.executemany(statement,batch)


def _same_overall(db, data: dict) -> dict:
    stats=data['packet']['references'][1]['stats']
    for mode in MODES:
        if data[mode]['references'][1]['stats']!=stats:
            raise ValueError(f'{mode}.overall: statistics differ between modes')
        for left,right in ((mode,'packet'),('packet',mode)):
            diff=db.execute('''SELECT packets,n FROM frequencies WHERE distribution=?
                EXCEPT SELECT packets,n FROM frequencies WHERE distribution=?''',
                (f'overall_{left}',f'overall_{right}')).fetchone()
            if diff:
                raise ValueError(f'{mode}.overall: exact frequencies differ between modes')
    db.execute("INSERT INTO frequencies SELECT 'overall_ipv4',packets,n FROM frequencies WHERE distribution='overall_packet'")
    return stats


def _prefixes(data: dict) -> tuple[dict,list]:
    sets={};merged={}
    for mode in MODES:
        sets[mode]=set()
        for card in data[mode]['prefixes']:
            prefix=card['prefix'];sets[mode].add(prefix)
            row=merged.setdefault(prefix,dict(prefix_24=prefix,modes=[],native_prefixes={},stats=card['stats']))
            if row['stats']!=card['stats']:
                raise ValueError(f'{mode}.{prefix}: same normalized /24 has inconsistent statistics')
            row['modes'].append(mode)
            row['native_prefixes'][mode]=card['native_prefixes']
    return sets,[merged[key] for key in sorted(merged)]


def _publish(work: Path, output: Path) -> None:
    output.mkdir()
    files=[];directories=[output]
    try:
        paths=sorted(p for p in work.rglob('*') if p.is_file() and p.name!='comparison_manifest.json')
        paths.append(work/'comparison_manifest.json')
        for source in paths:
            target=output/source.relative_to(work)
            missing=[];parent=target.parent
            while parent!=output and not parent.exists():
                missing.append(parent);parent=parent.parent
            for folder in reversed(missing):
                folder.mkdir();directories.append(folder)
            os.link(source,target);files.append((source,target))
    except BaseException:
        for source,target in reversed(files):
            if target.exists() and target.samefile(source):
                target.unlink()
        for folder in reversed(directories):
            try: folder.rmdir()
            except OSError: pass
        raise


def generate_comparison(root: Path, dataset_id: str, *, packet_run: str, byte_run: str,
                        flow_run: str, output_dir: Path, scratch_dir: Path | None = None,
                        chunksize: int = 100_000, max_ecdf_points: int = 2000) -> Path:
    """Validate saved runs, compute exact metrics, and publish a new offline bundle."""
    if type(max_ecdf_points) is not int or not 2<=max_ecdf_points<=50_000:
        raise ValueError('max_ecdf_points must be an integer in [2,50000]')
    root=Path(root).expanduser().resolve()
    output=Path(output_dir).expanduser()
    if output.is_symlink():
        raise FileExistsError(f'existing output symlink: {output}')
    output=output.resolve();_new_output(root,output)
    runs=dict(packet_run=packet_run,byte_run=byte_run,flow_run=flow_run)
    validation=validate_comparison(root,dataset_id,chunksize=chunksize,**runs)
    # No output directory, parent or temporary work is created before validation succeeds.
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.rls-comparison-',dir=output.parent) as temporary:
        work=Path(temporary);data={}
        for mode,run in zip(MODES,(packet_run,byte_run,flow_run)):
            summary=export_raw_statistics(root,dataset_id,run,work/'modes'/mode,
                                           chunksize=chunksize,scratch_dir=scratch_dir)
            data[mode]=_json(summary)
        with tempfile.TemporaryDirectory(prefix='rls-comparison-sqlite-',dir=scratch_dir) as scratch:
            db=sqlite3.connect(Path(scratch)/'comparison.sqlite')
            try:
                db.execute('PRAGMA cache_size=-32768');db.execute('PRAGMA temp_store=FILE')
                db.executescript('''CREATE TABLE flow_sets(id TEXT PRIMARY KEY,mask INTEGER) WITHOUT ROWID;
                    CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER,
                    PRIMARY KEY(distribution,packets)) WITHOUT ROWID;''')
                for mode,run in zip(MODES,(packet_run,byte_run,flow_run)):
                    _load_frequencies(db,mode,work/'modes'/mode/'frequencies.csv')
                    _load_membership(db,root,dataset_id,run,mode,chunksize)
                    actual=db.execute('SELECT COUNT(*) FROM flow_sets WHERE mask & ? != 0',(BITS[mode],)).fetchone()[0]
                    if actual!=data[mode]['references'][0]['stats']['flow_count']:
                        raise ValueError(f'{mode}.membership: union ID count differs from validated statistics')
                overall=_same_overall(db,data)
                sets,prefixes=_prefixes(data)
                jaccard=flow_jaccards(db)
                for a,b in combinations(MODES,2):
                    intersection,union=len(sets[a]&sets[b]),len(sets[a]|sets[b])
                    jaccard.append(dict(mode_a=a,mode_b=b,set_kind='normalized24',intersection_count=intersection,
                                        union_count=union,jaccard=ratio(intersection,union)))
                    if sets[a]==sets[b]:
                        flow=next(r for r in jaccard if r['mode_a']==a and r['mode_b']==b and r['set_kind']=='flow_id')
                        if (flow['intersection_count']!=flow['union_count']
                                or data[a]['references'][0]['stats']!=data[b]['references'][0]['stats']):
                            raise ValueError(f'{a}/{b}: same normalized sets have different unions/statistics')
                modes={}
                for mode in MODES:
                    stats=data[mode]['references'][0]['stats']
                    modes[mode]=dict(selected_native_prefix_count=len(data[mode]['provenance']['selected_native_prefixes']),
                        normalized_prefix_count=len(sets[mode]),stats=stats,
                        coverage={key:ratio(stats[field],overall[field]) for key,field in
                                  (('flow','flow_count'),('packet','packet_total'),('byte','byte_total'))},
                        **ks_distance(db,mode,'overall_ipv4'))
                with (work/'ecdf_counts.csv').open('w',encoding='utf-8',newline='') as stream:
                    curves=write_ecdf(db,{'overall_ipv4':overall['flow_count'],**{m:modes[m]['stats']['flow_count'] for m in MODES}},
                                      stream,max_points=max_ecdf_points)
                    stream.flush();os.fsync(stream.fileno())
            finally:
                db.close()
        native=[];normalized=[];prefix_stats=[];selection=[]
        for mode in MODES:
            for card in data[mode]['prefixes']:
                normalized.append(dict(mode=mode,prefix_24=card['prefix']))
                prefix_stats.append(dict(mode=mode,prefix_24=card['prefix'],
                    native_prefixes=json.dumps(card['native_prefixes']),**card['stats']))
                for prefix in card['native_prefixes']:
                    native.append(dict(mode=mode,native_prefix=prefix,prefix_length=ipaddress.ip_network(prefix).prefixlen,
                                       normalized_prefix_24=card['prefix']))
            record=modes[mode]
            selection.append(dict(mode=mode,selected_native_prefix_count=record['selected_native_prefix_count'],
                normalized_prefix_count=record['normalized_prefix_count'],**record['stats'],
                **{f'{key}_coverage':value for key,value in record['coverage'].items()},
                **{key:record[key] for key in ('ks_distance','ks_numerator','ks_denominator')}))
        _write_csv(work/CSV_NAMES[0],('mode','native_prefix','prefix_length','normalized_prefix_24'),native)
        _write_csv(work/CSV_NAMES[1],('mode','prefix_24'),normalized)
        _write_csv(work/CSV_NAMES[2],('mode','selected_native_prefix_count','normalized_prefix_count',*STATS,
            'flow_coverage','packet_coverage','byte_coverage','ks_distance','ks_numerator','ks_denominator'),selection)
        _write_csv(work/CSV_NAMES[3],('mode_a','mode_b','set_kind','intersection_count','union_count','jaccard'),jaccard)
        _write_csv(work/CSV_NAMES[4],('mode','prefix_24','native_prefixes',*STATS),prefix_stats)
        per_prefix_ecdf=build_prefix_ecdfs(work,prefixes,scratch_dir=scratch_dir)
        from .dashboard import render_dashboard
        repo=Path(__file__).resolve().parents[3]
        implementation={'sha256':{name:sha256_file(Path(__file__).with_name(name)) for name in
            ('generation.py','metrics.py','validation.py','cli.py','dashboard.py','dashboard.html','prefix_ecdf.py','refresh.py')}}
        git=subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],capture_output=True,text=True,check=False)
        implementation['git_commit']=git.stdout.strip() if git.returncode==0 else None
        display={'max_ecdf_points':max_ecdf_points,'sampling':'uniform observed-size rank; retained exact points',
            'simplified_interpolation':'lower HV bound with next-retained-point upper envelope; not exact between points',
            'statistics_source':'full exact frequencies, never display samples',
            'null_rules':'zero denominator: null; both-empty Jaccard: null; empty KS: null',
            'csv_null_encoding':'empty cells represent JSON null; integer numerators/counts remain exact',
            'browser_integer_encoding':'integers beyond 2**53-1 are decimal strings; research JSON/CSV preserve integers',
            'per_prefix_ecdf':{k:v for k,v in per_prefix_ecdf.items() if k!='curves'},
            'self_hash':'dashboard.html hash is in comparison_manifest.json; HTML cannot embed its own hash'}
        payload=dict(schema_version='rls-weight-comparison-dashboard-v1',dataset_id=dataset_id,
            evidence='Saved-run descriptive comparison; synthetic fixtures are not real MAWI findings.',
            conditions=validation['common'],runs=validation['runs'],modes=modes,overall={'stats':overall},
            jaccard=jaccard,prefixes=prefixes,ecdf=curves,per_prefix_ecdf=per_prefix_ecdf,
            provenance={'validation':validation,'inputs':{m:data[m]['provenance']['inputs'] for m in MODES},
                'schemas':{'comparison':SCHEMA,'per_prefix_ecdf':PREFIX_ECDF_SCHEMA,'dashboard':'rls-weight-comparison-dashboard-v1',
                    'modes':{m:{'payload_schema_version':data[m]['schema_version'],
                        'aggregation_version':data[m]['provenance']['aggregation']['version'],
                        'export_schema_version':data[m]['export_schema_version'],
                        'frequency_schema_version':data[m]['artifacts']['frequencies']['schema_version']} for m in MODES}},
                'implementation':implementation,'artifacts':_entries(work),'display':display})
        _write_text(work/'dashboard.html',render_dashboard(payload))
        final_validation=validate_comparison(root,dataset_id,chunksize=chunksize,**runs)
        if final_validation!=validation:
            raise ValueError('comparison inputs changed during generation')
        entries=_entries(work);_verify_artifacts(work,entries)
        manifest=dict(schema_version=SCHEMA,status='success',dataset_id=dataset_id,
            validation=validation,final_validation=final_validation,conditions=validation['common'],
            source_runs={m:data[m]['provenance'] for m in MODES},implementation=implementation,
            schemas=payload['provenance']['schemas'],
            artifacts=entries,dashboard_generation=display,evidence=payload['evidence'])
        _write_text(work/'comparison_manifest.json',json.dumps(manifest,ensure_ascii=False,allow_nan=False,sort_keys=True,indent=2)+'\n')
        verify_comparison_manifest(work/'comparison_manifest.json')
        _new_output(root,output);_publish(work,output)
    return output/'comparison_manifest.json'
