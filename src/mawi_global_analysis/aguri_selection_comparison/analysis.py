"""Disk-backed exact native unions and post-selection contribution analysis."""
from __future__ import annotations

import csv
from itertools import combinations
import ipaddress
import json
from pathlib import Path
import sqlite3
import tempfile

from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.prefix import _parse_concrete_network
from mawi_global_analysis.normalized24.analysis import _summarize, summarize_frequencies
from mawi_global_analysis.normalized24.statistics import _write_frequencies
from mawi_global_analysis.rls_weight_comparison.generation import _write_csv, _write_text, STATS
from mawi_global_analysis.rls_weight_comparison.metrics import ratio, ks_distance, write_ecdf
from mawi_global_analysis.rls_weight_comparison.native_analysis import _ingest
from .validation import CONDITIONS, CONDITIONS_V2, DEFAULT_RUNS, _validate_inputs

TARGET='93.139.29.123/32'


def _view(db,sql,params=(),*,spec):
    db.execute('DROP TABLE IF EXISTS cohort_ids');db.execute('CREATE TEMP TABLE cohort_ids(id TEXT PRIMARY KEY) WITHOUT ROWID')
    db.execute('INSERT INTO cohort_ids '+sql,params)
    for table in ('dist','totals'):db.execute(f'DROP TABLE IF EXISTS {table}')
    db.executescript("CREATE TABLE dist(target TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(target,packets)) WITHOUT ROWID;\n"
        "INSERT INTO dist SELECT 'cohort',f.packets,COUNT(*) FROM facts f JOIN cohort_ids c ON f.id=c.id GROUP BY f.packets;")
    row=db.execute('SELECT exact_integer_sum(f.bytes) FROM facts f JOIN cohort_ids c ON f.id=c.id').fetchone()
    return summarize_frequencies(db,'cohort',spec,byte_total=int(row[0]) if row[0] is not None else 0)['stats']


def _component(db,name,sql,params=(),*,spec):
    stats=_view(db,sql,params,spec=spec)
    db.execute('INSERT INTO frequencies SELECT ?,packets,n FROM dist',(name,));return stats


def _candidate_focus(path,target):
    net=ipaddress.ip_network(target);exact=False;covering=set()
    with Path(path).open(encoding='utf-8',newline='') as stream:
        for row in csv.DictReader(stream):
            for field in ('src_prefix','dst_prefix'):
                value=row[field]
                candidate=_parse_concrete_network(value)
                if candidate is not None and candidate.version==4 and net.subnet_of(candidate):
                    covering.add(str(candidate));exact|=candidate==net
    return exact,sorted(covering)


def analyze_inputs(root: Path,dataset_id: str,output: Path,*,run_a=DEFAULT_RUNS['A'],run_b=DEFAULT_RUNS['B'],run_c=None,run_c_packet=None,run_c_flow=None,
                   chunksize=100_000,scratch_dir=None,max_ecdf_points=2000,target=TARGET,validation=None,legacy_reference=None) -> dict:
    if type(max_ecdf_points) is not int or not 2<=max_ecdf_points<=50000:raise ValueError('max_ecdf_points must be in [2,50000]')
    target=str(ipaddress.ip_network(target,strict=True));target_net=ipaddress.ip_network(target)
    if target_net.version!=4 or target_net.prefixlen<24:raise ValueError('target must be a concrete IPv4 /24..32 prefix')
    root=Path(root).resolve()
    validation=validation or _validate_inputs(root,dataset_id,run_a=run_a,run_b=run_b,run_c=run_c,
                                              run_c_packet=run_c_packet,run_c_flow=run_c_flow,chunksize=chunksize)
    version=1 if set(validation['runs'])==set(CONDITIONS) else 2
    condition_keys=CONDITIONS if version==1 else CONDITIONS_V2
    if set(validation['runs'])!=set(condition_keys):
        raise ValueError('unexpected comparison conditions')
    infos={key:inspect_run(root,dataset_id,validation['runs'][key]['run_name'],raw_only=True)
           for key in condition_keys}
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    conditions={};prefixes={};focus={};sensitivities={};components={};changes=[]
    with tempfile.TemporaryDirectory(prefix='abc-native-',dir=scratch_dir) as temp:
        db=sqlite3.connect(Path(temp)/'working.sqlite')
        try:
            db.execute('PRAGMA cache_size=-32768');db.execute('PRAGMA temp_store=FILE');_ingest(db,infos,chunksize)
            db.executescript('''CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(distribution,packets)) WITHOUT ROWID;
                CREATE TABLE unions(condition TEXT,id TEXT,PRIMARY KEY(condition,id)) WITHOUT ROWID;
                INSERT INTO unions SELECT mode,id FROM edges WHERE scope='native' GROUP BY mode,id;
                CREATE INDEX unions_id ON unions(id,condition);''')
            overall=None;spec=None
            for key in condition_keys:
                db.execute('DROP VIEW IF EXISTS membership')
                db.execute(f"CREATE TEMP VIEW membership AS SELECT prefix,id FROM edges WHERE mode='{key}' AND scope='native'")
                for table in ('dist','totals'):db.execute(f'DROP TABLE IF EXISTS {table}')
                cards,refs,spec=_summarize(db,{p:[p] for p in infos[key].selected_prefixes},spec)
                if overall is None:
                    overall=refs[1]['stats'];db.execute("INSERT INTO frequencies SELECT 'overall_ipv4',packets,n FROM dist WHERE target='overall_ipv4'")
                elif overall!=refs[1]['stats']:raise ValueError('Overall differs across conditions')
                db.execute("INSERT INTO frequencies SELECT ?,packets,n FROM dist WHERE target='selected_union'",(key,))
                folder=output/'modes'/key;folder.mkdir(parents=True)
                with (folder/'frequencies.csv').open('w',encoding='utf-8',newline='') as stream:_write_frequencies(db,stream)
                _write_text(folder/'summary.json',json.dumps(dict(schema_version=f'aguri-selection-statistics-v{version}',condition=key,
                    prefixes=cards,references=refs,inputs=validation['runs'][key]['inputs'],histogram_spec=spec.to_dict()),indent=2,allow_nan=False)+'\n')
                stats=refs[0]['stats'];conditions[key]=dict(selected_native_prefix_count=len(cards),stats=stats,
                    coverage={k:ratio(stats[f],overall[f]) for k,f in (('flow','flow_count'),('packet','packet_total'),('byte','byte_total'))},
                    **ks_distance(db,key,'overall_ipv4'))
                for card in cards:
                    p=card['prefix'];row=prefixes.setdefault(p,dict(prefix=p,conditions=[],stats=card['stats']))
                    if row['stats']!=card['stats']:raise ValueError('shared prefix statistics differ')
                    row['conditions'].append(key)
            # Completeness and canonical identity imply shared-prefix population
            # identity; additionally compare EVERY exported frequency row.
            db.execute('CREATE TABLE prefix_dist(condition TEXT,prefix TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(condition,prefix,packets)) WITHOUT ROWID')
            for key in condition_keys:
                with (output/'modes'/key/'frequencies.csv').open() as stream:
                    for r in csv.DictReader(stream):
                        if r['distribution'] not in ('selected_union','overall_ipv4'):
                            db.execute('INSERT INTO prefix_dist VALUES (?,?,?,?)',(key,r['distribution'],int(r['packet_count']),int(r['frequency'])))
            for p,row in prefixes.items():
                first=row['conditions'][0]
                for key in row['conditions'][1:]:
                    for a,b in ((first,key),(key,first)):
                        if db.execute('SELECT packets,n FROM prefix_dist WHERE condition=? AND prefix=? EXCEPT SELECT packets,n FROM prefix_dist WHERE condition=? AND prefix=?',(a,p,b,p)).fetchone():raise ValueError('shared prefix frequencies differ')
            # Per-prefix exclusive counts are the actual number removed by a
            # single-prefix exclusion; shared flows survive via another edge.
            db.execute("CREATE TABLE degrees AS SELECT mode,id,COUNT(*) AS n FROM edges WHERE scope='native' GROUP BY mode,id")
            db.execute('CREATE UNIQUE INDEX degree_key ON degrees(mode,id)')
            contribution=[]
            for key in condition_keys:
                for p,row in prefixes.items():
                    if key not in row['conditions']:continue
                    exclusive=db.execute("SELECT COUNT(*),COALESCE(SUM(f.packets=1),0) FROM edges e JOIN degrees d ON e.mode=d.mode AND e.id=d.id JOIN facts f ON f.id=e.id WHERE e.mode=? AND e.scope='native' AND e.prefix=? AND d.n=1",(key,p)).fetchone()
                    contribution.append(dict(condition=key,prefix=p,**row['stats'],one_packet_count=db.execute('SELECT COALESCE(SUM(n),0) FROM prefix_dist WHERE condition=? AND prefix=? AND packets=1',(key,p)).fetchone()[0],
                        union_share=ratio(row['stats']['flow_count'],conditions[key]['stats']['flow_count']),exclusive_union_flow_count=exclusive[0],exclusive_one_packet_count=exclusive[1]))
            lo,hi=int(target_net.network_address),int(target_net.broadcast_address)
            target_stats=_component(db,'target_membership','SELECT id FROM facts WHERE ipv=4 AND ((src BETWEEN ? AND ?) OR (dst BETWEEN ? AND ?))',(lo,hi,lo,hi),spec=spec)
            for key in condition_keys:
                exact,covering=_candidate_focus(validation['runs'][key]['candidate_path'],target)
                in_union=db.execute('SELECT COUNT(*) FROM cohort_ids t JOIN unions u ON t.id=u.id WHERE u.condition=?',(key,)).fetchone()[0]
                focus[key]=dict(selected=target in infos[key].selected_prefixes,candidate_exact=exact,candidate_covering=covering,
                    **target_stats,one_packet_count=db.execute('SELECT COALESCE(SUM(n),0) FROM frequencies WHERE distribution=? AND packets=1',('target_membership',)).fetchone()[0],
                    in_union_flow_count=in_union,union_share=ratio(in_union,conditions[key]['stats']['flow_count']))
            for key in condition_keys[1:]:
                name=key+'_without_target'
                after=_component(db,name,"SELECT DISTINCT id FROM edges WHERE mode=? AND scope='native' AND prefix!=?",(key,target),spec=spec)
                sensitivities[key]=dict(before=conditions[key]['stats'],after=after,**ks_distance(db,name,'overall_ipv4'),
                    before_ks={k:conditions[key][k] for k in ('ks_distance','ks_numerator','ks_denominator')},
                    removed_flow_count=conditions[key]['stats']['flow_count']-after['flow_count'],excluded_prefix=target,
                    selected_before=target in infos[key].selected_prefixes,interpretation='post-selection exact-CIDR exclusion; union rebuilt from remaining edges')
            jaccard=[];pair_rows=[]
            for a,b in combinations(condition_keys,2):
                for kind,sa,sb in [('native_prefix',set(infos[a].selected_prefixes),set(infos[b].selected_prefixes)),
                    ('normalized24',{str(ipaddress.ip_network(p).supernet(new_prefix=24)) for p in infos[a].selected_prefixes},
                     {str(ipaddress.ip_network(p).supernet(new_prefix=24)) for p in infos[b].selected_prefixes})]:
                    jaccard.append(dict(condition_a=a,condition_b=b,set_kind=kind,intersection_count=len(sa&sb),union_count=len(sa|sb),jaccard=ratio(len(sa&sb),len(sa|sb))))
                    for p in sorted(sa|sb):pair_rows.append(dict(condition_a=a,condition_b=b,set_kind=kind,prefix=p,presence='common' if p in sa&sb else a+'_only' if p in sa else b+'_only'))
                intersection=db.execute('SELECT COUNT(*) FROM unions a JOIN unions b ON a.id=b.id WHERE a.condition=? AND b.condition=?',(a,b)).fetchone()[0]
                union=db.execute('SELECT COUNT(*) FROM (SELECT id FROM unions WHERE condition IN (?,?) GROUP BY id)',(a,b)).fetchone()[0]
                jaccard.append(dict(condition_a=a,condition_b=b,set_kind='flow_id',intersection_count=intersection,union_count=union,jaccard=ratio(intersection,union)))
            added=set(infos['B'].selected_prefixes)-set(infos['A'].selected_prefixes)
            db.execute('CREATE TEMP TABLE added(prefix TEXT PRIMARY KEY) WITHOUT ROWID');db.executemany('INSERT INTO added VALUES (?)',[(p,) for p in sorted(added)])
            components['B_added_prefix_union']=_component(db,'B_added_prefix_union',"SELECT DISTINCT e.id FROM edges e JOIN added a ON e.prefix=a.prefix WHERE e.mode='B' AND e.scope='native'",spec=spec)
            for name,sql in [('B_only_union',"SELECT b.id FROM unions b WHERE condition='B' AND NOT EXISTS(SELECT 1 FROM unions a WHERE a.condition='A' AND a.id=b.id)"),
                             ('A_only_union',"SELECT a.id FROM unions a WHERE condition='A' AND NOT EXISTS(SELECT 1 FROM unions b WHERE b.condition='B' AND b.id=a.id)"),
                             ('AB_common_union',"SELECT a.id FROM unions a JOIN unions b ON a.id=b.id WHERE a.condition='A' AND b.condition='B'")]:
                components[name]=_component(db,name,sql,spec=spec)
            with (output/'ecdf_counts.csv').open('w',newline='',encoding='utf-8') as stream:
                all_curves=write_ecdf(db,{'overall_ipv4':overall['flow_count'],**{k:r['stats']['flow_count'] for k,r in conditions.items()},
                    **{k+'_without_target':r['after']['flow_count'] for k,r in sensitivities.items()},
                    **{k:r['flow_count'] for k,r in components.items()},'target_membership':target_stats['flow_count']},stream,max_points=max_ecdf_points)
            # Notebook union semantics independently expressed as SQL IN/UNIQUE.
            notebook_n=db.execute("SELECT COUNT(*) FROM facts WHERE ipv=4 AND id IN(SELECT DISTINCT id FROM edges WHERE mode='A' AND scope='native')").fetchone()[0]
            if notebook_n!=conditions['A']['stats']['flow_count']:raise ValueError('Notebook union-expression mismatch')
            from .notebook_audit import audit_archives
            archive_audit=audit_archives()
            # Optional legacy-reference comparisons happen while exact facts/IDs remain on disk.
            result=dict(schema_version=f'aguri-selection-analysis-v{version}',dataset_id=dataset_id,target=target,overall=overall,
                conditions=conditions,prefixes=list(prefixes.values()),prefix_contribution=contribution,focus=focus,
                sensitivities=sensitivities,components=components,jaccard=jaccard,pairwise_prefixes=pair_rows,
                curves={k:all_curves[k] for k in ('overall_ipv4',*condition_keys)},all_curves=all_curves,
                legacy={'status':'reference_not_provided','current_A_union_matches_documented_expression':True,
                        'historical_reproduction_verified':False,'reason':'Historical input/ID/frequency reference is required; matching source code is not historical reproduction.'})
            if legacy_reference is not None:
                from .legacy import compare_reference
                result['legacy']=compare_reference(db,Path(legacy_reference),validation['common']['canonical'],infos['A'].selected_prefixes,conditions['A']['stats'])
            result['legacy']['archive_code_audit']=archive_audit
            result['legacy'].setdefault('tracked_files',{}).update(archive_audit['tracked_files'])
            _write_csv(output/'pairwise_prefixes.csv',('condition_a','condition_b','set_kind','prefix','presence'),pair_rows)
            _write_csv(output/'prefix_stats.csv',('condition','prefix',*STATS,'one_packet_count','union_share','exclusive_union_flow_count','exclusive_one_packet_count'),contribution)
            _write_csv(output/'jaccard.csv',('condition_a','condition_b','set_kind','intersection_count','union_count','jaccard'),jaccard)
            _write_csv(output/'selection_summary.csv',('condition','selected_native_prefix_count',*STATS,'flow_coverage','packet_coverage','byte_coverage','ks_distance','ks_numerator','ks_denominator'),
                [dict(condition=k,selected_native_prefix_count=r['selected_native_prefix_count'],**r['stats'],**{x+'_coverage':v for x,v in r['coverage'].items()},**{x:r[x] for x in ('ks_distance','ks_numerator','ks_denominator')}) for k,r in conditions.items()])
            return result
        finally:db.close()
