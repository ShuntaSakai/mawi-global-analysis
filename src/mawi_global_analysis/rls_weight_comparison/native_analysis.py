"""Exact native evaluation of fixed saved selections, using temporary SQLite."""
from __future__ import annotations

from collections import Counter
import csv
from itertools import combinations
import ipaddress
import json
from pathlib import Path
import sqlite3
import tempfile

from mawi_global_analysis.flow_length import _bools, _chunks, _insert, _integers
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24.analysis import HistogramSpec, _summarize, _input_hashes
from mawi_global_analysis.normalized24.statistics import _write_frequencies
from .generation import STATS, _json, _write_csv, _write_text
from .metrics import BITS, MODES, flow_jaccards, ks_distance, ratio, write_ecdf
from .prefix_ecdf import build_prefix_ecdfs

SCHEMA='rls-native-statistics-v1'


def _ingest(db, infos, chunksize):
    db.executescript('''CREATE TABLE facts(id TEXT PRIMARY KEY,ipv INTEGER,packets INTEGER,bytes INTEGER,src INTEGER,dst INTEGER) WITHOUT ROWID;
        CREATE TABLE edges(mode TEXT,scope TEXT,prefix TEXT,id TEXT,sm INTEGER,dm INTEGER,PRIMARY KEY(mode,scope,prefix,id)) WITHOUT ROWID;
        CREATE INDEX edges_id ON edges(mode,scope,id);
        CREATE TABLE networks(scope TEXT,prefix TEXT,low INTEGER,high INTEGER,PRIMARY KEY(scope,prefix)) WITHOUT ROWID;''')
    targets={};allowed={}
    for mode,info in infos.items():
        pairs=set()
        for p in info.selected_prefixes:
            network=ipaddress.ip_network(p)
            for scope,net in (('native',network),('normalized_24',network.supernet(new_prefix=24))):
                key=(scope,str(net));targets[key]=(int(net.network_address),int(net.broadcast_address));pairs.add(key)
        allowed[mode]=pairs
    db.executemany('INSERT INTO networks VALUES (?,?,?,?)',[(s,p,*bounds) for (s,p),bounds in targets.items()])
    # Native prefix lengths are 24..32. At most nine lookups per endpoint,
    # independent of the total number of prefixes (no flows x prefixes loop).
    native={p for s,p in targets if s=='native'};normal={p for s,p in targets if s=='normalized_24'}
    lookup={}
    for p in native:
        net=ipaddress.ip_network(p);lookup[(net.prefixlen,int(net.network_address))]=p
    masks={length:(0xffffffff<<(32-length))&0xffffffff for length in {key[0] for key in lookup}}
    expected=Counter(dict.fromkeys(targets,0))
    first=next(iter(infos.values()))
    for chunk in _chunks(first,'flows',('flow_id','ip_version','packet_count','byte_count','src_ip','dst_ip','protocol'),chunksize):
        packets=_integers(chunk.packet_count,'flows.packet_count',1)
        sizes=_integers(chunk.byte_count,'flows.byte_count',0)
        versions=_integers(chunk.ip_version,'flows.ip_version')
        protocols=_integers(chunk.protocol,'flows.protocol',0)
        if (protocols>255).any():raise ValueError('flows.protocol must be in [0,255]')
        rows=[]
        for row,n,b,version,protocol in zip(chunk.itertuples(index=False),packets,sizes,versions,protocols):
            if not row.flow_id:raise ValueError('flows: empty flow_id')
            src,dst=ipaddress.ip_address(row.src_ip),ipaddress.ip_address(row.dst_ip)
            if src.version!=version or dst.version!=version:raise ValueError('flows: IP version mismatch')
            if version==4 and int(protocol) not in (6,17):raise ValueError('flows: Overall requires IPv4 TCP/UDP')
            si,di=(int(src),int(dst)) if version==4 else (-1,-1)
            matched=set()
            if version==4:
                for address in {si,di}:
                    for length,mask in masks.items():
                        p=lookup.get((length,address&mask))
                        if p:matched.add(('native',p))
                    p=str(ipaddress.ip_network((address,24),strict=False))
                    if p in normal:matched.add(('normalized_24',p))
            for key in matched:expected[key]+=1
            rows.append((row.flow_id,int(version),int(n),int(b),si,di))
        _insert(db,'INSERT INTO facts VALUES (?,?,?,?,?,?)',rows,'flows')
    for mode,info in infos.items():
        for chunk in _chunks(info,'flow_prefix_membership',MEMBERSHIP_COLUMNS,chunksize):
            sm=_bools(chunk.src_match,'membership.src_match');dm=_bools(chunk.dst_match,'membership.dst_match')
            rows=[]
            for row,s,d in zip(chunk.itertuples(index=False),sm,dm):
                if (row.analysis_scope,row.analysis_prefix) not in allowed[mode]:
                    raise ValueError(f'{mode}.membership: unknown scope/prefix {row.analysis_scope}/{row.analysis_prefix}')
                rows.append((mode,row.analysis_scope,row.analysis_prefix,row.flow_id,int(s),int(d)))
            _insert(db,'INSERT INTO edges VALUES (?,?,?,?,?,?)',rows,'membership')
        bad=db.execute('''SELECT e.id FROM edges e LEFT JOIN facts f ON e.id=f.id
            JOIN networks n ON n.scope=e.scope AND n.prefix=e.prefix WHERE e.mode=? AND
            (f.id IS NULL OR f.ipv!=4 OR (e.sm=0 AND e.dm=0) OR
            e.sm!=(f.src BETWEEN n.low AND n.high) OR e.dm!=(f.dst BETWEEN n.low AND n.high)) LIMIT 1''',(mode,)).fetchone()
        if bad:raise ValueError(f'{mode}.membership: invalid flow_id or endpoint flags: {bad[0]}')
        actual={(s,p):n for s,p,n in db.execute('SELECT scope,prefix,COUNT(*) FROM edges WHERE mode=? GROUP BY scope,prefix',(mode,))}
        for key in allowed[mode]:
            if actual.get(key,0)!=expected[key]:
                raise ValueError(f'{mode}.membership incomplete: {key}: expected={expected[key]}, actual={actual.get(key,0)}')
        # Validate subset by actual IDs, rather than inferring it from totals.
        bad=db.execute('''SELECT e.id FROM edges e WHERE mode=? AND scope='native' AND NOT EXISTS
            (SELECT 1 FROM edges n WHERE n.mode=e.mode AND n.scope='normalized_24' AND n.id=e.id) LIMIT 1''',(mode,)).fetchone()
        if bad:raise ValueError(f'{mode}.native union is not a subset of normalized24 union: {bad[0]}')


def _scope_summary(db,mode,scope,cohort,spec):
    # Shared normalized24 aggregation expects a membership(prefix,id) view.
    # Parameters cannot be used in SQLite views; modes/scopes are fixed enums.
    db.execute('DROP VIEW IF EXISTS membership')
    db.execute(f"CREATE TEMP VIEW membership AS SELECT prefix,id FROM edges WHERE mode='{mode}' AND scope='{scope}'")
    for name in ('dist','totals'):db.execute(f'DROP TABLE IF EXISTS {name}')
    return _summarize(db,cohort,spec)


def _assert_normalized(db,summary,cards,refs,path):
    for key,actual in (('prefixes',cards),('references',refs)):
        if summary[key]!=actual:raise ValueError(f'normalized24.{key}: saved summary differs from canonical membership')
    db.execute('DROP TABLE IF EXISTS saved_dist')
    db.execute('CREATE TABLE saved_dist(target TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(target,packets)) WITHOUT ROWID')
    with path.open(encoding='utf-8',newline='') as stream:
        reader=csv.DictReader(stream,strict=True)
        if reader.fieldnames!=['distribution','packet_count','frequency']:raise ValueError('normalized24 frequencies: invalid columns')
        for row in reader:
            db.execute('INSERT INTO saved_dist VALUES (?,?,?)',(row['distribution'],int(row['packet_count']),int(row['frequency'])))
    for a,b in (('dist','saved_dist'),('saved_dist','dist')):
        if db.execute(f'SELECT * FROM {a} EXCEPT SELECT * FROM {b} LIMIT 1').fetchone():
            raise ValueError('normalized24 exact frequencies differ from canonical membership')


def analyze_native_runs(infos: dict, normalized_base: Path, output: Path, *, chunksize: int=100_000,
                        scratch_dir: Path | None=None, max_ecdf_points: int=2000) -> dict:
    """Use saved native edges and canonical observations; never select or run RLS.

    Output is private staging owned by the caller, not an existing run/cache.
    Aggregation/quantiles/bytes use normalized24._summarize without modification.
    """
    if type(chunksize) is not int or chunksize<1:raise ValueError('chunksize must be positive')
    if type(max_ecdf_points) is not int or not 2<=max_ecdf_points<=50000:raise ValueError('max_ecdf_points must be in [2,50000]')
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    data={m:_json(Path(normalized_base)/'modes'/m/'summary.json') for m in MODES}
    spec=HistogramSpec.from_dict(data['packet']['histogram_spec'])
    actual_inputs={}
    for mode in MODES:
        info=infos[mode];actual_inputs[mode]=_input_hashes(info,info.manifest_path.resolve().parents[3])
        expected_run=info.manifest.get('run_name',info.manifest_path.parent.name)
        if (data[mode].get('run_name')!=expected_run or data[mode].get('dataset_id')!=info.manifest['dataset_id']
                or data[mode]['provenance'].get('config_sha256')!=info.manifest['config']['hash']):
            raise ValueError(f'{mode}.normalized provenance: saved run/config does not match actual run')
        recorded=data[mode]['provenance'].get('inputs',{})
        if (set(recorded)!=set(actual_inputs[mode]) or any(recorded[k].get('sha256')!=v['sha256'] for k,v in actual_inputs[mode].items())):
            raise ValueError(f'{mode}.normalized inputs: saved digests differ from actual run inputs')
        if data[mode]['provenance']['selected_native_prefixes']!=infos[mode].selected_prefixes:
            raise ValueError(f'{mode}.selected native prefix set differs from normalized baseline')
        if data[mode]['histogram_spec']!=spec.to_dict():raise ValueError('histogram specification differs across modes')
    merged={};modes={};scope_rows={};overall=None
    with tempfile.TemporaryDirectory(prefix='native-comparison-',dir=scratch_dir) as temp:
        db=sqlite3.connect(Path(temp)/'working.sqlite')
        try:
            db.execute('PRAGMA cache_size=-32768');db.execute('PRAGMA temp_store=FILE')
            _ingest(db,infos,chunksize)
            db.executescript('''CREATE TABLE flow_sets(id TEXT PRIMARY KEY,mask INTEGER) WITHOUT ROWID;
                CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(distribution,packets)) WITHOUT ROWID;''')
            for mode in MODES:
                cohort={}
                for native in infos[mode].selected_prefixes:
                    parent=str(ipaddress.ip_network(native).supernet(new_prefix=24))
                    cohort.setdefault(parent,[]).append(native)
                cohort={p:sorted(cohort[p]) for p in sorted(cohort)}
                norm_cards,norm_refs,_=_scope_summary(db,mode,'normalized_24',cohort,spec)
                _assert_normalized(db,data[mode],norm_cards,norm_refs,Path(normalized_base)/'modes'/mode/'frequencies.csv')
                db.execute("INSERT INTO frequencies SELECT ?,packets,n FROM dist WHERE target='selected_union'",('normalized_'+mode,))
                cohort={p:[p] for p in infos[mode].selected_prefixes}
                cards,refs,_=_scope_summary(db,mode,'native',cohort,spec)
                folder=output/'modes'/mode;folder.mkdir(parents=True)
                with (folder/'frequencies.csv').open('w',encoding='utf-8',newline='') as stream:frequency_rows=_write_frequencies(db,stream)
                provenance={'inputs':actual_inputs[mode],'membership_scope':'native','endpoint_rule':'src_ip OR dst_ip','union_deduplication':'flow_id',
                    'selected_native_prefixes':infos[mode].selected_prefixes,'quantile':'linear: (n-1)*q',
                    'statistics_implementation':'normalized24.analysis._summarize',
                    'native_union_subset_normalized24':True,'validation':'unique IDs/edges; endpoint-correct and complete both scopes'}
                _write_text(folder/'summary.json',json.dumps(dict(schema_version=SCHEMA,prefixes=cards,references=refs,
                    histogram_spec=spec.to_dict(),provenance=provenance,artifacts={'frequencies':{'schema_version':'normalized24-exact-frequencies-v1',
                    'path':'frequencies.csv','sha256':sha256_file(folder/'frequencies.csv'),'row_count':frequency_rows}}),allow_nan=False,indent=2)+'\n')
                stats=refs[0]['stats'];norm=norm_refs[0]['stats']
                for field in ('flow_count','packet_total','byte_total'):
                    if stats[field]>norm[field]:raise ValueError(f'{mode}.native {field} exceeds normalized24')
                if overall is None:
                    overall=refs[1]['stats']
                    db.execute("INSERT INTO frequencies SELECT 'overall_ipv4',packets,n FROM dist WHERE target='overall_ipv4'")
                elif overall!=refs[1]['stats']:raise ValueError('Overall statistics differ across modes')
                db.execute("INSERT INTO frequencies SELECT ?,packets,n FROM dist WHERE target='selected_union'",(mode,))
                db.execute('''INSERT INTO flow_sets SELECT id,? FROM edges WHERE mode=? AND scope='native' GROUP BY id
                    ON CONFLICT(id) DO UPDATE SET mask=mask|excluded.mask''',(BITS[mode],mode))
                modes[mode]=dict(selected_native_prefix_count=len(cohort),stats=stats,
                    coverage={k:ratio(stats[f],overall[f]) for k,f in (('flow','flow_count'),('packet','packet_total'),('byte','byte_total'))},
                    **ks_distance(db,mode,'overall_ipv4'))
                scope_rows[mode]=dict(mode=mode,selection_fixed=True,native_union_subset_normalized24=True,
                    **{'native_'+k:stats[k] for k in STATS},**{'normalized24_'+k:norm[k] for k in STATS},
                    native_flow_coverage=ratio(stats['flow_count'],overall['flow_count']),
                    normalized24_flow_coverage=ratio(norm['flow_count'],overall['flow_count']),
                    **ks_distance(db,mode,'normalized_'+mode))
                for card in cards:
                    p=card['prefix'];row=merged.setdefault(p,dict(prefix=p,modes=[],native_prefixes={},stats=card['stats']))
                    if row['stats']!=card['stats']:raise ValueError(f'{p}: native statistics differ between modes')
                    row['modes'].append(mode);row['native_prefixes'][mode]=[p]
            jaccard=flow_jaccards(db)
            for a,b in combinations(MODES,2):
                sa,sb=set(infos[a].selected_prefixes),set(infos[b].selected_prefixes)
                jaccard.append(dict(mode_a=a,mode_b=b,set_kind='native_prefix',intersection_count=len(sa&sb),union_count=len(sa|sb),jaccard=ratio(len(sa&sb),len(sa|sb))))
            with (output/'ecdf_counts.csv').open('w',encoding='utf-8',newline='') as stream:
                ecdf=write_ecdf(db,{'overall_ipv4':overall['flow_count'],**{m:modes[m]['stats']['flow_count'] for m in MODES}},stream,max_points=max_ecdf_points)
            with (output/'scope_ecdf_counts.csv').open('w',encoding='utf-8',newline='') as stream:
                scope_ecdf=write_ecdf(db,{'overall_ipv4':overall['flow_count'],**{m:modes[m]['stats']['flow_count'] for m in MODES},
                **{'normalized_'+m:scope_rows[m]['normalized24_flow_count'] for m in MODES}},stream,max_points=max_ecdf_points)
        finally:db.close()
    prefixes=[merged[p] for p in sorted(merged)]
    per_prefix=build_prefix_ecdfs(output,prefixes,scratch_dir=scratch_dir,prefix_field='prefix',membership_scope='native')
    return dict(schema_version='rls-native-comparison-dashboard-v1',evaluation_scope='native',modes=modes,overall={'stats':overall},
                prefixes=prefixes,jaccard=jaccard,ecdf=ecdf,scope_comparison=scope_rows,scope_ecdf=scope_ecdf,per_prefix_ecdf=per_prefix)
