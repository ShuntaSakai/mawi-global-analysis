"""Compare a bound manual Notebook export; static code agreement is not evidence."""
import csv
import math
from pathlib import Path

from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.rls_weight_comparison.generation import _json
from .validation import equal


def compare_reference(db,path: Path,canonical: dict,selected: list,stats: dict) -> dict:
    path=path.expanduser().resolve();manifest=_json(path);tracked={str(path):sha256_file(path)}
    equal('legacy.schema',manifest.get('schema_version'),'society-union-reference-v1')
    equal('legacy.canonical',manifest.get('canonical_csv_sha256'),canonical['csv_sha256'])
    equal('legacy.capture',manifest.get('input_capture_sha256'),canonical['capture_sha256'])
    files={}
    for kind in ('flow_ids','frequencies'):
        record=manifest.get('artifacts',{}).get(kind,{});name=record.get('path','');relative=Path(name)
        if not name or relative.is_absolute() or '..' in relative.parts or relative.as_posix()!=name:raise ValueError('legacy unsafe artifact path')
        file=(path.parent/relative).resolve()
        if not file.is_relative_to(path.parent):raise ValueError('legacy artifact escapes bundle')
        equal('legacy.'+kind+'.sha256',sha256_file(file),record.get('sha256'));tracked[str(file)]=record['sha256'];files[kind]=file
    db.executescript('CREATE TABLE legacy_ids(id TEXT PRIMARY KEY) WITHOUT ROWID; CREATE TABLE legacy_freq(packets INTEGER PRIMARY KEY,n INTEGER) WITHOUT ROWID;')
    with files['flow_ids'].open(newline='') as stream:
        reader=csv.DictReader(stream,strict=True);equal('legacy.flow_ids.columns',reader.fieldnames,['flow_id'])
        for row in reader:
            if not row['flow_id']:raise ValueError('legacy empty flow_id')
            db.execute('INSERT INTO legacy_ids VALUES (?)',(row['flow_id'],))
    with files['frequencies'].open(newline='') as stream:
        reader=csv.DictReader(stream,strict=True);equal('legacy.frequencies.columns',reader.fieldnames,['packet_count','frequency'])
        for row in reader:
            p,n=int(row['packet_count']),int(row['frequency'])
            if p<1 or n<1:raise ValueError('legacy frequencies must be positive integers')
            db.execute('INSERT INTO legacy_freq VALUES (?,?)',(p,n))
    equal('legacy count consistency',db.execute('SELECT COUNT(*) FROM legacy_ids').fetchone()[0],db.execute('SELECT COALESCE(SUM(n),0) FROM legacy_freq').fetchone()[0])
    missing=db.execute("SELECT COUNT(*) FROM legacy_ids WHERE id NOT IN(SELECT id FROM unions WHERE condition='A')").fetchone()[0]
    extra=db.execute("SELECT COUNT(*) FROM unions WHERE condition='A' AND id NOT IN(SELECT id FROM legacy_ids)").fetchone()[0]
    differences=0
    for query in ("SELECT packets,n FROM legacy_freq EXCEPT SELECT packets,n FROM frequencies WHERE distribution='A'",
                  "SELECT packets,n FROM frequencies WHERE distribution='A' EXCEPT SELECT packets,n FROM legacy_freq"):
        differences+=db.execute('SELECT COUNT(*) FROM ('+query+')').fetchone()[0]
    source_stats=manifest.get('statistics',{})
    if not isinstance(source_stats,dict):raise ValueError('legacy.statistics must be an object')
    stats_diff={};rounding_diff={}
    float_fields={'median','p95','mean_packet_count','one_packet_rate'}
    for key,value in source_stats.items():
        current=stats.get(key)
        if current==value:continue
        difference={'reference':value,'current':current}
        # Integers, IDs and frequencies stay exact. Only last-bit differences
        # in derived floating statistics are accepted and explicitly retained.
        if (key in float_fields and type(value) in (int,float) and type(current) in (int,float)
                and math.isfinite(value) and math.isfinite(current)
                and abs(value-current)<=4*max(math.ulp(value),math.ulp(current))):
            rounding_diff[key]=difference
        else:stats_diff[key]=difference
    prefix_equal=sorted(manifest.get('selected_native_prefixes',[]))==sorted(selected)
    verified=not (missing or extra or differences or stats_diff) and prefix_equal
    for name,checksum in tracked.items():equal('legacy input changed',sha256_file(Path(name)),checksum)
    return dict(status='matched' if verified else 'mismatch',historical_reproduction_verified=False,supplied_reference_matches=verified,statistics_supplied=bool(source_stats),
                flow_ids_equal=not(missing or extra),frequencies_equal=differences==0,prefix_sets_equal=prefix_equal,
                reference_only_flow_count=missing,current_only_flow_count=extra,frequency_differences=differences,
                reference_only_ids_sample=[r[0] for r in db.execute("SELECT id FROM legacy_ids WHERE id NOT IN(SELECT id FROM unions WHERE condition='A') ORDER BY id LIMIT 20")],
                current_only_ids_sample=[r[0] for r in db.execute("SELECT id FROM unions WHERE condition='A' AND id NOT IN(SELECT id FROM legacy_ids) ORDER BY id LIMIT 20")],
                frequency_difference_sample=[{'side':side,'packet_count':p,'frequency':n} for side,query in [
                    ('reference',"SELECT packets,n FROM legacy_freq EXCEPT SELECT packets,n FROM frequencies WHERE distribution='A'"),
                    ('current',"SELECT packets,n FROM frequencies WHERE distribution='A' EXCEPT SELECT packets,n FROM legacy_freq")] for p,n in db.execute('SELECT * FROM ('+query+') ORDER BY packets LIMIT 20')],
                statistics_differences=stats_diff,statistics_rounding_differences=rounding_diff,
                statistics_comparison='exact integers; derived floating statistics allow at most 4 ULPs, with differences retained',reference_quantile_rule=manifest.get('quantile_rule'),
                current_quantile_rule='linear: (n-1)*q',tracked_files=tracked,reference_source=manifest.get('reference_source'),
                interpretation='Match/mismatch with the supplied export only. Original conference Notebook execution and published values are not independently authenticated.')
