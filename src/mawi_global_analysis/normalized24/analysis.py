"""Exact Raw distributions over validated normalized /24 membership.

Only the agurim cohort adapter is implemented. HistogramSpec and the SQLite
frequency summarizer do not depend on a selection method. No cache is read or
written; canonical CSVs are streamed into temporary disk-backed working state.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from dataclasses import asdict, dataclass
import ipaddress
import math
from pathlib import Path
import re
import sqlite3
import tempfile

from mawi_global_analysis.flow_length import (
    Inspection, _bools, _chunks, _insert, _integers, _json, inspect_run,
)
from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS


@dataclass(frozen=True)
class HistogramSpec:
    """Portable common bins/axes; final bin covers all positive int64 sizes."""

    bin_edges: tuple[int, ...] = (1, 2, 3, *(2**i for i in range(2, 21)), 2**63)
    count_axis_upper: int = 1
    count_scale: str = 'log1p'
    proportion_axis_upper: int = 100
    x_scale: str = 'equal_width_integer_intervals'

    def __post_init__(self):
        edges = self.bin_edges
        if (len(edges) < 3 or edges[:2] != (1, 2) or edges[-1] != 2**63
                or any(type(e) is not int for e in edges)
                or any(a >= b for a,b in zip(edges, edges[1:]))):
            raise ValueError('histogram bin_edges must increase from 1,2 to 2**63')
        if (type(self.count_axis_upper) is not int or not 1 <= self.count_axis_upper <= 2**53-1
                or self.count_scale != 'log1p' or self.proportion_axis_upper != 100
                or self.x_scale != 'equal_width_integer_intervals'):
            raise ValueError('invalid shared histogram axes')

    def to_dict(self) -> dict:
        return {**asdict(self), 'bin_edges': list(self.bin_edges)}

    @classmethod
    def from_dict(cls, data: dict) -> HistogramSpec:
        if not isinstance(data, dict) or set(data) != set(cls.__dataclass_fields__):
            raise ValueError('invalid histogram specification fields')
        try:
            return cls(**{**data, 'bin_edges': tuple(data['bin_edges'])})
        except (TypeError, KeyError) as exc:
            raise ValueError('invalid histogram specification') from exc


def _cohort(info: Inspection, size: int) -> dict[str, list[str]]:
    cohort: dict[str, list[str]] = {}
    for chunk in _chunks(info, 'prefixes', ('prefix','normalized_prefix_24','selected_for_analysis'), size):
        selected = _bools(chunk.selected_for_analysis, 'prefixes.selected_for_analysis')
        for row in chunk.loc[selected].itertuples(index=False):
            native = ipaddress.ip_network(row.prefix)
            containing = str(native.supernet(new_prefix=24))
            if row.normalized_prefix_24 != containing:
                raise ValueError(f'prefixes: normalized_prefix_24 mismatch: {row.prefix}')
            cohort.setdefault(containing, []).append(row.prefix)
    if sorted(p for natives in cohort.values() for p in natives) != info.selected_prefixes:
        raise ValueError('prefixes changed during inspection')
    return {key: sorted(cohort[key]) for key in sorted(cohort)}


def _ingest(db: sqlite3.Connection, info: Inspection, cohort: dict,
            size: int, progress) -> dict:
    db.executescript('''
        CREATE TABLE facts (id TEXT PRIMARY KEY, ipv INTEGER, packets INTEGER,
                            src24 TEXT, dst24 TEXT) WITHOUT ROWID;
        CREATE TABLE membership (prefix TEXT, id TEXT, sm INTEGER, dm INTEGER,
                                 PRIMARY KEY(prefix,id)) WITHOUT ROWID;
        CREATE INDEX membership_id ON membership(id);
    ''')
    expected = Counter(dict.fromkeys(cohort, 0))
    columns = ('flow_id','ip_version','packet_count','src_ip','dst_ip')
    for chunk in _chunks(info, 'flows', columns, size, progress):
        packets = _integers(chunk.packet_count, 'flows.packet_count', 1)
        versions = _integers(chunk.ip_version, 'flows.ip_version')
        rows = []
        for row, n, version in zip(chunk.itertuples(index=False), packets, versions):
            if not row.flow_id:
                raise ValueError('flows: empty flow_id')
            src, dst = ipaddress.ip_address(row.src_ip), ipaddress.ip_address(row.dst_ip)
            if src.version != version or dst.version != version:
                raise ValueError('flows: endpoint / ip_version mismatch')
            src24 = str(ipaddress.ip_network(f'{src}/24', strict=False)) if version == 4 else ''
            dst24 = str(ipaddress.ip_network(f'{dst}/24', strict=False)) if version == 4 else ''
            for prefix in {src24,dst24}:
                if prefix in cohort:
                    expected[prefix] += 1
            rows.append((row.flow_id,int(version),int(n),src24,dst24))
        _insert(db, 'INSERT INTO facts VALUES (?,?,?,?,?)', rows, 'flows')
    for chunk in _chunks(info, 'flow_prefix_membership', MEMBERSHIP_COLUMNS, size, progress):
        if not chunk.analysis_scope.isin(['native','normalized_24']).all():
            raise ValueError('membership: unknown analysis_scope')
        chunk = chunk.loc[chunk.analysis_scope.eq('normalized_24')]
        sm = _bools(chunk.src_match, 'membership.src_match')
        dm = _bools(chunk.dst_match, 'membership.dst_match')
        rows = []
        for row,s,d in zip(chunk.itertuples(index=False),sm,dm):
            if row.analysis_prefix not in cohort:
                raise ValueError(f'membership: unknown normalized /24: {row.analysis_prefix}')
            rows.append((row.analysis_prefix,row.flow_id,int(s),int(d)))
        _insert(db, 'INSERT INTO membership VALUES (?,?,?,?)', rows, 'membership')
    invalid = db.execute('''SELECT m.id FROM membership m LEFT JOIN facts f ON m.id=f.id
        WHERE f.id IS NULL OR f.ipv != 4 OR (m.sm=0 AND m.dm=0)
        OR m.sm != (f.src24=m.prefix) OR m.dm != (f.dst24=m.prefix) LIMIT 1''').fetchone()
    if invalid:
        raise ValueError(f'membership: unknown flow_id or endpoint flags mismatch: {invalid[0]}')
    actual = dict(db.execute('SELECT prefix,COUNT(*) FROM membership GROUP BY prefix'))
    for prefix,count in expected.items():
        if count != actual.get(prefix, 0):
            raise ValueError(f'membership incomplete: {prefix}: expected={count}, actual={actual.get(prefix,0)}')
    return {'flow_rows': info.entries['flows']['row_count'],
            'selected_native_prefix_count': len(info.selected_prefixes),
            'normalized_prefix_count': len(cohort),
            'normalized_membership_rows': sum(actual.values())}


def summarize_frequencies(db: sqlite3.Connection, target: str, spec: HistogramSpec) -> dict:
    """Summarize a disk frequency table exactly, retaining only quantile ranks.

    Contract for future adapters: dist(target TEXT, packets INTEGER, n INTEGER),
    positive integer packets/frequencies, unique (target,packets).
    """
    n = db.execute('SELECT COALESCE(SUM(n),0) FROM dist WHERE target=?', (target,)).fetchone()[0]
    if n > 2**53-1:
        raise ValueError('flow count exceeds safe HTML integer range')
    positions = [(n-1)*q for q in (.5,.95)] if n else []
    ranks = {r for p in positions for r in (math.floor(p),math.ceil(p))}
    values, counts, offset, one = {}, [0]*(len(spec.bin_edges)-1), 0, 0
    for packets,count in db.execute('SELECT packets,n FROM dist WHERE target=? ORDER BY packets', (target,)):
        counts[bisect_right(spec.bin_edges, packets)-1] += count
        if packets == 1:
            one += count
        for rank in ranks:
            if offset <= rank < offset+count:
                values[rank] = packets
        offset += count
    if max(counts, default=0) > spec.count_axis_upper:
        raise ValueError('shared histogram count axis would clip data')
    quantiles = [values[math.floor(p)] + (values[math.ceil(p)]-values[math.floor(p)])*(p-math.floor(p))
                 for p in positions] if n else [None,None]
    return {'prefix':target, 'stats':{'flow_count':n,'median':quantiles[0], 'p95':quantiles[1],
                                     'one_packet_rate':one/n if n else None}, 'counts':counts}


def _summarize(db: sqlite3.Connection, cohort: dict, spec: HistogramSpec | None) -> tuple[list, list, HistogramSpec]:
    overall = db.execute('SELECT COUNT(*) FROM facts WHERE ipv=4').fetchone()[0]
    if spec is None:
        # Derivation uses the common overall IPv4 population, never the method's cohort.
        upper = 10**len(str(overall)) if overall else 1
        spec = HistogramSpec(count_axis_upper=upper)
    db.executescript('''
        CREATE TABLE dist (target TEXT, packets INTEGER, n INTEGER,
                           PRIMARY KEY(target,packets)) WITHOUT ROWID;
        INSERT INTO dist SELECT m.prefix,f.packets,COUNT(*) FROM membership m
            JOIN facts f ON m.id=f.id GROUP BY m.prefix,f.packets;
        INSERT INTO dist SELECT 'selected_union',f.packets,COUNT(*) FROM facts f
            WHERE EXISTS(SELECT 1 FROM membership m WHERE m.id=f.id) GROUP BY f.packets;
        INSERT INTO dist SELECT 'overall_ipv4',packets,COUNT(*) FROM facts
            WHERE ipv=4 GROUP BY packets;
    ''')
    cards = []
    for prefix,natives in cohort.items():
        card = summarize_frequencies(db,prefix,spec)
        card['native_prefixes'] = natives
        cards.append(card)
    references = [summarize_frequencies(db,p,spec) for p in ('selected_union','overall_ipv4')]
    return cards, references, spec


def _input_hashes(info: Inspection, root: Path) -> dict:
    cache = info.manifest.get('cache',{}).get('flows',{})
    fm = Path(cache.get('manifest_path',info.paths['flows'].parent/'flow_manifest.json'))
    if not fm.is_absolute():
        fm = root/fm
    paths = {**info.paths,'run_manifest':info.manifest_path,'flow_manifest':fm}
    return {name:{'path':str(path.resolve()),'sha256':sha256_file(path)} for name,path in paths.items()}


def _aguri_lineage(info: Inspection) -> dict:
    """Reject contradictory recorded bindings without requiring old Aguri files.

    Older saved runs may omit these records. Absence is explicitly preserved;
    it is not evidence of a verified executable or a historical byte identity.
    """
    artifacts = info.manifest['artifacts']
    candidate = artifacts.get('aguri_candidates',{})
    cache = info.manifest.get('cache',{}).get('aguri',{})
    if not isinstance(candidate,dict) or not isinstance(cache,dict):
        raise ValueError('aguri provenance records must be objects')
    producers = [info.entries['prefixes'].get('producer',{}),
                 candidate.get('producer',{}),cache.get('producer',{})]
    if any(not isinstance(p,dict) for p in producers):
        raise ValueError('aguri producer records must be objects')
    bindings = {
        'aguri_fingerprint':[cache.get('fingerprint'),*[p.get('aguri_fingerprint') for p in producers]],
        'aguri_candidates_sha256':[candidate.get('sha256'),*[p.get('aguri_candidates_sha256') for p in producers]],
        'aguri_manifest_sha256':[p.get('cache_manifest_sha256') for p in producers[1:]],
    }
    result = {}
    for key,values in bindings.items():
        recorded = [v for v in values if v is not None]
        if any(not isinstance(v,str) or re.fullmatch('[0-9a-f]{64}',v) is None for v in recorded):
            raise ValueError(f'aguri provenance: invalid {key}')
        if len(set(recorded)) > 1:
            raise ValueError(f'aguri provenance: contradictory {key}')
        result[key] = recorded[0] if recorded else None
    result['record_status'] = 'recorded_bindings_consistent' if any(result.values()) else 'historical_bindings_absent'
    result['verification'] = 'recorded consistency only; executable and historical Aguri files not revalidated'
    return result


def analyze_agurim_run(root: Path, dataset_id: str, run_name: str, *,
                       chunksize: int = 100_000, scratch_dir: Path | None = None,
                       spec: HistogramSpec | None = None, progress=None) -> dict:
    """Read an existing successful corrected run; fail closed on incomplete /24s.

    RAM: O(chunksize + number of prefixes + histogram output); SQLite page cache
    is 32 MiB, intermediate sorting spills to disk. Scratch is deleted on failure
    and success. CSVs are hashed before and after to detect concurrent changes.
    Raw analysis never reads labels or the native distribution cache.
    """
    if type(chunksize) is not int or chunksize < 1:
        raise ValueError('chunksize must be a positive integer')
    root = Path(root).expanduser().resolve()
    info = inspect_run(root,dataset_id,run_name,raw_only=True,verify_content_hashes=False)
    lineage = _aguri_lineage(info)
    inputs = _input_hashes(info,root)
    if (_json(info.manifest_path) != info.manifest
            or _json(Path(inputs['flow_manifest']['path'])) != info.flow_manifest):
        raise ValueError('input manifests changed during inspection')
    for name,entry in info.entries.items():
        if entry.get('sha256') is not None and entry['sha256'] != inputs[name]['sha256']:
            raise ValueError(f'{name}: checksum mismatch during inspection')
    recorded_prefix_hash = info.entries['flow_prefix_membership'].get('producer',{}).get('prefixes_sha256')
    if recorded_prefix_hash is not None and recorded_prefix_hash != inputs['prefixes']['sha256']:
        raise ValueError('membership: producer.prefixes_sha256 mismatch during inspection')
    cohort = _cohort(info,chunksize)
    with tempfile.TemporaryDirectory(prefix='mawi-normalized24-',dir=scratch_dir) as work:
        db = sqlite3.connect(Path(work)/'working.sqlite')
        try:
            db.execute('PRAGMA cache_size=-32768')
            db.execute('PRAGMA temp_store=FILE')
            audit = _ingest(db,info,cohort,chunksize,progress)
            cards,references,spec = _summarize(db,cohort,spec)
        finally:
            db.close()
    if inputs != _input_hashes(info,root):
        raise ValueError('input files changed during /24 analysis')
    provenance = {
        'inputs':inputs,'input_capture_sha256':info.manifest['input']['sha256'],
        'dataset_id':dataset_id,'run_name':run_name,'config_sha256':info.manifest['config']['hash'],
        'config':info.manifest['config']['text'],'source_git_commit':info.manifest.get('git_commit'),
        'aguri_lineage':lineage,
        'source_evidence':info.manifest.get('evidence_level','saved_artifact_analysis'),
        'selection':{'method':'agurim','native':'selected_for_analysis=True',
                     'normalization':'normalized_prefix_24; deduplicate /24', 'additional_filters':[]},
        'selected_native_prefixes':info.selected_prefixes,'normalized_prefixes':list(cohort),
        'aggregation':{'version':'normalized24-raw-v1','flow_size':'packet_count',
                       'membership_scope':'normalized_24','endpoint_rule':'src_ip OR dst_ip',
                       'union_deduplication':'flow_id','quantile':'linear: (n-1)*q',
                       'one_packet_denominator':'all Raw flows in the distribution',
                       'undefined_statistics':None,'groups':['Raw'], 'histogram_spec':spec.to_dict()},
        'histogram_spec_sha256':stable_json_hash(spec.to_dict()),
        'validation':'canonical IDs unique; normalized edges unique, endpoint-correct and complete',
        'evidence':'saved_artifact_analysis; no real-data validation asserted',
        'implementation_sha256':{name:sha256_file(Path(__file__).resolve().parents[1]/name)
                                 for name in ('normalized24/analysis.py','flow_length.py','hashing.py')},
    }
    provenance['identity_sha256'] = stable_json_hash(provenance)
    return {'schema_version':1,'method':'agurim','group':'Raw','dataset_id':dataset_id,
            'run_name':run_name,'histogram_spec':spec.to_dict(),'prefixes':cards,
            'references':references,'audit':audit,'provenance':provenance}
