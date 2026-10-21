"""Bounded-memory analysis of existing run artifacts. Never reads a PCAP.

SQLite is temporary working storage, not a new pipeline cache. No source file
is changed. Frequency tables preserve exact integer packet counts for quantiles.
"""
from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import sqlite3
import tempfile
from typing import Any

import pandas as pd
import yaml

from mawi_global_analysis.config import ExperimentConfig, load_config
from mawi_global_analysis.flow_stage import FLOW_COLUMNS, FLOW_SCHEMA_VERSION
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config, sha256_file
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS


SCHEMAS = {'flows': FLOW_COLUMNS, 'flow_labels': FLOW_LABEL_COLUMNS,
           'prefixes': CORRECTED_LEDGER_COLUMNS, 'flow_prefix_membership': MEMBERSHIP_COLUMNS}
FLOW_USE = ('flow_id', 'ip_version', 'packet_count', 'src_ip', 'dst_ip',
            'protocol', 'initial_syn_sender_ip', 'observed_tcp_pattern')
GROUPS = ('Raw', 'removed', 'retained')
CONFIG_PATH = Path(__file__).resolve().parents[2] / 'configs/scan_source_driven_removal.yaml'


@dataclass
class Inspection:
    manifest_path: Path
    manifest: dict[str, Any]
    paths: dict[str, Path]
    entries: dict[str, dict[str, Any]]
    selected_prefixes: list[str]
    flow_manifest: dict[str, Any]


@dataclass
class FlowLengthResult:
    inspection: Inspection
    summary: pd.DataFrame
    histogram: pd.DataFrame
    bin_edges: list[int]
    audit: dict[str, int]
    exact_counts_path: Path | None = None


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f'必要な保存ファイルがありません: {path}\n'
            'このMacに実データはありません。研究室PCの成功済みrunを指定してください。'
            '再処理・転送・デモへの自動切替は行いません。')
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError) as exc:
        raise ValueError(f'JSONを読めません: {path}: {exc}') from exc
    if not isinstance(data, dict):
        raise ValueError(f'JSON objectが必要です: {path}')
    return data


def _resolve(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError('manifest pathは空でない文字列が必要です')
    path = Path(value)
    return path if path.is_absolute() else root / path


def _row_count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'{label}: manifestに非負整数row_countが必要です')
    return value


def _bools(values: pd.Series, label: str) -> pd.Series:
    mapped = values.str.lower().map({'true': True, 'false': False, '1': True, '0': False})
    if mapped.isna().any():
        raise ValueError(f'{label}: invalid boolean (True/False/1/0のみ)')
    return mapped.astype(bool)


def _integers(values: pd.Series, label: str, minimum: int = 0) -> pd.Series:
    # Reject decimals, infinities and values that SQLite cannot represent.
    if not values.str.fullmatch(r'\d+').all():
        raise ValueError(f'{label}: 整数が必要です')
    try:
        result = values.astype('int64')
    except (ValueError, OverflowError) as exc:
        raise ValueError(f'{label}: int64範囲の整数が必要です') from exc
    if (result < minimum).any():
        raise ValueError(f'{label}: {minimum}以上が必要です')
    return result


def _chunks(info: Inspection, name: str, columns: tuple[str, ...], size: int,
            progress: Callable[[str, int], None] | None = None) -> Iterator[pd.DataFrame]:
    count = 0
    try:
        for chunk in pd.read_csv(info.paths[name], usecols=list(columns), dtype=str,
                                 keep_default_na=False, chunksize=size):
            chunk = chunk.loc[:, list(columns)]
            count += len(chunk)
            yield chunk
            if progress:
                progress(name, count)
    except (OSError, UnicodeError, pd.errors.ParserError) as exc:
        raise ValueError(f'{name}: CSV読込失敗: {info.paths[name]}: {exc}') from exc
    expected = info.entries[name]['row_count']
    if count != expected:
        raise ValueError(f'{name}: row_count mismatch: manifest={expected}, CSV={count}')


def inspect_run(root: Path, dataset_id: str, run_name: str, *,
                verify_content_hashes: bool = True) -> Inspection:
    """Resolve only manifest-recorded files; check identities and small metadata.

    Absolute paths are never rewritten. CSV contents have no pipeline-recorded
    checksum in older runs: header, row count and relational checks are necessary
    but cannot certify byte-for-byte identity with the historical run.
    """
    root = Path(root).expanduser().resolve()
    for value in (dataset_id, run_name):
        if not value or Path(value).name != value or value in ('.', '..'):
            raise ValueError('dataset_id/run_nameは単一の空でない名前が必要です')
    path = root / 'results' / dataset_id / run_name / 'run_manifest.json'
    manifest = _json(path)
    if manifest.get('dataset_id') != dataset_id:
        raise ValueError(f'dataset identity mismatch: {path}')
    if manifest.get('status') != 'success':
        raise ValueError(f'run status must be success: {manifest.get("status")}: {path}')
    config = manifest.get('config')
    if not isinstance(config, dict) or not isinstance(config.get('text'), str):
        raise ValueError('保存config.textがありません')
    text = config['text']
    if hashlib.sha256(text.encode('utf-8')).hexdigest() != config.get('hash'):
        raise ValueError('saved config hash mismatch')
    cfg = ExperimentConfig.model_validate(yaml.safe_load(text))
    expected = load_config(CONFIG_PATH)
    if cfg.experiment.name != 'scan_source_driven_removal':
        raise ValueError('scan_source_driven_removal実験の保存設定が必要です')
    for section in ('flow', 'prefix', 'scan', 'analysis'):
        if getattr(cfg, section) != getattr(expected, section):
            raise ValueError(f'{section} settings differ from configs/scan_source_driven_removal.yaml')
    if cfg.aguri.options != expected.aguri.options:
        raise ValueError('aguri options differ from scan_source_driven_removal')
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, dict):
        raise ValueError('manifest.artifacts objectがありません')
    entries, paths = {}, {}
    for name, schema in SCHEMAS.items():
        aliases = (name, 'flows_csv') if name == 'flows' else (name,)
        present = [key for key in aliases if key in artifacts]
        if len(present) > 1:
            raise ValueError(f'ambiguous artifact entries: {name}')
        if not present:
            raise FileNotFoundError(f'missing required artifact entry: {name}: {path}')
        entry = artifacts[present[0]]
        if not isinstance(entry, dict):
            raise ValueError(f'{name}: artifact entry must be an object')
        _row_count(entry.get('row_count'), name)
        file_path = _resolve(root, entry.get('path'))
        if not file_path.is_file():
            raise FileNotFoundError(f'{name}: manifest参照CSVがありません: {file_path}\n'
                '絶対パスは自動置換しません。研究室PCでmanifestの記録先を確認してください。')
        header = pd.read_csv(file_path, nrows=0).columns
        missing = set(schema) - set(header)
        if missing:
            raise ValueError(f'{name}: missing required columns: {sorted(missing)}')
        if verify_content_hashes and entry.get('sha256') is not None and sha256_file(file_path) != entry['sha256']:
            raise ValueError(f'{name}: checksum mismatch')
        entries[name], paths[name] = entry, file_path
    flow_cache = manifest.get('cache', {}).get('flows', {})
    fm_path = _resolve(root, flow_cache['manifest_path']) if 'manifest_path' in flow_cache else paths['flows'].parent / 'flow_manifest.json'
    fm = _json(fm_path)
    sha = (manifest.get('input') or {}).get('sha256')
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('input SHA-256が不正です')
    fingerprint = flow_fingerprint(sha, cfg, FLOW_SCHEMA_VERSION)
    for key, value in {'schema_version': FLOW_SCHEMA_VERSION, 'input_sha256': sha,
                       'flow_config': flow_generation_config(cfg), 'fingerprint': fingerprint}.items():
        if fm.get(key) != value:
            raise ValueError(f'flow cache identity mismatch: {key}: {fm_path}')
    if flow_cache.get('fingerprint', fingerprint) != fingerprint:
        raise ValueError('run cache flows fingerprint mismatch')
    if _row_count(fm.get('row_count'), 'flow cache') != entries['flows']['row_count']:
        raise ValueError('flow cache / run row_count mismatch')
    # Older runs can omit producer records; contradictory recorded bindings
    # must never be ignored merely because the CSV row counts still match.
    for name, entry in entries.items():
        producer = entry.get('producer', {})
        if not isinstance(producer, dict):
            raise ValueError(f'{name}: producer must be an object')
        if 'flow_fingerprint' in producer and producer['flow_fingerprint'] is not None:
            if producer['flow_fingerprint'] != fingerprint:
                raise ValueError(f'{name}: producer.flow_fingerprint mismatch')
        if name == 'flows':
            if 'cache_manifest_path' in producer and _resolve(root, producer['cache_manifest_path']).resolve() != fm_path.resolve():
                raise ValueError('flows: producer.cache_manifest_path mismatch')
            if 'cache_manifest_sha256' in producer and producer['cache_manifest_sha256'] != sha256_file(fm_path):
                raise ValueError('flows: producer.cache_manifest_sha256 mismatch')
        if name == 'flow_prefix_membership' and 'prefixes_sha256' in producer:
            if producer['prefixes_sha256'] != sha256_file(paths['prefixes']):
                raise ValueError('membership: producer.prefixes_sha256 mismatch')
    info = Inspection(path, manifest, paths, entries, [], fm)
    seen = set()
    for chunk in _chunks(info, 'prefixes', ('prefix', 'selected_for_analysis'), 10000):
        selected = _bools(chunk.selected_for_analysis, 'prefixes.selected_for_analysis')
        for prefix, choose in zip(chunk.prefix, selected):
            if prefix in seen:
                raise ValueError(f'duplicate prefix ledger row: {prefix}')
            seen.add(prefix)
            if choose:
                network = ipaddress.ip_network(prefix, strict=True)
                if network.version != 4 or network.prefixlen < 24:
                    raise ValueError(f'invalid selected native prefix: {prefix}')
                info.selected_prefixes.append(prefix)
    info.selected_prefixes.sort()
    if not info.selected_prefixes:
        raise ValueError('selected native prefixが0件です。別runや空台帳を確認してください')
    networks = [ipaddress.ip_network(p) for p in info.selected_prefixes]
    if any(a.overlaps(b) for i, a in enumerate(networks) for b in networks[i+1:]):
        raise ValueError('selected native prefixes overlap: prefer_broader設定と不整合です')
    return info


def _targets(info: Inspection) -> dict[tuple[str, str], tuple[int, int]]:
    targets = {}
    for prefix in info.selected_prefixes:
        native = ipaddress.ip_network(prefix)
        normalized = ipaddress.ip_network(f'{native.network_address}/24', strict=False)
        for scope, net in [('native', native), ('normalized_24', normalized)]:
            targets[(scope, str(net))] = (int(net.network_address), int(net.broadcast_address))
    return targets


def _insert(db: sqlite3.Connection, statement: str, rows, label: str) -> None:
    try:
        db.executemany(statement, rows)
        db.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError(f'{label}: duplicate key or invalid flow_id: {exc}') from exc


def _ingest(db: sqlite3.Connection, info: Inspection, size: int, progress) -> dict[str, int]:
    db.executescript('''
        CREATE TABLE facts (id TEXT PRIMARY KEY, ipv INTEGER, packets INTEGER,
                            src INTEGER, dst INTEGER, pattern TEXT, syn_tcp INTEGER) WITHOUT ROWID;
        CREATE TABLE labels (id TEXT PRIMARY KEY, strict_removed INTEGER,
                             broad_removed INTEGER) WITHOUT ROWID;
        CREATE TABLE membership (scope TEXT, prefix TEXT, id TEXT, sm INTEGER, dm INTEGER,
                                 PRIMARY KEY(scope,prefix,id)) WITHOUT ROWID;
        CREATE INDEX membership_id ON membership(id,scope);
    ''')
    targets = _targets(info)
    expected = dict.fromkeys(targets, 0)
    for chunk in _chunks(info, 'flows', FLOW_USE, size, progress):
        if chunk.flow_id.eq('').any():
            raise ValueError('flows: empty flow_id')
        packets = _integers(chunk.packet_count, 'flows.packet_count', 1)
        ipv = _integers(chunk.ip_version, 'flows.ip_version')
        if not ipv.isin([4, 6]).all():
            raise ValueError('flows.ip_version must be 4 or 6')
        src, dst = [], []
        for version, s, d in zip(ipv, chunk.src_ip, chunk.dst_ip):
            try:
                a, b = ipaddress.ip_address(s), ipaddress.ip_address(d)
            except ValueError as exc:
                raise ValueError('flows: invalid endpoint IP') from exc
            if a.version != version or b.version != version:
                raise ValueError('flows: IP version disagrees with endpoint')
            src.append(int(a) if version == 4 else -1)
            dst.append(int(b) if version == 4 else -1)
        src_series, dst_series = pd.Series(src), pd.Series(dst)
        for key, (low, high) in targets.items():
            expected[key] += int((src_series.between(low, high) | dst_series.between(low, high)).sum())
        syn_tcp = (chunk.protocol.eq('6') & chunk.initial_syn_sender_ip.ne('')).astype(int)
        _insert(db, 'INSERT INTO facts VALUES (?,?,?,?,?,?,?)',
                zip(chunk.flow_id, ipv, packets, src, dst, chunk.observed_tcp_pattern, syn_tcp), 'flows')
    for chunk in _chunks(info, 'flow_labels', FLOW_LABEL_COLUMNS, size, progress):
        flags = {name: _bools(chunk[name], f'labels.{name}') for name in FLOW_LABEL_COLUMNS[1:]}
        if (flags['strict_removed'] & ~flags['broad_removed']).any():
            raise ValueError('strict_removed must be a subset of broad_removed')
        if (flags['strict_scan_like'] != flags['strict_removed']).any() or (flags['broad_scan_like'] != flags['broad_removed']).any():
            raise ValueError('scan_like / removed labels disagree with saved removal settings')
        _insert(db, 'INSERT INTO labels VALUES (?,?,?)',
                zip(chunk.flow_id, flags['strict_removed'].astype(int), flags['broad_removed'].astype(int)), 'labels')
    for a, b in [('facts', 'labels'), ('labels', 'facts')]:
        if db.execute(f'SELECT 1 FROM {a} a LEFT JOIN {b} b ON a.id=b.id WHERE b.id IS NULL LIMIT 1').fetchone():
            raise ValueError('flows / labels flow_id sets differ')
    invalid = db.execute('''SELECT f.id FROM facts f JOIN labels l ON f.id=l.id
        WHERE (l.strict_removed=1 AND (f.pattern NOT IN ('syn_to_rst','syn_synack_rst') OR f.syn_tcp=0))
        OR (l.broad_removed=1 AND (f.pattern NOT IN ('syn_to_rst','syn_synack_rst','syn_only_observed') OR f.syn_tcp=0))
        OR (l.broad_removed=1 AND l.strict_removed=0 AND f.pattern!='syn_only_observed') LIMIT 1''').fetchone()
    if invalid:
        raise ValueError(f'labels / observed scan pattern mismatch: flow_id={invalid[0]}')
    for chunk in _chunks(info, 'flow_prefix_membership', MEMBERSHIP_COLUMNS, size, progress):
        sm, dm = _bools(chunk.src_match, 'membership.src_match'), _bools(chunk.dst_match, 'membership.dst_match')
        if not (sm | dm).all():
            raise ValueError('membership: src_match OR dst_match must be true')
        rows = []
        for row, s, d in zip(chunk.itertuples(index=False), sm, dm):
            if (row.analysis_scope, row.analysis_prefix) not in targets:
                raise ValueError(f'membership: unknown scope/prefix: {row.analysis_scope}/{row.analysis_prefix}')
            rows.append((row.analysis_scope, row.analysis_prefix, row.flow_id, int(s), int(d)))
        _insert(db, 'INSERT INTO membership VALUES (?,?,?,?,?)', rows, 'membership')
    if db.execute('SELECT 1 FROM membership m LEFT JOIN facts f ON m.id=f.id WHERE f.id IS NULL LIMIT 1').fetchone():
        raise ValueError('membership: unknown flow_id')
    # Every recorded edge must be correct, and every eligible edge must exist.
    # Uniqueness + matching expected cardinality proves membership completeness.
    for (scope, prefix), (low, high) in targets.items():
        count = db.execute('SELECT COUNT(*) FROM membership WHERE scope=? AND prefix=?', (scope, prefix)).fetchone()[0]
        if count != expected[(scope, prefix)]:
            raise ValueError(f'membership count mismatch: {scope}/{prefix}: expected={expected[(scope,prefix)]}, got={count}')
        invalid = db.execute('''SELECT m.id FROM membership m JOIN facts f ON m.id=f.id
            WHERE m.scope=? AND m.prefix=? AND
            (m.sm != (f.src BETWEEN ? AND ?) OR m.dm != (f.dst BETWEEN ? AND ?)) LIMIT 1''',
            (scope, prefix, low, high, low, high)).fetchone()
        if invalid:
            raise ValueError(f'membership endpoint flags mismatch: flow_id={invalid[0]}')
    native_rows = db.execute("SELECT COUNT(*) FROM membership WHERE scope='native'").fetchone()[0]
    union = db.execute("SELECT COUNT(DISTINCT id) FROM membership WHERE scope='native'").fetchone()[0]
    multi = db.execute("SELECT COUNT(*) FROM (SELECT id FROM membership WHERE scope='native' GROUP BY id HAVING COUNT(*)>1)").fetchone()[0]
    return {'selected_prefix_count': len(info.selected_prefixes),
            'flow_rows': info.entries['flows']['row_count'],
            'native_membership_rows': native_rows, 'selected_unique_flows': union,
            'extra_memberships': native_rows - union, 'multi_prefix_flows': multi}


def _summarize(db: sqlite3.Connection, info: Inspection):
    db.execute('CREATE TABLE dist (prefix TEXT, packets INTEGER, removed INTEGER, n INTEGER)')
    for prefix in info.selected_prefixes:
        db.execute('''INSERT INTO dist SELECT ?,f.packets,l.broad_removed,COUNT(*)
            FROM membership m JOIN facts f ON m.id=f.id JOIN labels l ON f.id=l.id
            WHERE m.scope='native' AND m.prefix=? GROUP BY f.packets,l.broad_removed''', (prefix, prefix))
    for name, condition in [('selected_union', "EXISTS (SELECT 1 FROM membership m WHERE m.scope='native' AND m.id=f.id)"),
                            ('overall_ipv4', 'f.ipv=4')]:
        db.execute(f'''INSERT INTO dist SELECT ?,f.packets,l.broad_removed,COUNT(*)
            FROM facts f JOIN labels l ON f.id=l.id WHERE {condition}
            GROUP BY f.packets,l.broad_removed''', (name,))
    db.execute('CREATE INDEX dist_prefix ON dist(prefix,packets,removed)')
    maximum = db.execute('SELECT MAX(packets) FROM dist').fetchone()[0] or 1
    edges = [1, 2, 3, 4]
    while edges[-1] <= maximum:
        edges.append(edges[-1] * 2)
    summary, hist = [], []
    for prefix in [*info.selected_prefixes, 'selected_union', 'overall_ipv4']:
        raw_n = db.execute('SELECT COALESCE(SUM(n),0) FROM dist WHERE prefix=?', (prefix,)).fetchone()[0]
        removed_n = db.execute('SELECT COALESCE(SUM(n),0) FROM dist WHERE prefix=? AND removed=1', (prefix,)).fetchone()[0]
        for group, condition in [('Raw','1'), ('removed','removed=1'), ('retained','removed=0')]:
            n = db.execute(f'SELECT COALESCE(SUM(n),0) FROM dist WHERE prefix=? AND {condition}', (prefix,)).fetchone()[0]
            positions = [(n - 1) * q for q in (.5, .95)]
            ranks = {r for p in positions for r in (math.floor(p), math.ceil(p))} if n else set()
            values, bins, offset, one = {}, [0] * (len(edges) - 1), 0, 0
            for packets, count in db.execute(f'SELECT packets,SUM(n) FROM dist WHERE prefix=? AND {condition} GROUP BY packets ORDER BY packets', (prefix,)):
                bins[bisect_right(edges, packets) - 1] += count
                if packets == 1:
                    one += count
                for rank in ranks:
                    if offset <= rank < offset + count:
                        values[rank] = packets
                offset += count
            quantiles = [values[math.floor(p)] + (values[math.ceil(p)] - values[math.floor(p)]) * (p - math.floor(p)) for p in positions] if n else [math.nan, math.nan]
            summary.append(dict(prefix=prefix, group=group, flow_count=n,
                removal_rate=removed_n / raw_n if raw_n else math.nan,
                median=quantiles[0], p95=quantiles[1], one_packet_rate=one/n if n else math.nan))
            hist.extend(dict(prefix=prefix, group=group, lower=lo, upper=hi,
                flow_count=count, proportion=count/n if n else math.nan)
                for lo, hi, count in zip(edges, edges[1:], bins))
    return pd.DataFrame(summary), pd.DataFrame(hist), edges


def analyze_run(root: Path, dataset_id: str, run_name: str, *, chunksize: int = 100_000,
                scratch_dir: Path | None = None,
                progress: Callable[[str, int], None] | None = None,
                exact_cache_dir: Path | None = None) -> FlowLengthResult:
    """Validate all rows, then return exact summaries and common-bin frequencies.

    Scratch disk grows with flow/label IDs and memberships; RAM is bounded by
    chunksize and SQLite's 32 MiB page cache. Temporary files are cleaned on
    success and failure. The caller chooses a sufficiently large local disk.
    """
    if type(chunksize) is not int or chunksize < 1:
        raise ValueError('chunksize must be a positive integer')
    if exact_cache_dir is not None:
        from mawi_global_analysis.flow_length_cache import load_cache, source_identity, store_cache
        info = inspect_run(root, dataset_id, run_name, verify_content_hashes=False)
        cached = load_cache(info, exact_cache_dir, source_identity(info))
        if cached is not None:
            if progress:
                progress('整数度数cacheを再利用（フローCSVの全行読込なし）', cached.audit['flow_rows'])
            return cached
        if progress:
            progress('整数度数の追加集計が必要です（既存CSVのみ、PCAP再処理なし）', 0)
    info = inspect_run(root, dataset_id, run_name)
    identity = source_identity(info) if exact_cache_dir is not None else None
    exact_path = None
    if scratch_dir is not None and not Path(scratch_dir).is_dir():
        raise FileNotFoundError(f'scratch_dirがありません: {scratch_dir}')
    with tempfile.TemporaryDirectory(prefix='mawi-flow-length-', dir=scratch_dir) as work:
        db = sqlite3.connect(Path(work) / 'working.sqlite')
        try:
            db.execute('PRAGMA cache_size=-32768')
            db.execute('PRAGMA temp_store=FILE')
            audit = _ingest(db, info, chunksize, progress)
            if progress:
                progress('集計・分位点計算', audit['flow_rows'])
            summary, histogram, edges = _summarize(db, info)
            if exact_cache_dir is not None:
                exact_path = store_cache(info, exact_cache_dir, identity, db,
                                         summary, histogram, edges, audit)
        finally:
            db.close()
    return FlowLengthResult(info, summary, histogram, edges, audit, exact_path)


def make_demo_run(root: Path) -> tuple[str, str]:
    """Write a tiny, explicitly synthetic saved-run bundle in a new directory.

    This exercises artifact I/O and plotting, not source detection or a real
    MAWI run. The notebook calls this only after the user selects demo mode.
    """
    from mawi_global_analysis.membership import build_membership
    from mawi_global_analysis.prefix import build_corrected_prefix_ledger

    root = Path(root).resolve()
    dataset, run_name = 'synthetic_flow_length_demo', 'scan_source_driven_removal'
    run_dir = root / 'results' / dataset / run_name
    cache = root / 'data' / dataset / 'processed' / 'flows' / 'synthetic'
    if run_dir.exists() or cache.exists():
        raise FileExistsError('demo artifacts already exist; use a new temporary root')
    run_dir.mkdir(parents=True)
    cache.mkdir(parents=True)
    cfg = load_config(CONFIG_PATH)
    pairs = [('192.0.2.1', '203.0.113.200'), ('203.0.113.200', '192.0.2.2'),
             ('192.0.2.3', '198.51.100.3'), ('198.51.100.4', '203.0.113.200'),
             ('198.51.100.5', '198.51.100.6'), ('192.0.2.4', '203.0.113.200'),
             ('203.0.113.200', '192.0.2.5'), ('203.0.113.200', '203.0.113.201'),
             ('2001:db8::1', '2001:db8::2')]
    packets = [1, 2, 3, 4, 7, 8, 131072, 1, 1]
    patterns = ['syn_only_observed', 'syn_to_rst', 'none', 'none', 'syn_synack_rst',
                'none', 'none', 'none', 'none']
    rows, label_rows = [], []
    for i, ((src, dst), count, pattern) in enumerate(zip(pairs, packets, patterns)):
        row = dict.fromkeys(FLOW_COLUMNS, 0)
        row.update(flow_id=f'demo-{i}', ip_version=6 if ':' in src else 4,
                   protocol=6, src_ip=src, dst_ip=dst, packet_count=count,
                   initial_syn_sender_ip=src if pattern != 'none' else '',
                   observed_tcp_pattern=pattern)
        rows.append(row)
        strict, broad = i in (1, 4), i in (0, 1, 4)
        label_rows.append(dict(zip(FLOW_LABEL_COLUMNS, [row['flow_id'], strict, broad, strict, broad])))
    flows = pd.DataFrame(rows, columns=FLOW_COLUMNS)
    labels = pd.DataFrame(label_rows, columns=FLOW_LABEL_COLUMNS).iloc[::-1]
    prefixes = build_corrected_prefix_ledger(pd.DataFrame({
        'src_prefix': ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.7/32'],
        'dst_prefix': ['*', '*', '*']}), cfg)
    membership = build_membership(flows, prefixes)
    artifacts = {}
    for name, path, frame in [('flows', cache/'flows.csv', flows),
            ('flow_labels', run_dir/'flow_labels.csv', labels),
            ('prefixes', run_dir/'prefixes.csv', prefixes),
            ('flow_prefix_membership', run_dir/'flow_prefix_membership.csv', membership)]:
        frame.to_csv(path, index=False)
        artifacts[name] = {'path': str(path.relative_to(root)), 'row_count': len(frame)}
    text = CONFIG_PATH.read_text(encoding='utf-8')
    sha = hashlib.sha256(b'synthetic demo; no PCAP input').hexdigest()
    fp = flow_fingerprint(sha, cfg, FLOW_SCHEMA_VERSION)
    fm_path = cache/'flow_manifest.json'
    fm_path.write_text(json.dumps({'input_sha256': sha, 'fingerprint': fp,
        'schema_version': FLOW_SCHEMA_VERSION, 'flow_config': flow_generation_config(cfg),
        'row_count': len(flows), 'skipped_packet_counts': {}}), encoding='utf-8')
    manifest = {'dataset_id': dataset, 'status': 'success', 'evidence_level': 'synthetic_demo',
        'input': {'sha256': sha}, 'config': {'text': text, 'hash': hashlib.sha256(text.encode()).hexdigest()},
        'artifacts': artifacts, 'cache': {'flows': {'fingerprint': fp,
        'manifest_path': str(fm_path.relative_to(root))}}, 'git_commit': None}
    (run_dir/'run_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return dataset, run_name
