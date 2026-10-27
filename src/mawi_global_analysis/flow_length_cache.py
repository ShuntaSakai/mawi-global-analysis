"""Immutable exact packet-count frequencies for replotting saved run analyses.

Fast source identity uses manifests plus artifact path/size/mtime, not a fresh
full scan of the very large flow CSV. It does not authenticate unchanged bytes
when somebody deliberately preserves those metadata. Cache contents are hashed.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile

import pandas as pd

from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.host_counts import HOST_COUNT_DEFINITION, validate_host_counts


SCHEMA = 'flow-length-exact-v2'
LEGACY_SCHEMA = 'flow-length-exact-v1'


def source_identity(info, *, legacy: bool = False) -> dict:
    files = {}
    for name, path in info.paths.items():
        stat = path.stat()
        files[name] = {'path': str(path.resolve()), 'size': stat.st_size,
                       'mtime_ns': stat.st_mtime_ns}
    identity = {'schema': LEGACY_SCHEMA if legacy else SCHEMA, 'source_manifest': str(info.manifest_path.resolve()),
            'source_manifest_sha256': sha256_file(info.manifest_path),
            'flow_manifest': info.flow_manifest, 'artifacts': files}
    if not legacy:
        identity['host_count_definition'] = HOST_COUNT_DEFINITION
    return identity


def _cache_path(base: Path, identity: dict) -> Path:
    return Path(base).expanduser().resolve() / stable_json_hash(identity)


def load_cache(info, base: Path, identity: dict):
    """Return None only when absent; corrupt or contradictory caches must stop."""
    from mawi_global_analysis.flow_length import FlowLengthResult

    folder = _cache_path(base, identity)
    if not folder.exists():
        return None
    try:
        record = json.loads((folder/'cache_manifest.json').read_text(encoding='utf-8'))
        if (identity.get('schema') not in (SCHEMA, LEGACY_SCHEMA)
                or record['schema'] != identity['schema'] or record['source_identity'] != identity):
            raise ValueError('exact cache identity mismatch')
        for name in ('exact_counts.sqlite', 'flow_length_summary.csv', 'flow_length_histogram.csv'):
            if sha256_file(folder/name) != record['sha256'][name]:
                raise ValueError(f'exact cache checksum mismatch: {name}')
        summary = pd.read_csv(folder/'flow_length_summary.csv', float_precision='round_trip')
        histogram = pd.read_csv(folder/'flow_length_histogram.csv', float_precision='round_trip')
        definition = record.get('host_count_definition')
        if record['schema'] == SCHEMA and definition != HOST_COUNT_DEFINITION:
            raise ValueError('host IP cache definition mismatch')
        if record['schema'] == LEGACY_SCHEMA and definition is not None:
            raise ValueError('legacy cache cannot claim a host IP definition')
        validate_host_counts(summary, definition, info.selected_prefixes)
        return FlowLengthResult(info, summary, histogram, record['bin_edges'],
                                record['audit'], folder/'exact_counts.sqlite', definition)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f'整数度数cacheが破損または不整合です: {folder}: {exc}\n'
                         '上書きや自動再集計はしません。別の新規cache保存先で追加集計してください。') from exc


def store_cache(info, base: Path, identity: dict, db, summary, histogram, edges, audit) -> Path:
    """Publish compact counts, never the multi-million-row temporary facts DB."""
    base = Path(base).expanduser().resolve()
    validate_host_counts(summary, HOST_COUNT_DEFINITION, info.selected_prefixes)
    base.mkdir(parents=True, exist_ok=True)
    destination = _cache_path(base, identity)
    if source_identity(info) != identity:
        raise ValueError('入力が集計中に変更されました。cacheは保存しません')
    if destination.exists():
        raise FileExistsError(f'exact cache already exists: {destination}')
    with tempfile.TemporaryDirectory(prefix='.building-', dir=base) as temporary:
        work = Path(temporary)
        with sqlite3.connect(work/'exact_counts.sqlite') as counts:
            counts.execute('''CREATE TABLE counts (
                prefix TEXT NOT NULL, packets INTEGER NOT NULL CHECK(packets>=1),
                removed INTEGER NOT NULL CHECK(removed IN (0,1)),
                n INTEGER NOT NULL CHECK(n>0), PRIMARY KEY(prefix,removed,packets)
            ) WITHOUT ROWID''')
            counts.executemany('INSERT INTO counts VALUES (?,?,?,?)',
                               db.execute('SELECT prefix,packets,removed,n FROM dist'))
        # sqlite3 context manager commits but does not close the connection.
        counts.close()
        summary.to_csv(work/'flow_length_summary.csv', index=False)
        histogram.to_csv(work/'flow_length_histogram.csv', index=False)
        record = {'schema': SCHEMA, 'source_identity': identity,
                  'host_count_definition': HOST_COUNT_DEFINITION,
                  'selected_prefixes': info.selected_prefixes,
                  'dataset_id': info.manifest['dataset_id'],
                  'bin_edges': edges, 'audit': audit,
                  'evidence': info.manifest.get('evidence_level', 'saved_artifact_analysis'),
                  'sha256': {name: sha256_file(work/name) for name in
                    ('exact_counts.sqlite','flow_length_summary.csv','flow_length_histogram.csv')}}
        (work/'cache_manifest.json').write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        # rename fails on an occupied non-empty directory; existing caches stay immutable.
        work.rename(destination)
    return destination/'exact_counts.sqlite'


def load_cached_run(root: Path, dataset_id: str, run_name: str, cache_dir: Path):
    """Read-only replot path. Missing/stale exact counts require explicit aggregation."""
    from mawi_global_analysis.flow_length import inspect_run
    info = inspect_run(root, dataset_id, run_name, verify_content_hashes=False)
    result = load_cache(info, cache_dir, source_identity(info))
    if result is None:
        # Read-only legacy display. Explicit analyze_run writes a new v2 cache.
        result = load_cache(info, cache_dir, source_identity(info, legacy=True))
    if result is None:
        raise ValueError('一致する整数度数cacheがありません。06 Notebookで追加集計が必要です。PCAP再処理は不要です')
    return result
