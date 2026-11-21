"""Immutable Random /24 runs, streaming membership and reconstructive verification."""
from __future__ import annotations

import csv
from datetime import UTC, datetime
from ipaddress import IPv4Network
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile

import pandas as pd
import yaml

from mawi_global_analysis.aguri_two_stage.stage import publish
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS, build_membership
from .population import build_population, exclusion_set, included, iter_flow_chunks, iter_population
from .sampling import ALGORITHM, prefix_hash, select_prefixes, validate_settings
from .validation import check_name, recheck_inputs, validate_inputs

SCHEMA = 'random-prefix-selection-run-v1'
PREFIX_COLUMNS = ('prefix', 'prefix_length', 'normalized_prefix_24', 'selected_for_analysis',
                  'analysis_scope', 'selection_rank', 'observed_flow_count',
                  'observed_packet_count', 'observed_byte_count')
OUTPUTS = {'prefixes': 'prefixes.csv', 'flow_prefix_membership': 'flow_prefix_membership.csv',
           'selection_population': 'selection_population.csv', 'excluded_prefixes': 'excluded_prefixes.csv',
           'selection_config': 'selection_config.yaml'}


def implementation() -> dict:
    package = Path(__file__).resolve().parent
    shared = package.parent
    paths = [*package.glob('*.py'), *(shared / name for name in
             ('membership.py', 'prefix.py', 'hashing.py', 'flow_stage.py', 'flow_length.py',
              'agurim_prime/stage.py', 'aguri_two_stage/stage.py', 'aguri_two_stage/validation.py',
              'normalized24/analysis.py'))]
    return {str(p.relative_to(shared)): sha256_file(p) for p in sorted(paths)}


def config(count: int, seed: int) -> dict:
    validate_settings(count, seed)
    return dict(method='random24-exclude-flow-packet', algorithm=ALGORITHM, algorithm_version=1,
                count=count, seed=seed, prefix_length=24, replacement=False,
                hash_input='ASCII(algorithm) + NUL + uint64be(seed) + IPv4 network address (4 bytes)',
                ranking='digest bytes ascending; ties by numeric network address ascending',
                set_hash='SHA256(ASCII(mawi-random24-set-v1) + NUL + numeric-ascending packed addresses)',
                selection_hash='SHA256(ASCII(mawi-random24-selection-v1) + NUL + rank-ordered packed addresses)',
                population='observed canonical IPv4 TCP/UDP src OR dst /24s minus parents of selected Flow18 and Packet15 prefixes',
                minimum_traffic_thresholds=[], scan_removal=False, membership='src_ip OR dst_ip',
                source_selected_counts=dict(flow=18, packet=15),
                canonical_byte_definition='sum of captured Ethernet frame lengths; byte_count = frame_byte_count',
                downstream_byte_definition='original_frame_bytes uses original PCAP record lengths; may differ on truncation',
                comparison_limitations=['native prefix lengths differ: Random fixed /24, source /24-/32',
                                        'selection counts remain Flow18/Packet15/Random default18',
                                        'flows can be shared across groups through their other endpoint',
                                        'conditional observed-TCP/UDP population; not all IPv4 space',
                                        'SHA-256 pseudorandom ranking; no exact-uniformity proof over finite seeds'])


def write_membership_and_counts(flows: Path, selected: tuple[IPv4Network, ...], output: Path,
                                *, chunksize: int) -> dict:
    ledger = pd.DataFrame([dict(prefix=str(p), selected_for_analysis=True) for p in selected])
    counts = {str(p): [0, 0, 0] for p in selected}
    edge_count = 0
    # Disk-backed global uniqueness also protects callers using this writer alone.
    with tempfile.TemporaryDirectory(prefix='.random-membership-', dir=output.parent) as temp:
        with sqlite3.connect(Path(temp)/'ids.sqlite') as db, output.open('w', newline='', encoding='utf-8') as stream:
            db.execute('PRAGMA cache_size=-8192')
            db.execute('CREATE TABLE ids (id TEXT PRIMARY KEY) WITHOUT ROWID')
            writer = csv.DictWriter(stream, fieldnames=MEMBERSHIP_COLUMNS, lineterminator='\n')
            writer.writeheader()
            for chunk in iter_flow_chunks(flows, chunksize):
                try:
                    db.executemany('INSERT INTO ids VALUES (?)', ((row['flow_id'],) for row in chunk))
                    db.commit()
                except sqlite3.IntegrityError as exc:
                    raise ValueError('duplicate canonical flow_id across chunks') from exc
                rows = [row for row in chunk if included(row)]
                if not rows:
                    continue
                edges = build_membership(pd.DataFrame(rows), ledger)
                facts = {r['flow_id']: r for r in rows}
                positions = {r['flow_id']: i for i, r in enumerate(rows)}
                prefix_positions = {str(p): i for i, p in enumerate(selected)}
                records = sorted(edges.to_dict('records'), key=lambda e: (
                    positions[e['flow_id']], e['analysis_scope'] != 'native',
                    prefix_positions[e['analysis_prefix']]))
                for edge in records:
                    writer.writerow(edge)
                    edge_count += 1
                    if edge['analysis_scope'] == 'native':
                        row = facts[edge['flow_id']]
                        totals = counts[edge['analysis_prefix']]
                        totals[0] += 1
                        totals[1] += row['packet_count']
                        totals[2] += row['byte_count']
            stream.flush()
            os.fsync(stream.fileno())
    return dict(row_count=edge_count, counts=counts)


def _write_csv(path: Path, columns: tuple, rows) -> int:
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, lineterminator='\n')
        writer.writerow(columns)
        n = 0
        for row in rows:
            writer.writerow(row)
            n += 1
        stream.flush()
        os.fsync(stream.fileno())
    return n


def _produce(work: Path, scratch: Path, validated: dict, count: int, seed: int, chunksize: int) -> dict:
    settings = config(count, seed)
    flows = Path(validated['source']['path'])
    runs = validated['runs']
    excluded = exclusion_set(runs['flow']['selected_prefixes'], runs['packet']['selected_prefixes'])
    excluded_set = set(excluded)
    with sqlite3.connect(scratch/'population.sqlite') as db:
        audit = build_population(flows, db, chunksize=chunksize)
        if audit['input_rows'] != validated['source']['row_count']:
            raise ValueError('canonical row count mismatch')
        selected = select_prefixes((p for p in iter_population(db) if p not in excluded_set), count=count, seed=seed)
        ranks = {p: i for i, p in enumerate(selected, 1)}
        membership = write_membership_and_counts(flows, selected, work/OUTPUTS['flow_prefix_membership'], chunksize=chunksize)
        row_counts = dict(flow_prefix_membership=membership['row_count'])
        row_counts['prefixes'] = _write_csv(work/OUTPUTS['prefixes'], PREFIX_COLUMNS,
            ((str(p), 24, str(p), True, 'native', i, *membership['counts'][str(p)]) for i, p in enumerate(selected, 1)))
        row_counts['selection_population'] = _write_csv(work/OUTPUTS['selection_population'],
            ('prefix', 'excluded', 'eligible', 'selected_for_analysis', 'selection_rank'),
            ((str(p), p in excluded_set, p not in excluded_set, p in ranks, ranks.get(p, '')) for p in iter_population(db)))
        row_counts['excluded_prefixes'] = _write_csv(work/OUTPUTS['excluded_prefixes'],
            ('source_basis', 'run_name', 'native_prefix', 'parent_prefix_24'),
            ((mode, runs[mode]['run_name'], native, str(exclusion_set([native], [])[0]))
             for mode in ('flow', 'packet') for native in runs[mode]['selected_prefixes']))
        original = audit['population_count']
        removed = sum(p in excluded_set for p in iter_population(db))
        population = dict(original_count=original, exclusion_count=len(excluded), removed_count=removed,
                          eligible_count=original-removed, population_sha256=prefix_hash(iter_population(db)),
                          exclusion_sha256=prefix_hash(excluded),
                          eligible_sha256=prefix_hash(p for p in iter_population(db) if p not in excluded_set), audit=audit)
    text = yaml.safe_dump(settings, sort_keys=True)
    with (work/OUTPUTS['selection_config']).open('w', encoding='utf-8') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    row_counts['selection_config'] = 1  # one configuration document
    return dict(config=dict(content=settings, text=text, hash=sha256_file(work/OUTPUTS['selection_config'])),
                population=population, selection=dict(count=count, seed=seed, algorithm=ALGORITHM,
                algorithm_version=1, prefixes=list(map(str, selected)), sha256=prefix_hash(selected, ranked=True)),
                row_counts=row_counts)


def _verify_staged(work: Path, manifest: dict, validated: dict, *, chunksize: int) -> None:
    if manifest.get('schema_version') != SCHEMA or manifest.get('status') != 'success':
        raise ValueError('invalid random run schema/status')
    if manifest.get('input') != {'sha256': validated['source']['capture_sha256']}:
        raise ValueError('random input capture identity mismatch')
    if manifest.get('validated_inputs') != validated:
        raise ValueError('random source identity mismatch')
    if manifest.get('implementation_sha256') != implementation():
        raise ValueError('random implementation identity mismatch')
    selection = manifest['selection']
    with tempfile.TemporaryDirectory(prefix='.random-verify-', dir=work.parent) as temp:
        temp = Path(temp)
        expected = temp/'outputs'; expected.mkdir()
        result = _produce(expected, temp, validated, selection['count'], selection['seed'], chunksize)
        for key in ('config', 'population', 'selection'):
            if manifest.get(key) != result[key]:
                raise ValueError(f'random {key} differs from reconstructed selection')
        if set(manifest.get('artifacts', {})) != set(OUTPUTS):
            raise ValueError('random artifact inventory mismatch')
        for key, name in OUTPUTS.items():
            entry = manifest['artifacts'][key]
            digest = sha256_file(work/name)
            if (digest != entry.get('sha256') or digest != sha256_file(expected/name)
                    or entry.get('row_count') != result['row_counts'][key]):
                raise ValueError(f'random artifact content/hash/count mismatch: {key}')
    recheck_inputs(validated['tracked_inputs'])


def run_random_selection(root: Path, dataset_id: str, run_name: str, flows: Path,
                         flow_run: str, packet_run: str, *, count: int = 18,
                         seed: int = 20260408, chunksize: int = 100000) -> Path:
    root = Path(root).expanduser().resolve()
    for name in (dataset_id, run_name, flow_run, packet_run):
        check_name(name)
    validate_settings(count, seed)
    if type(chunksize) is not int or chunksize < 1:
        raise ValueError('chunksize must be positive')
    run = root/'results'/dataset_id/run_name
    if run.exists() or run.is_symlink():
        raise FileExistsError(run)
    for parent in (root/'results', run.parent):
        if parent.is_symlink():
            raise ValueError('output parent symlink not accepted')
    code = implementation()
    validated = validate_inputs(root, dataset_id, flows, flow_run, packet_run)
    run.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.random-run-', dir=run.parent) as temp:
        scratch = Path(temp)
        work = scratch/'outputs'; work.mkdir()
        result = _produce(work, scratch, validated, count, seed, chunksize)
        try:
            repo = Path(__file__).resolve().parents[3]
            commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            commit = None
        artifacts = {key: dict(path=str(run/name), row_count=result['row_counts'][key], sha256=sha256_file(work/name)) for key, name in OUTPUTS.items()}
        manifest = dict(schema_version=SCHEMA, status='success', dataset_id=dataset_id, run_name=run_name,
                        input={'sha256': validated['source']['capture_sha256']}, validated_inputs=validated,
                        implementation_sha256=code, git_commit=commit, created_at=datetime.now(UTC).isoformat(),
                        evidence_level='saved canonical selection; real MAWI execution and capture window not independently asserted',
                        stages=[dict(name='canonical_flows', status='reused'), dict(name='selection', status='completed'),
                                dict(name='membership', status='completed')],
                        **{k: result[k] for k in ('config', 'population', 'selection')}, artifacts=artifacts)
        _verify_staged(work, manifest, validated, chunksize=chunksize)
        with (work/'run_manifest.json').open('w', encoding='utf-8') as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        recheck_inputs(validated['tracked_inputs'])
        if implementation() != code:
            raise ValueError('implementation changed during processing')
        publish(work, run, 'run_manifest.json')
    return run/'run_manifest.json'


def verify_run(path: Path, *, chunksize: int = 100000) -> dict:
    path = Path(path).expanduser().resolve()
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(manifest, dict):
        raise ValueError('random manifest must be an object')
    check_name(manifest['dataset_id']); check_name(manifest['run_name'])
    saved = manifest['validated_inputs']
    root = Path(saved['root'])
    expected = root/'results'/manifest['dataset_id']/manifest['run_name']/'run_manifest.json'
    if path != expected:
        raise ValueError('random manifest path/name mismatch')
    validated = validate_inputs(root, manifest['dataset_id'], Path(saved['source']['path']),
                                saved['runs']['flow']['run_name'], saved['runs']['packet']['run_name'])
    for key, name in OUTPUTS.items():
        if manifest['artifacts'][key]['path'] != str(path.parent/name):
            raise ValueError('random artifact path mismatch')
    _verify_staged(path.parent, manifest, validated, chunksize=chunksize)
    return dict(status='valid', manifest=str(path), selected_count=manifest['selection']['count'],
                selection_sha256=manifest['selection']['sha256'])
