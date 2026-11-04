"""Validate saved RLS comparison contracts using read-only file operations.

Mode-specific config hashes/fingerprints are verified within their own run,
never required to match across modes. This is artifact/contract validation,
not membership reconstruction, distribution analysis or real-data validation.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import re

import pandas as pd
import yaml

from mawi_global_analysis.aguri import PINNED_AGURIM_SHA
from mawi_global_analysis.agurim_prime.input import CONVERTER_VERSION
from mawi_global_analysis.agurim_prime.stage import METHODS, REPO, _options, inspect_prime_lineage
from mawi_global_analysis.config import ExperimentConfig, load_config
from mawi_global_analysis.flow_length import _chunks, inspect_run
from mawi_global_analysis.flow_stage import _validate_cached_flows
from mawi_global_analysis.hashing import flow_generation_config, sha256_file, stable_json_hash
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.normalized24.analysis import _cohort, _input_hashes
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS, build_corrected_prefix_ledger


class ComparisonValidationError(ValueError):
    """A mode/run fails a named comparison requirement or integrity check."""


def _equal(field: str, actual, expected) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise ComparisonValidationError(f'{field}: expected {expected!r}; got {actual!r}')


def _compare(field: str, actual, expected) -> None:
    if isinstance(expected, dict) and isinstance(actual, dict):
        _equal(f'{field}.fields', sorted(actual), sorted(expected))
        for key, value in expected.items():
            _compare(f'{field}.{key}' if field else key, actual[key], value)
    else:
        _equal(field, actual, expected)


def _object(value, field: str) -> dict:
    if not isinstance(value, dict):
        raise ComparisonValidationError(f'{field}: expected a JSON object')
    return value


def _digest(value, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ComparisonValidationError(f'{field}: missing or invalid SHA-256')
    return value


def _path(root: Path, value, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ComparisonValidationError(f'{field}: expected a nonempty file path')
    path = Path(value)
    return (path if path.is_absolute() else root/path).resolve()


def _record(path: Path, tracked: dict[Path, str], field: str) -> str:
    try:
        digest = sha256_file(path)
    except OSError as exc:
        raise ComparisonValidationError(f'{field} ({path}): {exc}') from exc
    if path in tracked:
        _equal(f'{field}.changed_during_validation', digest, tracked[path])
    tracked[path] = digest
    return digest


def _read(path: Path, tracked: dict[Path, str], field: str) -> dict:
    _record(path, tracked, field)
    try:
        return _object(json.loads(path.read_text(encoding='utf-8')), field)
    except (ValueError, OSError) as exc:
        raise ComparisonValidationError(f'{field} ({path}): {exc}') from exc


def _validate_run(root: Path, dataset: str, run: str, mode: str,
                  chunksize: int, tracked: dict[Path, str]):
    manifest_path = root/'results'/dataset/run/'run_manifest.json'
    manifest = _read(manifest_path, tracked, 'run_manifest')
    _equal('run_manifest.schema_version', manifest.get('schema_version'), 'agurim-prime-run-v1')
    _equal('run_manifest.run_name', manifest.get('run_name'), run)
    selection = _object(manifest.get('selection'), 'selection')
    for field, expected in {'basis':mode, 'method':METHODS[mode], 'additional_filters':[],
                            'top_k':None, 'endpoint_orientation':'first_observed'}.items():
        if field not in selection:
            raise ComparisonValidationError(f'selection.{field}: missing required field')
        _equal(f'selection.{field}', selection[field], expected)

    config = _object(manifest.get('config'), 'config')
    if not isinstance(config.get('text'), str):
        raise ComparisonValidationError('config.text: expected saved YAML text')
    try:
        cfg = ExperimentConfig.model_validate(yaml.safe_load(config['text']))
    except (ValueError, yaml.YAMLError) as exc:
        raise ComparisonValidationError(f'config.text: {exc}') from exc
    baseline = load_config(REPO/'configs/baseline.yaml')
    _compare('config.flow', flow_generation_config(cfg), flow_generation_config(baseline))
    for section in ('prefix', 'analysis', 'scan', 'aguri'):
        _compare(f'config.{section}', getattr(cfg, section).model_dump(),
                 getattr(baseline, section).model_dump())

    caches = _object(manifest.get('cache'), 'cache')
    cache_ref = _object(caches.get('agurim_prime'), 'cache.agurim_prime')
    cache_path = _path(root, cache_ref.get('manifest_path'), 'cache.agurim_prime.manifest_path')
    cache = _read(cache_path, tracked, 'prime_manifest')
    identity = _object(cache.get('identity'), 'prime_manifest.identity')
    _equal('prime_manifest.identity.schema_version', identity.get('schema_version'), 'agurim-prime-v1')
    _equal('selection.basis (cache)', identity.get('basis'), mode)
    _equal('rls.threshold_percent', identity.get('threshold'), 1)
    options = _options(mode, 1, 2)
    _equal('rls.options', identity.get('options'), options)
    _equal('converter_version', identity.get('converter_version'), CONVERTER_VERSION)
    command = _object(cache.get('command'), 'command')
    argv = command.get('argv')
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ComparisonValidationError('command.argv: expected executable and argument strings')
    _equal('command.argv options', argv[1:], options)
    _equal('command.returncode', command.get('returncode'), 0)
    executable = _path(root, argv[0], 'command.argv[0]')
    executable_sha = _digest(identity.get('executable_sha256'), 'executable_sha256')
    _equal('fork.executable_sha256 (actual binary)',
           _record(executable, tracked, 'executable'), executable_sha)
    fork = _object(identity.get('fork'), 'fork')
    _equal('fork.upstream_commit', fork.get('upstream_commit'), PINNED_AGURIM_SHA)
    _equal('fork.patch_sha256', fork.get('patch_sha256'), sha256_file(REPO/'vendor/agurim-prime/flow-mode.patch'))
    _equal('fork.executable_sha256', fork.get('executable_sha256'), executable_sha)
    build_path = executable.parent/'build_manifest.json'
    build = _read(build_path, tracked, 'build_manifest')
    _equal('fork.status', build.get('status'), 'success')
    _equal('build_manifest.schema_version', build.get('schema_version'), 'agurim-prime-build-v1')
    expected_fork = stable_json_hash({'upstream_commit':PINNED_AGURIM_SHA,
                                     'patch_sha256':fork['patch_sha256']})
    _equal('fork.fork_identity', fork.get('fork_identity'), expected_fork)
    if 'fork_commit' not in fork:
        raise ComparisonValidationError('fork.fork_commit: required; record null for an unpublished fork')
    commit = fork['fork_commit']
    if commit is not None and (not isinstance(commit, str) or re.fullmatch('[0-9a-f]{40}', commit) is None):
        raise ComparisonValidationError('fork.fork_commit: expected an explicit null or Git commit SHA')
    if not isinstance(fork.get('compiler'), str) or not fork['compiler'].strip():
        raise ComparisonValidationError('fork.compiler: missing or empty compiler identity')
    compiler_argv = fork.get('compiler_argv')
    if (not isinstance(compiler_argv, list) or not compiler_argv
            or not all(isinstance(arg, str) and arg.strip() for arg in compiler_argv)):
        raise ComparisonValidationError('fork.compiler_argv: expected a nonempty list of compiler arguments')
    _compare('fork', fork, {**build, 'build_manifest_sha256':tracked[build_path]})
    source_hashes = _object(fork.get('source_sha256'), 'fork.source_sha256')
    if not source_hashes:
        raise ComparisonValidationError('fork.source_sha256: missing source identity')
    for name, digest in source_hashes.items():
        _digest(digest, f'fork.source_sha256.{name}')

    implementation = _object(manifest.get('implementation_sha256'), 'implementation_sha256')
    converter = _object(identity.get('implementation_sha256'), 'converter.implementation_sha256')
    for name in ('agurim_prime/stage.py', 'prefix.py', 'membership.py'):
        _digest(implementation.get(name), f'implementation_sha256.{name}')
    for name in ('input.py', 'stage.py'):
        _digest(converter.get(name), f'converter.implementation_sha256.{name}')
    _equal('implementation_sha256.agurim_prime/stage.py',
           implementation['agurim_prime/stage.py'], converter['stage.py'])

    # Existing checks verify canonical schema/settings, producer bindings and caches.
    info = inspect_run(root, dataset, run, raw_only=True, verify_content_hashes=False)
    inputs = _input_hashes(info, root)
    for name, entry in inputs.items():
        path = Path(entry['path'])
        if path in tracked:
            _equal(f'{name}.changed_during_validation', entry['sha256'], tracked[path])
        tracked[path] = entry['sha256']
    for name, entry in info.entries.items():
        _equal(f'{name}.sha256', inputs[name]['sha256'], _digest(entry.get('sha256'), f'{name}.sha256'))
    lineage = inspect_prime_lineage(info, root, inputs)
    _equal('prime_manifest.changed_during_validation', lineage['cache_manifest_sha256'], tracked[cache_path])
    # Track cache data too, so a change after lineage inspection is detected.
    for name, entry in cache['artifacts'].items():
        path = cache_path.parent/entry['name']
        _equal(f'cache.artifacts.{name}.sha256', _record(path, tracked, name), entry['sha256'])
    _cohort(info, chunksize)  # Validate native -> normalized /24 mapping, no distributions.
    for _ in _chunks(info, 'flow_prefix_membership', MEMBERSHIP_COLUMNS, chunksize):
        pass  # Exhaustion verifies the declared membership row count without aggregation.
    candidates = pd.read_csv(cache_path.parent/'prime_candidates.csv')
    expected = build_corrected_prefix_ledger(candidates, cfg)
    expected = pd.read_csv(io.StringIO(expected.to_csv(index=False)), dtype=str, keep_default_na=False)
    actual = pd.read_csv(info.paths['prefixes'], dtype=str, keep_default_na=False)
    columns = list(CORRECTED_LEDGER_COLUMNS)
    if not actual[columns].sort_values('prefix').reset_index(drop=True).equals(expected[columns]):
        raise ComparisonValidationError('prefixes.corrected_selection: ledger differs from corrected candidate selection')

    source = lineage['identity']['input']
    common = {
        'canonical':{key:source[key] for key in ('csv_sha256','manifest_sha256',
                    'flow_fingerprint','capture_sha256','row_count')},
        'rls':{'threshold_percent':1, 'disable_heuristics':2},
        'fork':fork,
        'converter':{'version':identity['converter_version'], 'implementation_sha256':converter},
        'implementation_sha256':implementation,
        'evaluation':{'group':'Raw','scope':'IPv4 TCP/UDP','normalization':'full containing /24',
                      'endpoint_rule':'src_ip OR dst_ip','union_deduplication':'flow_id',
                      'additional_filters':[],'top_k':None},
    }
    common['canonical']['binary_sha256'] = cache['artifacts']['binary_input']['sha256']
    common['canonical']['flow_config'] = flow_generation_config(cfg)
    record = {'run_name':run,'run_manifest_sha256':inputs['run_manifest']['sha256'],
              'config_sha256':config['hash'],'prime_fingerprint':lineage['fingerprint']}
    audit = _object(lineage['audit'], 'canonical.audit')
    for field, expected in {'unit_packets':False, 'scope':'IPv4 TCP/UDP',
                            'orientation':'first observed packet; not initiator/responder'}.items():
        _equal(f'canonical.audit.{field}', audit.get(field), expected)
    return common, record, info, audit


def _validate_scope(info, chunksize: int) -> dict:
    """One common canonical pass checks the selector/evaluator scope agreement."""
    _validate_cached_flows(info.paths['flows'], info.entries['flows']['row_count'])
    audit = {'input_rows':0, 'included_flows':0, 'excluded_ipv6':0, 'excluded_protocol':0}
    for chunk in _chunks(info, 'flows', ('ip_version','protocol'), chunksize):
        for version, protocol in chunk.itertuples(index=False, name=None):
            if version not in ('4','6'):
                raise ComparisonValidationError(f'canonical.ip_version: expected 4 or 6; got {version!r}')
            if not re.fullmatch('[0-9]+', protocol) or not 0 <= int(protocol) <= 255:
                raise ComparisonValidationError(f'canonical.protocol: invalid protocol {protocol!r}')
            if version == '4' and int(protocol) not in (6,17):
                raise ComparisonValidationError('canonical.protocol: IPv4 rows must be TCP/UDP for the same Overall scope')
            audit['input_rows'] += 1
            audit['included_flows' if version == '4' else 'excluded_ipv6'] += 1
    return audit


def validate_comparison(root: Path, dataset_id: str, *, packet_run: str,
                        byte_run: str, flow_run: str, chunksize: int = 100_000) -> dict:
    """Read three existing runs and return validation metadata; never write files.

    The recorded executable and adjacent build_manifest must still be available.
    Checks saved normalized24 evaluation settings and artifact integrity; does not
    reconstruct every membership edge or compute distributions/coverage.
    """
    if type(chunksize) is not int or chunksize < 1:
        raise ComparisonValidationError('chunksize: expected a positive integer')
    runs = {'packet':packet_run, 'byte':byte_run, 'flow':flow_run}
    for field, value in {'dataset_id':dataset_id, **runs}.items():
        if not isinstance(value, str) or not value or Path(value).name != value or value in ('.','..'):
            raise ComparisonValidationError(f'{field}: expected a single nonempty path component')
    root = Path(root).expanduser().resolve()
    tracked: dict[Path, str] = {}
    result = {'schema_version':'rls-weight-comparison-validation-v1', 'status':'valid',
              'dataset_id':dataset_id, 'runs':{},
              'validation_scope':'saved contracts and artifact integrity; no membership reconstruction or distributions'}
    audits = {}
    for mode, run in runs.items():
        try:
            common, record, info, audits[mode] = _validate_run(root, dataset_id, run, mode, chunksize, tracked)
            if mode == 'packet':
                result['common'] = common
                canonical_info = info
            else:
                _compare('', common, result['common'])
            result['runs'][mode] = record
        except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
            raise ComparisonValidationError(f'{mode} run {run!r}: {exc}') from exc
    try:
        audit = _validate_scope(canonical_info, chunksize)
    except (ValueError, OSError) as exc:
        raise ComparisonValidationError(f'canonical.scope: {exc}') from exc
    for mode, recorded in audits.items():
        for field, value in audit.items():
            _equal(f'{mode}.canonical.audit.{field}', recorded.get(field), value)
    for path, digest in tracked.items():
        try:
            _equal(f'inputs.changed_during_validation ({path})', sha256_file(path), digest)
        except OSError as exc:
            raise ComparisonValidationError(f'inputs.changed_during_validation ({path}): {exc}') from exc
    return result
