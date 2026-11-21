"""Read-only strict Flow18/Packet15 lineage binding; never repairs sources."""
from __future__ import annotations

from pathlib import Path
import json

from mawi_global_analysis.aguri_two_stage.validation import inspect_lineage
from mawi_global_analysis.agurim_prime.stage import _source
from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24.analysis import _input_hashes
from .population import load_selected_prefixes


def check_name(value: str) -> None:
    if not isinstance(value, str) or not value or Path(value).name != value or value in ('.', '..'):
        raise ValueError('dataset/run must be a single nonempty name')


def recheck_inputs(tracked: dict[str, str]) -> None:
    for path, digest in tracked.items():
        if sha256_file(Path(path)) != digest:
            raise ValueError(f'input changed during processing: {path}')


def _bind(tracked: dict[str, str], path: Path, expected: str) -> None:
    path = str(path.resolve())
    if path in tracked and tracked[path] != expected:
        raise ValueError(f'conflicting input checksum bindings: {path}')
    tracked[path] = expected


def _snapshot_lineage(info, root: Path, tracked: dict[str, str]) -> None:
    """Pin expected bytes BEFORE the inspector reads them; never rebaseline."""
    path = Path(info.manifest['cache']['aguri_two_stage']['manifest_path'])
    if not path.is_absolute():
        path = root/path
    _bind(tracked, path, sha256_file(path))
    cache = json.loads(path.read_text(encoding='utf-8'))
    for entry in cache['artifacts'].values():
        name = entry['name']
        check_name(name)
        _bind(tracked, path.parent/name, entry['sha256'])
    build = cache['identity']['build']
    manifest = Path(build['build_manifest_path'])
    _bind(tracked, manifest, build['build_manifest_sha256'])
    for name, digest in build['source_sha256'].items():
        check_name(name)
        _bind(tracked, manifest.parent/'src'/name, digest)
    for name, digest in build['executable_sha256'].items():
        check_name(name)
        _bind(tracked, manifest.parent/name, digest)
    recheck_inputs(tracked)


def validate_inputs(root: Path, dataset_id: str, flows: Path | None,
                    flow_run: str, packet_run: str) -> dict:
    root = Path(root).expanduser().resolve()
    for name in (dataset_id, flow_run, packet_run):
        check_name(name)
    runs, tracked, common = {}, {}, None
    source = None
    for mode, name, count in (('flow', flow_run, 18), ('packet', packet_run, 15)):
        try:
            info = inspect_run(root, dataset_id, name, raw_only=True)
            inputs = _input_hashes(info, root)
            # Mandatory byte bindings for the new two-stage source schema.
            for key in ('flows', 'prefixes', 'flow_prefix_membership'):
                if info.entries[key].get('sha256') != inputs[key]['sha256']:
                    raise ValueError(f'{key}: missing or mismatching source artifact hash')
            selected = load_selected_prefixes(info.paths['prefixes'], count)
            for entry in inputs.values():
                _bind(tracked, Path(entry['path']), entry['sha256'])
            _snapshot_lineage(info, root, tracked)
            lineage = inspect_lineage(info, root, inputs)
            recheck_inputs(tracked)
            identity = lineage['identity']
            if identity['basis'] != mode or lineage['identity']['settings']['threshold'] != 1 or identity['settings']['heuristics'] != 0:
                raise ValueError('expected matching flow/packet basis, threshold=1, heuristics=0')
            contract = {k: identity[k] for k in ('input', 'build', 'settings', 'converter_version', 'wire_version', 'implementation_sha256')}
            if common is None:
                common = contract
                source, _, _ = _source(info.paths['flows'].resolve())
            elif common != contract:
                raise ValueError('Flow and Packet common input/settings/build identity mismatch')
            runs[mode] = dict(run_name=name, selected_prefixes=list(map(str, selected)),
                              selected_count=count, inputs=inputs, lineage=lineage)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise ValueError(f'{mode}/{name}: {exc}') from exc
    if flows is not None and Path(flows).expanduser().resolve() != Path(source['path']).resolve():
        raise ValueError('--flows must be the manifest-recorded common canonical CSV')
    recheck_inputs(tracked)
    return dict(status='valid', dataset_id=dataset_id, root=str(root), source=source,
                runs=runs, tracked_inputs=tracked,
                input_identity=dict(common_canonical_verified=True, source_lineage_verified=True,
                                    pcap_bytes_verified=False,
                                    observation_point_and_window='not independently verified; confirm original capture on lab PC'))
