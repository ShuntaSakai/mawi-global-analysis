"""Read-only offline presentation of validated, cached flow-length results.

No packet processing, flow generation, label classification or aggregation is
performed here. Counts and bins are consumed from FlowLengthResult unchanged.
"""
from __future__ import annotations

import base64
import hashlib
import re
from io import BytesIO
import json
import math
from numbers import Integral, Real
from pathlib import Path

from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd

from mawi_global_analysis.flow_length import FlowLengthResult, GROUPS
from mawi_global_analysis.flow_length_cache import load_cached_run
from mawi_global_analysis.hashing import sha256_file

COLORS = {'Raw': '#4477AA', 'removed': '#CC6677', 'retained': '#228833'}
REFERENCES = ('selected_union', 'overall_ipv4')
NOTE_FIELDS = ('observation', 'interpretation', 'next_check')
STAT_FIELDS = ('flow_count', 'median', 'p95', 'one_packet_rate', 'removal_rate')


def _invalid(message: str):
    raise ValueError(f'キャッシュのデータ整合性が不正です (invalid): {message}')


def _count(value, name: str) -> int:
    if (isinstance(value, (bool, np.bool_)) or not isinstance(value, Real)
            or not math.isfinite(value) or value < 0 or int(value) != value):
        _invalid(f'{name}: nonnegative integer required')
    return int(value)


def _optional(value, name: str) -> float | None:
    if pd.isna(value):
        return None
    if not isinstance(value, Real) or isinstance(value, (bool, np.bool_)) or not math.isfinite(value):
        _invalid(f'{name}: finite number or NaN required')
    return float(value)


def _same_rate(actual, expected, name: str):
    actual = _optional(actual, name)
    if ((expected is None and actual is not None)
            or (expected is not None and (actual is None or not math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-12)))):
        _invalid(f'{name}: rate mismatch')


def load_notes(path: Path | None, dataset_id: str, run_name: str) -> dict:
    """Read only the explicitly selected experiment's notes; never infer labels."""
    if path is None:
        return {}
    try:
        record = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(record, dict) or record.get('schema_version') != 1:
            raise ValueError('schema_version must be 1')
        scopes = record['notes']
        if not isinstance(scopes, dict):
            raise ValueError('notes must be an object')
        dataset = scopes.get(dataset_id, {})
        if not isinstance(dataset, dict):
            raise ValueError('dataset scope must be an object')
        selected = dataset.get(run_name, {})
        if not isinstance(selected, dict):
            raise ValueError('run scope must be an object')
        notes = {}
        for prefix, fields in selected.items():
            if not isinstance(fields, dict) or set(fields) - set(NOTE_FIELDS):
                raise ValueError(f'{prefix}: use observation/interpretation/next_check')
            if any(not isinstance(value, str) for value in fields.values()):
                raise ValueError(f'{prefix}: note fields must be strings')
            notes[prefix] = {key: fields.get(key, '') for key in NOTE_FIELDS}
        return notes
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f'メモJSON (notes) を読めません: {path}: {exc}') from exc


def build_dashboard_data(result: FlowLengthResult, notes: dict | None = None) -> dict:
    """Validate and serialize existing results, without deriving distributions."""
    edges = result.bin_edges
    if (len(edges) < 4 or any(isinstance(v, bool) or not isinstance(v, Integral) for v in edges)
            or list(edges[:4]) != [1, 2, 3, 4] or any(a >= b for a, b in zip(edges, edges[1:]))):
        _invalid('invalid bin_edges')
    prefixes = result.inspection.selected_prefixes
    targets = [*prefixes, *REFERENCES]
    if not prefixes or len(targets) != len(set(targets)):
        _invalid('missing or duplicate selected prefixes')
    summary, histogram = result.summary, result.histogram
    if not {'prefix', 'group', *STAT_FIELDS}.issubset(summary.columns):
        _invalid('missing summary columns')
    if not {'prefix', 'group', 'lower', 'upper', 'flow_count', 'proportion'}.issubset(histogram.columns):
        _invalid('missing histogram columns')
    if (len(summary) != len(targets)*3 or len(histogram) != len(targets)*3*(len(edges)-1)
            or set(summary.prefix) != set(targets) or set(histogram.prefix) != set(targets)
            or set(summary.group) != set(GROUPS) or set(histogram.group) != set(GROUPS)
            or summary.duplicated(['prefix', 'group']).any()
            or histogram.duplicated(['prefix', 'group', 'lower']).any()):
        _invalid('missing/duplicate target, group or bin')
    cards = []
    expected_bins = list(zip(edges[:-1], edges[1:]))
    for prefix in targets:
        stats, counts = {}, {}
        for group in GROUPS:
            row = summary.loc[summary.prefix.eq(prefix) & summary.group.eq(group)]
            bins = histogram.loc[histogram.prefix.eq(prefix) & histogram.group.eq(group)].sort_values('lower')
            if len(row) != 1 or len(bins) != len(expected_bins):
                _invalid(f'{prefix}/{group}: missing group/bin')
            boundaries = [(_count(r.lower, 'lower'), _count(r.upper, 'upper')) for r in bins.itertuples()]
            if boundaries != expected_bins:
                _invalid(f'{prefix}/{group}: bin boundary mismatch')
            row = row.iloc[0]
            n = _count(row.flow_count, 'summary.flow_count')
            values = [_count(v, 'histogram.flow_count') for v in bins.flow_count]
            if sum(values) != n:
                _invalid(f'{prefix}/{group}: histogram/summary count mismatch')
            for value, proportion in zip(values, bins.proportion):
                _same_rate(proportion, value/n if n else None, 'histogram.proportion')
            _same_rate(row.one_packet_rate, values[0]/n if n else None, 'one_packet_rate')
            stats[group] = {key: _optional(row[key], key) for key in STAT_FIELDS if key != 'flow_count'}
            stats[group]['flow_count'] = n
            for key in ('median', 'p95'):
                value = stats[group][key]
                if value is not None and (value < 1 or value >= edges[-1] or n == 0):
                    _invalid(f'{prefix}/{group}: invalid {key}')
            median, p95 = stats[group]['median'], stats[group]['p95']
            if median is not None and p95 is not None and median > p95:
                _invalid(f'{prefix}/{group}: median > p95')
            counts[group] = values
        raw, removed, retained = (stats[g]['flow_count'] for g in GROUPS)
        if raw != removed + retained or any(a != b+c for a, b, c in zip(*(counts[g] for g in GROUPS))):
            _invalid(f'{prefix}: Raw != removed + retained')
        for group in GROUPS:
            _same_rate(stats[group]['removal_rate'], removed/raw if raw else None, 'removed / Raw')
        cards.append({'prefix': prefix, 'stats': stats, 'counts': counts,
                      'notes': {key: (notes or {}).get(prefix, {}).get(key, '') for key in NOTE_FIELDS}})
    manifest = result.inspection.manifest
    return {'schema_version': 1, 'dataset_id': manifest['dataset_id'],
            'run_name': result.inspection.manifest_path.parent.name,
            'evidence': manifest.get('evidence_level', 'saved_artifact_analysis'),
            'config_sha256': manifest['config']['hash'],
            'source_git_commit': manifest.get('git_commit'),
            'bin_edges': [int(v) for v in edges],
            'bin_labels': [str(a) if b == a+1 else f'{a}–{b-1}' for a, b in expected_bins],
            'prefixes': cards[:-2], 'references': cards[-2:]}


def _comparison(target: dict, labels: list[str], synthetic: bool) -> Figure:
    fig = Figure(figsize=(17, 5), layout='constrained')
    left, right = fig.subplots(1, 2)
    x = np.arange(len(labels))
    for index, group in enumerate(GROUPS):
        values = np.asarray(target['counts'][group])
        n = target['stats'][group]['flow_count']
        legend = f'{group} (n={n:,})'
        left.bar(x+(index-1)*.26, values, width=.25, color=COLORS[group], label=legend)
        right.bar(x+(index-1)*.26, values/n*100 if n else np.zeros(len(x)),
                  width=.25, color=COLORS[group], label=legend)
    left.set_yscale('symlog', linthresh=1)
    left.set_ylim(0, max(1, left.get_ylim()[1]))
    left.set_ylabel('Flow count (symlog, linthresh=1)')
    right.set_ylim(0, 100)
    right.set_ylabel('Flows within each full group (%)')
    for ax in (left, right):
        ax.set_xticks(x, labels, rotation=55, ha='right', fontsize=8)
        ax.set_xlabel('Packets per flow — common integer intervals')
        ax.grid(axis='y', alpha=.2)
        ax.set_axisbelow(True)
        ax.legend(fontsize=8, loc='upper right')
    rate = target['stats']['Raw']['removal_rate']
    rate_text = 'NA' if rate is None else f'{rate:.2%}'
    fig.suptitle(f'{target["prefix"]} | removed / Raw = {rate_text}'
                 + (' | SYNTHETIC DEMO' if synthetic else ''), fontsize=13)
    return fig


def render_comparison(result: FlowLengthResult, target: str) -> Figure:
    """Create the notebook-style count/proportion figure for one existing target."""
    data = build_dashboard_data(result)
    selected = next((item for item in data['prefixes']+data['references'] if item['prefix'] == target), None)
    if selected is None:
        raise ValueError(f'未知の対象です: {target}')
    return _comparison(selected, data['bin_labels'], data['evidence'] == 'synthetic_demo')


def _image(fig: Figure) -> str:
    stream = BytesIO()
    try:
        FigureCanvasAgg(fig).print_png(stream)
        return 'data:image/png;base64,' + base64.b64encode(stream.getvalue()).decode('ascii')
    finally:
        fig.clear()


def _thumbnail(target: dict, group: str, labels: list[str]) -> str:
    fig = Figure(figsize=(3.7, 1.65), layout='constrained')
    axis = fig.subplots()
    axis.bar(np.arange(len(labels)), target['counts'][group], width=.85, color=COLORS[group])
    axis.set_yscale('symlog', linthresh=1)
    axis.set_ylim(0, max(1, axis.get_ylim()[1]))
    indices = sorted(set([0, 1, 2, len(labels)-1]))
    axis.set_xticks(indices, [labels[i] for i in indices], fontsize=7)
    axis.tick_params(axis='y', labelsize=7)
    axis.grid(axis='y', alpha=.15)
    axis.set_axisbelow(True)
    return _image(fig)


def export_dashboard(root: Path, dataset_id: str, run_name: str, cache_dir: Path,
                     output: Path, *, notes: Path | None = None) -> Path:
    """Export once from a matching cache; never create, modify or repair a cache."""
    output, cache_dir = Path(output).expanduser().resolve(), Path(cache_dir).expanduser().resolve()
    if output.suffix.lower() != '.html':
        raise ValueError('出力先は新しい .html ファイルを指定してください')
    if output.is_relative_to(cache_dir):
        raise ValueError('cache / キャッシュ内には出力できません')
    if output.exists():
        raise FileExistsError(f'既存ファイルは上書きしません: {output}')
    result = load_cached_run(Path(root), dataset_id, run_name, cache_dir)
    if output.is_relative_to(result.exact_counts_path.parent.resolve()):
        raise ValueError('cache / キャッシュ実体内には出力できません')
    protected = [*result.inspection.paths.values(), result.inspection.manifest_path,
                 result.exact_counts_path, notes]
    if any(p is not None and Path(p).resolve() == output for p in protected):
        raise ValueError('入力成果物は上書きできません')
    data = build_dashboard_data(result, load_notes(notes, dataset_id, run_name))
    data['run_manifest_sha256'] = sha256_file(result.inspection.manifest_path)
    for target in data['prefixes']+data['references']:
        target['thumbnail'] = {g: _thumbnail(target, g, data['bin_labels']) for g in GROUPS}
        target['detail_image'] = _image(_comparison(target, data['bin_labels'], data['evidence'] == 'synthetic_demo'))
    # Script-data escaping is distinct from HTML text escaping: a literal
    # </script> must never terminate the application/json element.
    encoded = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    for char, escaped in [('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                          ('\u2028', '\\u2028'), ('\u2029', '\\u2029')]:
        encoded = encoded.replace(char, escaped)
    template = Path(__file__).with_name('prefix_dashboard.html').read_text(encoding='utf-8')
    # CSP hashes the exact UTF-8 script text, including its boundary newlines.
    scripts = re.findall(r'<script>(.*?)</script>', template, re.S)
    if len(scripts) != 1 or template.count('__DASHBOARD_SCRIPT_HASH__') != 1:
        raise ValueError('Dashboard template must contain one application script and CSP hash slot')
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode('utf-8')).digest()).decode('ascii')
    html = template.replace('__DASHBOARD_SCRIPT_HASH__', digest).replace('__DASHBOARD_DATA__', encoded)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        stream.write(html)
    return output
