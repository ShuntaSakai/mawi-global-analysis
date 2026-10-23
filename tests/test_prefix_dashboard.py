"""Offline dashboard contracts, using explicitly synthetic saved-run artifacts."""
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from mawi_global_analysis import flow_length as fl
from mawi_global_analysis.hashing import sha256_file


def dashboard():
    try:
        return importlib.import_module('mawi_global_analysis.prefix_dashboard')
    except ModuleNotFoundError:
        pytest.fail('offline prefix dashboard is not implemented')


@pytest.fixture(scope='module')
def saved(tmp_path_factory):
    root = tmp_path_factory.mktemp('dashboard-source')
    dataset, run = fl.make_demo_run(root)
    cache = root / 'exact-cache'
    result = fl.analyze_run(root, dataset, run, chunksize=2, exact_cache_dir=cache)
    return root, dataset, run, cache, result


def payload(html):
    match = re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>', html, re.S)
    assert match, 'offline document must carry its own data'
    return json.loads(match.group(1))


def test_export_reads_cache_without_reaggregation_or_mutating_inputs(saved, tmp_path, monkeypatch):
    root, dataset, run, cache, result = saved
    before = {p: sha256_file(p) for p in root.rglob('*') if p.is_file()}
    monkeypatch.setattr(fl, 'analyze_run', lambda *a, **k: pytest.fail('export must never aggregate'))
    monkeypatch.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('export must never ingest'))
    out = dashboard().export_dashboard(root, dataset, run, cache, tmp_path / 'report.html')
    html = out.read_text()
    data = payload(html)
    assert data['dataset_id'] == dataset and data['run_name'] == run
    assert data['evidence'] == 'synthetic_demo'
    assert [t['prefix'] for t in data['prefixes']] == result.inspection.selected_prefixes
    assert [t['prefix'] for t in data['references']] == ['selected_union', 'overall_ipv4']
    target = next(t for t in data['prefixes'] if t['prefix'] == '192.0.2.0/24')
    assert target['stats']['Raw']['flow_count'] == 5
    assert target['stats']['removed']['flow_count'] == 2
    assert target['stats']['retained']['flow_count'] == 3
    assert target['stats']['Raw']['removal_rate'] == pytest.approx(0.4)
    assert all(t['detail_image'].startswith('data:image/png;base64,') for t in data['prefixes'] + data['references'])
    assert all(t['thumbnail'][g].startswith('data:image/png;base64,') for t in data['prefixes'] for g in fl.GROUPS)
    assert not re.search(r'<(?:script|link|img)[^>]+(?:src|href)=["\'](?:https?:|//)', html)
    assert "connect-src 'none'" in html
    assert before == {p: sha256_file(p) for p in root.rglob('*') if p.is_file()}


def test_empty_groups_nan_statistics_and_union_are_preserved(saved):
    result = saved[-1]
    data = dashboard().build_dashboard_data(result)
    empty = next(t for t in data['prefixes'] if t['prefix'] == '203.0.113.7/32')
    assert empty['stats']['Raw']['flow_count'] == 0
    assert empty['stats']['Raw']['median'] is None
    assert empty['stats']['Raw']['removal_rate'] is None
    union = data['references'][0]
    assert union['stats']['Raw']['flow_count'] == 7
    assert sum(t['stats']['Raw']['flow_count'] for t in data['prefixes']) == 8
    json.dumps(data, allow_nan=False)


def test_all_selected_prefixes_above_thirty_are_included(saved):
    from dataclasses import replace
    original = saved[-1]
    targets = [f'198.19.{i}.0/24' for i in range(35)]
    summary = [original.summary.loc[original.summary.prefix.isin(['selected_union', 'overall_ipv4'])]]
    hist = [original.histogram.loc[original.histogram.prefix.isin(['selected_union', 'overall_ipv4'])]]
    for target in targets:
        summary.append(original.summary.loc[original.summary.prefix.eq('192.0.2.0/24')].assign(prefix=target))
        hist.append(original.histogram.loc[original.histogram.prefix.eq('192.0.2.0/24')].assign(prefix=target))
    result = replace(original, inspection=replace(original.inspection, selected_prefixes=targets),
                     summary=pd.concat(summary), histogram=pd.concat(hist))
    assert [t['prefix'] for t in dashboard().build_dashboard_data(result)['prefixes']] == targets


@pytest.mark.parametrize('mutation', ['bin_count', 'summary_count', 'bin_edge', 'proportion', 'removal_rate', 'duplicate_bin', 'missing_group', 'negative_count'])
def test_inconsistent_cached_tables_are_rejected(saved, mutation):
    from dataclasses import replace
    original = saved[-1]
    result = replace(original, summary=original.summary.copy(), histogram=original.histogram.copy())
    if mutation == 'bin_count': result.histogram.loc[0, 'flow_count'] += 1
    elif mutation == 'summary_count': result.summary.loc[0, 'flow_count'] += 1
    elif mutation == 'bin_edge': result.histogram.loc[0, 'upper'] += 1
    elif mutation == 'proportion': result.histogram.loc[0, 'proportion'] = 0.777
    elif mutation == 'removal_rate': result.summary.loc[0, 'removal_rate'] = 0.777
    elif mutation == 'duplicate_bin': result.histogram = pd.concat([result.histogram, result.histogram.iloc[[0]]])
    elif mutation == 'missing_group': result.summary = result.summary.iloc[1:]
    elif mutation == 'negative_count': result.histogram.loc[0, 'flow_count'] = -1
    with pytest.raises(ValueError, match='整合|invalid|mismatch|duplicate|missing'):
        dashboard().build_dashboard_data(result)


def test_each_target_plot_uses_existing_bin_values_and_required_axes(saved):
    result = saved[-1]
    for prefix in [*result.inspection.selected_prefixes, 'selected_union', 'overall_ipv4']:
        fig = dashboard().render_comparison(result, prefix)
        assert len(fig.axes) == 2
        left, right = fig.axes
        assert left.get_yscale() == 'symlog'
        assert left.yaxis.get_transform().linthresh == 1
        assert right.get_yscale() == 'linear' and right.get_ylim() == (0, 100)
        assert len(left.containers) == len(right.containers) == 3
        for index, group in enumerate(fl.GROUPS):
            rows = result.histogram.loc[result.histogram.prefix.eq(prefix) & result.histogram.group.eq(group)]
            assert [bar.get_height() for bar in left.containers[index]] == rows.flow_count.tolist()
            np.testing.assert_allclose([bar.get_height() for bar in right.containers[index]],
                                       rows.proportion.fillna(0).to_numpy() * 100)
        assert prefix in fig._suptitle.get_text()


def test_scoped_notes_are_optional_and_script_safe(saved, tmp_path):
    root, dataset, run, cache, _ = saved
    evil = '</script><img src=x onerror=alert(1)> & 日本語'
    notes = tmp_path / 'notes.json'
    notes.write_text(json.dumps({'schema_version': 1, 'notes': {
        dataset: {run: {'192.0.2.0/24': {'observation': evil, 'interpretation': '', 'next_check': '確認'}},
                  'other-run': {'192.0.2.0/24': {'observation': 'WRONG EXPERIMENT'}}},
        'other-dataset': {run: {'192.0.2.0/24': {'observation': 'WRONG DATASET'}}}
    }}))
    html = dashboard().export_dashboard(root, dataset, run, cache, tmp_path/'notes.html', notes=notes).read_text()
    data = payload(html)
    assert data['prefixes'][0]['notes']['observation'] == evil
    assert data['prefixes'][1]['notes']['observation'] == ''
    assert evil not in html and 'WRONG EXPERIMENT' not in html and 'WRONG DATASET' not in html
    assert '\\u003c/script' in html
    loaded = dashboard().load_notes(notes, 'missing-dataset', run)
    assert loaded == {}


@pytest.mark.parametrize('content', ['[]', '{"schema_version":1,"notes":[]}', '{"schema_version":1,"notes":{"d":{"r":{"p":{"observation":3}}}}}'])
def test_malformed_notes_stop_with_diagnostic(tmp_path, content):
    notes = tmp_path/'bad.json'; notes.write_text(content)
    with pytest.raises(ValueError, match='メモ|notes'):
        dashboard().load_notes(notes, 'd', 'r')


def test_missing_stale_or_corrupt_cache_never_falls_back(tmp_path, monkeypatch):
    root = tmp_path/'source'; dataset, run = fl.make_demo_run(root)
    monkeypatch.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('must never ingest'))
    out = tmp_path/'missing.html'
    with pytest.raises(ValueError, match='cache|キャッシュ'):
        dashboard().export_dashboard(root, dataset, run, root/'missing-cache', out)
    assert not out.exists() and not (root/'missing-cache').exists()


def test_corrupt_cache_and_existing_output_are_not_modified(saved, tmp_path):
    root, dataset, run, cache, _ = saved
    out = tmp_path/'existing.html'; out.write_text('keep')
    with pytest.raises(FileExistsError):
        dashboard().export_dashboard(root, dataset, run, cache, out)
    assert out.read_text() == 'keep'
    with pytest.raises(ValueError, match='cache|キャッシュ'):
        dashboard().export_dashboard(root, dataset, run, cache, cache/'forbidden.html')
    assert not (cache/'forbidden.html').exists()


def test_cli_exports_and_reports_missing_cache(saved, tmp_path):
    root, dataset, run, cache, _ = saved
    script = Path(__file__).parents[1]/'scripts/export_prefix_dashboard.py'
    out = tmp_path/'cli.html'
    args = [sys.executable, str(script), '--root', str(root), '--dataset', dataset,
            '--run', run, '--cache-dir', str(cache), '--output', str(out)]
    success = subprocess.run(args, capture_output=True, text=True)
    assert success.returncode == 0, success.stderr
    assert out.is_file() and 'SYNTHETIC DEMO' in out.read_text()
    args[args.index('--cache-dir') + 1] = str(tmp_path/'absent')
    args[-1] = str(tmp_path/'absent.html')
    failure = subprocess.run(args, capture_output=True, text=True)
    assert failure.returncode != 0 and 'cache' in failure.stderr
    assert not (tmp_path/'absent.html').exists()


def test_balanced_bin_corruption_still_breaks_raw_partition(saved):
    from dataclasses import replace
    original = saved[-1]
    result = replace(original, summary=original.summary.copy(), histogram=original.histogram.copy())
    bins = result.histogram.index[result.histogram.prefix.eq('192.0.2.0/24') & result.histogram.group.eq('Raw')]
    result.histogram.loc[bins[0], 'flow_count'] += 1
    result.histogram.loc[bins[1], 'flow_count'] -= 1
    result.histogram.loc[bins, 'proportion'] = result.histogram.loc[bins, 'flow_count'] / 5
    result.summary.loc[result.summary.prefix.eq('192.0.2.0/24') & result.summary.group.eq('Raw'), 'one_packet_rate'] = .4
    with pytest.raises(ValueError, match='Raw != removed'):
        dashboard().build_dashboard_data(result)


def test_corrupt_cache_stops_without_output_or_repair(saved, tmp_path, monkeypatch):
    import shutil
    root, dataset, run, cache, result = saved
    copied = tmp_path/'cache'; shutil.copytree(cache, copied)
    exact = copied/result.exact_counts_path.parent.name/'exact_counts.sqlite'
    with exact.open('ab') as stream: stream.write(b'corruption')
    before = {p: sha256_file(p) for p in copied.rglob('*') if p.is_file()}
    monkeypatch.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('must never repair'))
    out = tmp_path/'corrupt.html'
    with pytest.raises(ValueError, match='checksum|破損'):
        dashboard().export_dashboard(root, dataset, run, copied, out)
    assert not out.exists()
    assert before == {p: sha256_file(p) for p in copied.rglob('*') if p.is_file()}


def test_changed_source_stops_without_reaggregation(tmp_path, monkeypatch):
    import os
    root=tmp_path/'source'; dataset, run=fl.make_demo_run(root)
    result=fl.analyze_run(root,dataset,run,exact_cache_dir=root/'cache')
    source=result.inspection.paths['flows']; stat=source.stat()
    os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns+1000000))
    monkeypatch.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('must never reaggregate'))
    with pytest.raises(ValueError, match='cache'):
        dashboard().export_dashboard(root,dataset,run,root/'cache',tmp_path/'stale.html')
    assert not (tmp_path/'stale.html').exists()


def test_output_cannot_write_into_a_symlinked_cache_folder(saved, tmp_path):
    import shutil
    root, dataset, run, cache, result = saved
    base = tmp_path/'cache'; base.mkdir()
    actual = tmp_path/'actual-counts'
    shutil.copytree(result.exact_counts_path.parent, actual)
    (base/result.exact_counts_path.parent.name).symlink_to(actual, target_is_directory=True)
    out = base/result.exact_counts_path.parent.name/'new.html'
    with pytest.raises(ValueError, match='cache|キャッシュ'):
        dashboard().export_dashboard(root, dataset, run, base, out)
    assert not (actual/'new.html').exists()


def test_impossible_quantile_order_is_rejected(saved):
    from dataclasses import replace
    original = saved[-1]
    result = replace(original, summary=original.summary.copy())
    result.summary.loc[0, 'p95'] = 1
    with pytest.raises(ValueError, match='median.*p95'):
        dashboard().build_dashboard_data(result)


def test_optional_nan_quantiles_remain_undefined(saved):
    from dataclasses import replace
    original = saved[-1]
    result = replace(original, summary=original.summary.copy())
    result.summary.loc[0, ['median', 'p95']] = np.nan
    target = dashboard().build_dashboard_data(result)['prefixes'][0]
    assert target['stats']['Raw']['median'] is None
    assert target['stats']['Raw']['p95'] is None
