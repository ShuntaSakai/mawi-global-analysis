"""Four saved selections evaluated against the same exact native populations."""
import csv
import json
import re
from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.aguri_selection_comparison import generate, validate_inputs, verify_manifest
from mawi_global_analysis.aguri_selection_comparison.cli import main
from mawi_global_analysis.aguri_two_stage import run_two_stage
from mawi_global_analysis.aguri_two_stage.comparison import generate_comparison
from mawi_global_analysis.hashing import sha256_file
from test_aguri_selection_comparison import api, fixture_root, save, state
from test_aguri_selection_two_stage_c import two_build


RUNS = {'run_c_packet': 'two-packet', 'run_c_flow': 'two-flow'}
KEYS = ('A', 'B', 'C-packet', 'C-flow')
FLAGS = ('--run-c-packet', 'two-packet', '--run-c-flow', 'two-flow')


def rows(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope='module')
def four(tmp_path_factory, two_build):
    root = tmp_path_factory.mktemp('four') / 'inputs'
    extra = [('192.0.2.1', f'198.19.{i}.1', 1, 100) for i in range(220)]
    extra.append(('198.18.0.1', '198.18.1.1', 50_000, 5_000_000))
    fixture_root(root, extra_flows=extra)
    flows = root / 'data/fixture/processed/flows/flows.csv'
    for mode in ('packet', 'flow', 'byte'):
        run_two_stage(root, 'fixture', 'two-' + mode, flows, two_build, mode=mode)
    return root


@pytest.mark.parametrize(('args', 'message'), [
    (('--run-c-packet', 'two-packet'), '指定'),
    (('--run-c-flow', 'two-flow'), '指定'),
    ((*FLAGS, '--run-c', 'two-packet'), '併用'),
    (('--run-c-packet', 'two-flow', '--run-c-flow', 'two-packet'), 'C-packet.*basis'),
    (('--run-c-packet', 'two-packet', '--run-c-flow', 'two-packet'), 'C-flow.*basis'),
    (('--run-c-packet', 'two-packet', '--run-c-flow', 'absent'), 'C-flow.*absent'),
])
def test_cli_rejects_invalid_four_run_arguments(four, args, message, capsys):
    with pytest.raises(SystemExit) as exc:
        main(['--root', str(four), '--dataset', 'fixture', '--validate-only', *args])
    assert exc.value.code == 2
    assert re.search(message, capsys.readouterr().err)


def test_validate_only_and_generate_cli(four, tmp_path, capsys):
    args = ['--root', str(four), '--dataset', 'fixture', '--json']
    before = state(four)
    assert main([*args, *FLAGS, '--validate-only']) == 0
    validation = json.loads(capsys.readouterr().out)
    assert validation['schema_version'] == 'aguri-selection-validation-v2'
    assert tuple(validation['runs']) == KEYS
    assert main([*args, '--validate-only']) == 0
    assert json.loads(capsys.readouterr().out)['schema_version'] == 'aguri-selection-validation-v1'
    assert main([*args, *FLAGS, '--output-dir', str(tmp_path / 'v2')]) == 0
    result = json.loads(capsys.readouterr().out)
    assert Path(result['dashboard']) == Path(result['manifest']).with_name('dashboard.html')
    assert Path(result['prefix_dashboard']) == Path(result['manifest']).with_name('prefix_dashboard.html')
    assert verify_manifest(Path(result['manifest']))['schema_version'] == 'aguri-selection-comparison-v2'
    assert state(four) == before


def test_validate_only_uses_explicit_scratch(four, tmp_path, monkeypatch):
    from mawi_global_analysis.rls_weight_comparison import native_analysis

    original = native_analysis._ingest
    seen = []

    def check_scratch(db, infos, chunksize):
        path = Path(db.execute('PRAGMA database_list').fetchone()[2])
        seen.append(path.is_relative_to(tmp_path.resolve()))
        return original(db, infos, chunksize)

    monkeypatch.setattr(native_analysis, '_ingest', check_scratch)
    args = ['--root', str(four), '--dataset', 'fixture', *FLAGS, '--validate-only']
    assert main([*args, '--scratch-dir', str(tmp_path)]) == 0
    assert seen == [True]
    assert not list(tmp_path.iterdir())
    with pytest.raises(ValueError, match='protected'):
        validate_inputs(four, 'fixture', **RUNS, scratch_dir=four / 'data')


def test_exact_v2_matches_v1_and_two_stage(four, tmp_path):
    old = generate(four, 'fixture', tmp_path / 'v1', run_c='two-packet').parent
    v2 = generate(four, 'fixture', tmp_path / 'v2', **RUNS, max_ecdf_points=2).parent
    two = generate_comparison(four, 'fixture', packet_run='two-packet', byte_run='two-byte',
                              flow_run='two-flow', output_dir=tmp_path / 'two').parent
    manifest = verify_manifest(v2 / 'comparison_manifest.json')
    assert verify_manifest(old / 'comparison_manifest.json')['schema_version'] == 'aguri-selection-comparison-v1'
    assert (old / 'dashboard.html').is_file()
    html = v2 / 'dashboard.html'
    assert manifest['bundle_kind'] == 'dashboard'
    assert manifest['artifacts']['dashboard.html']['sha256'] == sha256_file(html)
    assert 'id="tab-contribution"' not in html.read_text()
    assert manifest['schema_version'] == 'aguri-selection-comparison-v2'
    assert manifest['selection_conditions']['C-flow']['details']['basis'] == 'flow'
    old_summary = json.loads((old / 'summary.json').read_text())
    summary = json.loads((v2 / 'summary.json').read_text())
    assert summary['schema_version'] == 'aguri-selection-analysis-v2'
    assert summary['overall'] == old_summary['overall']
    assert summary['components'] == old_summary['components']
    for key in ('A', 'B'):
        assert summary['conditions'][key] == old_summary['conditions'][key]
        assert (v2 / 'modes' / key / 'frequencies.csv').read_bytes() == (old / 'modes' / key / 'frequencies.csv').read_bytes()

    def exact(path, key):
        columns = ('packet_count', 'frequency', 'cumulative_count', 'total_flow_count')
        return [tuple(int(r[c]) for c in columns) for r in rows(path) if r['distribution'] == key]

    for key in ('A', 'B', 'overall_ipv4'):
        assert exact(v2 / 'ecdf_counts.csv', key) == exact(old / 'ecdf_counts.csv', key)
    assert exact(v2 / 'ecdf_counts.csv', 'C-packet') == exact(old / 'ecdf_counts.csv', 'C')
    for basis in ('packet', 'flow'):
        assert exact(v2 / 'ecdf_counts.csv', 'C-' + basis) == exact(two / 'native_ecdf_counts.csv', basis)

    selected = {key: {r['prefix'] for r in summary['prefixes'] if key in r['conditions']} for key in KEYS}
    assert selected['C-packet'] != selected['C-flow']
    assert selected['A'] & selected['B']
    per_condition = {}
    flows = pd.read_csv(four / 'data/fixture/processed/flows/flows.csv').set_index('flow_id')
    for key in KEYS:
        run = manifest['selection_conditions'][key]['run_name']
        membership = pd.read_csv(four / 'results/fixture' / run / 'flow_prefix_membership.csv')
        ids = membership.loc[membership.analysis_scope == 'native', 'flow_id'].unique()
        expected = flows.loc[ids, 'packet_count'].value_counts().sort_index()
        curve = exact(v2 / 'ecdf_counts.csv', key)
        assert [(x, n) for x, n, _, _ in curve] == list(expected.items())
        running = 0
        for _, frequency, cumulative, total in curve:
            running += frequency
            assert frequency > 0 and cumulative == running and total == len(ids)
        per_condition[key] = rows(v2 / 'modes' / key / 'frequencies.csv')
    for prefix in selected['A'] & selected['B']:
        assert [r for r in per_condition['A'] if r['distribution'] == prefix] == [
            r for r in per_condition['B'] if r['distribution'] == prefix]
    assert len(summary['jaccard']) == 18
    assert {r['condition_b'] for r in summary['pairwise_prefixes'] if r['condition_a'] == 'B'} == {'C-packet', 'C-flow'}
    individual = json.loads((v2 / 'prefix_ecdf.json').read_text())
    assert individual['dataset_id'] == 'fixture'
    prefix_html = v2 / 'prefix_dashboard.html'
    assert manifest['artifacts']['prefix_dashboard.html']['sha256'] == sha256_file(prefix_html)
    assert not (old / 'prefix_dashboard.html').exists()
    embedded = json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',
                                    prefix_html.read_text(), re.S)[1])
    for key in ('conditions', 'prefixes', 'curves'):
        assert embedded[key] == individual[key]
    assert 'prefix_ecdf.json' not in verify_manifest(old / 'comparison_manifest.json')['artifacts']
    assert set(individual['curves']) == set.union(*selected.values())
    for key in KEYS:
        assert set(individual['conditions'][key]['prefixes']) == selected[key]
        assert individual['conditions'][key]['run_name'] == manifest['selection_conditions'][key]['run_name']
        for cidr in selected[key]:
            curve = individual['curves'][cidr]
            freq = [r for r in per_condition[key] if r['distribution'] == cidr]
            assert len(freq) == curve['exact_point_count']
            assert sum(int(r['frequency']) for r in freq) == int(curve['total_flow_count'])
    assert set(summary['sensitivities']) == {'B', 'C-packet', 'C-flow'}
    assert {r['condition'] for r in summary['prefix_contribution']} == set(KEYS)


def test_invalid_lineage_and_membership(four):
    path = four / 'results/fixture/two-flow/run_manifest.json'
    original = path.read_bytes()
    manifest = json.loads(original)
    membership = Path(manifest['artifacts']['flow_prefix_membership']['path'])
    original_membership = membership.read_bytes()
    try:
        manifest['selection']['basis'] = 'packet'
        save(path, manifest)
        with pytest.raises(ValueError, match='C-flow.*schema'):
            validate_inputs(four, 'fixture', **RUNS)
        # Rehash a truncated membership so the relational check must catch it.
        manifest = json.loads(original)
        lines = original_membership.splitlines(keepends=True)
        membership.write_bytes(b''.join(lines[:-1]))
        entry = manifest['artifacts']['flow_prefix_membership']
        entry.update(sha256=sha256_file(membership), row_count=entry['row_count'] - 1)
        save(path, manifest)
        with pytest.raises(ValueError, match='C-flow.*membership incomplete'):
            validate_inputs(four, 'fixture', **RUNS)
    finally:
        path.write_bytes(original)
        membership.write_bytes(original_membership)


def test_mismatched_canonical_and_settings(two_build, tmp_path):
    # A separate analysis root keeps the module-scoped fixture immutable.
    root = fixture_root(tmp_path / 'inputs')
    flows = root / 'data/fixture/processed/flows/flows.csv'
    run_two_stage(root, 'fixture', 'two-packet', flows, two_build, mode='packet')
    run_two_stage(root, 'fixture', 'different-settings', flows, two_build,
                  mode='flow', max_hashentries=100)
    with pytest.raises(ValueError, match='lineage'):
        validate_inputs(root, 'fixture', run_c_packet='two-packet', run_c_flow='different-settings')
    alternate = tmp_path / 'alternate'
    alternate.mkdir()
    changed = pd.read_csv(flows)
    changed.loc[0, ['packet_count', 'packets_from_src']] += 1
    changed.to_csv(alternate / 'flows.csv', index=False)
    (alternate / 'flow_manifest.json').write_bytes(flows.with_name('flow_manifest.json').read_bytes())
    run_two_stage(root, 'fixture', 'different-canonical', alternate / 'flows.csv', two_build, mode='flow')
    with pytest.raises(ValueError, match='C-flow.*canonical'):
        validate_inputs(root, 'fixture', run_c_packet='two-packet', run_c_flow='different-canonical')


@pytest.mark.parametrize('fail', [False, True])
def test_four_publication_rejects_changed_input_and_processing_failure(four, tmp_path, monkeypatch, fail):
    g = api('generation')
    actual = g.analyze_inputs
    path = four / 'results/fixture/two-flow/run_manifest.json'
    original = path.read_bytes()

    def changed(*args, **kwargs):
        result = actual(*args, **kwargs)
        if fail:
            raise ValueError('simulated analysis failure')
        path.write_bytes(original + b'\n')
        return result

    monkeypatch.setattr(g, 'analyze_inputs', changed)
    output = tmp_path / 'failed'
    message = 'simulated analysis failure' if fail else 'input provenance changed'
    try:
        with pytest.raises(ValueError, match=message):
            generate(four, 'fixture', output, **RUNS)
        assert not output.exists()
    finally:
        path.write_bytes(original)


def test_empty_v2_and_manifest_binding(tmp_path, two_build):
    root = fixture_root(tmp_path / 'inputs', empty=True)
    flows = root / 'data/fixture/processed/flows/flows.csv'
    for basis in ('packet', 'flow'):
        run_two_stage(root, 'fixture', 'two-' + basis, flows, two_build, mode=basis)
    path = generate(root, 'fixture', tmp_path / 'bundle', **RUNS)
    manifest = verify_manifest(path)
    summary = json.loads((path.parent / 'summary.json').read_text())
    assert summary['prefixes'] == []
    assert rows(path.parent / 'ecdf_counts.csv') == []
    assert all(r['stats']['median'] is None and r['ks_distance'] is None
               and r['coverage']['flow'] is None for r in summary['conditions'].values())
    assert len(summary['jaccard']) == 18
    assert all(r['jaccard'] is None for r in summary['jaccard'])
    for key in ('validation', 'final_validation'):
        manifest[key]['runs']['C-flow']['run_name'] = 'swapped'
    save(path, manifest)
    with pytest.raises(ValueError, match='binding'):
        verify_manifest(path)


def test_v2_dashboard_tampering_and_legacy_data_bundle(four, tmp_path):
    path = generate(four, 'fixture', tmp_path / 'bundle', **RUNS)
    manifest = verify_manifest(path)
    html = path.with_name('dashboard.html')
    original = html.read_bytes()
    html.write_bytes(original + b'<!-- changed -->')
    with pytest.raises(ValueError, match='dashboard.html.*SHA-256'):
        verify_manifest(path)
    html.write_bytes(original)

    prefix_file = path.with_name('prefix_ecdf.json')
    original_prefix = prefix_file.read_bytes()
    prefix_file.write_bytes(original_prefix + b' ')
    with pytest.raises(ValueError, match='prefix_ecdf.json.*SHA-256'):
        verify_manifest(path)
    prefix_file.write_bytes(original_prefix)
    missing = json.loads(path.read_text())
    missing['artifacts'].pop('prefix_ecdf.json')
    save(path, missing)
    with pytest.raises(ValueError, match='artifacts missing'):
        verify_manifest(path)
    save(path, manifest)

    prefix_html = path.with_name('prefix_dashboard.html')
    original_html = prefix_html.read_bytes()
    prefix_html.write_bytes(original_html + b'<!-- tampered -->')
    with pytest.raises(ValueError, match='prefix_dashboard.html.*SHA-256'):
        verify_manifest(path)
    prefix_html.write_bytes(original_html)

    # Task 3A has a sidecar but no individual-prefix HTML.
    summary = path.with_name('summary.json')
    data = json.loads(summary.read_text())
    manifest.pop('prefix_dashboard')
    manifest['artifacts'].pop('prefix_dashboard.html')
    data.pop('prefix_dashboard')
    save(summary, data)
    manifest['artifacts']['summary.json']['sha256'] = sha256_file(summary)
    prefix_html.unlink()
    save(path, manifest)
    assert verify_manifest(path) == manifest

    # Task 2 had an HTML dashboard but no individual-prefix sidecar.
    manifest.pop('prefix_ecdf')
    manifest['artifacts'].pop('prefix_ecdf.json')
    data.pop('prefix_ecdf')
    save(summary, data)
    manifest['artifacts']['summary.json']['sha256'] = sha256_file(summary)
    prefix_file.unlink()
    save(path, manifest)
    assert verify_manifest(path) == manifest

    manifest.pop('bundle_kind')
    manifest['artifacts'].pop('dashboard.html')
    save(path, manifest)
    with pytest.raises(ValueError, match='bundle kind'):
        verify_manifest(path)

    # Task 1 v2 bundles had neither the HTML nor the bundle_kind marker.
    data.pop('bundle_kind')
    save(summary, data)
    html.unlink()
    manifest['artifacts']['summary.json']['sha256'] = sha256_file(summary)
    save(path, manifest)
    assert verify_manifest(path) == manifest


def test_v2_render_failure_does_not_publish(four, tmp_path, monkeypatch):
    def fail(_payload):
        raise ValueError('simulated HTML render failure')

    monkeypatch.setattr(api('dashboard'), 'render', fail)
    output = tmp_path / 'failed-render'
    with pytest.raises(ValueError, match='simulated HTML render failure'):
        generate(four, 'fixture', output, **RUNS)
    assert not output.exists()



def test_prefix_ecdf_failure_does_not_publish(four, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError('simulated prefix ECDF failure')

    monkeypatch.setattr(api('prefix_ecdf'), 'build_prefix_ecdf_payload', fail)
    output = tmp_path / 'failed-prefix-ecdf'
    with pytest.raises(ValueError, match='simulated prefix ECDF failure'):
        generate(four, 'fixture', output, **RUNS)
    assert not output.exists()


def test_prefix_dashboard_failure_does_not_publish(four, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError('simulated prefix dashboard render failure')

    monkeypatch.setattr(api('dashboard'), 'render_prefix', fail)
    output = tmp_path / 'failed-prefix-render'
    with pytest.raises(ValueError, match='simulated prefix dashboard render failure'):
        generate(four, 'fixture', output, **RUNS)
    assert not output.exists()
