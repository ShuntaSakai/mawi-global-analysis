"""Hand-counted distinct IPs, direction evidence, and immutable-cache upgrades."""
import json
from pathlib import Path
import shutil

import pandas as pd
import pytest

from mawi_global_analysis import flow_length as fl
from mawi_global_analysis import flow_length_cache as cache
from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from test_flow_length import A, B, EMPTY, saved_run


@pytest.fixture
def host_run(saved_run):
    path, flows = saved_run[2]['flows']
    flows = flows.copy()
    # f1 observes a return packet from canonical dst; f6 does not.
    flows['packets_from_src'] = [1, 1, 2, 4, 7, 8, 100, 2, 1]
    flows['packets_from_dst'] = [0, 1, 1, 0, 0, 0, 0, 0, 0]
    flows.to_csv(path, index=False)
    return saved_run


def measured(saved, **kwargs):
    return fl.analyze_run(saved[0], 'fixture', 'scan_source_driven_removal', chunksize=2, **kwargs)


def test_distinct_ips_are_prefix_internal_and_senders_use_both_packet_counters(host_run):
    result = measured(host_run)
    # Literal counts, independently enumerated from f0..f8; IPv6 is excluded.
    want = {
        A: [(4, 3), (2, 2), (3, 2)],
        B: [(4, 3), (2, 1), (2, 2)],
        EMPTY: [(0, 0), (0, 0), (0, 0)],
        'selected_union': [(8, 6), (4, 3), (5, 4)],
        'overall_ipv4': [(10, 7), (5, 4), (7, 5)],
    }
    rows = result.summary.set_index(['prefix', 'group'])
    for prefix, values in want.items():
        for group, (endpoints, senders) in zip(fl.GROUPS, values):
            row = rows.loc[prefix, group]
            assert row.unique_endpoint_ips == endpoints, (prefix, group)
            assert row.unique_sender_ips == senders, (prefix, group)


def test_same_ip_in_both_endpoints_counts_once(host_run):
    path, _ = host_run[2]['flows']
    rows = pd.read_csv(path)
    rows.loc[rows.flow_id.eq('f7'), ['dst_ip', 'packets_from_src', 'packets_from_dst']] = ['203.0.113.200', 1, 1]
    rows.to_csv(path, index=False)
    row = measured(host_run).summary.set_index(['prefix', 'group']).loc['overall_ipv4', 'Raw']
    assert row.unique_endpoint_ips == 9
    assert row.unique_sender_ips == 7


def test_network_and_broadcast_addresses_are_counted_when_observed(host_run):
    path, _ = host_run[2]['flows']
    rows = pd.read_csv(path)
    rows['src_ip'] = rows.src_ip.replace({'192.0.2.1': '192.0.2.0'})
    rows['dst_ip'] = rows.dst_ip.replace({'192.0.2.4': '192.0.2.255'})
    rows.to_csv(path, index=False)
    row = measured(host_run).summary.set_index(['prefix', 'group']).loc[A, 'Raw']
    assert (row.unique_endpoint_ips, row.unique_sender_ips) == (4, 3)


@pytest.mark.parametrize('column,value', [
    ('packets_from_src', '-1'), ('packets_from_dst', '1.5'),
    ('packets_from_dst', 'nan'), ('packets_from_src', str(2**63)),
    ('packets_from_dst', '1'),
])
def test_invalid_directional_counters_stop_before_cache_publication(host_run, tmp_path, column, value):
    path, _ = host_run[2]['flows']
    rows = pd.read_csv(path, dtype=str, keep_default_na=False)
    rows.loc[0, column] = value
    rows.to_csv(path, index=False)
    output = tmp_path/'host-cache'
    with pytest.raises(ValueError, match='packets_from|direction'):
        measured(host_run, exact_cache_dir=output)
    assert not list(output.glob('*/cache_manifest.json'))


def test_host_counts_survive_cache_hits_without_csv_ingestion(host_run, tmp_path, monkeypatch):
    first = measured(host_run, exact_cache_dir=tmp_path/'host-cache')
    record = json.loads((first.exact_counts_path.parent/'cache_manifest.json').read_text())
    assert record.get('host_count_definition')
    saved = pd.read_csv(first.exact_counts_path.parent/'flow_length_summary.csv')
    row = saved.set_index(['prefix', 'group']).loc[A, 'Raw']
    assert (row.unique_endpoint_ips, row.unique_sender_ips) == (4, 3)
    monkeypatch.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('cache reuse must not read flow CSV rows'))
    second = measured(host_run, exact_cache_dir=tmp_path/'host-cache')
    pd.testing.assert_frame_equal(second.summary, first.summary)
    assert second.host_count_definition == first.host_count_definition


def as_legacy(result, base):
    """Make a genuine v1-layout cache from test-owned files; no host columns."""
    info = result.inspection
    identity = {
        'schema': 'flow-length-exact-v1',
        'source_manifest': str(info.manifest_path.resolve()),
        'source_manifest_sha256': sha256_file(info.manifest_path),
        'flow_manifest': info.flow_manifest,
        'artifacts': {name: {'path': str(p.resolve()), 'size': p.stat().st_size,
                             'mtime_ns': p.stat().st_mtime_ns} for name, p in info.paths.items()},
    }
    old = Path(base)/stable_json_hash(identity)
    current = result.exact_counts_path.parent
    if old != current:
        shutil.move(current, old)
    summary = old/'flow_length_summary.csv'
    pd.read_csv(summary, float_precision='round_trip').drop(
        columns=['unique_endpoint_ips', 'unique_sender_ips'], errors='ignore').to_csv(summary, index=False)
    record = json.loads((old/'cache_manifest.json').read_text())
    record.update(schema='flow-length-exact-v1', source_identity=identity)
    record.pop('host_count_definition', None)
    record['sha256']['flow_length_summary.csv'] = sha256_file(summary)
    (old/'cache_manifest.json').write_text(json.dumps(record))
    return old


def test_legacy_cache_is_read_only_and_explicit_analysis_writes_a_new_cache(host_run, tmp_path, monkeypatch):
    base = tmp_path/'host-cache'
    old = as_legacy(measured(host_run, exact_cache_dir=base), base)
    before = {p.name: sha256_file(p) for p in old.iterdir()}
    with monkeypatch.context() as m:
        m.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('legacy read must not reaggregate'))
        legacy = cache.load_cached_run(host_run[0], 'fixture', 'scan_source_driven_removal', base)
    assert 'unique_endpoint_ips' not in legacy.summary.columns
    upgraded = measured(host_run, exact_cache_dir=base)
    assert upgraded.exact_counts_path.parent != old
    row = upgraded.summary.set_index(['prefix', 'group']).loc[A, 'Raw']
    assert row.unique_sender_ips == 3
    assert before == {p.name: sha256_file(p) for p in old.iterdir()}


def test_v2_cache_cannot_claim_metrics_with_missing_columns(host_run, tmp_path):
    result = measured(host_run, exact_cache_dir=tmp_path/'host-cache')
    folder = result.exact_counts_path.parent
    summary = folder/'flow_length_summary.csv'
    pd.read_csv(summary).drop(columns=['unique_sender_ips'], errors='ignore').to_csv(summary, index=False)
    manifest = folder/'cache_manifest.json'
    record = json.loads(manifest.read_text())
    record['sha256']['flow_length_summary.csv'] = sha256_file(summary)
    manifest.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='host|IP|unique_sender'):
        measured(host_run, exact_cache_dir=tmp_path/'host-cache')


def test_metric_definition_changes_cache_identity(host_run, monkeypatch):
    info = fl.inspect_run(host_run[0], 'fixture', 'scan_source_driven_removal')
    before = cache.source_identity(info)
    monkeypatch.setattr(cache, 'HOST_COUNT_DEFINITION', 'different-metric-definition')
    after = cache.source_identity(info)
    assert stable_json_hash(before) != stable_json_hash(after)


def test_legacy_export_keeps_missing_counts_unmeasured(host_run, tmp_path, monkeypatch):
    from mawi_global_analysis.prefix_dashboard import export_dashboard
    import re
    base = tmp_path/'cache'
    old = as_legacy(measured(host_run, exact_cache_dir=base), base)
    before = {p.name: sha256_file(p) for p in old.iterdir()}
    monkeypatch.setattr(fl, '_ingest', lambda *a, **k: pytest.fail('legacy export cannot ingest'))
    out = export_dashboard(host_run[0], 'fixture', 'scan_source_driven_removal', base, tmp_path/'legacy.html')
    data = json.loads(re.search(r'type="application/json">(.*?)</script>', out.read_text(), re.S).group(1))
    assert data['host_count_definition'] is None
    assert all('host_summary' not in t for t in data['prefixes']+data['references'])
    assert before == {p.name: sha256_file(p) for p in old.iterdir()}


def test_legacy_csv_can_fill_missing_counts_without_claiming_flow_reaggregation(host_run, tmp_path):
    import csv
    from mawi_global_analysis.prefix_dashboard import build_dashboard_data, attach_host_summary
    from dataclasses import replace
    original = measured(host_run)
    legacy = replace(original, summary=original.summary.drop(columns=['unique_endpoint_ips', 'unique_sender_ips']),
                     host_count_definition=None)
    data = build_dashboard_data(legacy)
    data['run_manifest_sha256'] = 'a'*64
    source = tmp_path/'legacy-host-summary.csv'
    fields = ['prefix', 'group', 'flow_count', 'unique_endpoint_ips', 'unique_sender_ips', 'run_manifest_sha256']
    with source.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
        for row in original.summary.itertuples(index=False):
            if row.prefix in original.inspection.selected_prefixes:
                writer.writerow({**{k: getattr(row, k) for k in fields[:-1]}, 'run_manifest_sha256': 'a'*64})
    attach_host_summary(data, source)
    assert data['prefixes'][0]['host_summary']['Raw']['unique_sender_ips'] == 3
    assert data['host_count_definition'] is None
    assert all('host_summary' not in t for t in data['references'])
