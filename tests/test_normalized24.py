"""Synthetic saved artifacts only: these tests do not validate real MAWI data."""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_stage import FLOW_COLUMNS, FLOW_SCHEMA_VERSION
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config, sha256_file
from mawi_global_analysis.membership import build_membership
from mawi_global_analysis.prefix import build_corrected_prefix_ledger

ROOT = Path(__file__).resolve().parents[1]
A, B, EMPTY = '192.0.2.0/24', '198.51.100.0/24', '198.18.0.0/24'


def analysis():
    try:
        return importlib.import_module('mawi_global_analysis.normalized24')
    except ModuleNotFoundError:
        pytest.fail('normalized /24 Raw aggregation is not implemented')


def dashboard():
    try:
        return importlib.import_module('mawi_global_analysis.normalized24.dashboard')
    except ModuleNotFoundError:
        pytest.fail('normalized /24 offline dashboard is not implemented')


@pytest.fixture
def saved(tmp_path):
    root = tmp_path/'source'
    run = root/'results/fixture/baseline'
    cache = root/'data/fixture/processed/flows/cache'
    run.mkdir(parents=True)
    cache.mkdir(parents=True)
    text = (ROOT/'configs/baseline.yaml').read_text()
    cfg = load_config(ROOT/'configs/baseline.yaml')
    # A has two native /26s; f1 is outside both, but inside the normalized /24.
    ledger = build_corrected_prefix_ledger(pd.DataFrame({
        'src_prefix': ['192.0.2.0/26','192.0.2.64/26','198.51.100.0/25','198.18.0.7/32'],
        'dst_prefix': ['*','*','*','203.0.112.0/23']}), cfg)
    endpoints = [('192.0.2.1','203.0.113.1'), ('203.0.113.1','192.0.2.200'),
                 ('192.0.2.2','198.51.100.2'), ('198.51.100.3','198.51.100.4'),
                 ('203.0.113.2','203.0.113.3'), ('2001:db8::1','2001:db8::2')]
    rows = []
    for i, ((src,dst), packets) in enumerate(zip(endpoints, [1,2,10,4,100,9])):
        row = dict.fromkeys(FLOW_COLUMNS, 0)
        row.update(flow_id=f'f{i}',ip_version=6 if ':' in src else 4,src_ip=src,dst_ip=dst,
                   packet_count=packets,packets_from_src=packets,packets_from_dst=0,protocol=6)
        rows.append(row)
    flows = pd.DataFrame(rows, columns=FLOW_COLUMNS)
    tables = {'flows': (cache/'flows.csv', flows), 'prefixes': (run/'prefixes.csv',ledger),
              'flow_prefix_membership': (run/'flow_prefix_membership.csv', build_membership(flows,ledger))}
    artifacts = {}
    for name,(path,frame) in tables.items():
        frame.to_csv(path,index=False)
        artifacts[name] = {'path': str(path.relative_to(root)), 'row_count':len(frame)}
    sha = 'a'*64
    fp = flow_fingerprint(sha,cfg,FLOW_SCHEMA_VERSION)
    fm = cache/'flow_manifest.json'
    fm.write_text(json.dumps(dict(input_sha256=sha,fingerprint=fp,row_count=len(flows),
        flow_config=flow_generation_config(cfg),schema_version=FLOW_SCHEMA_VERSION)))
    manifest = dict(status='success',dataset_id='fixture',evidence_level='synthetic_fixture',
        input={'sha256':sha},config={'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()},
        artifacts=artifacts,cache={'flows':{'fingerprint':fp,'manifest_path':str(fm.relative_to(root))}})
    mp = run/'run_manifest.json'
    mp.write_text(json.dumps(manifest))
    return root, mp, tables


def analyze(saved, **kwargs):
    return analysis().analyze_agurim_run(saved[0],'fixture','baseline',chunksize=kwargs.pop('chunksize',2),**kwargs)


def rewrite(saved, name, frame):
    path,_ = saved[2][name]
    frame.to_csv(path,index=False)
    mp = saved[1]
    manifest = json.loads(mp.read_text())
    manifest['artifacts'][name]['row_count'] = len(frame)
    mp.write_text(json.dumps(manifest))


def test_full_24_exact_statistics_union_and_zero_flow(saved):
    data = analyze(saved)
    assert [c['prefix'] for c in data['prefixes']] == [A,EMPTY,B]
    assert data['method'] == 'agurim' and data['group'] == 'Raw'
    targets = {c['prefix']: c for c in data['prefixes']+data['references']}
    assert targets[A]['native_prefixes'] == ['192.0.2.0/26','192.0.2.64/26']
    expected = {A:[1,2,10],B:[10,4],EMPTY:[], 'selected_union':[1,2,10,4],
                'overall_ipv4':[1,2,10,4,100]}
    for name,values in expected.items():
        target = targets[name]
        assert target['stats']['flow_count'] == len(values)
        for key,q in [('median',.5),('p95',.95)]:
            assert target['stats'][key] == (pytest.approx(np.quantile(values,q)) if values else None)
        assert target['stats']['one_packet_rate'] == (values.count(1)/len(values) if values else None)
        assert target['counts'] == np.histogram(values,bins=data['histogram_spec']['bin_edges'])[0].tolist()
    assert sum(t['stats']['flow_count'] for t in data['prefixes']) == 5
    assert targets['selected_union']['stats']['flow_count'] == 4
    assert data['audit']['normalized_membership_rows'] == 5
    assert data['provenance']['normalized_prefixes'] == [A,EMPTY,B]
    assert data['provenance']['selection']['additional_filters'] == []
    for name,(path,_) in saved[2].items():
        assert data['provenance']['inputs'][name]['sha256'] == sha256_file(path)
    assert data['provenance']['inputs']['run_manifest']['sha256'] == sha256_file(saved[1])
    assert data['provenance']['aggregation']['quantile'] == 'linear: (n-1)*q'
    json.dumps(data,allow_nan=False)


def test_chunk_invariance_and_shared_histogram_spec(saved, monkeypatch):
    original = pd.read_csv
    def bounded(path,*args,**kwargs):
        if str(path).endswith('.csv') and not kwargs.get('nrows') == 0:
            assert kwargs.get('chunksize'), 'CSV content must be streamed'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(pd,'read_csv',bounded)
    first = analyze(saved,chunksize=1)
    second = analyze(saved,chunksize=100,spec=analysis().HistogramSpec.from_dict(first['histogram_spec']))
    assert first == second


@pytest.mark.parametrize('corrupt', ['missing','all_missing','duplicate','unknown_id','wrong_prefix','wrong_flags','same_count_wrong_edge'])
def test_invalid_normalized_membership_stops_without_repair(saved,corrupt):
    frame = saved[2]['flow_prefix_membership'][1].copy()
    normalized = frame.index[frame.analysis_scope.eq('normalized_24')]
    i = normalized[0]
    if corrupt == 'missing': frame = frame.drop(i)
    elif corrupt == 'all_missing': frame = frame.loc[frame.analysis_scope.ne('normalized_24')]
    elif corrupt == 'duplicate': frame = pd.concat([frame,frame.loc[[i]]])
    elif corrupt == 'unknown_id': frame.loc[i,'flow_id'] = 'unknown'
    elif corrupt == 'wrong_prefix': frame.loc[i,'analysis_prefix'] = '203.0.113.0/24'
    elif corrupt == 'wrong_flags': frame.loc[i,['src_match','dst_match']] = [False,True]
    else: frame.loc[i,'flow_id'] = 'f4'
    rewrite(saved,'flow_prefix_membership',frame)
    before = sha256_file(saved[2]['flow_prefix_membership'][0])
    with pytest.raises(ValueError,match='membership'):
        analyze(saved)
    assert before == sha256_file(saved[2]['flow_prefix_membership'][0])


@pytest.mark.parametrize('corrupt',['normalization','boolean','duplicate_flow','packet_count','checksum','producer'])
def test_invalid_inputs_stop(saved,corrupt):
    if corrupt in ('normalization','boolean'):
        frame = saved[2]['prefixes'][1].copy().astype(object)
        frame.loc[0,'normalized_prefix_24' if corrupt=='normalization' else 'selected_for_analysis'] = 'invalid'
        rewrite(saved,'prefixes',frame)
    elif corrupt in ('duplicate_flow','packet_count'):
        frame = saved[2]['flows'][1].copy()
        if corrupt=='duplicate_flow': frame.loc[1,'flow_id'] = frame.loc[0,'flow_id']
        else: frame.loc[0,'packet_count'] = 0
        rewrite(saved,'flows',frame)
    else:
        m = json.loads(saved[1].read_text())
        m['artifacts']['flow_prefix_membership'].update(
            {'sha256':'0'*64} if corrupt=='checksum' else {'producer':{'prefixes_sha256':'0'*64}})
        saved[1].write_text(json.dumps(m))
    with pytest.raises(ValueError): analyze(saved)


def test_no_top_k_and_empty_selection(saved):
    frame = saved[2]['prefixes'][1].copy()
    base = frame.loc[frame.selected_for_analysis.eq(True)].iloc[0]
    additions=[]
    for i in range(40):
        row=base.copy();row['prefix']=row['normalized_prefix_24']=f'198.19.{i}.0/24';row['prefix_length']=24
        additions.append(row)
    rewrite(saved,'prefixes',pd.concat([frame,pd.DataFrame(additions)]))
    assert len(analyze(saved)['prefixes']) == 43
    frame['selected_for_analysis'] = False
    rewrite(saved,'prefixes',frame)
    membership = saved[2]['flow_prefix_membership'][1].iloc[:0]
    rewrite(saved,'flow_prefix_membership',membership)
    data = analyze(saved)
    assert data['prefixes'] == []
    assert data['references'][0]['stats']['flow_count'] == 0


def test_export_is_self_contained_and_never_mutates_sources(saved,tmp_path):
    before = {p:sha256_file(p) for p in saved[0].rglob('*') if p.is_file()}
    out = dashboard().export_dashboard(saved[0],'fixture','baseline',tmp_path/'new.html',chunksize=2)
    html = out.read_text()
    data = json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',html,re.S)[1])
    assert data['method']=='agurim'
    assert "connect-src 'none'" in html
    assert not re.search(r'<(?:script|link|img)[^>]+(?:src|href)=["\'](?:https?:|//)',html)
    assert before == {p:sha256_file(p) for p in saved[0].rglob('*') if p.is_file()}
    with pytest.raises(FileExistsError):
        dashboard().export_dashboard(saved[0],'fixture','baseline',out)
    assert html == out.read_text()
    for location in [saved[0]/'data/report.html',saved[1].parent/'report.html']:
        with pytest.raises(ValueError): dashboard().export_dashboard(saved[0],'fixture','baseline',location)
        assert not location.exists()


def test_export_failure_does_not_publish_html(saved,tmp_path):
    frame = saved[2]['flow_prefix_membership'][1]
    rewrite(saved,'flow_prefix_membership',frame.loc[frame.analysis_scope.ne('normalized_24')])
    out = tmp_path/'bad.html'
    with pytest.raises(ValueError,match='membership'):
        dashboard().export_dashboard(saved[0],'fixture','baseline',out,chunksize=2)
    assert not out.exists()


@pytest.mark.parametrize('entrypoint',['script','module'])
def test_cli_exports_or_reports_failure(saved,tmp_path,entrypoint):
    script = ROOT/'scripts/export_normalized24_dashboard.py'
    command = [sys.executable,str(script)] if entrypoint=='script' else [sys.executable,'-m','mawi_global_analysis.normalized24']
    args = [*command,'--root',str(saved[0]),'--dataset','fixture',
            '--run','baseline','--output',str(tmp_path/'cli.html'),'--chunksize','1']
    result = subprocess.run(args,capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path/'cli.html').is_file()
    result = subprocess.run(args,capture_output=True,text=True)
    assert result.returncode != 0 and '上書き' in result.stderr


@pytest.mark.parametrize('edges', [[1,3,2**63],[1,2,2,2**63],[1,2,128],[1,2,4.0,2**63]])
def test_invalid_shared_bins_rejected(edges):
    with pytest.raises(ValueError): analysis().HistogramSpec(bin_edges=tuple(edges))


def test_shared_axes_cannot_clip_and_all_zero_flows_work(saved):
    flows = saved[2]['flows'][1].copy()
    flows['packet_count'] = 1
    rewrite(saved,'flows',flows)
    with pytest.raises(ValueError,match='clip'):
        analyze(saved,spec=analysis().HistogramSpec(count_axis_upper=1))
    flows = saved[2]['flows'][1].iloc[:0]
    rewrite(saved,'flows',flows)
    rewrite(saved,'flow_prefix_membership',saved[2]['flow_prefix_membership'][1].iloc[:0])
    fm=saved[2]['flows'][0].parent/'flow_manifest.json'
    m=json.loads(fm.read_text());m['row_count']=0;fm.write_text(json.dumps(m))
    data=analyze(saved)
    assert len(data['prefixes'])==3
    assert data['histogram_spec']['count_axis_upper']==1
    assert all(t['stats']['flow_count']==0 and t['stats']['median'] is None
               and sum(t['counts'])==0 for t in data['prefixes']+data['references'])


def test_input_change_during_analysis_is_rejected(saved):
    def change(name,count):
        if name=='flows':
            with saved[2]['flows'][0].open('a') as stream: stream.write('\n')
    with pytest.raises(ValueError,match='changed'):
        analyze(saved,progress=change)


def test_provenance_identity_is_consistent_in_export(saved,tmp_path):
    from mawi_global_analysis.hashing import stable_json_hash
    out=dashboard().export_dashboard(saved[0],'fixture','baseline',tmp_path/'identity.html')
    data=json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',out.read_text(),re.S)[1])
    provenance=data['provenance'].copy()
    digest=provenance.pop('identity_sha256')
    assert digest==stable_json_hash(provenance)


def test_render_escapes_untrusted_provenance(saved):
    data=analyze(saved)
    malicious='</script><img src=x onerror=alert(1)> & 日本語'
    data['dataset_id']=malicious
    html=dashboard().render_dashboard(data)
    assert malicious not in html
    payload=json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',html,re.S)[1])
    assert payload['dataset_id']==malicious


def test_scratch_is_removed_on_failure(saved,tmp_path):
    scratch=tmp_path/'scratch';scratch.mkdir()
    frame=saved[2]['flow_prefix_membership'][1]
    rewrite(saved,'flow_prefix_membership',frame.loc[frame.analysis_scope.ne('normalized_24')])
    with pytest.raises(ValueError): analyze(saved,scratch_dir=scratch)
    assert list(scratch.iterdir())==[]


@pytest.mark.parametrize('field',['aguri_fingerprint','aguri_candidates_sha256'])
def test_contradictory_aguri_selection_provenance_is_rejected(saved,field):
    manifest=json.loads(saved[1].read_text())
    prefix_producer={'aguri_fingerprint':'b'*64,'aguri_candidates_sha256':'c'*64}
    manifest['artifacts']['prefixes']['producer']=prefix_producer
    manifest['artifacts']['aguri_candidates']={'producer':{**prefix_producer,field:'d'*64}}
    manifest['cache']['aguri']={'fingerprint':'b'*64}
    saved[1].write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match=field): analyze(saved)


def test_matching_recorded_aguri_provenance_is_retained(saved):
    manifest=json.loads(saved[1].read_text())
    producer={'aguri_fingerprint':'b'*64,'aguri_candidates_sha256':'c'*64}
    manifest['artifacts']['prefixes']['producer']=producer
    manifest['artifacts']['aguri_candidates']={'producer':producer}
    manifest['cache']['aguri']={'fingerprint':'b'*64}
    saved[1].write_text(json.dumps(manifest))
    assert analyze(saved)['provenance']['aguri_lineage']['aguri_fingerprint']=='b'*64


@pytest.mark.parametrize('sentinel',['aguri_manifest.json','context_manifest.json','ip_behavior_manifest.json'])
def test_external_caches_are_protected(saved,tmp_path,sentinel):
    cache=tmp_path/'external-cache';cache.mkdir()
    (cache/sentinel).write_text('{}')
    out=cache/'nested/report.html'
    with pytest.raises(ValueError,match='cache'): dashboard().export_dashboard(saved[0],'fixture','baseline',out)
    assert not out.exists()


@pytest.fixture
def byte_saved(saved):
    flows = saved[2]['flows'][1].copy()
    flows['byte_count'] = [60,120,700,230,1000,9999]
    flows['frame_byte_count'] = flows['byte_count']
    rewrite(saved,'flows',flows)
    return saved


def test_exact_packet_byte_totals_and_mean_keep_existing_statistics(byte_saved):
    data = analyze(byte_saved)
    targets = {t['prefix']:t for t in data['prefixes']+data['references']}
    expected = {A:(3,13,880), B:(2,14,930), EMPTY:(0,0,0),
                'selected_union':(4,17,1110), 'overall_ipv4':(5,117,2110)}
    assert data['schema_version'] == 2
    assert data['provenance']['aggregation']['version'] == 'normalized24-raw-v2'
    for target,(n,packets,byte_count) in expected.items():
        stats = targets[target]['stats']
        assert stats['flow_count'] == n
        assert stats['packet_total'] == packets
        assert stats['byte_total'] == byte_count
        assert stats['mean_packet_count'] == (packets/n if n else None)
    assert targets['selected_union']['stats']['median'] == 3
    assert targets['selected_union']['stats']['p95'] == pytest.approx(9.1)
    assert targets['selected_union']['stats']['one_packet_rate'] == .25
    assert targets[EMPTY]['stats']['median'] is None
    assert targets[EMPTY]['stats']['mean_packet_count'] is None
    assert sum(t['stats']['byte_total'] for t in data['prefixes']) == 1810
    assert targets['selected_union']['stats']['byte_total'] == 1110


def export_stats(saved, output, **kwargs):
    return analysis().export_raw_statistics(saved[0],'fixture','baseline',output,**kwargs)


def test_export_streams_exact_frequencies_and_binds_provenance(byte_saved,tmp_path):
    import csv
    output = tmp_path/'statistics'
    before = {p:sha256_file(p) for p in byte_saved[0].rglob('*') if p.is_file()}
    summary_path = export_stats(byte_saved,output,chunksize=1)
    assert summary_path == output/'summary.json'
    data = json.loads(summary_path.read_text())
    assert data['status'] == 'success'
    assert data['export_schema_version'] == 'normalized24-statistics-v1'
    descriptor = data['artifacts']['frequencies']
    assert descriptor['path'] == 'frequencies.csv'
    assert descriptor['schema_version'] == 'normalized24-exact-frequencies-v1'
    assert descriptor['sha256'] == sha256_file(output/'frequencies.csv')
    with (output/'frequencies.csv').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert descriptor['row_count'] == len(rows)
    assert [(r['distribution'],int(r['packet_count'])) for r in rows] == sorted(
        (r['distribution'],int(r['packet_count'])) for r in rows)
    targets = {t['prefix']:t for t in data['prefixes']+data['references']}
    for target,record in targets.items():
        values = [r for r in rows if r['distribution']==target]
        assert sum(int(r['frequency']) for r in values) == record['stats']['flow_count']
        assert sum(int(r['packet_count'])*int(r['frequency']) for r in values) == record['stats']['packet_total']
    assert not [r for r in rows if r['distribution']==EMPTY]
    provenance = data['provenance'].copy()
    identity = provenance.pop('identity_sha256')
    from mawi_global_analysis.hashing import stable_json_hash
    assert identity == stable_json_hash(provenance)
    assert provenance['frequency_export'] == descriptor
    assert before == {p:sha256_file(p) for p in byte_saved[0].rglob('*') if p.is_file()}


def test_exact_export_keeps_distinct_packet_counts_inside_one_bin(byte_saved,tmp_path):
    import csv
    flows = byte_saved[2]['flows'][1].copy()
    flows['packet_count'] = [4,5,6,7,100,9]
    flows['byte_count'] = [60,120,700,230,1000,9999]
    rewrite(byte_saved,'flows',flows)
    path = export_stats(byte_saved,tmp_path/'within-bin')
    data = json.loads(path.read_text())
    union = next(t for t in data['references'] if t['prefix']=='selected_union')
    assert union['stats']['packet_total'] == 22
    assert max(union['counts']) == 4
    with path.with_name('frequencies.csv').open(newline='') as stream:
        rows = [r for r in csv.DictReader(stream) if r['distribution']=='selected_union']
    assert [(int(r['packet_count']),int(r['frequency'])) for r in rows] == [(4,1),(5,1),(6,1),(7,1)]


def test_statistics_and_exact_export_are_chunk_invariant(byte_saved,tmp_path):
    first = analyze(byte_saved,chunksize=1)
    second = analyze(byte_saved,chunksize=100)
    assert first == second
    a = export_stats(byte_saved,tmp_path/'chunk-one',chunksize=1)
    b = export_stats(byte_saved,tmp_path/'chunk-large',chunksize=100)
    assert a.with_name('frequencies.csv').read_bytes() == b.with_name('frequencies.csv').read_bytes()
    assert json.loads(a.read_text()) == json.loads(b.read_text())


def test_large_totals_are_exact_and_html_does_not_round_them(byte_saved,tmp_path):
    maximum = 2**63-1
    flows = byte_saved[2]['flows'][1].copy()
    flows['byte_count'] = maximum
    flows['packet_count'] = maximum
    rewrite(byte_saved,'flows',flows)
    data = analyze(byte_saved)
    union = data['references'][0]
    assert union['stats']['packet_total'] == 4*maximum
    assert union['stats']['byte_total'] == 4*maximum
    path = export_stats(byte_saved,tmp_path/'large')
    assert json.loads(path.read_text())['references'][0]['stats']['byte_total'] == 4*maximum
    html = dashboard().render_dashboard(data)
    embedded = json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',html,re.S)[1])
    assert embedded['references'][0]['stats']['byte_total'] == str(4*maximum)
    assert data['references'][0]['stats']['byte_total'] == 4*maximum


def test_empty_statistics_export_has_header_only_and_null_means(byte_saved,tmp_path):
    rewrite(byte_saved,'flows',byte_saved[2]['flows'][1].iloc[:0])
    rewrite(byte_saved,'flow_prefix_membership',byte_saved[2]['flow_prefix_membership'][1].iloc[:0])
    fm = byte_saved[2]['flows'][0].parent/'flow_manifest.json'
    manifest = json.loads(fm.read_text());manifest['row_count']=0;fm.write_text(json.dumps(manifest))
    path = export_stats(byte_saved,tmp_path/'empty')
    data = json.loads(path.read_text())
    for target in data['prefixes']+data['references']:
        assert target['stats']['flow_count'] == target['stats']['packet_total'] == target['stats']['byte_total'] == 0
        assert target['stats']['mean_packet_count'] is None
    assert path.with_name('frequencies.csv').read_text().splitlines() == ['distribution,packet_count,frequency']


def test_export_rejects_existing_or_protected_directories(byte_saved,tmp_path):
    occupied = tmp_path/'occupied';occupied.mkdir()
    with pytest.raises(FileExistsError):
        export_stats(byte_saved,occupied)
    assert list(occupied.iterdir()) == []
    for location in (byte_saved[0]/'data/export',byte_saved[1].parent/'export'):
        with pytest.raises(ValueError): export_stats(byte_saved,location)
        assert not location.exists()
    cache = tmp_path/'external-cache';cache.mkdir()
    (cache/'flow_manifest.json').write_text('{}')
    with pytest.raises(ValueError): export_stats(byte_saved,cache/'export')


def test_export_failure_or_input_change_does_not_publish_bundle(byte_saved,tmp_path):
    def change(name,count):
        if name=='flows':
            with byte_saved[2]['flows'][0].open('a') as stream: stream.write('\n')
    output = tmp_path/'changed'
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError,match='changed'):
        export_stats(byte_saved,output,progress=change)
    assert not output.exists()
    assert set(tmp_path.iterdir()) == before


def test_default_payload_and_html_do_not_embed_exact_frequency_arrays(byte_saved):
    data = analyze(byte_saved)
    assert 'frequencies' not in data
    assert 'artifacts' not in data
    html = dashboard().render_dashboard(data)
    embedded = json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',html,re.S)[1])
    assert 'frequencies' not in embedded
    for old,new in zip(data['prefixes']+data['references'],embedded['prefixes']+embedded['references']):
        assert old['counts'] == new['counts']
        for key in ('flow_count','median','p95','one_packet_rate'):
            assert old['stats'][key] == new['stats'][key]


def test_export_preserves_frequencies_greater_than_one(byte_saved,tmp_path):
    import csv
    flows = byte_saved[2]['flows'][1].copy()
    flows['packet_count'] = [1,1,10,10,100,9]
    rewrite(byte_saved,'flows',flows)
    path = export_stats(byte_saved,tmp_path/'repeated')
    with path.with_name('frequencies.csv').open(newline='') as stream:
        rows = [r for r in csv.DictReader(stream) if r['distribution']=='selected_union']
    assert [(int(r['packet_count']),int(r['frequency'])) for r in rows] == [(1,2),(10,2)]
    stats = json.loads(path.read_text())['references'][0]['stats']
    assert stats['flow_count'] == 4 and stats['packet_total'] == 22


def test_legacy_frequency_adapter_does_not_invent_byte_total():
    import sqlite3
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE dist (target TEXT, packets INTEGER, n INTEGER)')
        db.executemany('INSERT INTO dist VALUES (?,?,?)',[('adapter',1,2),('adapter',7,3)])
        record = analysis().summarize_frequencies(db,'adapter',analysis().HistogramSpec(count_axis_upper=10))
        assert record['stats']['flow_count'] == 5
        assert record['stats']['packet_total'] == 23
        assert record['stats']['mean_packet_count'] == 4.6
        assert record['stats']['byte_total'] is None


@pytest.mark.parametrize('value', [-1, 'bad', 2**63])
def test_invalid_canonical_byte_count_is_rejected(byte_saved,value):
    flows = byte_saved[2]['flows'][1].astype(object)
    flows.loc[0,'byte_count'] = value
    rewrite(byte_saved,'flows',flows)
    with pytest.raises(ValueError,match='flows.byte_count'):
        analyze(byte_saved)


def test_failed_publication_removes_only_its_own_partial_bundle(byte_saved,tmp_path,monkeypatch):
    import os
    real_link = os.link
    def fail_summary(source,destination,*args,**kwargs):
        if Path(destination).name=='summary.json':
            raise OSError('simulated publication failure')
        return real_link(source,destination,*args,**kwargs)
    monkeypatch.setattr(os,'link',fail_summary)
    before = set(tmp_path.iterdir())
    output = tmp_path/'failed-publication'
    with pytest.raises(OSError,match='publication failure'):
        export_stats(byte_saved,output)
    assert not output.exists()
    assert set(tmp_path.iterdir()) == before


def test_bad_membership_cannot_publish_statistics_bundle(byte_saved,tmp_path):
    membership = byte_saved[2]['flow_prefix_membership'][1]
    rewrite(byte_saved,'flow_prefix_membership',membership.loc[membership.analysis_scope.ne('normalized_24')])
    output = tmp_path/'incomplete-membership'
    with pytest.raises(ValueError,match='membership'):
        export_stats(byte_saved,output)
    assert not output.exists()
