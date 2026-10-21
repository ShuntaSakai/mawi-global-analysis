"""Known distributions and corrupt saved-run contracts; no PCAP input."""
from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from mawi_global_analysis.flow_stage import FLOW_COLUMNS, FLOW_SCHEMA_VERSION
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config
from mawi_global_analysis.config import load_config
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS

ROOT = Path(__file__).parents[2]
A, B, EMPTY = '192.0.2.0/24', '198.51.100.0/24', '203.0.113.7/32'


def module():
    try:
        return importlib.import_module('mawi_global_analysis.flow_length')
    except ModuleNotFoundError:
        pytest.fail('saved-artifact flow-length analysis is not implemented')


@pytest.fixture
def saved_run(tmp_path):
    config_path = ROOT / 'configs/scan_source_driven_removal.yaml'
    cfg = load_config(config_path)
    text = config_path.read_text()
    cache = tmp_path / 'data/fixture/processed/flows/cache'
    run = tmp_path / 'results/fixture/scan_source_driven_removal'
    cache.mkdir(parents=True)
    run.mkdir(parents=True)
    # c belongs to A and B; e matches B on both sides; EMPTY has zero native flows.
    endpoints = [('192.0.2.1','203.0.113.200'), ('203.0.113.200','192.0.2.2'),
                 ('192.0.2.1','198.51.100.2'), ('198.51.100.3','203.0.113.200'),
                 ('198.51.100.4','198.51.100.5'), ('192.0.2.3','203.0.113.200'),
                 ('203.0.113.200','192.0.2.4'), ('203.0.113.200','203.0.113.201'),
                 ('2001:db8::1','2001:db8::2')]
    packets = [1,2,3,4,7,8,100,2,1]
    patterns = ['syn_only_observed','syn_to_rst','none','none','syn_synack_rst',
                'none','none','none','none']
    rows, labels, membership = [], [], []
    for i, ((src,dst), n, pat) in enumerate(zip(endpoints,packets,patterns)):
        row = dict.fromkeys(FLOW_COLUMNS, 0)
        row.update(flow_id=f'f{i}', ip_version=6 if ':' in src else 4,
                   protocol=6, src_ip=src, dst_ip=dst, packet_count=n,
                   initial_syn_sender_ip=src if pat != 'none' else '', observed_tcp_pattern=pat)
        rows.append(row)
        strict, broad = i in [1,4], i in [0,1,4]
        labels.append(dict(zip(FLOW_LABEL_COLUMNS,[f'f{i}',strict,broad,strict,broad])))
        for scope, prefixes in [('native',[A,B,EMPTY]), ('normalized_24',[A,B,'203.0.113.0/24'])]:
            for prefix in prefixes:
                net = ipaddress.ip_network(prefix)
                sm, dm = ipaddress.ip_address(src) in net, ipaddress.ip_address(dst) in net
                if sm or dm:
                    membership.append(dict(zip(MEMBERSHIP_COLUMNS,[f'f{i}',scope,prefix,sm,dm])))
    ledger=[]
    for prefix in [A,B,EMPTY]:
        row=dict.fromkeys(CORRECTED_LEDGER_COLUMNS, '')
        row.update(prefix=prefix, prefix_length=ipaddress.ip_network(prefix).prefixlen,
                   normalized_prefix_24=str(ipaddress.ip_network(prefix).supernet(new_prefix=24)) if prefix==EMPTY else prefix,
                   selected_for_analysis=True)
        ledger.append(row)
    tables = {'flows':(cache/'flows.csv',pd.DataFrame(rows)),
              'flow_labels':(run/'flow_labels.csv',pd.DataFrame(labels).iloc[::-1]),
              'prefixes':(run/'prefixes.csv',pd.DataFrame(ledger)),
              'flow_prefix_membership':(run/'flow_prefix_membership.csv',pd.DataFrame(membership))}
    artifacts={}
    for name,(path,df) in tables.items():
        df.to_csv(path,index=False)
        artifacts[name]={'path':str(path.relative_to(tmp_path)), 'row_count':len(df)}
    sha='a'*64
    fp=flow_fingerprint(sha,cfg,FLOW_SCHEMA_VERSION)
    (cache/'flow_manifest.json').write_text(json.dumps(dict(input_sha256=sha,
        fingerprint=fp, row_count=9, flow_config=flow_generation_config(cfg),
        schema_version=FLOW_SCHEMA_VERSION, skipped_packet_counts={})))
    manifest=dict(status='success',dataset_id='fixture', input={'sha256':sha},
        config={'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()},
        artifacts=artifacts, cache={'flows':{'fingerprint':fp,
        'manifest_path':str((cache/'flow_manifest.json').relative_to(tmp_path))}})
    mp=run/'run_manifest.json'
    mp.write_text(json.dumps(manifest))
    return tmp_path, mp, tables


def analyze(saved_run, chunksize=2):
    root,_,_=saved_run
    return module().analyze_run(root, 'fixture', 'scan_source_driven_removal', chunksize=chunksize)


def edit_manifest(saved_run, fn):
    _,path,_=saved_run
    data=json.loads(path.read_text()); fn(data); path.write_text(json.dumps(data))


def test_exact_statistics_and_union_match_independent_numpy_reference(saved_run):
    result=analyze(saved_run)
    expected={A:([1,2,3,8,100],[1,2]), B:([3,4,7],[7]), EMPTY:([],[]),
              'selected_union':([1,2,3,4,7,8,100],[1,2,7]),
              'overall_ipv4':([1,2,3,4,7,8,100,2],[1,2,7])}
    for prefix,(raw,removed) in expected.items():
        retained=list(raw)
        for n in removed:retained.remove(n)
        for group,values in [('Raw',raw),('removed',removed),('retained',retained)]:
            row=result.summary.set_index(['prefix','group']).loc[(prefix,group)]
            assert row.flow_count==len(values)
            if values:
                assert row['median']==pytest.approx(np.median(values))
                assert row['p95']==pytest.approx(np.quantile(values,.95))
                assert row['one_packet_rate']==pytest.approx(values.count(1)/len(values))
            else:assert pd.isna(row['median'])
        histogram=result.histogram.query('prefix == @prefix')
        for group,values in [('Raw',raw),('removed',removed),('retained',retained)]:
            expected_bins=np.histogram(values,bins=result.bin_edges)[0]
            np.testing.assert_array_equal(histogram.query('group == @group').flow_count,expected_bins)
        raw_counts=histogram.query('group == "Raw"').flow_count.to_numpy()
        split_counts=(histogram.query('group == "removed"').flow_count.to_numpy()+
                      histogram.query('group == "retained"').flow_count.to_numpy())
        np.testing.assert_array_equal(raw_counts,split_counts)
    assert result.audit['native_membership_rows']==8
    assert result.audit['selected_unique_flows']==7
    assert result.audit['extra_memberships']==1
    assert result.audit['multi_prefix_flows']==1
    assert result.audit['selected_prefix_count']==3
    assert result.bin_edges[:5]==[1,2,3,4,8]
    assert result.bin_edges[-1]>100


def test_chunk_size_does_not_change_results(saved_run):
    a,b=analyze(saved_run,1),analyze(saved_run,100)
    pd.testing.assert_frame_equal(a.summary,b.summary)
    pd.testing.assert_frame_equal(a.histogram,b.histogram)


@pytest.mark.parametrize('mutation, message',[
    (lambda m:m.update(status='running'),'success'),
    (lambda m:m.update(dataset_id='wrong'),'dataset'),
    (lambda m:m['artifacts'].pop('flows'),'flows'),
    (lambda m:m['artifacts'].update(flows_csv=m['artifacts']['flows']),'ambiguous'),
    (lambda m:m['artifacts']['flows'].update(path='/nonexistent/lab/flows.csv'),'flows.csv'),
    (lambda m:m['artifacts']['flow_labels'].update(row_count=123),'row_count'),
    (lambda m:m['config'].update(hash='0'*64),'config hash'),
])
def test_manifest_failures_stop(saved_run,mutation,message):
    edit_manifest(saved_run,mutation)
    with pytest.raises((ValueError,FileNotFoundError),match=message):analyze(saved_run)


def test_wrong_saved_thresholds_rejected_even_with_correct_hash(saved_run):
    def change(m):
        text=m['config']['text'].replace('min_pattern_count: 3','min_pattern_count: 20')
        m['config'].update(text=text,hash=hashlib.sha256(text.encode()).hexdigest())
    edit_manifest(saved_run,change)
    with pytest.raises(ValueError,match='scan'):analyze(saved_run)


@pytest.mark.parametrize('table,column,value,message',[
    ('flows','packet_count',0,'packet_count'),
    ('flows','packet_count',1.5,'packet_count'),
    ('flow_labels','broad_removed','maybe','boolean'),
    ('flow_prefix_membership','src_match','False','membership'),
])
def test_bad_values_rejected(saved_run,table,column,value,message):
    path,df=saved_run[2][table]
    df=df.copy().astype({column:object});df.iloc[0,df.columns.get_loc(column)]=value
    df.to_csv(path,index=False)
    with pytest.raises(ValueError,match=message):analyze(saved_run)


@pytest.mark.parametrize('table',['flows','flow_labels','flow_prefix_membership'])
def test_duplicate_keys_across_chunks_rejected(saved_run,table):
    path,df=saved_run[2][table]
    pd.concat([df,df.iloc[:1]]).to_csv(path,index=False)
    edit_manifest(saved_run,lambda m:m['artifacts'][table].update(row_count=len(df)+1))
    if table=='flows':
        fm=path.parent/'flow_manifest.json';m=json.loads(fm.read_text());m['row_count']+=1;fm.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='duplicate'):analyze(saved_run)


@pytest.mark.parametrize('table',['flow_labels','flow_prefix_membership'])
def test_unknown_flow_ids_rejected(saved_run,table):
    path,df=saved_run[2][table];df=df.copy();df.iloc[0,0]='alien';df.to_csv(path,index=False)
    with pytest.raises(ValueError,match='flow_id'):analyze(saved_run)


def test_missing_native_membership_rejected(saved_run):
    path,df=saved_run[2]['flow_prefix_membership'];df=df.iloc[1:];df.to_csv(path,index=False)
    edit_manifest(saved_run,lambda m:m['artifacts']['flow_prefix_membership'].update(row_count=len(df)))
    with pytest.raises(ValueError,match='membership'):analyze(saved_run)


def test_strict_must_be_subset_of_broad(saved_run):
    path,df=saved_run[2]['flow_labels'];df=df.copy()
    df.loc[df.flow_id.eq('f1'),['broad_removed','broad_scan_like']]=False;df.to_csv(path,index=False)
    with pytest.raises(ValueError,match='strict'):analyze(saved_run)


@pytest.mark.parametrize('table,field',[
    ('flows','flow_fingerprint'),('flows','cache_manifest_sha256'),
    ('flow_labels','flow_fingerprint'),('flow_prefix_membership','flow_fingerprint'),
    ('flow_prefix_membership','prefixes_sha256'),
])
def test_recorded_producer_contradictions_rejected(saved_run,table,field):
    edit_manifest(saved_run,lambda m:m['artifacts'][table].update(producer={field:'0'*64}))
    with pytest.raises(ValueError,match=field):analyze(saved_run)


def test_absent_input_is_diagnostic_and_never_creates_demo(tmp_path):
    with pytest.raises(FileNotFoundError,match='run_manifest.json'):
        module().inspect_run(tmp_path,'missing','scan_source_driven_removal')
    assert not list(tmp_path.iterdir())


def test_demo_is_explicit_synthetic_and_refuses_existing_run(tmp_path):
    m=module()
    dataset,run=m.make_demo_run(tmp_path)
    info=m.inspect_run(tmp_path,dataset,run)
    assert info.manifest['evidence_level']=='synthetic_demo'
    assert m.analyze_run(tmp_path,dataset,run,chunksize=2).audit['multi_prefix_flows']>0
    with pytest.raises(FileExistsError):m.make_demo_run(tmp_path)


def test_notebook_executes_all_cells_in_demo_mode(tmp_path,monkeypatch):
    notebook=ROOT/'notebooks/06_prefix_flow_length_histograms.ipynb'
    assert notebook.is_file(), 'new notebook must exist'
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv('MAWI_FLOW_LENGTH_DEMO','1')
    monkeypatch.delenv('MAWI_FLOW_LENGTH_OUTPUT_DIR',raising=False)
    import matplotlib
    matplotlib.use('Agg')
    namespace={'__name__':'__main__'}
    for i,cell in enumerate(json.loads(notebook.read_text())['cells']):
        if cell['cell_type']=='code':
            exec(compile(''.join(cell['source']),f'{notebook.name}:cell-{i}','exec'),namespace)
    assert namespace['result'].inspection.manifest['evidence_level']=='synthetic_demo'
    assert namespace['result'].summary.flow_count.sum()>0


def test_notebook_real_mode_stops_before_any_plot_if_data_missing(tmp_path,monkeypatch):
    notebook=ROOT/'notebooks/06_prefix_flow_length_histograms.ipynb'
    assert notebook.is_file(), 'new notebook must exist'
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv('MAWI_FLOW_LENGTH_DEMO','0')
    monkeypatch.setenv('MAWI_ANALYSIS_ROOT',str(tmp_path))
    monkeypatch.setenv('MAWI_DATASET_ID','missing')
    monkeypatch.setenv('MAWI_RUN_NAME','scan_source_driven_removal')
    namespace={'__name__':'__main__'}
    with pytest.raises(FileNotFoundError,match='run_manifest.json'):
        for cell in json.loads(notebook.read_text())['cells']:
            if cell['cell_type']=='code':exec(''.join(cell['source']),namespace)
    assert namespace.get('result') is None
    assert 'figures' not in namespace


def test_failed_notebook_rerun_cannot_display_or_export_previous_results(tmp_path,monkeypatch):
    notebook=ROOT/'notebooks/06_prefix_flow_length_histograms.ipynb'
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv('MAWI_FLOW_LENGTH_DEMO','1')
    monkeypatch.delenv('MAWI_FLOW_LENGTH_OUTPUT_DIR',raising=False)
    cells=[''.join(c['source']) for c in json.loads(notebook.read_text())['cells'] if c['cell_type']=='code']
    namespace={'__name__':'__main__'}
    for code in cells:exec(code,namespace)
    namespace.update(DATASET_ID='missing',OUTPUT_DIR=str(tmp_path/'must-not-exist'))
    analysis=next(c for c in cells if 'result = analyze_run(' in c)
    with pytest.raises(FileNotFoundError):exec(analysis,namespace)
    assert namespace['result'] is None
    for code in cells[-3:]:
        with pytest.raises(RuntimeError,match='再実行|結果|入力'):
            exec(code,namespace)
    assert not (tmp_path/'must-not-exist').exists()
