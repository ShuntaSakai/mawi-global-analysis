"""Exact comparison tests use synthetic canonical observations, not MAWI results."""
from __future__ import annotations

import csv
import hashlib
import importlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pandas as pd
import pytest

from test_rls_weight_comparison import binary, saved, edit_config, tree_state
from mawi_global_analysis.agurim_prime import run_prime
from mawi_global_analysis.config import load_config
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config, sha256_file


def metrics():
    try:
        return importlib.import_module('mawi_global_analysis.rls_weight_comparison.metrics')
    except ModuleNotFoundError:
        pytest.fail('exact comparison metrics are missing')


def generation():
    try:
        return importlib.import_module('mawi_global_analysis.rls_weight_comparison.generation')
    except ModuleNotFoundError:
        pytest.fail('comparison generation is missing')


def frequency_db():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER,PRIMARY KEY(distribution,packets))')
    return db


def test_ks_uses_exact_integer_frequencies_inside_histogram_bins():
    with frequency_db() as db:
        db.executemany('INSERT INTO frequencies VALUES (?,?,?)',
            [('left',1,2),('left',6,2),('right',1,1),('right',5,3)])
        got = metrics().ks_distance(db,'left','right')
        assert got == {'ks_distance':.5,'ks_numerator':'1','ks_denominator':'2'}
        assert metrics().ks_distance(db,'left','empty')['ks_distance'] is None


def test_disk_flow_sets_have_hand_calculated_jaccards():
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE flow_sets(id TEXT PRIMARY KEY,mask INTEGER)')
        db.executemany('INSERT INTO flow_sets VALUES (?,?)',[('f1',3),('f2',5),('f3',2)])
        got = {(r['mode_a'],r['mode_b']):r for r in metrics().flow_jaccards(db)}
        assert got['packet','byte']['intersection_count'] == 1
        assert got['packet','byte']['union_count'] == 3
        assert got['packet','byte']['jaccard'] == pytest.approx(1/3)
        assert got['packet','flow']['jaccard'] == .5
        assert got['byte','flow']['jaccard'] == 0


def test_ratio_null_rules_and_invalid_coverage():
    assert metrics().ratio(0,0) is None
    assert metrics().ratio(0,10) == 0
    assert metrics().ratio(2,3) == pytest.approx(2/3)
    with pytest.raises(ValueError): metrics().ratio(4,3)


def test_display_reduction_leaves_exact_csv_and_statistics_untouched():
    import io
    with frequency_db() as db:
        for name in ('overall_ipv4','packet','byte','flow'):
            db.executemany('INSERT INTO frequencies VALUES (?,?,?)',[(name,n,1) for n in range(1,101)])
        first,second = io.StringIO(),io.StringIO()
        full = metrics().write_ecdf(db,dict.fromkeys(('overall_ipv4','packet','byte','flow'),100),first,max_points=200)
        reduced = metrics().write_ecdf(db,dict.fromkeys(('overall_ipv4','packet','byte','flow'),100),second,max_points=4)
        assert first.getvalue() == second.getvalue()
        assert reduced['packet']['simplified']
        assert reduced['packet']['displayed_point_count'] <= 4
        assert reduced['packet']['points'][-1]['cumulative_fraction'] == 1
        assert reduced['packet']['exact_point_count'] == 100
        assert full['packet']['points'][49]['cumulative_fraction'] == .5


def generate(saved,output,**kwargs):
    return generation().generate_comparison(saved[0],'fixture',packet_run='packet',
        byte_run='byte',flow_run='flow',output_dir=output,**kwargs)


def test_real_three_runs_export_complete_readonly_comparison(saved,tmp_path):
    before = tree_state(saved[0])
    output = tmp_path.parent/(tmp_path.name+'-comparison')
    manifest_path = generate(saved,output,chunksize=2)
    manifest = json.loads(manifest_path.read_text())
    assert manifest['status'] == 'success'
    assert manifest['schema_version'] == 'rls-weight-comparison-v1'
    assert generation().verify_comparison_manifest(manifest_path)['status'] == 'success'
    assert tree_state(saved[0]) == before
    with (output/'selection_summary.csv').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 3
    assert all(int(r['flow_count'])==6 and float(r['flow_coverage'])==1 and float(r['ks_distance'])==0 for r in rows)
    with (output/'pairwise_jaccard.csv').open(newline='') as stream:
        assert all(float(r['jaccard'])==1 for r in csv.DictReader(stream))
    assert (output/'dashboard.html').is_file()
    for entry in manifest['artifacts'].values():
        assert entry['sha256']
    with pytest.raises(FileExistsError): generate(saved,output)


def test_condition_mismatch_does_not_create_output_or_parents(saved,tmp_path):
    edit_config(saved,'prefix','membership_mode','dst_only')
    output = tmp_path/'new-parent'/'comparison'
    with pytest.raises(ValueError,match='membership_mode'): generate(saved,output)
    assert not output.parent.exists()


def test_saved_artifact_hashes_are_reverified(saved,tmp_path):
    output = tmp_path/'comparison'
    path = generate(saved,output)
    with (output/'ecdf_counts.csv').open('a') as stream: stream.write('corrupt\n')
    with pytest.raises(ValueError,match='ecdf_counts.csv'):
        generation().verify_comparison_manifest(path)


def test_chunk_and_display_limits_do_not_change_exact_outputs(saved,tmp_path):
    a,b=tmp_path/'a',tmp_path/'b'
    generate(saved,a,chunksize=1,max_ecdf_points=2)
    generate(saved,b,chunksize=100,max_ecdf_points=100)
    for name in ('selected_native_prefixes.csv','selected_normalized24.csv','selection_summary.csv',
                 'pairwise_jaccard.csv','prefix24_stats.csv','ecdf_counts.csv'):
        assert (a/name).read_bytes() == (b/name).read_bytes()


@pytest.fixture
def different(saved,binary):
    root,flows,_=saved
    base=pd.read_csv(flows).iloc[0].to_dict()
    rows=[]
    for i in range(301):
        elephant=i==0
        n=100000 if elephant else 1
        byte_count=6000000 if elephant else 1500
        rows.append({**base,'flow_id':f'synthetic-{i}','ip_version':4,'protocol':6,
            'src_ip':'192.0.2.1' if elephant else f'203.0.113.{1+(i%200)}',
            'dst_ip':'198.51.100.1' if elephant else f'198.18.0.{1+(i%200)}',
            'src_port':10000+i,'dst_port':80,'packet_count':n,'byte_count':byte_count,
            'frame_byte_count':byte_count,'packets_from_src':n,'packets_from_dst':0,
            'bytes_from_src':byte_count,'bytes_from_dst':0})
    definition=flows.parent/'synthetic_definition.json'
    definition.write_text(json.dumps({'evidence':'synthetic canonical rows; not PCAP observations',
                                      'rows':rows},sort_keys=True))
    pd.DataFrame(rows).to_csv(flows,index=False)
    fm=json.loads(flows.with_name('flow_manifest.json').read_text())
    cfg=load_config(Path(__file__).parents[1]/'configs/baseline.yaml')
    fm.update(row_count=301,input_sha256=sha256_file(definition),
        fingerprint=flow_fingerprint(sha256_file(definition),cfg),
        synthetic_definition={'path':str(definition),'sha256':sha256_file(definition)})
    flows.with_name('flow_manifest.json').write_text(json.dumps(fm))
    for mode in ('packet','byte','flow'):
        run_prime(root,'fixture',f'different-{mode}',flows,binary,mode=mode,heuristics=2)
    return root


def test_natural_different_selections_match_hand_calculated_coverage_and_sets(different,tmp_path):
    output=tmp_path/'different-comparison'
    generation().generate_comparison(different,'fixture',packet_run='different-packet',
        byte_run='different-byte',flow_run='different-flow',output_dir=output)
    with (output/'selection_summary.csv').open(newline='') as stream:
        records={r['mode']:r for r in csv.DictReader(stream)}
    assert [int(records[m]['normalized_prefix_count']) for m in ('packet','byte','flow')] == [2,4,2]
    assert [int(records[m]['flow_count']) for m in ('packet','byte','flow')] == [1,301,300]
    assert float(records['packet']['flow_coverage']) == pytest.approx(1/301)
    assert float(records['packet']['packet_coverage']) == pytest.approx(100000/100300)
    assert float(records['flow']['byte_coverage']) == pytest.approx(450000/6450000)
    assert float(records['packet']['ks_distance']) == pytest.approx(300/301)
    assert float(records['flow']['ks_distance']) == pytest.approx(1/301)
    assert float(records['byte']['ks_distance']) == 0
    import re
    html=(output/'dashboard.html').read_text()
    embedded=json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',html,re.S)[1])
    for mode in ('packet','byte','flow'):
        for field in ('flow_count','packet_total','byte_total','mean_packet_count','median','p95','one_packet_rate'):
            assert float(embedded['modes'][mode]['stats'][field]) == float(records[mode][field])
    assert all(0<=float(r[k])<=1 for r in records.values() for k in ('flow_coverage','packet_coverage','byte_coverage'))
    with (output/'pairwise_jaccard.csv').open(newline='') as stream:
        j={(r['mode_a'],r['mode_b'],r['set_kind']):r for r in csv.DictReader(stream)}
    assert float(j['packet','byte','normalized24']['jaccard']) == .5
    assert float(j['packet','flow','normalized24']['jaccard']) == 0
    assert float(j['packet','byte','flow_id']['jaccard']) == pytest.approx(1/301)
    with (output/'ecdf_counts.csv').open(newline='') as stream:
        rows=list(csv.DictReader(stream))
    for name in ('overall_ipv4','packet','byte','flow'):
        curve=[r for r in rows if r['distribution']==name]
        assert float(curve[-1]['cumulative_fraction']) == 1
    with (output/'prefix24_stats.csv').open(newline='') as stream:
        assert sum(int(r['flow_count']) for r in csv.DictReader(stream) if r['mode']=='byte') == 602


def test_generation_cli_and_validation_cli_remain_compatible(saved,tmp_path):
    output=tmp_path/'cli-comparison'
    command=[sys.executable,'-m','mawi_global_analysis.rls_weight_comparison','--root',str(saved[0]),
             '--dataset','fixture','--packet-run','packet','--byte-run','byte','--flow-run','flow']
    result=subprocess.run([*command,'--output-dir',str(output),'--chunksize','2'],capture_output=True,text=True)
    assert result.returncode == 0,result.stderr
    assert (output/'comparison_manifest.json').is_file()
    result=subprocess.run([*command,'--validate-only','--json'],capture_output=True,text=True)
    assert result.returncode == 0 and json.loads(result.stdout)['status']=='valid'


def test_failure_during_publication_leaves_no_success_manifest(saved,tmp_path,monkeypatch):
    import os
    real_link=os.link
    def fail_final(source,destination,*args,**kwargs):
        if Path(destination).name=='comparison_manifest.json':
            raise OSError('simulated final publication failure')
        return real_link(source,destination,*args,**kwargs)
    monkeypatch.setattr(os,'link',fail_final)
    output=tmp_path/'failed-comparison'
    with pytest.raises(OSError,match='publication failure'): generate(saved,output)
    assert not output.exists()
    assert not list(tmp_path.glob('.rls-comparison-*'))


def test_source_change_after_statistics_export_prevents_completion(saved,tmp_path,monkeypatch):
    module=generation();real_export=module.export_raw_statistics
    calls=0
    def external_change(*args,**kwargs):
        nonlocal calls
        path=real_export(*args,**kwargs);calls+=1
        if calls==3:
            with saved[1].open('a') as stream: stream.write('\n')
        return path
    monkeypatch.setattr(module,'export_raw_statistics',external_change)
    output=tmp_path/'changed-comparison'
    with pytest.raises(ValueError): generate(saved,output)
    assert not output.exists()


def test_empty_comparison_has_explicit_null_ratios_and_no_ecdf_rows(saved,binary,tmp_path):
    root,flows,_=saved
    pd.read_csv(flows).iloc[:0].to_csv(flows,index=False)
    fm=json.loads(flows.with_name('flow_manifest.json').read_text())
    cfg=load_config(Path(__file__).parents[1]/'configs/baseline.yaml')
    source=hashlib.sha256(b'synthetic empty canonical definition').hexdigest()
    fm.update(row_count=0,input_sha256=source,fingerprint=flow_fingerprint(source,cfg))
    flows.with_name('flow_manifest.json').write_text(json.dumps(fm))
    for mode in ('packet','byte','flow'):
        run_prime(root,'fixture',f'empty-{mode}',flows,binary,mode=mode,heuristics=2)
    output=tmp_path/'empty-comparison'
    generation().generate_comparison(root,'fixture',packet_run='empty-packet',byte_run='empty-byte',
        flow_run='empty-flow',output_dir=output)
    with (output/'selection_summary.csv').open(newline='') as stream:
        rows=list(csv.DictReader(stream))
    assert all(r['flow_coverage']==r['packet_coverage']==r['byte_coverage']==r['ks_distance']=='' for r in rows)
    with (output/'pairwise_jaccard.csv').open(newline='') as stream:
        assert all(r['jaccard']=='' for r in csv.DictReader(stream))
    assert len((output/'ecdf_counts.csv').read_text().splitlines())==1
    import re
    embedded=json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',
                                 (output/'dashboard.html').read_text(),re.S)[1])
    assert all(all(value is None for value in record['coverage'].values()) for record in embedded['modes'].values())


@pytest.mark.parametrize('target', ['data/new-comparison','results/new-comparison'])
def test_generation_rejects_protected_output_trees(saved,target):
    output=saved[0]/target
    with pytest.raises(ValueError): generate(saved,output)
    assert not output.exists()


def test_dashboard_records_actual_aggregation_and_frequency_schemas(saved,tmp_path):
    import re
    output=tmp_path/'schema-comparison'
    generate(saved,output)
    html=(output/'dashboard.html').read_text()
    payload=json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',html,re.S)[1])
    assert payload['provenance']['schemas']['modes']['packet'] == {
        'payload_schema_version':2,'aggregation_version':'normalized24-raw-v2',
        'export_schema_version':'normalized24-statistics-v1',
        'frequency_schema_version':'normalized24-exact-frequencies-v1'}
