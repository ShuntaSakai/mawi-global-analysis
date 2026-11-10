"""Exact shared statistics and dedicated two-stage comparison bundles."""
import importlib
import json
from pathlib import Path
import csv
from mawi_global_analysis.hashing import sha256_file
import pytest
from test_aguri_two_stage_pipeline import runs,canonical,compiled_two,state

def api():return importlib.import_module('mawi_global_analysis.aguri_two_stage.comparison')

def test_two_stage_runs_use_shared_normalized_statistics(runs):
    from mawi_global_analysis.normalized24 import analyze_agurim_run
    root,_,_,_=runs
    payload=analyze_agurim_run(root,'fixture','two-flow',chunksize=1)
    assert payload['method']=='aguri-two-stage-flow'
    assert payload['references'][1]['stats']['flow_count']==6
    assert 'aguri_two_stage_lineage' in payload['provenance']


def test_dedicated_bundle_exact_native_ecdfs_and_hashes(runs,tmp_path,monkeypatch):
    root,_,_,_=runs;before=state(root)
    import subprocess
    def forbidden(*args,**kwargs):raise AssertionError('comparison must not execute any selector/process')
    monkeypatch.setattr(subprocess,'run',forbidden)
    path=api().generate_comparison(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow',output_dir=tmp_path/'bundle',chunksize=1,max_ecdf_points=2)
    manifest=api().verify_manifest(path)
    assert manifest['schema_version']=='aguri-two-stage-comparison-v2'
    assert 'dashboard.html' not in manifest['artifacts']
    assert not (path.parent/'dashboard.html').exists()
    after=state(root)
    assert all(after.get(k)==v for k,v in before.items())
    result=json.loads((path.parent/'summary.json').read_text())
    assert result['overall']['stats']['flow_count']==6
    for mode in ('packet','byte','flow'):
        data=json.loads((path.parent/'native/modes'/mode/'summary.json').read_text())
        with (path.parent/'native/modes'/mode/'frequencies.csv').open() as s:rows=list(csv.DictReader(s))
        for card in [*data['prefixes'],*data['references']]:
            key=card.get('prefix',card.get('id'))
            if key is None:key=card['key']
            counts=[r for r in rows if r['distribution']==key]
            assert sum(int(r['frequency']) for r in counts)==card['stats']['flow_count']
    for filename in ('ecdf_counts.csv','native_ecdf_counts.csv','scope_ecdf_counts.csv'):
        with (path.parent/filename).open() as stream:
            distributions={r['distribution'] for r in csv.DictReader(stream)}
        assert 'byte' in distributions
        if filename=='scope_ecdf_counts.csv':
            assert 'normalized_byte' in distributions
    assert all((path.parent/f'{scope}modes/byte/frequencies.csv').is_file() for scope in ('','native/'))
    other=api().generate_comparison(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow',output_dir=tmp_path/'other-bundle',chunksize=4,max_ecdf_points=2000)
    for name in manifest['artifacts']:
        if name.endswith('.csv'):assert (path.parent/name).read_bytes()==(other.parent/name).read_bytes()
    assert all(r['stats']['byte_total']==711 and r['coverage']['flow']==1 for r in result['modes'].values())
    with pytest.raises(FileExistsError):api().generate_comparison(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow',output_dir=path.parent)
    (path.parent/'native_ecdf_counts.csv').write_text('corrupt')
    with pytest.raises(ValueError,match='SHA|hash'):api().verify_manifest(path)


def test_validation_cli_has_no_output_side_effects(runs):
    import subprocess,sys
    root,_,_,_=runs;before=state(root)
    result=subprocess.run([sys.executable,'-m','mawi_global_analysis.aguri_two_stage','compare','--root',str(root),'--dataset','fixture',
        '--packet-run','two-packet','--byte-run','two-byte','--flow-run','two-flow','--validate-only','--json'],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)['status']=='valid' and state(root)==before


def test_empty_canonical_comparison_retains_nulls(canonical,compiled_two,tmp_path):
    from mawi_global_analysis.aguri_two_stage import run_two_stage
    root,flows=canonical;build,_=compiled_two
    flows.write_text(flows.read_text().splitlines()[0]+'\n')
    fm=flows.parent/'flow_manifest.json';m=json.loads(fm.read_text());m['row_count']=0
    if 'flows_sha256' in m:
        from mawi_global_analysis.hashing import sha256_file
        m['flows_sha256']=sha256_file(flows)
    fm.write_text(json.dumps(m))
    for mode in ('packet','byte','flow'):run_two_stage(root,'fixture','empty-'+mode,flows,build,mode=mode)
    path=api().generate_comparison(root,'fixture',packet_run='empty-packet',byte_run='empty-byte',flow_run='empty-flow',output_dir=tmp_path/'empty-bundle')
    api().verify_manifest(path);s=json.loads((path.parent/'summary.json').read_text())
    assert s['overall']['stats']['flow_count']==0
    assert all(r['stats']['mean_packet_count'] is None and r['ks_distance'] is None for r in s['modes'].values())
    assert s['prefixes']==[] and all(row['jaccard'] is None for row in s['jaccard'])


def test_completed_manifest_run_names_are_bound_to_hashed_summary(runs,tmp_path):
    root,_,_,_=runs
    path=api().generate_comparison(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow',output_dir=tmp_path/'bound-bundle')
    m=json.loads(path.read_text());m['validation']['runs']['packet']['run_name']='wrong-run';m['final_validation']['runs']['packet']['run_name']='wrong-run';path.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='binding'):api().verify_manifest(path)


def test_data_export_cli_and_legacy_html_verification(runs,tmp_path):
    from mawi_global_analysis.aguri_two_stage.cli import main
    import contextlib
    import io
    root,_,_,_=runs
    output=tmp_path/'bundle'
    stdout=io.StringIO()
    with contextlib.redirect_stdout(stdout):
        assert main(['compare','--root',str(root),'--dataset','fixture',
                     '--packet-run','two-packet','--byte-run','two-byte','--flow-run','two-flow',
                     '--output-dir',str(output),'--json'])==0
    reply=json.loads(stdout.getvalue())
    assert reply['status']=='success' and 'dashboard' not in reply
    path=Path(reply['manifest'])
    assert path==output/'comparison_manifest.json'
    for name in ('summary.json','native_ecdf_counts.csv','ecdf_counts.csv','scope_comparison.csv','scope_ecdf_counts.csv'):
        assert Path(reply['artifacts'][name])==output/name
        assert (output/name).is_file()

    manifest=api().verify_manifest(path)
    csv_name='scope_comparison.csv'
    counts=manifest['artifacts'][csv_name]
    counts['row_count']+=1
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='scope_comparison.csv.*schema/count'):
        api().verify_manifest(path)
    counts['row_count']-=1
    summary=output/'native/modes/byte/summary.json'
    original=summary.read_bytes()
    summary.write_text('[]')
    metadata=manifest['artifacts']['native/modes/byte/summary.json']
    metadata['sha256']=sha256_file(summary)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='expected a JSON object'):
        api().verify_manifest(path)
    summary.write_bytes(original)
    metadata['sha256']=sha256_file(summary)
    html=output/'dashboard.html'
    html.write_text('<!doctype html><title>Archived two-stage dashboard</title>')
    manifest['artifacts']['dashboard.html']={'sha256':sha256_file(html),'record_count':1}
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='data-only'):
        api().verify_manifest(path)
    manifest['schema_version']='aguri-two-stage-comparison-v1'
    path.write_text(json.dumps(manifest))
    assert api().verify_manifest(path)==manifest
    html.write_text('changed')
    with pytest.raises(ValueError,match='dashboard.html.*SHA-256'):
        api().verify_manifest(path)


def test_validation_failure_never_publishes_data_bundle(runs,tmp_path,monkeypatch):
    root,_,_,_=runs
    module=api()
    validate=module.validate_runs
    first=True

    def validate_changed(*args,**kwargs):
        nonlocal first
        record=validate(*args,**kwargs)
        if not first:
            record['input_changed']=True
        first=False
        return record

    monkeypatch.setattr(module,'validate_runs',validate_changed)
    output=tmp_path/'failed'
    with pytest.raises(ValueError,match='inputs changed'):
        module.generate_comparison(root,'fixture',packet_run='two-packet',byte_run='two-byte',
                                   flow_run='two-flow',output_dir=output)
    assert not output.exists()
