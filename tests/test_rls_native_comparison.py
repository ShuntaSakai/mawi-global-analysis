"""Native scope tests use synthetic saved canonical observations only."""
import csv
import importlib
import json
from pathlib import Path
import shutil

import pandas as pd
import pytest

from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_length import inspect_run
from mawi_global_analysis.membership import build_membership
from mawi_global_analysis.prefix import build_corrected_prefix_ledger
from mawi_global_analysis.normalized24 import export_raw_statistics
from test_normalized24 import saved as normalized_saved, rewrite
from test_rls_weight_comparison import binary, saved, tree_state
from test_rls_weight_comparison_generation import generate


def analysis():
    return importlib.import_module('mawi_global_analysis.rls_weight_comparison.native_analysis')


@pytest.fixture
def narrow(normalized_saved,tmp_path):
    root,mp,tables=normalized_saved
    cfg=load_config(Path(__file__).parents[1]/'configs/baseline.yaml')
    ledger=build_corrected_prefix_ledger(pd.DataFrame({'src_prefix':['192.0.2.1/32','198.51.100.0/28'], 'dst_prefix':['*','*']}),cfg)
    flows=tables['flows'][1].copy()
    flows['byte_count']=[60,120,700,230,1000,9999]
    rewrite(normalized_saved,'prefixes',ledger)
    rewrite(normalized_saved,'flows',flows)
    rewrite(normalized_saved,'flow_prefix_membership',build_membership(flows,ledger))
    base=tmp_path/'normalized'
    export_raw_statistics(root,'fixture','baseline',base/'modes/packet',chunksize=1)
    for mode in ('byte','flow'):shutil.copytree(base/'modes/packet',base/'modes'/mode)
    infos={m:inspect_run(root,'fixture','baseline',raw_only=True) for m in ('packet','byte','flow')}
    return normalized_saved,base,infos


def run_analysis(narrow,tmp_path,**kwargs):
    _,base,infos=narrow
    return analysis().analyze_native_runs(infos,base,tmp_path/'native',chunksize=kwargs.pop('chunksize',2),**kwargs)


def test_native_32_and_28_keep_exact_populations_and_quantile_rule(narrow,tmp_path):
    before=tree_state(narrow[0][0])
    result=run_analysis(narrow,tmp_path)
    assert tree_state(narrow[0][0])==before
    cards={p['prefix']:p for p in result['prefixes']}
    assert cards['192.0.2.1/32']['stats']==dict(flow_count=1,packet_total=1,byte_total=60,mean_packet_count=1,median=1,p95=1,one_packet_rate=1)
    b=cards['198.51.100.0/28']['stats']
    assert b['flow_count']==2 and b['packet_total']==14 and b['byte_total']==930
    assert b['median']==7 and b['p95']==pytest.approx(9.7) and b['mean_packet_count']==7
    union=result['modes']['packet']['stats']
    assert union['flow_count']==3 and union['packet_total']==15 and union['byte_total']==990
    assert union['median']==4 and union['p95']==pytest.approx(9.4)
    assert result['overall']['stats']['flow_count']==5
    for mode in ('packet','byte','flow'):
        r=result['scope_comparison'][mode]
        assert r['native_flow_count']==3 and r['normalized24_flow_count']==4
        assert r['native_packet_total']==15 and r['normalized24_packet_total']==17
        assert r['ks_distance']==pytest.approx(1/6)
        assert r['ks_numerator']=='1' and r['ks_denominator']=='6'
    assert result['ecdf']['packet']['points'][-1]['cumulative_fraction']==1
    assert result['per_prefix_ecdf']['prefix_count']==2
    with (tmp_path/'native/modes/packet/frequencies.csv').open(newline='') as stream:rows=list(csv.DictReader(stream))
    for p in cards:
        values=[r for r in rows if r['distribution']==p]
        assert sum(int(r['frequency']) for r in values)==cards[p]['stats']['flow_count']
        assert sum(int(r['packet_count'])*int(r['frequency']) for r in values)==cards[p]['stats']['packet_total']


def test_cross_prefix_and_both_endpoint_flow_id_dedup(narrow,tmp_path):
    state,base,infos=narrow
    # /32 A and /28 B now both contain f2; both B endpoints contain f3.
    cfg=load_config(Path(__file__).parents[1]/'configs/baseline.yaml')
    ledger=build_corrected_prefix_ledger(pd.DataFrame({'src_prefix':['192.0.2.2/32','198.51.100.0/28'],'dst_prefix':['*','*']}),cfg)
    flows=pd.read_csv(state[2]['flows'][0])
    rewrite(state,'prefixes',ledger);rewrite(state,'flow_prefix_membership',build_membership(flows,ledger))
    infos={m:inspect_run(state[0],'fixture','baseline',raw_only=True) for m in infos}
    # Build the matching baseline for this fixed synthetic selection.
    base=tmp_path/'new-normalized'
    export_raw_statistics(state[0],'fixture','baseline',base/'modes/packet')
    for mode in ('byte','flow'):shutil.copytree(base/'modes/packet',base/'modes'/mode)
    result=analysis().analyze_native_runs(infos,base,tmp_path/'native',chunksize=1)
    assert sum(p['stats']['flow_count'] for p in result['prefixes'])==3
    assert result['modes']['packet']['stats']['flow_count']==2
    assert result['modes']['packet']['stats']['packet_total']==14


def test_chunks_and_display_limits_do_not_change_exact_native_outputs(narrow,tmp_path):
    a=analysis().analyze_native_runs(narrow[2],narrow[1],tmp_path/'a',chunksize=1,max_ecdf_points=2)
    b=analysis().analyze_native_runs(narrow[2],narrow[1],tmp_path/'b',chunksize=99,max_ecdf_points=500)
    assert a['modes']==b['modes'] and a['scope_comparison']==b['scope_comparison']
    for path in (tmp_path/'a').rglob('*.csv'):
        assert path.read_bytes()==(tmp_path/'b'/path.relative_to(tmp_path/'a')).read_bytes()


@pytest.mark.parametrize('corrupt',['missing','duplicate','wrong_flags','unknown_id'])
def test_native_membership_is_validated_not_just_trusted(narrow,tmp_path,corrupt):
    state,base,infos=narrow
    frame=pd.read_csv(state[2]['flow_prefix_membership'][0]);indices=frame.index[frame.analysis_scope=='native']
    if corrupt=='missing':frame=frame.drop(indices[0])
    elif corrupt=='duplicate':frame=pd.concat([frame,frame.loc[[indices[0]]]])
    elif corrupt=='wrong_flags':frame.loc[indices[0],['src_match','dst_match']]=False
    else:frame.loc[indices[0],'flow_id']='unknown'
    rewrite(state,'flow_prefix_membership',frame)
    infos={m:inspect_run(state[0],'fixture','baseline',raw_only=True) for m in infos}
    # The normalized scope remains correct: bind a newly exported baseline to
    # this corrupt-native file so the native EDGE validation itself is tested.
    base=tmp_path/'rebound-baseline'
    export_raw_statistics(state[0],'fixture','baseline',base/'modes/packet')
    for mode in ('byte','flow'):shutil.copytree(base/'modes/packet',base/'modes'/mode)
    with pytest.raises(ValueError,match='membership'):
        analysis().analyze_native_runs(infos,base,tmp_path/'native',chunksize=2)


def test_native_extension_preserves_normalized_bundle_and_inputs(saved,tmp_path):
    module=importlib.import_module('mawi_global_analysis.rls_weight_comparison.native_generation')
    source=generate(saved,tmp_path/'normalized')
    before=tree_state(saved[0]);original=tree_state(source.parent)
    path=module.generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',
                                          output_dir=tmp_path.parent/(tmp_path.name+'-new-bundle'),comparison_manifest=source,chunksize=2)
    assert tree_state(saved[0])==before and tree_state(source.parent)==original
    manifest=json.loads(path.read_text())
    assert manifest['native_extension']['schema_version']=='rls-native-comparison-v1'
    for p in source.parent.rglob('*'):
        if p.is_file() and p.name!='comparison_manifest.json':
            assert p.read_bytes()==(path.parent/p.relative_to(source.parent)).read_bytes()
    from mawi_global_analysis.rls_weight_comparison import verify_comparison_manifest
    assert verify_comparison_manifest(path)['status']=='success'
    assert (path.parent/'dashboard_native.html').exists()
    (path.parent/'native_ecdf_counts.csv').unlink()
    with pytest.raises((ValueError,OSError)):verify_comparison_manifest(path)


def test_native_render_reuses_safe_offline_payload_without_mutation(narrow,tmp_path):
    from copy import deepcopy
    from test_rls_weight_comparison_dashboard import Document
    payload=run_analysis(narrow,tmp_path)
    payload.update(dataset_id='synthetic',runs={},conditions={},provenance={})
    payload['prefixes'][0]['prefix']='</script><img src=x onerror=alert(1)>'
    original=deepcopy(payload)
    module=importlib.import_module('mawi_global_analysis.rls_weight_comparison.native_dashboard')
    html=module.render_native_dashboard(payload)
    doc=Document(html)
    assert len(doc.scripts)==2 and not doc.external
    assert "connect-src 'none'" in doc.csp
    assert json.loads(next(s for s in doc.scripts if s['attrs'].get('id')=='dashboard-data')['text'])==payload
    assert payload==original
    assert '\\u003c/script\\u003e' in html


def test_empty_native_populations_are_null_and_renderable(normalized_saved,tmp_path):
    state=normalized_saved
    ledger=state[2]['prefixes'][1].iloc[:0]
    flows=state[2]['flows'][1]
    rewrite(state,'prefixes',ledger);rewrite(state,'flow_prefix_membership',build_membership(flows,ledger))
    base=tmp_path/'baseline'
    export_raw_statistics(state[0],'fixture','baseline',base/'modes/packet')
    for m in ('byte','flow'):shutil.copytree(base/'modes/packet',base/'modes'/m)
    infos={m:inspect_run(state[0],'fixture','baseline',raw_only=True) for m in ('packet','byte','flow')}
    result=analysis().analyze_native_runs(infos,base,tmp_path/'native')
    assert not result['prefixes']
    assert all(r['stats']['flow_count']==0 and r['stats']['mean_packet_count'] is None and r['ks_distance'] is None for r in result['modes'].values())
    assert all(r['ks_distance'] is None for r in result['scope_comparison'].values())
    renderer=importlib.import_module('mawi_global_analysis.rls_weight_comparison.native_dashboard')
    assert renderer.render_native_dashboard(result)


def test_native_cli_can_generate_without_a_preexisting_comparison(saved,tmp_path):
    from mawi_global_analysis.rls_weight_comparison.cli import main
    out=tmp_path/'native-bundle'
    assert main(['--include-native','--root',str(saved[0]),'--dataset','fixture',
                 '--packet-run','packet','--byte-run','byte','--flow-run','flow',
                 '--output-dir',str(out),'--chunksize','1'])==0
    assert (out/'dashboard_native.html').exists() and (out/'dashboard.html').exists()


def test_extension_rejects_different_comparison_runs_without_creating_parent(saved,tmp_path):
    from mawi_global_analysis.rls_weight_comparison.native_generation import generate_native_comparison
    source=generate(saved,tmp_path/'base')
    manifest=json.loads(source.read_text());manifest['validation']['runs']['packet']['run_name']='other'
    source.write_text(json.dumps(manifest))
    output=tmp_path/'absent'/'result'
    with pytest.raises(ValueError,match='does not match'):
        generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',output_dir=output,comparison_manifest=source)
    assert not output.parent.exists()


def test_native_manifest_requires_extension_artifacts_even_if_record_removed(saved,tmp_path):
    from mawi_global_analysis.rls_weight_comparison.native_generation import generate_native_comparison
    from mawi_global_analysis.rls_weight_comparison import verify_comparison_manifest
    path=generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',output_dir=tmp_path/'native')
    manifest=json.loads(path.read_text());manifest['artifacts'].pop('native_prefix_stats.csv');path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='native artifacts missing'):verify_comparison_manifest(path)


def test_native_publication_failure_removes_partial_bundle(saved,tmp_path,monkeypatch):
    import os
    from mawi_global_analysis.rls_weight_comparison.native_generation import generate_native_comparison
    source=generate(saved,tmp_path/'base');real=os.link
    def fail(source,target,*a,**k):
        if Path(target).name=='comparison_manifest.json':raise OSError('native publication failure')
        return real(source,target,*a,**k)
    monkeypatch.setattr(os,'link',fail)
    out=tmp_path/'failed'
    with pytest.raises(OSError,match='publication failure'):
        generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',output_dir=out,comparison_manifest=source)
    assert not out.exists()


def test_large_byte_totals_preserve_exact_integers(narrow,tmp_path):
    state,_,_=narrow
    flows=pd.read_csv(state[2]['flows'][0]);maximum=2**63-1;flows['byte_count']=maximum
    rewrite(state,'flows',flows)
    base=tmp_path/'baseline'
    export_raw_statistics(state[0],'fixture','baseline',base/'modes/packet')
    for m in ('byte','flow'):shutil.copytree(base/'modes/packet',base/'modes'/m)
    infos={m:inspect_run(state[0],'fixture','baseline',raw_only=True) for m in ('packet','byte','flow')}
    result=analysis().analyze_native_runs(infos,base,tmp_path/'native')
    assert result['modes']['packet']['stats']['byte_total']==3*maximum
    assert result['overall']['stats']['byte_total']==5*maximum


def test_refresh_does_not_silently_change_extended_bundle_provenance(saved,tmp_path):
    from mawi_global_analysis.rls_weight_comparison import generate_native_comparison,refresh_dashboard
    path=generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',output_dir=tmp_path/'native')
    with pytest.raises(ValueError,match='native'):
        refresh_dashboard(path,tmp_path/'refresh')
    assert not (tmp_path/'refresh').exists()


@pytest.mark.parametrize('damage',['remove','partial','scope','invariant','final_validation','required'])
def test_native_manifest_cannot_be_downgraded_or_contradict_scope(saved,tmp_path,damage):
    from mawi_global_analysis.rls_weight_comparison import generate_native_comparison,verify_comparison_manifest
    path=generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',output_dir=tmp_path/'native')
    manifest=json.loads(path.read_text());extension=manifest['native_extension']
    if damage=='remove':manifest.pop('native_extension')
    elif damage=='partial':manifest['native_extension']={'schema_version':extension['schema_version']}
    elif damage=='scope':extension['membership_scope']='normalized_24'
    elif damage=='invariant':extension['invariants']['selection_fixed']=False
    elif damage=='final_validation':extension['final_validation']['status']='invalid'
    else:extension['required_artifacts']=[]
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='native'):verify_comparison_manifest(path)


def test_current_root_scratch_is_protected_even_with_old_source_root(saved,tmp_path):
    from mawi_global_analysis.rls_weight_comparison import generate_native_comparison
    source=generate(saved,tmp_path/'base');manifest=json.loads(source.read_text())
    for record in manifest['source_runs'].values():record['inputs']['run_manifest']['path']='/old-location/results/fixture/run/run_manifest.json'
    source.write_text(json.dumps(manifest))
    output=tmp_path/'native'
    with pytest.raises(ValueError,match='scratch'):
        generate_native_comparison(saved[0],'fixture',packet_run='packet',byte_run='byte',flow_run='flow',
                                   output_dir=output,comparison_manifest=source,scratch_dir=saved[0]/'data')
    assert not output.exists()


@pytest.mark.parametrize('damage',['missing_parent','wrong_native_parent'])
def test_normalized_parent_mapping_is_derived_from_fixed_selection(narrow,tmp_path,damage):
    state,base,infos=narrow
    for mode in ('packet','byte','flow'):
        path=base/'modes'/mode/'summary.json';data=json.loads(path.read_text())
        if damage=='missing_parent':data['prefixes']=data['prefixes'][1:]
        else:data['prefixes'][0]['native_prefixes']=['198.51.100.0/28']
        path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='normalized24|mapping'):
        analysis().analyze_native_runs(infos,base,tmp_path/'native')


def test_native_provenance_records_actual_inputs_not_old_paths(narrow,tmp_path):
    _,base,infos=narrow
    for mode in ('packet','byte','flow'):
        path=base/'modes'/mode/'summary.json';data=json.loads(path.read_text())
        for record in data['provenance']['inputs'].values():record['path']='/old-location/'+Path(record['path']).name
        path.write_text(json.dumps(data))
    analysis().analyze_native_runs(infos,base,tmp_path/'native')
    summary=json.loads((tmp_path/'native/modes/packet/summary.json').read_text())
    assert summary['provenance']['inputs']['flows']['path']==str(infos['packet'].paths['flows'].resolve())


def test_swapped_mode_summary_is_rejected_even_if_populations_identical(saved,tmp_path):
    source=generate(saved,tmp_path/'base')
    a,b=source.parent/'modes/packet/summary.json',source.parent/'modes/byte/summary.json'
    left,right=a.read_bytes(),b.read_bytes();a.write_bytes(right);b.write_bytes(left)
    infos={m:inspect_run(saved[0],'fixture',m,raw_only=True) for m in ('packet','byte','flow')}
    with pytest.raises(ValueError,match='run|provenance|input'):
        analysis().analyze_native_runs(infos,source.parent,tmp_path/'native')


def test_protocol_integer_spelling_matches_shared_scope_contract(narrow,tmp_path):
    state,_,_=narrow
    flows=pd.read_csv(state[2]['flows'][0],dtype=str);flows['protocol']='006';rewrite(state,'flows',flows)
    base=tmp_path/'baseline';export_raw_statistics(state[0],'fixture','baseline',base/'modes/packet')
    for m in ('byte','flow'):shutil.copytree(base/'modes/packet',base/'modes'/m)
    infos={m:inspect_run(state[0],'fixture','baseline',raw_only=True) for m in ('packet','byte','flow')}
    result=analysis().analyze_native_runs(infos,base,tmp_path/'native')
    assert result['overall']['stats']['flow_count']==5
