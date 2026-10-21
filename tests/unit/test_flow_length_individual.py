"""Integer-bin visualizations reuse exact counts; never interpolate coarse bins."""
import importlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytest

from mawi_global_analysis import flow_length as fl


def individual():
    try:
        return importlib.import_module('mawi_global_analysis.flow_length_individual')
    except ModuleNotFoundError:
        pytest.fail('integer-bin individual visualization is not implemented')


@pytest.fixture
def exact_result(tmp_path):
    dataset, run = fl.make_demo_run(tmp_path/'source')
    result = fl.analyze_run(tmp_path/'source',dataset,run,chunksize=2,
                            exact_cache_dir=tmp_path/'exact-cache')
    return tmp_path/'source',dataset,run,tmp_path/'exact-cache',result


def test_exact_cache_reuses_previous_results_without_ingesting_flows(exact_result,monkeypatch):
    root,dataset,run,cache,first=exact_result
    def forbidden(*args,**kwargs):
        pytest.fail('cache hit must not re-ingest large CSVs')
    monkeypatch.setattr(fl,'_ingest',forbidden)
    second=fl.analyze_run(root,dataset,run,exact_cache_dir=cache)
    pd.testing.assert_frame_equal(first.summary,second.summary)
    pd.testing.assert_frame_equal(first.histogram,second.histogram)
    assert first.audit==second.audit
    assert second.exact_counts_path.is_file()


def test_integer_bins_and_hidden_tail_have_exact_known_counts(exact_result):
    result=exact_result[-1]
    data=individual().integer_distribution(result,'192.0.2.0/24',x_max=3)
    assert data.x_max==3
    rows=data.counts.set_index(['group','packet_count'])
    assert rows.loc[('Raw',1),'flow_count']==1
    assert rows.loc[('Raw',2),'flow_count']==1
    assert rows.loc[('Raw',3),'flow_count']==1
    stats=data.statistics.set_index('group')
    assert stats.loc['Raw','outside_flow_count']==2
    assert stats.loc['Raw','outside_rate']==pytest.approx(2/5)
    assert stats.loc['retained','outside_flow_count']==2
    assert stats.loc['retained','outside_rate']==pytest.approx(2/3)
    # The visible fraction uses full group N, not the truncated-range N.
    assert rows.loc[('Raw',1),'percent']==pytest.approx(20)
    assert stats.loc['Raw','median']==3
    assert stats.loc['Raw','p95']==pytest.approx(104859.2)


def test_full_range_keeps_longest_flow_without_allocating_empty_integer_bins(exact_result):
    data=individual().integer_distribution(exact_result[-1],'192.0.2.0/24')
    assert data.x_max==131072
    assert data.statistics.outside_flow_count.sum()==0
    assert 131072 in data.counts.packet_count.values
    assert len(data.counts)<20  # sparse exact counts, not 131072 dense bins


def test_individual_figures_are_three_separate_linear_axes_and_save_pngs(exact_result,tmp_path):
    view=individual().plot_individual_target(exact_result[-1],'192.0.2.0/24',x_max=3,
                                            y_axis='percent',output_dir=tmp_path/'plots')
    assert list(view.figures)==['Raw','removed','retained']
    for group,fig in view.figures.items():
        assert len(fig.axes)==1
        axis=fig.axes[0]
        assert axis.get_xscale()=='linear'
        assert axis.get_yscale()=='linear'
        assert axis.get_xlim()==(.5,3.5)
        assert any('outside' in t.get_text() for t in axis.texts)
        # A rectangle for each occupied integer bin, always width one.
        for collection in axis.collections:
            for polygon in collection.get_paths():
                assert np.ptp(polygon.vertices[:,0])==1
        plt.close(fig)
    assert len(view.saved_paths)==3
    assert all(p.read_bytes().startswith(b'\x89PNG') for p in view.saved_paths)
    with pytest.raises(FileExistsError):
        individual().plot_individual_target(exact_result[-1],'192.0.2.0/24',x_max=3,
                                            y_axis='percent',output_dir=tmp_path/'plots')


def test_empty_selected_prefix_is_kept_and_empty_percent_is_undefined(exact_result):
    data=individual().integer_distribution(exact_result[-1],'203.0.113.7/32')
    assert data.counts.empty
    assert data.statistics.flow_count.sum()==0
    assert data.statistics.outside_rate.isna().all()
    view=individual().plot_individual_target(exact_result[-1],'203.0.113.7/32')
    assert all('No flows' in [t.get_text() for t in f.axes[0].texts] for f in view.figures.values())
    for f in view.figures.values():plt.close(f)


@pytest.mark.parametrize('x_max',[0,-1,1.5,True])
def test_invalid_display_limit_is_rejected(exact_result,x_max):
    with pytest.raises(ValueError,match='X_MAX'):
        individual().integer_distribution(exact_result[-1],'selected_union',x_max=x_max)


def test_old_coarse_histogram_cannot_be_used_as_exact_counts(tmp_path):
    dataset,run=fl.make_demo_run(tmp_path/'source')
    old=fl.analyze_run(tmp_path/'source',dataset,run)
    old.histogram.to_csv(tmp_path/'flow_length_histogram.csv',index=False)
    with pytest.raises(ValueError,match='整数|exact|追加集計'):
        individual().integer_distribution(old,'selected_union')


def test_corrupt_exact_cache_stops_without_silently_reprocessing(exact_result,monkeypatch):
    root,dataset,run,cache,result=exact_result
    with result.exact_counts_path.open('ab') as f:f.write(b'corrupt')
    monkeypatch.setattr(fl,'_ingest',lambda *a,**k:pytest.fail('corruption must stop'))
    with pytest.raises(ValueError,match='checksum|破損'):
        fl.analyze_run(root,dataset,run,exact_cache_dir=cache)


def test_changed_source_invalidates_exact_cache(exact_result,monkeypatch):
    root,dataset,run,cache,result=exact_result
    flows=result.inspection.paths['flows']
    frame=pd.read_csv(flows);frame.loc[0,'packet_count']=2;frame.to_csv(flows,index=False)
    calls=[]; original=fl._ingest
    def ingest(*args,**kwargs):
        calls.append(1);return original(*args,**kwargs)
    monkeypatch.setattr(fl,'_ingest',ingest)
    fresh=fl.analyze_run(root,dataset,run,exact_cache_dir=cache)
    assert calls==[1]
    assert fresh.exact_counts_path!=result.exact_counts_path
    assert result.exact_counts_path.is_file()


def test_generated_notebook_has_one_real_heading_and_code_cell_per_target(exact_result,tmp_path):
    result=exact_result[-1]
    path=individual().write_individual_notebook(result,tmp_path/'individual.ipynb',x_max=3)
    nb=json.loads(path.read_text())
    targets=result.inspection.selected_prefixes+['selected_union','overall_ipv4']
    per_target=[c for c in nb['cells'] if c.get('metadata',{}).get('flow_length_target')]
    assert len(per_target)==2*len(targets)
    for target in targets:
        pair=[c for c in per_target if c['metadata']['flow_length_target']==target]
        assert [c['cell_type'] for c in pair]==['markdown','code']
        assert target in ''.join(pair[0]['source'])
    with pytest.raises(FileExistsError):individual().write_individual_notebook(result,path)
    namespace={'__name__':'__main__'}
    for cell in nb['cells']:
        if cell['cell_type']=='code':exec(''.join(cell['source']),namespace)
    assert namespace['rendered_targets']==targets


def test_integer_histogram_preserves_deduplicated_union(exact_result):
    data=individual().integer_distribution(exact_result[-1],'selected_union',x_max=100)
    assert data.statistics.set_index('group').loc['Raw','flow_count']==7
    assert data.statistics.set_index('group').loc['Raw','outside_flow_count']==1
    assert data.counts.query('group == "Raw"').flow_count.sum()==6


def test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports(tmp_path,monkeypatch):
    root=Path(__file__).parents[2]
    monkeypatch.chdir(root)
    monkeypatch.setenv('MAWI_FLOW_LENGTH_DEMO','1')
    monkeypatch.setenv('MAWI_FLOW_LENGTH_OUTPUT_DIR',str(tmp_path/'legacy-output'))
    monkeypatch.setenv('MAWI_FLOW_LENGTH_INDIVIDUAL_NOTEBOOK',str(tmp_path/'targets.ipynb'))
    monkeypatch.setenv('MAWI_FLOW_LENGTH_INDIVIDUAL_OUTPUT_DIR',str(tmp_path/'linear-png'))
    monkeypatch.setenv('MAWI_FLOW_LENGTH_X_MAX','100')
    notebook=json.loads((root/'notebooks/06_prefix_flow_length_histograms.ipynb').read_text())
    namespace={'__name__':'__main__'}
    for cell in notebook['cells']:
        if cell['cell_type']=='code':exec(''.join(cell['source']),namespace)
    assert (tmp_path/'targets.ipynb').is_file()
    assert len(list((tmp_path/'legacy-output').glob('flow_length_page_*.png')))==2
    assert len(list((tmp_path/'linear-png').glob('individual_*.png')))==3
    report=json.loads((tmp_path/'legacy-output/analysis_manifest.json').read_text())
    assert report['evidence']=='synthetic_demo'
    monkeypatch.setattr(fl,'_ingest',lambda *a,**k:pytest.fail('Notebook rerun re-read flows'))
    analysis=next(c for c in notebook['cells'] if c['cell_type']=='code' and 'result = analyze_run(' in ''.join(c['source']))
    exec(''.join(analysis['source']),namespace)
    assert namespace['result'].exact_counts_path.is_file()


def test_eighteen_ledger_prefixes_generate_twenty_independent_sections(tmp_path):
    root=tmp_path/'source';dataset,run=fl.make_demo_run(root)
    from mawi_global_analysis.config import load_config
    from mawi_global_analysis.prefix import build_corrected_prefix_ledger
    from mawi_global_analysis.membership import build_membership
    selected=['192.0.2.0/24','198.51.100.0/24']+[f'198.19.{i}.0/24' for i in range(16)]
    ledger=build_corrected_prefix_ledger(pd.DataFrame({'src_prefix':selected,'dst_prefix':['*']*18}),load_config(fl.CONFIG_PATH))
    info=fl.inspect_run(root,dataset,run)
    flows=pd.read_csv(info.paths['flows'])
    membership=build_membership(flows,ledger)
    ledger.to_csv(info.paths['prefixes'],index=False)
    membership.to_csv(info.paths['flow_prefix_membership'],index=False)
    manifest=info.manifest
    manifest['artifacts']['prefixes']['row_count']=len(ledger)
    manifest['artifacts']['flow_prefix_membership']['row_count']=len(membership)
    info.manifest_path.write_text(json.dumps(manifest))
    result=fl.analyze_run(root,dataset,run,exact_cache_dir=tmp_path/'cache')
    output=individual().write_individual_notebook(result,tmp_path/'twenty.ipynb')
    cells=json.loads(output.read_text())['cells']
    target_code=[c for c in cells if c['cell_type']=='code' and c['metadata'].get('flow_length_target')]
    assert len(target_code)==20
    assert {c['metadata']['flow_length_target'] for c in target_code}==set(selected+['selected_union','overall_ipv4'])


def test_generated_saved_run_view_loads_only_matching_cache(exact_result,tmp_path,monkeypatch):
    root,dataset,run,cache,old=exact_result
    manifest=old.inspection.manifest
    manifest['evidence_level']='saved_fixture'
    old.inspection.manifest_path.write_text(json.dumps(manifest))
    result=fl.analyze_run(root,dataset,run,exact_cache_dir=cache)
    output=individual().write_individual_notebook(result,tmp_path/'read-only-view.ipynb',x_max=3)
    monkeypatch.setattr(fl,'_ingest',lambda *a,**k:pytest.fail('view must never ingest flows'))
    notebook=json.loads(output.read_text())
    namespace={'__name__':'__main__'}
    for cell in notebook['cells']:
        if cell['cell_type']=='code':exec(''.join(cell['source']),namespace)
    assert namespace['rendered_targets']==result.inspection.selected_prefixes+['selected_union','overall_ipv4']
    # A changed source makes the view stop; it cannot fall back to heavy ingest.
    flows=old.inspection.paths['flows']
    flows.touch()
    setup=next(c for c in notebook['cells'] if c['cell_type']=='code')
    with pytest.raises(ValueError,match='追加集計'):
        exec(''.join(setup['source']),namespace)
    target=next(c for c in notebook['cells'] if c['cell_type']=='code' and c['metadata'].get('flow_length_target'))
    with pytest.raises(RuntimeError,match='結果|再実行|入力'):
        exec(''.join(target['source']),namespace)
