"""Per-prefix rendering uses synthetic exact counts, never real MAWI evidence."""
import csv
import importlib
import json
import re
from pathlib import Path

import pytest
from test_rls_weight_comparison import binary, saved, tree_state
from test_rls_weight_comparison_generation import generate, generation


def builder():
    return importlib.import_module('mawi_global_analysis.rls_weight_comparison.prefix_ecdf')


def embedded(path):
    return json.loads(re.search(r'<script id="dashboard-data" type="application/json">(.*?)</script>',
                               path.read_text(),re.S)[1])


def write_modes(base, records):
    for mode in ('packet','byte','flow'):
        folder=base/'modes'/mode
        folder.mkdir(parents=True)
        with (folder/'frequencies.csv').open('w',newline='') as stream:
            writer=csv.writer(stream)
            writer.writerow(('distribution','packet_count','frequency'))
            writer.writerows(records.get(mode,[]))


def cards(*names, modes=('packet','byte','flow'), count=4, packets=14):
    return [dict(prefix_24=p,modes=list(modes),stats={'flow_count':count,'packet_total':packets}) for p in names]


def test_exact_prefix_curves_use_integer_counts_and_retain_distinct_values(tmp_path):
    p='192.0.2.0/24'
    rows=[(p,1,2),(p,5,1),(p,7,1)]
    write_modes(tmp_path,dict.fromkeys(('packet','byte','flow'),rows))
    got=builder().build_prefix_ecdfs(tmp_path,cards(p))
    c=got['curves'][p]
    points=json.loads(c['encoded_points'])
    assert [(r['packet_count'],r['frequency'],r['cumulative_count']) for r in points] == [
        ('1','2','2'),('5','1','3'),('7','1','4')]
    assert points[-1]['cumulative_fraction']==1
    assert sum(int(r['frequency']) for r in points)==4
    assert c['exact_point_count']==3 and not c['simplified']
    assert got['prefix_count']==1  # shared by three modes, one stored curve


@pytest.mark.parametrize('bad,reason', [([(1,2),(6,2)],'frequencies differ'),
                                      ([(1,2),(5,1)],'flow_count'),
                                      ([(1,2),(5,1),(8,1)],'packet_total')])
def test_same_prefix_must_have_same_exact_frequency_shape(tmp_path,bad,reason):
    p='192.0.2.0/24'
    records={'packet':[(p,1,2),(p,5,1),(p,7,1)],'byte':[(p,x,n) for x,n in bad]}
    write_modes(tmp_path,records)
    with pytest.raises(ValueError,match=reason):
        builder().build_prefix_ecdfs(tmp_path,cards(p,modes=('packet','byte')))


def test_budget_keeps_endpoints_and_conserves_exact_source(tmp_path):
    p='192.0.2.0/24'
    rows=[(p,i,1) for i in range(1,501)]
    write_modes(tmp_path,{'packet':rows})
    path=tmp_path/'modes/packet/frequencies.csv'
    before=path.read_bytes()
    result=builder().build_prefix_ecdfs(tmp_path,cards(p,modes=('packet',),count=500,packets=125250))
    curve=result['curves'][p];points=json.loads(curve['encoded_points'])
    assert len(points)==200 and curve['simplified']
    assert points[0]['packet_count']=='1' and points[-1]['packet_count']=='500'
    assert points[-1]['cumulative_count']=='500' and points[-1]['cumulative_fraction']==1
    assert path.read_bytes()==before
    assert builder().display_limit(2000)==100
    assert builder().display_limit(200000)==2


def test_empty_prefix_has_no_points_or_undefined_one(tmp_path):
    p='192.0.2.0/24'
    write_modes(tmp_path,{})
    result=builder().build_prefix_ecdfs(tmp_path,cards(p,count=0,packets=0))
    assert json.loads(result['curves'][p]['encoded_points'])==[]
    assert result['curves'][p]['error_bound'] is None


def test_generation_and_refresh_preserve_research_outputs(saved,tmp_path,monkeypatch):
    original=tmp_path/'original'
    source=generate(saved,original)
    original_state=tree_state(original)
    old=embedded(original/'dashboard.html')
    assert old['per_prefix_ecdf']['curves']
    # Saved-bundle refresh must not touch input runs or invoke phase-2 analysis.
    monkeypatch.setattr(generation(),'export_raw_statistics',lambda *a,**k: pytest.fail('canonical reanalysis'))
    refresh=importlib.import_module('mawi_global_analysis.rls_weight_comparison.refresh').refresh_dashboard
    output=tmp_path/'refreshed'
    manifest=refresh(source,output)
    assert tree_state(original)==original_state
    data=embedded(output/'dashboard.html')
    assert data['ecdf']==old['ecdf']
    assert data['prefixes']==old['prefixes'] and data['modes']==old['modes']
    for path in original.rglob('*'):
        if path.is_file() and path.name not in ('dashboard.html','comparison_manifest.json'):
            assert path.read_bytes()==(output/path.relative_to(original)).read_bytes()
    verified=generation().verify_comparison_manifest(manifest)
    assert verified['dashboard_refresh']['source_manifest_sha256']
    assert 'generation.py' in verified['dashboard_refresh']['implementation_sha256']
    assert 'cli.py' in verified['dashboard_refresh']['implementation_sha256']
    assert verified['schemas']['per_prefix_ecdf']=='rls-per-prefix-ecdf-v1'
    with pytest.raises(FileExistsError): refresh(source,output)
    # Corrupted source is rejected before creating output/parent.
    with (original/'modes/packet/frequencies.csv').open('a') as s:s.write('bad\n')
    with pytest.raises(ValueError,match='SHA-256'):
        refresh(source,tmp_path/'absent'/'no-output')
    assert not (tmp_path/'absent').exists()


def test_refresh_cli_requires_no_canonical_root(saved,tmp_path):
    from mawi_global_analysis.rls_weight_comparison.cli import main
    source=generate(saved,tmp_path/'source')
    output=tmp_path/'fresh'
    assert main(['--from-comparison',str(source),'--output-dir',str(output)])==0
    assert (output/'dashboard.html').exists()


# Reuse a canonical fixture containing one flow whose BOTH endpoints are in B,
# and another flow shared by A and B. The phase-2 export remains the only
# population aggregator; the display layer must keep these counts unchanged.
from test_normalized24 import saved as normalized_saved


def test_display_preserves_both_endpoint_dedup_and_cross_prefix_overlap(normalized_saved,tmp_path):
    import shutil
    from mawi_global_analysis.normalized24 import export_raw_statistics
    base=tmp_path/'bundle'
    summary=export_raw_statistics(normalized_saved[0],'fixture','baseline',base/'modes/packet')
    payload=json.loads(summary.read_text())
    for mode in ('byte','flow'):
        shutil.copytree(summary.parent,base/'modes'/mode)
    records=[dict(prefix_24=p['prefix'],modes=['packet','byte','flow'],stats=p['stats']) for p in payload['prefixes']]
    curves=builder().build_prefix_ecdfs(base,records)['curves']
    b=json.loads(curves['198.51.100.0/24']['encoded_points'])
    assert [(p['packet_count'],p['frequency']) for p in b]==[('4','1'),('10','1')]
    assert b[-1]['cumulative_count']=='2' and b[-1]['cumulative_fraction']==1
    a=json.loads(curves['192.0.2.0/24']['encoded_points'])
    assert [(p['packet_count'],p['frequency']) for p in a]==[('1','1'),('2','1'),('10','1')]
    # Individual total is 5, while union has 4 unique flows: never mix them.
    assert int(a[-1]['cumulative_count'])+int(b[-1]['cumulative_count'])==5
    assert payload['references'][0]['stats']['flow_count']==4


@pytest.mark.parametrize('rows', [ [('192.0.2.0/24',1,0)],
                                  [('192.0.2.0/24',1,2),('192.0.2.0/24',1,2)],
                                  [('203.0.113.0/24',1,4)] ])
def test_malformed_saved_frequencies_are_rejected(tmp_path,rows):
    write_modes(tmp_path,{'packet':rows})
    with pytest.raises(ValueError):
        builder().build_prefix_ecdfs(tmp_path,cards('192.0.2.0/24',modes=('packet',)))


def test_refresh_source_changes_prevent_publication(saved,tmp_path,monkeypatch):
    source=generate(saved,tmp_path/'source')
    module=importlib.import_module('mawi_global_analysis.rls_weight_comparison.refresh')
    real=module.build_prefix_ecdfs
    def change(*a,**k):
        result=real(*a,**k)
        with source.with_name('ecdf_counts.csv').open('a') as stream:stream.write('changed\n')
        return result
    monkeypatch.setattr(module,'build_prefix_ecdfs',change)
    output=tmp_path/'no-publication'
    with pytest.raises(ValueError,match='SHA-256'):module.refresh_dashboard(source,output)
    assert not output.exists()


def test_refresh_rejects_alias_paths_without_writing_outside_staging(saved,tmp_path):
    source=generate(saved,tmp_path/'source')
    manifest=json.loads(source.read_text())
    manifest['artifacts']['../source/selection_summary.csv']=manifest['artifacts']['selection_summary.csv']
    source.write_text(json.dumps(manifest))
    sentinel=tmp_path/'elsewhere/source/selection_summary.csv'
    sentinel.parent.mkdir(parents=True);sentinel.write_text('unrelated user data\n')
    refresh=importlib.import_module('mawi_global_analysis.rls_weight_comparison.refresh').refresh_dashboard
    error=None
    try:refresh(source,tmp_path/'elsewhere/new')
    except Exception as exc:error=exc
    assert sentinel.read_text()=='unrelated user data\n'
    assert isinstance(error,ValueError)
    assert not (tmp_path/'elsewhere/new').exists()


def test_refresh_reads_only_hash_verified_staged_snapshot(saved,tmp_path,monkeypatch):
    source=generate(saved,tmp_path/'source')
    module=importlib.import_module('mawi_global_analysis.rls_weight_comparison.refresh')
    html=source.with_name('dashboard.html');original=html.read_text()
    payload=embedded(html);payload['ecdf']['overall_ipv4']['points'][0]['cumulative_fraction']=.123
    tampered=re.sub(r'(<script id="dashboard-data" type="application/json">).*?(</script>)',
                    lambda m:m[1]+json.dumps(payload)+m[2],original,flags=re.S)
    real_verify=module.verify_comparison_manifest;real_build=module.build_prefix_ecdfs;calls=0
    def alter_after_validation(path):
        nonlocal calls
        result=real_verify(path);calls+=1
        if calls==1:html.write_text(tampered)
        return result
    def restore_before_final_check(*a,**k):
        result=real_build(*a,**k);html.write_text(original);return result
    monkeypatch.setattr(module,'verify_comparison_manifest',alter_after_validation)
    monkeypatch.setattr(module,'build_prefix_ecdfs',restore_before_final_check)
    try:
        with pytest.raises(ValueError,match='SHA-256|snapshot'):
            module.refresh_dashboard(source,tmp_path/'unverified-snapshot')
    finally:html.write_text(original)
    assert not (tmp_path/'unverified-snapshot').exists()


@pytest.mark.parametrize('tree',['data','results','notebooks','sources'])
def test_refresh_keeps_recorded_analysis_trees_protected(saved,tmp_path,tree):
    source=generate(saved,tmp_path/'source')
    refresh=importlib.import_module('mawi_global_analysis.rls_weight_comparison.refresh').refresh_dashboard
    with pytest.raises(ValueError):refresh(source,saved[0]/tree/'refreshed')
    assert not (saved[0]/tree/'refreshed').exists()


def test_refresh_rejects_scratch_inside_readonly_source(saved,tmp_path):
    source=generate(saved,tmp_path/'source')
    before=tree_state(source.parent)
    refresh=importlib.import_module('mawi_global_analysis.rls_weight_comparison.refresh').refresh_dashboard
    with pytest.raises(ValueError,match='scratch'):
        refresh(source,tmp_path/'no-write',scratch_dir=source.parent)
    assert tree_state(source.parent)==before
