"""A/B stay fixed; C dispatches by saved schema. Synthetic data only."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pandas as pd
import pytest

from test_aguri_selection_comparison import fixture_root,api,save,state,ROOT
from mawi_global_analysis.aguri_two_stage import run_two_stage

NEW_C='canonical-2stage-packet-t1-h0'

@pytest.fixture(scope='module')
def two_build(tmp_path_factory):
    path=ROOT/'scripts/build_agurim_two_stage.py'
    spec=importlib.util.spec_from_file_location('abc_two_builder',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.build(tmp_path_factory.mktemp('abc-two-build')/'fork',ROOT).parent

@pytest.fixture
def modern(tmp_path,two_build):
    root=fixture_root(tmp_path/'inputs')
    flows=root/'data/fixture/processed/flows/flows.csv'
    run_two_stage(root,'fixture',NEW_C,flows,two_build,mode='packet',chunksize=2)
    return root,flows,two_build


def test_new_c_uses_shared_inspector_readonly_and_does_not_change_ab(modern,monkeypatch):
    root,_,_=modern;v=api('validation');old=v.validate_inputs(root,'fixture');before=state(root)
    shared=v.inspect_two_stage_lineage;calls=[]
    def spy(*args,**kwargs):calls.append(True);return shared(*args,**kwargs)
    monkeypatch.setattr(v,'inspect_two_stage_lineage',spy)
    def forbidden(*args,**kwargs):raise AssertionError('saved comparison must not execute processes')
    monkeypatch.setattr(subprocess,'run',forbidden)
    new=v.validate_inputs(root,'fixture',run_c=NEW_C,chunksize=1)
    assert calls and state(root)==before
    assert new['runs']['A']==old['runs']['A'] and new['runs']['B']==old['runs']['B']
    assert new['common']==old['common']
    c=new['runs']['C'];details=c['selection_details']
    assert details['method']=='aguri-two-stage-packet' and details['heuristics']==0
    assert details['basis']=='packet' and details['threshold_percent']==1
    assert [s['program'] for s in details['stages']]==['aguri3','agurim']
    assert c['canonical_audit']['included_flows']==6
    assert set(c['executable'])=={'aguri3','agurim'}
    assert 'Aguri3' in c['selection_input'] and 'Agurim' in c['selection_input']


def test_legacy_c_remains_available_with_correct_description(tmp_path):
    root=fixture_root(tmp_path/'old');v=api('validation').validate_inputs(root,'fixture')
    details=v['runs']['C']['selection_details']
    assert details['method']=='agurim-canonical-packet' and details['heuristics']==2
    assert details['threshold_percent']==1 and len(details['stages'])==1


@pytest.mark.parametrize('mode,threshold,heuristics',[
    ('byte',1,0),('flow',1,0),('combination',1,0),('packet',2,0),('packet',1,1),('packet',1,2)])
def test_authentic_two_stage_wrong_weight_or_settings_are_rejected(tmp_path,two_build,mode,threshold,heuristics):
    root=fixture_root(tmp_path/'inputs');flows=root/'data/fixture/processed/flows/flows.csv'
    run_two_stage(root,'fixture','other-c',flows,two_build,mode=mode,threshold=threshold,heuristics=heuristics)
    with pytest.raises(ValueError,match='C.*(basis|threshold|heuristics)'):
        api('validation').validate_inputs(root,'fixture',run_c='other-c')


@pytest.mark.parametrize('kind',['intermediate','cache-manifest','run-manifest','prefix-ledger','binary'])
def test_new_c_corrupt_saved_artifacts_are_rejected(modern,kind):
    root,_,_=modern;mp=root/'results/fixture'/NEW_C/'run_manifest.json';m=json.loads(mp.read_text())
    cm_path=Path(m['cache']['aguri_two_stage']['manifest_path']);cm=json.loads(cm_path.read_text())
    if kind=='intermediate':
        p=cm_path.parent/'stage1.agw';p.write_bytes(p.read_bytes()+b'corrupt')
    elif kind=='binary':
        p=cm_path.parent/'canonical.bin';p.write_bytes(p.read_bytes()+b'corrupt')
    elif kind=='cache-manifest':
        cm['identity']['settings']['heuristics']=2;save(cm_path,cm)
    elif kind=='run-manifest':
        m['selection']['method']='agurim-canonical-packet';save(mp,m)
    else:
        p=Path(m['artifacts']['prefixes']['path']);p.write_text(p.read_text().replace('True','False',1))
    with pytest.raises(ValueError,match='C run'):
        api('validation').validate_inputs(root,'fixture',run_c=NEW_C)


def test_new_c_must_use_the_same_canonical_content(tmp_path,two_build):
    root=fixture_root(tmp_path/'inputs');source=root/'data/fixture/processed/flows/flows.csv'
    alternate=tmp_path/'alternate';alternate.mkdir();flows=alternate/'flows.csv'
    rows=pd.read_csv(source);rows.loc[0,'packet_count']+=1;rows.loc[0,'packets_from_src']+=1;rows.to_csv(flows,index=False)
    save(alternate/'flow_manifest.json',json.loads(source.with_name('flow_manifest.json').read_text()))
    run_two_stage(root,'fixture','different-canonical',flows,two_build,mode='packet')
    with pytest.raises(ValueError,match='C.*canonical'):
        api('validation').validate_inputs(root,'fixture',run_c='different-canonical')


@pytest.mark.parametrize('schema',['unsupported-run-v1',None])
def test_unknown_c_schema_does_not_fall_back_to_another_method(modern,schema):
    root,_,_=modern;mp=root/'results/fixture'/NEW_C/'run_manifest.json';m=json.loads(mp.read_text());m['schema_version']=schema;save(mp,m)
    with pytest.raises(ValueError,match='C.*schema'):
        api('validation').validate_inputs(root,'fixture',run_c=NEW_C)


def test_new_c_generation_preserves_ab_results_and_binds_condition_metadata(modern,tmp_path,monkeypatch):
    root,_,_=modern;g=api('generation');old_path=g.generate(root,'fixture',tmp_path/'old-bundle')
    old=json.loads((old_path.parent/'summary.json').read_text());before=state(root)
    def forbidden(*args,**kwargs):raise AssertionError('generation must not execute selectors')
    monkeypatch.setattr(subprocess,'run',forbidden)
    new_path=g.generate(root,'fixture',tmp_path/'new-bundle',run_c=NEW_C,chunksize=1)
    m=g.verify_manifest(new_path);new=json.loads((new_path.parent/'summary.json').read_text())
    assert state(root)==before
    for k in ('A','B'):assert new['conditions'][k]==old['conditions'][k]
    assert new['overall']==old['overall'] and new['components']==old['components']
    for k in ('A','B'):assert (new_path.parent/'modes'/k/'frequencies.csv').read_bytes()==(old_path.parent/'modes'/k/'frequencies.csv').read_bytes()
    assert m['selection_conditions']['C']['details']['heuristics']==0
    assert new['selection_conditions']==m['selection_conditions']
    assert 'aguri_two_stage/validation.py' in m['implementation_sha256']
    html=(new_path.parent/'dashboard.html').read_text()
    assert 'id="selection-description"' in html and 'heuristics=0' in html
    assert 'C：canonical packet Agurim′</p>' not in html
    m['selection_conditions']['C']['details']['heuristics']=2;save(new_path,m)
    with pytest.raises(ValueError,match='selection.*binding'):g.verify_manifest(new_path)


def test_expected_cli_accepts_new_c_without_modifying_saved_runs(modern):
    root,_,_=modern;before=state(root)
    result=subprocess.run([sys.executable,'-m','mawi_global_analysis.aguri_selection_comparison','--root',str(root),'--dataset','fixture',
        '--run-a','baseline','--run-b','agurim-ipv4-tcp-udp','--run-c',NEW_C,'--validate-only','--json'],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)['runs']['C']['selection_details']['heuristics']==0
    assert state(root)==before


def test_new_c_dispatch_does_not_depend_on_run_name(modern):
    root,flows,build=modern
    run_two_stage(root,'fixture','custom-c-name',flows,build,mode='packet')
    c=api('validation').validate_inputs(root,'fixture',run_c='custom-c-name')['runs']['C']
    assert c['selection_details']['heuristics']==0 and c['run_name']=='custom-c-name'


@pytest.mark.parametrize('cache_key,artifact_key',[
    ('aguri_two_stage','aguri_two_stage_candidates'),('agurim_prime','agurim_prime_candidates')])
def test_mixed_c_lineage_is_rejected(modern,cache_key,artifact_key):
    root,_,_=modern
    run='canonical-packet-t1-h2' if cache_key=='aguri_two_stage' else NEW_C
    mp=root/'results/fixture'/run/'run_manifest.json';m=json.loads(mp.read_text())
    m['cache'][cache_key]={};m['artifacts'][artifact_key]={};save(mp,m)
    with pytest.raises(ValueError,match='C.*conflicting'):
        api('validation').validate_inputs(root,'fixture',run_c=run)


def test_pre_extension_v1_bundle_still_verifies(tmp_path):
    from mawi_global_analysis.hashing import sha256_file
    root=fixture_root(tmp_path/'inputs');g=api('generation');mp=g.generate(root,'fixture',tmp_path/'bundle')
    m=json.loads(mp.read_text());summary_path=mp.parent/'summary.json';summary=json.loads(summary_path.read_text())
    m.pop('selection_conditions');summary.pop('selection_conditions');save(summary_path,summary)
    m['artifacts']['summary.json']['sha256']=sha256_file(summary_path)
    for key in ('validation','final_validation'):
        m[key]['runs']['C'].pop('canonical_audit');m[key]['runs']['C'].pop('selection_details')
    save(mp,m)
    assert g.verify_manifest(mp)['status']=='success'
