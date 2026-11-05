"""Immutable two-stage run contracts over synthetic canonical observations."""
import importlib
import json
from pathlib import Path
import pytest
from test_agurim_prime import canonical
from test_aguri_two_stage_c import compiled_two
from mawi_global_analysis.hashing import sha256_file

MODES=('packet','byte','flow')
def api():return importlib.import_module('mawi_global_analysis.aguri_two_stage')
def state(root):return {str(p.relative_to(root)):(p.stat().st_mtime_ns,sha256_file(p)) for p in root.rglob('*') if p.is_file()}

@pytest.fixture
def runs(canonical,compiled_two):
    root,flows=canonical;build,_=compiled_two
    paths={mode:api().run_two_stage(root,'fixture','two-'+mode,flows,build,mode=mode,chunksize=2) for mode in MODES}
    return root,flows,build,paths

def test_run_executes_both_stages_preserves_counters_and_immutable_cache(runs):
    root,flows,build,paths=runs;before=sha256_file(flows)
    for mode,path in paths.items():
        m=json.loads(path.read_text());cache=json.loads(Path(m['cache']['aguri_two_stage']['manifest_path']).read_text())
        assert m['selection']['basis']==mode and m['selection']['method']=='aguri-two-stage-'+mode
        assert [Path(r['argv'][0]).name for r in cache['commands']]==['aguri3','agurim']
        assert all(r['returncode']==0 for r in cache['commands'])
        assert cache['audits']['stage1']['totals']==cache['audits']['stage2']['totals']=={'packet':13,'byte':711,'flow':6}
        assert cache['identity']['settings']['heuristics']==0 and cache['identity']['settings']['threshold']==1
        snapshot=state(Path(m['cache']['aguri_two_stage']['manifest_path']).parent)
        reused=api().run_two_stage(root,'fixture','reuse-'+mode,flows,build,mode=mode)
        assert json.loads(reused.read_text())['cache']==m['cache']
        assert state(Path(m['cache']['aguri_two_stage']['manifest_path']).parent)==snapshot
    assert sha256_file(flows)==before

def test_three_run_validation_is_read_only_and_mode_specific(runs):
    root,flows,build,paths=runs;before=state(root)
    v=api().validate_runs(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow',chunksize=1)
    assert v['status']=='valid' and v['common']['settings']['heuristics']==0
    assert set(v['runs'])==set(MODES) and state(root)==before

@pytest.mark.parametrize('artifact',['intermediate','binary_input','candidates'])
def test_corrupt_cached_input_or_output_is_rejected(runs,artifact):
    root,flows,build,paths=runs;m=json.loads(paths['flow'].read_text());cp=Path(m['cache']['aguri_two_stage']['manifest_path'])
    cm=json.loads(cp.read_text());file=cp.parent/cm['artifacts'][artifact]['name'];file.write_bytes(file.read_bytes()+b'broken')
    with pytest.raises(ValueError,match='checksum|hash|wire'):api().run_two_stage(root,'fixture','must-fail',flows,build,mode='flow')
    assert not (root/'results/fixture/must-fail').exists()

def test_existing_run_refused_without_changes(runs):
    root,flows,build,_=runs;before=state(root)
    with pytest.raises(FileExistsError):api().run_two_stage(root,'fixture','two-flow',flows,build,mode='flow')
    assert state(root)==before

def test_mixed_method_or_settings_is_not_accepted(runs):
    root,_,_,paths=runs;m=json.loads(paths['flow'].read_text());m['selection']['method']='agurim-prime';paths['flow'].write_text(json.dumps(m))
    with pytest.raises(ValueError,match='method|selection'):api().validate_runs(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow')


def test_saved_evaluation_config_cannot_disagree_with_run_identity(runs):
    import yaml,hashlib
    root,_,_,paths=runs;m=json.loads(paths['flow'].read_text());cfg=yaml.safe_load(m['config']['text']);cfg['scan']['strict']['enabled']=True
    text=yaml.safe_dump(cfg);m['config']={'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()};paths['flow'].write_text(json.dumps(m))
    with pytest.raises(ValueError,match='config|scan'):api().validate_runs(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='two-flow')


def test_stage2_cannot_claim_binary_stdin_instead_of_intermediate(runs):
    root,flows,build,paths=runs;m=json.loads(paths['flow'].read_text());cp=Path(m['cache']['aguri_two_stage']['manifest_path']);cache=json.loads(cp.read_text())
    cache['commands'][1]['stdin']=cache['artifacts']['binary_input'];cp.write_text(json.dumps(cache))
    with pytest.raises(ValueError,match='stage2.*binding'):api().run_two_stage(root,'fixture','wrong-chain',flows,build,mode='flow')


def test_resigned_binary_artifact_still_must_equal_canonical(runs):
    root,flows,build,paths=runs;m=json.loads(paths['flow'].read_text());cp=Path(m['cache']['aguri_two_stage']['manifest_path']);cache=json.loads(cp.read_text())
    binary=cp.parent/'canonical.bin';binary.write_bytes(b'\0'*binary.stat().st_size);cache['artifacts']['binary_input']['sha256']=sha256_file(binary);cp.write_text(json.dumps(cache))
    with pytest.raises(ValueError,match='binary|record'):api().run_two_stage(root,'fixture','resigned',flows,build,mode='flow')


def test_different_hash_limit_is_a_different_comparison_condition(runs):
    root,flows,build,paths=runs
    api().run_two_stage(root,'fixture','other-flow',flows,build,mode='flow',max_hashentries=10)
    with pytest.raises(ValueError,match='common|max_hashentries'):api().validate_runs(root,'fixture',packet_run='two-packet',byte_run='two-byte',flow_run='other-flow')


def test_failed_second_stage_leaves_no_success_cache_or_run(canonical,compiled_two,monkeypatch):
    import subprocess
    from mawi_global_analysis.aguri_two_stage import stage
    root,flows=canonical;build,_=compiled_two;real=stage.subprocess.run
    def fail(argv,**kwargs):
        return subprocess.CompletedProcess(argv,2,stderr=b'intentional synthetic failure') if Path(argv[0]).name=='agurim' else real(argv,**kwargs)
    monkeypatch.setattr(stage.subprocess,'run',fail)
    with pytest.raises(ValueError,match='agurim failed'):api().run_two_stage(root,'fixture','failed',flows,build,mode='flow')
    assert not (root/'results/fixture/failed').exists()
    assert not list((root/'data/fixture/processed/aguri-two-stage').rglob('two_stage_manifest.json'))
