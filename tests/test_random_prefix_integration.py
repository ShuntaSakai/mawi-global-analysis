import csv
import importlib
import json
from pathlib import Path
import pytest
from test_random_prefix_validation import source_runs, compiled_two
from mawi_global_analysis.hashing import sha256_file


def api():
    try: return importlib.import_module('mawi_global_analysis.random_prefix_selection.run')
    except ModuleNotFoundError: pytest.fail('random run module missing')


def snapshot(root): return {str(p):(sha256_file(p),p.stat().st_mtime_ns) for p in root.rglob('*') if p.is_file()}


def test_random18_artifacts_exclusion_and_independent_verify(source_runs):
    root, flows=source_runs; s=api(); before=snapshot(root)
    path=s.run_random_selection(root,'fixture','random-test',flows,'flow','packet',chunksize=7)
    manifest=json.loads(path.read_text()); artifacts=manifest['artifacts']
    with Path(artifacts['prefixes']['path']).open() as f:
        reader=csv.DictReader(f); names=reader.fieldnames; rows=list(reader)
    assert len(rows)==18
    assert names==['prefix','prefix_length','normalized_prefix_24','selected_for_analysis','analysis_scope','selection_rank','observed_flow_count','observed_packet_count','observed_byte_count']
    assert all(r['prefix'].startswith('172.16.') and r['prefix_length']=='24' and r['analysis_scope']=='native' for r in rows)
    assert all((r['observed_flow_count'],r['observed_packet_count'],r['observed_byte_count'])==('1','2','120') for r in rows)
    assert manifest['population']['original_count']==58
    assert manifest['population']['exclusion_count']==manifest['population']['removed_count']==18
    assert manifest['population']['eligible_count']==40
    assert manifest['input']['sha256']==sha256_file(root/'synthetic.pcap')
    assert s.verify_run(path)['status']=='valid'
    assert all(snapshot(root)[p]==state for p,state in before.items())
    with pytest.raises(FileExistsError): s.run_random_selection(root,'fixture','random-test',flows,'flow','packet')
    again=s.run_random_selection(root,'fixture','random-test-chunk',flows,'flow','packet',chunksize=1)
    other=json.loads(again.read_text())
    assert other['selection']==manifest['selection']
    assert other['artifacts']['prefixes']['sha256']==artifacts['prefixes']['sha256']


@pytest.mark.parametrize('damage', ['prefixes','flow_prefix_membership','selection_population','excluded_prefixes','selection_config'])
def test_tampered_output_rejected(source_runs, damage):
    root, flows=source_runs;s=api()
    path=s.run_random_selection(root,'fixture','tamper-'+damage,flows,'flow','packet')
    m=json.loads(path.read_text()); entry=m['artifacts'][damage]; p=Path(entry['path'])
    p.write_bytes(p.read_bytes()+b'bad\n')
    # Even resigning a hash is insufficient: verify reconstructs expected outputs.
    entry['sha256']=sha256_file(p);path.write_text(json.dumps(m))
    with pytest.raises(ValueError): s.verify_run(path)


def test_failure_before_publication_leaves_no_success(source_runs, monkeypatch):
    root,flows=source_runs;s=api()
    def fail(*args,**kwargs): raise ValueError('intentional validation failure')
    monkeypatch.setattr(s,'_verify_staged',fail)
    with pytest.raises(ValueError, match='intentional'): s.run_random_selection(root,'fixture','failed',flows,'flow','packet')
    assert not (root/'results/fixture/failed').exists()


def test_existing_directory_and_symlink_refused(source_runs):
    root,flows=source_runs;s=api();parent=root/'results/fixture'
    (parent/'empty').mkdir();(parent/'link').symlink_to(parent/'flow', target_is_directory=True)
    for name in ['empty','link']:
        with pytest.raises(FileExistsError):s.run_random_selection(root,'fixture',name,flows,'flow','packet')


def test_shortage_and_wrong_canonical_path_fail_without_success(source_runs,tmp_path):
    root,flows=source_runs;s=api()
    with pytest.raises(ValueError,match='insufficient'):
        s.run_random_selection(root,'fixture','shortage',flows,'flow','packet',count=41)
    assert not (root/'results/fixture/shortage').exists()
    copied=tmp_path/'flows.csv';copied.write_bytes(flows.read_bytes())
    with pytest.raises(ValueError,match='manifest-recorded'):
        s.run_random_selection(root,'fixture','wrong-path',copied,'flow','packet')
    assert not (root/'results/fixture/wrong-path').exists()


def test_publication_link_failure_rolls_back_owned_files(source_runs,monkeypatch):
    from mawi_global_analysis.aguri_two_stage import stage
    root,flows=source_runs;s=api();real=stage.os.link
    def fail(src,dst):
        if Path(dst).name=='run_manifest.json': raise OSError('intentional link failure')
        return real(src,dst)
    monkeypatch.setattr(stage.os,'link',fail)
    with pytest.raises(OSError,match='intentional'):
        s.run_random_selection(root,'fixture','link-failed',flows,'flow','packet')
    assert not (root/'results/fixture/link-failed').exists()


def test_concurrent_destination_is_never_replaced(source_runs,monkeypatch):
    root,flows=source_runs;s=api();real=s.publish;destination=root/'results/fixture/concurrent'
    def race(work,output,completion):
        destination.mkdir();(destination/'owner').write_text('another writer')
        return real(work,output,completion)
    monkeypatch.setattr(s,'publish',race)
    with pytest.raises(FileExistsError):s.run_random_selection(root,'fixture','concurrent',flows,'flow','packet')
    assert (destination/'owner').read_text()=='another writer'
    assert not (destination/'run_manifest.json').exists()


def test_input_mutation_after_staged_validation_prevents_publication(source_runs,monkeypatch):
    root,flows=source_runs;s=api();real=s._verify_staged;original=flows.read_bytes()
    def change_after_check(*args,**kwargs):
        real(*args,**kwargs)
        flows.write_bytes(original+b'\n')
    monkeypatch.setattr(s,'_verify_staged',change_after_check)
    try:
        with pytest.raises(ValueError,match='input changed'):
            s.run_random_selection(root,'fixture','changed-input',flows,'flow','packet')
        assert not (root/'results/fixture/changed-input').exists()
    finally:
        # This fixture is owned by the test, never a repository data artifact.
        flows.write_bytes(original)


def test_verify_rejects_incomplete_status_and_altered_seed(source_runs):
    root,flows=source_runs;s=api()
    path=s.run_random_selection(root,'fixture','bad-manifest',flows,'flow','packet')
    m=json.loads(path.read_text());m['status']='running';path.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='schema/status'):s.verify_run(path)
    m['status']='success';m['selection']['seed']=9;path.write_text(json.dumps(m))
    with pytest.raises(ValueError):s.verify_run(path)


def test_cache_mutation_immediately_after_lineage_check_is_not_rebaselined(source_runs,monkeypatch):
    from mawi_global_analysis.random_prefix_selection import validation
    root,flows=source_runs;s=api();real=validation.inspect_lineage;changed=[]
    def corrupt_after_check(info,*args,**kwargs):
        result=real(info,*args,**kwargs)
        if info.manifest['selection']['basis']=='flow':
            p=Path(result['cache_manifest_path']).parent/'stage1.agw'
            original=p.read_bytes();changed.append((p,original));p.write_bytes(original+b'corrupt')
        return result
    monkeypatch.setattr(validation,'inspect_lineage',corrupt_after_check)
    try:
        with pytest.raises(ValueError,match='changed|checksum'):
            s.run_random_selection(root,'fixture','cache-changed',flows,'flow','packet')
        assert not (root/'results/fixture/cache-changed').exists()
    finally:
        for p,original in changed:p.write_bytes(original)
