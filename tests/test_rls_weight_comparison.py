"""Real synthetic runs test validation contracts, never MAWI conclusions."""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pandas as pd
import pytest
import yaml

from mawi_global_analysis.agurim_prime import run_prime
from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_stage import run_flow_stage
from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.models import InputContext

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT / 'tests/fixtures/pcaps/tcp_patterns.pcap'


def api():
    try:
        return importlib.import_module('mawi_global_analysis.rls_weight_comparison')
    except ModuleNotFoundError:
        pytest.fail('RLS weight comparison validation API is not implemented')


@pytest.fixture(scope='module')
def binary(tmp_path_factory):
    output = tmp_path_factory.mktemp('weight-validation-build') / 'build'
    subprocess.run([sys.executable, str(ROOT/'scripts/build_agurim_prime.py'),
                    '--output-dir', str(output)], check=True, capture_output=True)
    return output / 'agurim'


@pytest.fixture
def saved(tmp_path, monkeypatch, binary):
    monkeypatch.chdir(tmp_path)
    context = InputContext(dataset_id='fixture', path=PCAP,
                           sha256=sha256_file(PCAP), size_bytes=PCAP.stat().st_size)
    flows = run_flow_stage(context, load_config(ROOT/'configs/baseline.yaml'))
    runs = {}
    for mode in ('packet', 'byte', 'flow'):
        runs[mode] = run_prime(tmp_path, 'fixture', mode, flows, binary,
                               mode=mode, threshold=1, heuristics=2)
    return tmp_path, flows, runs


def validate(saved, **kwargs):
    return api().validate_comparison(saved[0], 'fixture', packet_run='packet',
                                     byte_run='byte', flow_run='flow', **kwargs)


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def edit_config(saved, section, key, value):
    path = saved[2]['byte']
    manifest = read(path)
    cfg = yaml.safe_load(manifest['config']['text'])
    cfg[section][key] = value
    text = yaml.safe_dump(cfg)
    import hashlib
    manifest['config'] = {'text': text, 'hash': hashlib.sha256(text.encode()).hexdigest()}
    write(path, manifest)


def reseal_cache(saved, edit):
    """Keep artifact bindings coherent so semantic guards, not stale hashes, fail."""
    run_path = saved[2]['byte']
    manifest = read(run_path)
    path = Path(manifest['cache']['agurim_prime']['manifest_path'])
    cache = read(path)
    edit(cache)
    fingerprint = stable_json_hash(cache['identity'])
    cache['fingerprint'] = fingerprint
    write(path, cache)
    manifest['cache']['agurim_prime']['fingerprint'] = fingerprint
    manifest['selection']['prime_fingerprint'] = fingerprint
    for name in ('agurim_prime_candidates', 'prefixes', 'flow_prefix_membership'):
        manifest['artifacts'][name]['producer'].update(
            prime_fingerprint=fingerprint, cache_manifest_sha256=sha256_file(path))
    write(run_path, manifest)


def tree_state(root):
    return {str(p.relative_to(root)): (p.is_dir(), p.stat().st_mtime_ns,
            None if p.is_dir() else sha256_file(p)) for p in root.rglob('*')}


def test_accepts_real_three_modes_with_distinct_mode_identities(saved):
    configs = {read(p)['config']['hash'] for p in saved[2].values()}
    fingerprints = {read(p)['selection']['prime_fingerprint'] for p in saved[2].values()}
    assert len(configs) == len(fingerprints) == 3
    result = validate(saved, chunksize=2)
    assert result['status'] == 'valid'
    assert set(result['runs']) == {'packet', 'byte', 'flow'}
    assert result['common']['rls']['threshold_percent'] == 1
    assert result['common']['rls']['disable_heuristics'] == 2
    assert result['common']['evaluation']['endpoint_rule'] == 'src_ip OR dst_ip'
    assert result['common']['evaluation']['union_deduplication'] == 'flow_id'
    assert result['common']['fork']['fork_commit'] is None
    json.dumps(result, allow_nan=False)


def test_accepts_descriptive_metadata_changes(saved):
    edit_config(saved, 'experiment', 'description', 'A different human-readable description')
    assert validate(saved)['status'] == 'valid'


@pytest.mark.parametrize('field,value,diagnostic', [
    ('threshold', 2, 'rls.threshold_percent'),
    ('options', ['-F','-m','byte','-t','1','-n','0'], 'rls.options'),
    ('converter_version', 'different-converter', 'converter_version'),
])
def test_rejects_coherent_but_wrong_rls_conditions(saved, field, value, diagnostic):
    reseal_cache(saved, lambda cache: cache['identity'].__setitem__(field, value))
    with pytest.raises(ValueError, match=diagnostic):
        validate(saved)


@pytest.mark.parametrize('section,key,value,diagnostic', [
    ('prefix','membership_mode','dst_only','prefix.membership_mode'),
    ('prefix','normalized_24_enabled',False,'prefix.normalized_24_enabled'),
    ('prefix','candidate_sources',['dst_prefix'],'prefix.candidate_sources'),
    ('prefix','top_k',1,'prefix.top_k'),
    ('analysis','overall_ip_scope','ipv4_ipv6','analysis.overall_ip_scope'),
    ('flow','inactive_timeout_seconds',10.0,'flow.inactive_timeout_seconds'),
    ('flow','protocols',['tcp'],'flow.protocols'),
    ('scan','broad',{'enabled':True},'scan.broad.enabled'),
])
def test_rejects_config_contract_mismatches(saved, section, key, value, diagnostic):
    edit_config(saved, section, key, value)
    with pytest.raises(ValueError, match=diagnostic):
        validate(saved)


@pytest.mark.parametrize('field', ['basis','method','additional_filters','top_k','endpoint_orientation'])
def test_rejects_wrong_selection_metadata(saved, field):
    path = saved[2]['byte']
    manifest = read(path)
    manifest['selection'][field] = {'basis':'unit-packet','method':'agurim',
        'additional_filters':['top-k'],'top_k':1,'endpoint_orientation':'initiator'}[field]
    write(path, manifest)
    with pytest.raises(ValueError, match='selection.'+field):
        validate(saved)


def test_rejects_other_canonical_csv_even_with_same_row_count_and_capture(saved, binary):
    root, flows, runs = saved
    other = root/'other-input'
    other.mkdir()
    frame = pd.read_csv(flows, dtype={'flow_id':str})
    frame.loc[0,'flow_id'] = 'different-canonical-id'
    frame.to_csv(other/'flows.csv', index=False)
    shutil.copyfile(flows.parent/'flow_manifest.json', other/'flow_manifest.json')
    alternate = run_prime(root, 'fixture', 'other-byte', other/'flows.csv', binary,
                          mode='byte', threshold=1, heuristics=2)
    saved = (root, flows, {**runs, 'byte':alternate})
    with pytest.raises(ValueError, match='canonical.csv_sha256'):
        api().validate_comparison(root,'fixture',packet_run='packet',
                                  byte_run='other-byte',flow_run='flow')


def test_rejects_different_actual_command(saved):
    reseal_cache(saved, lambda c: c['command']['argv'].pop())
    with pytest.raises(ValueError, match='command.argv'):
        validate(saved)


@pytest.mark.parametrize('field', ['patch_sha256','upstream_commit','executable_sha256'])
def test_rejects_fork_identity_mismatch(saved, field):
    reseal_cache(saved, lambda c: c['identity']['fork'].__setitem__(field, '0'*64))
    with pytest.raises(ValueError, match='fork.'+field):
        validate(saved)


def test_rejects_different_selection_implementation(saved):
    path = saved[2]['byte']
    manifest = read(path)
    manifest['implementation_sha256']['membership.py'] = '0'*64
    write(path, manifest)
    with pytest.raises(ValueError, match='implementation_sha256.membership.py'):
        validate(saved)


@pytest.mark.parametrize('artifact', ['prefixes','flow_prefix_membership','agurim_prime_candidates'])
def test_rejects_modified_saved_artifacts(saved, artifact):
    manifest = read(saved[2]['byte'])
    path = Path(manifest['artifacts'][artifact]['path'])
    with path.open('a') as stream:
        stream.write('corrupted\n')
    with pytest.raises(ValueError, match=artifact+'|candidate|checksum'):
        validate(saved)


def test_rejects_corrupt_binary_input(saved):
    manifest = read(saved[2]['byte'])
    path = Path(manifest['cache']['agurim_prime']['manifest_path']).with_name('canonical.bin')
    with path.open('ab') as stream:
        stream.write(b'x')
    with pytest.raises(ValueError, match='binary_input|checksum'):
        validate(saved)


def test_readonly_success_and_failure_do_not_touch_input_tree(saved):
    before = tree_state(saved[0])
    assert validate(saved)['status'] == 'valid'
    assert tree_state(saved[0]) == before
    with pytest.raises(ValueError):
        api().validate_comparison(saved[0],'fixture',packet_run='packet',
                                  byte_run='packet',flow_run='flow')
    assert tree_state(saved[0]) == before


@pytest.mark.parametrize('chunksize', [0, -1, True])
def test_rejects_invalid_chunksize(saved, chunksize):
    with pytest.raises(ValueError, match='chunksize'):
        validate(saved, chunksize=chunksize)


def invoke(saved, *extra, validate_only=True):
    command = [sys.executable,'-m','mawi_global_analysis.rls_weight_comparison',
        '--root',str(saved[0]),'--dataset','fixture','--packet-run','packet',
        '--byte-run','byte','--flow-run','flow']
    if validate_only:
        command.append('--validate-only')
    return subprocess.run([*command,*extra], capture_output=True, text=True,
                          env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})


def test_cli_validates_to_stdout_without_writes(saved):
    before = tree_state(saved[0])
    result = invoke(saved, '--json', '--chunksize', '2')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'valid'
    assert tree_state(saved[0]) == before


def test_cli_failure_names_mode_and_field_without_traceback(saved):
    edit_config(saved,'prefix','membership_mode','dst_only')
    before = tree_state(saved[0])
    result = invoke(saved)
    assert result.returncode == 2
    assert 'byte' in result.stderr and 'prefix.membership_mode' in result.stderr
    assert 'Traceback' not in result.stderr
    assert tree_state(saved[0]) == before


def test_cli_requires_validate_only_and_rejects_output_option(saved):
    result = invoke(saved, validate_only=False)
    assert result.returncode == 2 and '--validate-only' in result.stderr
    output = saved[0]/'should-not-be-created'
    result = invoke(saved,'--output-dir',str(output))
    assert result.returncode == 2
    assert not output.exists()


@pytest.mark.parametrize('threshold,heuristics', [(2,2),(1,0),(1,1)])
def test_rejects_authentic_runs_generated_with_other_parameters(saved, binary, threshold, heuristics):
    root, flows, _ = saved
    run_prime(root,'fixture','other-byte',flows,binary,mode='byte',
              threshold=threshold,heuristics=heuristics)
    with pytest.raises(ValueError, match='byte.*rls.threshold_percent|byte.*rls.options'):
        api().validate_comparison(root,'fixture',packet_run='packet',
                                  byte_run='other-byte',flow_run='flow')


def test_accepts_same_build_bundle_at_another_executable_path(saved, binary):
    root, flows, _ = saved
    copied = root/'copied-build'
    shutil.copytree(binary.parent,copied)
    canonical = root/'copied-canonical'
    canonical.mkdir()
    shutil.copyfile(flows,canonical/'flows.csv')
    shutil.copyfile(flows.parent/'flow_manifest.json',canonical/'flow_manifest.json')
    run_prime(root,'fixture','copied-byte',canonical/'flows.csv',copied/'agurim',mode='byte',heuristics=2)
    result = api().validate_comparison(root,'fixture',packet_run='packet',
                                       byte_run='copied-byte',flow_run='flow')
    assert result['status'] == 'valid'


def test_rejects_changed_actual_executable(saved, binary):
    root, flows, _ = saved
    copied = root/'copied-build'
    shutil.copytree(binary.parent,copied)
    canonical = root/'copied-canonical'
    canonical.mkdir()
    shutil.copyfile(flows,canonical/'flows.csv')
    shutil.copyfile(flows.parent/'flow_manifest.json',canonical/'flow_manifest.json')
    manifest_path = run_prime(root,'fixture','copied-byte',canonical/'flows.csv',copied/'agurim',mode='byte',heuristics=2)
    cache = read(Path(read(manifest_path)['cache']['agurim_prime']['manifest_path']))
    assert cache['command']['argv'][0] == str(copied/'agurim')
    with (copied/'agurim').open('ab') as stream:
        stream.write(b'changed')
    with pytest.raises(ValueError, match='byte.*fork.executable_sha256'):
        api().validate_comparison(root,'fixture',packet_run='packet',
                                  byte_run='copied-byte',flow_run='flow')


def test_rejects_other_flow_manifest_even_with_same_csv(saved, binary):
    root, flows, _ = saved
    other = root/'other-input'
    other.mkdir()
    shutil.copyfile(flows,other/'flows.csv')
    fm = read(flows.parent/'flow_manifest.json')
    fm['extra_note'] = 'different manifest bytes'
    write(other/'flow_manifest.json',fm)
    run_prime(root,'fixture','other-byte',other/'flows.csv',binary,mode='byte',heuristics=2)
    with pytest.raises(ValueError, match='canonical.manifest_sha256'):
        api().validate_comparison(root,'fixture',packet_run='packet',
                                  byte_run='other-byte',flow_run='flow')


def test_rejects_membership_row_count_mismatch(saved):
    path = saved[2]['byte']
    manifest = read(path)
    manifest['artifacts']['flow_prefix_membership']['row_count'] += 1
    write(path,manifest)
    with pytest.raises(ValueError, match='flow_prefix_membership.*row_count'):
        validate(saved)


def test_rejects_normalization_column_mismatch_with_updated_checksums(saved):
    path = saved[2]['byte']
    manifest = read(path)
    entry = manifest['artifacts']['prefixes']
    ledger_path = Path(entry['path'])
    frame = pd.read_csv(ledger_path)
    frame.loc[frame.selected_for_analysis,'normalized_prefix_24'] = '203.0.113.0/24'
    frame.to_csv(ledger_path,index=False)
    entry['sha256'] = sha256_file(ledger_path)
    manifest['artifacts']['flow_prefix_membership']['producer']['prefixes_sha256'] = entry['sha256']
    write(path,manifest)
    with pytest.raises(ValueError, match='normalized_prefix_24'):
        validate(saved)


def test_rejects_hidden_postselection_with_coherent_ledger_hash(saved):
    path = saved[2]['byte']
    manifest = read(path)
    entry = manifest['artifacts']['prefixes']
    ledger_path = Path(entry['path'])
    frame = pd.read_csv(ledger_path)
    frame['selected_for_analysis'] = False
    frame.to_csv(ledger_path,index=False)
    entry['sha256'] = sha256_file(ledger_path)
    manifest['artifacts']['flow_prefix_membership']['producer']['prefixes_sha256'] = entry['sha256']
    write(path,manifest)
    with pytest.raises(ValueError, match='prefixes.corrected_selection'):
        validate(saved)


@pytest.mark.parametrize('arguments', [
    {'dataset_id':'../escape','packet_run':'packet','byte_run':'byte','flow_run':'flow'},
    {'dataset_id':'fixture','packet_run':'../packet','byte_run':'byte','flow_run':'flow'},
])
def test_rejects_path_traversal_before_reading_runs(saved, arguments):
    with pytest.raises(ValueError, match='single nonempty path component'):
        api().validate_comparison(saved[0],**arguments)


@pytest.mark.parametrize('which', ['run_manifest','prime_manifest'])
def test_cli_reports_the_file_kind_for_malformed_json(saved, which):
    path = saved[2]['byte']
    if which == 'prime_manifest':
        path = Path(read(path)['cache']['agurim_prime']['manifest_path'])
    path.write_text('{broken JSON')
    before = tree_state(saved[0])
    result = invoke(saved)
    assert result.returncode == 2
    assert which in result.stderr
    assert 'byte' in result.stderr and 'Traceback' not in result.stderr
    assert tree_state(saved[0]) == before


def test_rejects_non_tcp_udp_ipv4_scope_even_in_coherent_runs(saved, binary):
    root, flows, _ = saved
    canonical = root/'non-tcp-input'
    canonical.mkdir()
    frame = pd.read_csv(flows)
    frame.loc[0,'protocol'] = 1
    frame.to_csv(canonical/'flows.csv',index=False)
    shutil.copyfile(flows.parent/'flow_manifest.json',canonical/'flow_manifest.json')
    names = {mode:f'non-tcp-{mode}' for mode in ('packet','byte','flow')}
    for mode, name in names.items():
        run_prime(root,'fixture',name,canonical/'flows.csv',binary,mode=mode,heuristics=2)
    with pytest.raises(ValueError, match='canonical.protocol'):
        api().validate_comparison(root,'fixture',packet_run=names['packet'],
                                  byte_run=names['byte'],flow_run=names['flow'])


def test_rejects_input_changed_during_validation(saved, monkeypatch):
    module = importlib.import_module('mawi_global_analysis.rls_weight_comparison.validation')
    real_scope = module._validate_scope
    def external_change(info, chunksize):
        audit = real_scope(info,chunksize)
        with info.paths['flows'].open('a') as stream:
            stream.write('\n')
        return audit
    monkeypatch.setattr(module,'_validate_scope',external_change)
    with pytest.raises(ValueError, match='changed_during_validation'):
        validate(saved)


def test_cli_reports_malformed_saved_yaml_without_traceback(saved):
    import hashlib
    path = saved[2]['byte']
    manifest = read(path)
    text = 'prefix: [\n'
    manifest['config'] = {'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()}
    write(path,manifest)
    result = invoke(saved)
    assert result.returncode == 2
    assert 'byte' in result.stderr and 'config.text' in result.stderr
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('field,value', [
    ('unit_packets',True), ('scope','IPv4/IPv6'), ('orientation','initiator'),
])
def test_rejects_contradictory_converter_audit(saved, field, value):
    reseal_cache(saved, lambda c: c['audit'].__setitem__(field,value))
    with pytest.raises(ValueError, match='byte.*canonical.audit.'+field):
        validate(saved)


@pytest.mark.parametrize('audit', [None, []])
def test_cli_rejects_non_object_audit_with_context(saved, audit):
    reseal_cache(saved, lambda c: c.__setitem__('audit',audit))
    before = tree_state(saved[0])
    result = invoke(saved)
    assert result.returncode == 2
    assert 'byte' in result.stderr and 'canonical.audit' in result.stderr
    assert 'Traceback' not in result.stderr
    assert tree_state(saved[0]) == before


@pytest.mark.parametrize('field,value,remove,diagnostic', [
    ('schema_version','unknown-build',False,'build_manifest.schema_version'),
    ('schema_version',None,True,'build_manifest.schema_version'),
    ('fork_identity','0'*64,False,'fork.fork_identity'),
    ('fork_identity',None,True,'fork.fork_identity'),
    ('fork_commit',None,True,'fork.fork_commit'),
    ('compiler',None,True,'fork.compiler'),
    ('compiler_argv',None,True,'fork.compiler_argv'),
])
def test_rejects_coherent_but_invalid_build_provenance(saved, binary, field, value, remove, diagnostic):
    root, flows, _ = saved
    copied = root/'bad-build'
    shutil.copytree(binary.parent,copied)
    build_path = copied/'build_manifest.json'
    build = read(build_path)
    if remove:
        del build[field]
    else:
        build[field] = value
    write(build_path,build)
    names = {mode:f'bad-build-{mode}' for mode in ('packet','byte','flow')}
    for mode, name in names.items():
        run_prime(root,'fixture',name,flows,copied/'agurim',mode=mode,heuristics=2)
    with pytest.raises(ValueError, match=diagnostic):
        api().validate_comparison(root,'fixture',packet_run=names['packet'],
                                  byte_run=names['byte'],flow_run=names['flow'])
