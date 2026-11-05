"""Regression reproductions for the independent A/B/C review findings."""
import csv
import json
from pathlib import Path

import pytest
import yaml

from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from test_aguri_selection_comparison import abc, api, save, validate, TARGET


def reseal_prime(root,edit):
    mp=root/'results/fixture/canonical-packet-t1-h2/run_manifest.json';m=json.loads(mp.read_text())
    cp=Path(m['cache']['agurim_prime']['manifest_path']);cache=json.loads(cp.read_text())
    edit(cache,cp.parent);cache['fingerprint']=stable_json_hash(cache['identity']);save(cp,cache)
    fp=cache['fingerprint'];m['cache']['agurim_prime']['fingerprint']=fp;m['selection']['prime_fingerprint']=fp
    for entry in m['artifacts'].values():
        if 'prime_fingerprint' in entry.get('producer',{}):
            entry['producer'].update(prime_fingerprint=fp,cache_manifest_sha256=sha256_file(cp))
    save(mp,m)


def set_old_options(root,condition,options):
    run='baseline' if condition=='A' else 'agurim-ipv4-tcp-udp'
    mp=root/'results/fixture'/run/'run_manifest.json';m=json.loads(mp.read_text())
    config=yaml.safe_load(m['config']['text']);config['aguri']['options']=options
    import hashlib
    text=yaml.safe_dump(config);m['config']={'text':text,'hash':hashlib.sha256(text.encode()).hexdigest()}
    cp=Path(m['cache']['aguri']['manifest_path']);cache=json.loads(cp.read_text())
    cache['options']=options;argv=cache['commands'][0]['argv'];cache['commands'][0]['argv']=[argv[0],*options,*argv[-4:]]
    fp=stable_json_hash(dict(schema_version='aguri-v1',input_sha256=cache['input_sha256'],
        agurim_submodule_sha=cache['agurim_submodule_sha'],executable_sha256={k:v['sha256'] for k,v in cache['executables'].items()},options=options))
    cache['fingerprint']=fp;save(cp,cache);m['cache']['aguri']['fingerprint']=fp
    for entry in m['artifacts'].values():
        if 'aguri_fingerprint' in entry.get('producer',{}):entry['producer'].update(aguri_fingerprint=fp,cache_manifest_sha256=sha256_file(cp))
    save(mp,m)


def test_resealed_binary_must_encode_the_actual_canonical_rows(abc):
    def mutate(cache,folder):
        (folder/'canonical.bin').write_bytes(b'\0'*(6*56))
        cache['artifacts']['binary_input']['sha256']=sha256_file(folder/'canonical.bin')
    reseal_prime(abc,mutate)
    with pytest.raises(ValueError,match='binary|record'):validate(abc)


@pytest.mark.parametrize('field',['included_packets','included_frame_bytes'])
def test_prime_audit_totals_bind_packet_and_byte_weights(abc,field):
    reseal_prime(abc,lambda cache,folder:cache['audit'].__setitem__(field,0))
    with pytest.raises(ValueError,match='audit|binary'):validate(abc)


@pytest.mark.parametrize('option',['-fudp','-dfudp'])
def test_attached_or_clustered_filter_cannot_hide_from_bpf_contract(abc,option):
    set_old_options(abc,'A',[option]);set_old_options(abc,'B',['-f','ip and (tcp or udp)',option])
    with pytest.raises(ValueError,match='BPF|filter|options'):validate(abc)


@pytest.mark.parametrize('field',['src_prefix','dst_prefix'])
def test_ipv6_wildcard_is_not_a_concrete_covering_candidate(tmp_path,field):
    path=tmp_path/'candidates.csv'
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['src_prefix','dst_prefix']);writer.writeheader()
        writer.writerow({'src_prefix':TARGET,'dst_prefix':TARGET,field:'*::'})
    exact,covering=api('analysis')._candidate_focus(path,TARGET)
    assert exact and covering==[TARGET]


def test_gzip_temporary_input_is_explicitly_recorded_only(abc):
    for key,run in [('A','baseline'),('B','agurim-ipv4-tcp-udp')]:
        mp=abc/'results/fixture'/run/'run_manifest.json';m=json.loads(mp.read_text())
        cp=Path(m['cache']['aguri']['manifest_path']);cache=json.loads(cp.read_text())
        m['input']['path']=str(abc/'capture.pcap.gz');cache['commands'][0]['argv'][-3]=str(abc/('temporary-'+key+'.pcap'));save(cp,cache)
        for e in m['artifacts'].values():
            if 'cache_manifest_sha256' in e.get('producer',{}):e['producer']['cache_manifest_sha256']=sha256_file(cp)
        save(mp,m)
    result=validate(abc)
    assert result['ab_config_bpf_only'] is True and result['ab_bpf_only'] is False
    assert result['runs']['A']['capture_input']['verification']=='recorded_gzip_temporary_input_only'
    assert result['runs']['A']['commands'][0]['argv'][-3].endswith('temporary-A.pcap')


def test_available_conflicting_build_manifest_is_rejected(abc):
    save(abc/'bin/build_manifest.json',{'status':'failed','schema_version':'wrong'})
    with pytest.raises(ValueError,match='build|fork'):validate(abc)


def test_missing_fork_commit_record_is_not_inferred(abc):
    reseal_prime(abc,lambda cache,folder:cache['identity']['fork'].pop('fork_commit',None))
    with pytest.raises(ValueError,match='fork_commit|fork'):validate(abc)


def test_reference_match_does_not_claim_original_conference_reproduction(abc,tmp_path):
    ref=tmp_path/'reference';ref.mkdir();(ref/'ids.csv').write_text('flow_id\nf0\nf1\nf3\n')
    (ref/'freq.csv').write_text('packet_count,frequency\n1,1\n4,1\n10,1\n')
    canonical=validate(abc)['common']['canonical']
    save(ref/'legacy_manifest.json',dict(schema_version='society-union-reference-v1',
        canonical_csv_sha256=canonical['csv_sha256'],input_capture_sha256=canonical['capture_sha256'],
        selected_native_prefixes=['192.0.2.0/24'],artifacts={key:{'path':name,'sha256':sha256_file(ref/name)} for key,name in [('flow_ids','ids.csv'),('frequencies','freq.csv')]}))
    path=api('generation').generate(abc,'fixture',tmp_path/'bundle',legacy_reference=ref/'legacy_manifest.json')
    result=json.loads((path.parent/'legacy_comparison.json').read_text())
    assert result['historical_reproduction_verified'] is False
    assert result['supplied_reference_matches'] is True
    assert result['reference_quantile_rule'] is None and not result['statistics_supplied']


def test_complete_recorded_fork_remains_usable_without_build_file(abc):
    (abc/'bin/build_manifest.json').unlink()
    result=validate(abc)
    assert 'unavailable' in result['runs']['C']['build_manifest_verification']


def test_gzip_bundle_keeps_limited_contrast_label(abc,tmp_path):
    for key,run in [('A','baseline'),('B','agurim-ipv4-tcp-udp')]:
        mp=abc/'results/fixture'/run/'run_manifest.json';m=json.loads(mp.read_text());cp=Path(m['cache']['aguri']['manifest_path']);cache=json.loads(cp.read_text())
        m['input']['path']=str(abc/'capture.gz');cache['commands'][0]['argv'][-3]=str(abc/('temp-'+key+'.pcap'));save(cp,cache)
        for e in m['artifacts'].values():
            if 'cache_manifest_sha256' in e.get('producer',{}):e['producer']['cache_manifest_sha256']=sha256_file(cp)
        save(mp,m)
    path=api('generation').generate(abc,'fixture',tmp_path/'bundle')
    assert api('generation').verify_manifest(path)['validation']['ab_bpf_only'] is False


def test_reference_mismatch_preserves_specific_id_and_frequency_evidence(abc,tmp_path):
    ref=tmp_path/'reference';ref.mkdir();(ref/'ids.csv').write_text('flow_id\nf1\nf3\nf4\n')
    (ref/'freq.csv').write_text('packet_count,frequency\n1,1\n2,1\n10,1\n')
    canonical=validate(abc)['common']['canonical']
    save(ref/'legacy_manifest.json',dict(schema_version='society-union-reference-v1',canonical_csv_sha256=canonical['csv_sha256'],
        input_capture_sha256=canonical['capture_sha256'],selected_native_prefixes=['192.0.2.0/24'],
        artifacts={k:{'path':n,'sha256':sha256_file(ref/n)} for k,n in [('flow_ids','ids.csv'),('frequencies','freq.csv')]}))
    path=api('generation').generate(abc,'fixture',tmp_path/'bundle',legacy_reference=ref/'legacy_manifest.json')
    result=json.loads((path.parent/'legacy_comparison.json').read_text())
    assert result['status']=='mismatch' and not result['supplied_reference_matches']
    assert result['reference_only_ids_sample']==['f4'] and result['current_only_ids_sample']==['f0']
    assert len(result['frequency_difference_sample'])==2


def test_manifest_rejects_missing_validation_structure(abc,tmp_path):
    path=api('generation').generate(abc,'fixture',tmp_path/'bundle');m=json.loads(path.read_text())
    m['validation'].pop('runs');m['final_validation'].pop('runs');save(path,m)
    with pytest.raises(ValueError,match='validation'):api('generation').verify_manifest(path)


def test_synthetic_input_is_explicit_in_validation_evidence(abc):
    result=validate(abc)
    assert all(result['runs'][key]['source_evidence']=='synthetic_fixture_only' for key in 'ABC')


def test_reference_distinguishes_float_rounding_from_exact_integer_mismatch(tmp_path):
    import sqlite3
    ref=tmp_path/'reference';ref.mkdir()
    (ref/'ids.csv').write_text('flow_id\na\nb\n');(ref/'freq.csv').write_text('packet_count,frequency\n1,1\n34,1\n')
    record=dict(schema_version='society-union-reference-v1',canonical_csv_sha256='canonical',input_capture_sha256='capture',
        selected_native_prefixes=['192.0.2.0/24'],statistics={'flow_count':2,'p95':32.35},
        artifacts={k:{'path':n,'sha256':sha256_file(ref/n)} for k,n in [('flow_ids','ids.csv'),('frequencies','freq.csv')]})
    path=ref/'manifest.json';save(path,record)
    def compare(stats):
        with sqlite3.connect(':memory:') as db:
            db.executescript("CREATE TABLE unions(condition TEXT,id TEXT); INSERT INTO unions VALUES ('A','a'),('A','b'); CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER); INSERT INTO frequencies VALUES ('A',1,1),('A',34,1);")
            return api('legacy').compare_reference(db,path,{'csv_sha256':'canonical','capture_sha256':'capture'},['192.0.2.0/24'],stats)
    result=compare({'flow_count':2,'p95':1+33*.95})
    assert result['supplied_reference_matches'] and not result['statistics_differences']
    assert result['statistics_rounding_differences']['p95']['reference']==32.35
    assert not compare({'flow_count':3,'p95':1+33*.95})['supplied_reference_matches']
    assert not compare({'flow_count':2,'p95':32.36})['supplied_reference_matches']


@pytest.mark.parametrize('field,value',[('target','192.0.2.9/32'),('dataset_id','wrong')])
def test_manifest_metadata_must_match_hash_bound_summary(abc,tmp_path,field,value):
    path=api('generation').generate(abc,'fixture',tmp_path/'bundle');m=json.loads(path.read_text())
    m[field]=value
    if field=='dataset_id':
        m['validation']['dataset_id']=value;m['final_validation']['dataset_id']=value
    save(path,m)
    with pytest.raises(ValueError,match='summary|binding'):api('generation').verify_manifest(path)
