"""Agurim prime: synthetic inputs, never a real MAWI validation."""
from __future__ import annotations

import csv
import importlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import pandas as pd
import pytest

from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_stage import run_flow_stage
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.models import InputContext

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT/'tests/fixtures/pcaps/tcp_patterns.pcap'


def prime():
    try:
        return importlib.import_module('mawi_global_analysis.agurim_prime')
    except ModuleNotFoundError:
        pytest.fail('Agurim prime canonical input adapter is missing')


@pytest.fixture
def canonical(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = InputContext(dataset_id='fixture',path=PCAP,sha256=sha256_file(PCAP),size_bytes=PCAP.stat().st_size)
    flows = run_flow_stage(ctx,load_config(ROOT/'configs/baseline.yaml'))
    return tmp_path, flows


@pytest.fixture(scope='module')
def binary(tmp_path_factory):
    output = tmp_path_factory.mktemp('prime-build')/'build'
    subprocess.run([sys.executable,str(ROOT/'scripts/build_agurim_prime.py'),'--output-dir',str(output)],check=True,capture_output=True)
    return output/'agurim'


def test_adapter_one_record_per_bidirectional_flow_preserves_packet_weights(canonical,tmp_path):
    _, flows = canonical
    path = tmp_path/'flows.bin'
    audit = prime().convert_flows(flows,path)
    data = path.read_bytes()
    assert len(data) == 6*56
    assert audit['included_flows'] == 6
    records = [struct.unpack('!16s16sHHBBHIIII',data[i:i+56]) for i in range(0,len(data),56)]
    source = pd.read_csv(flows)
    source = source.loc[source.ip_version.eq(4)]
    assert [r[-4] for r in records] == source.packet_count.tolist()
    assert [r[-3] for r in records] == source.byte_count.tolist()
    assert any((source.packets_from_src>0)&(source.packets_from_dst>0))
    probe = tmp_path/'probe.bin'
    prime().convert_flows(flows,probe,unit_packets=True)
    assert [struct.unpack('!16s16sHHBBHIIII',probe.read_bytes()[i:i+56])[-4] for i in range(0,len(data),56)] == [1]*6


@pytest.mark.parametrize('kind',['id','tuple','overflow','packet','ip','protocol','time'])
def test_adapter_rejects_ambiguous_or_unrepresentable_rows(canonical,tmp_path,kind):
    _, flows = canonical
    rows = pd.read_csv(flows).astype(object)
    if kind=='id': rows.loc[1,'flow_id']=rows.loc[0,'flow_id']
    if kind=='tuple':
        for col in ('src_ip','src_port','dst_ip','dst_port','protocol'): rows.loc[1,col]=rows.loc[0,col]
    if kind=='overflow': rows.loc[0,'packet_count']=2**32
    if kind=='packet': rows.loc[0,'packet_count']=0
    if kind=='ip': rows.loc[0,'ip_version']=6
    if kind=='protocol': rows.loc[0,'protocol']='bad'
    if kind=='time': rows.loc[0,'end_time']='nan'
    altered=tmp_path/'altered.csv';rows.to_csv(altered,index=False)
    with pytest.raises(ValueError): prime().convert_flows(altered,tmp_path/'must-not-exist.bin')
    assert not (tmp_path/'must-not-exist.bin').exists()


def test_prime_control_probe_and_dashboard_share_exact_aggregation(canonical,binary):
    root,flows=canonical
    api=prime()
    from mawi_global_analysis.normalized24 import analyze_agurim_run
    from mawi_global_analysis.normalized24.dashboard import export_dashboard
    manifests={}
    payloads={}
    for mode in ('flow','packet','byte','unit-packet'):
        path=api.run_prime(root,'fixture',f'prime-{mode}',flows,binary,mode=mode,threshold=10)
        manifests[mode]=json.loads(path.read_text())
        payloads[mode]=analyze_agurim_run(root,'fixture',f'prime-{mode}',chunksize=2)
        assert payloads[mode]['method']==manifests[mode]['selection']['method']
        assert payloads[mode]['references'][1]['stats']['flow_count']==6
        assert payloads[mode]['provenance']['selection']['additional_filters']==[]
    assert payloads['flow']['histogram_spec']==payloads['packet']['histogram_spec']
    assert payloads['flow']['provenance']['normalized_prefixes']==payloads['unit-packet']['provenance']['normalized_prefixes']
    assert payloads['flow']['references']==payloads['unit-packet']['references']
    m=manifests['flow']
    candidates=pd.read_csv(m['artifacts']['agurim_prime_candidates']['path'])
    assert candidates.discounted_flow_count.sum()==6
    cache=json.loads(Path(m['cache']['agurim_prime']['manifest_path']).read_text())
    identity=cache['identity']
    assert identity['basis']=='flow' and identity['input']['flow_fingerprint']
    assert identity['fork']['upstream_commit'] and identity['fork']['patch_sha256']
    assert 'fork_commit' in identity['fork'] and identity['executable_sha256']==sha256_file(binary)
    assert identity['converter_version'] and identity['threshold']==10 and identity['options']
    html=export_dashboard(root,'fixture','prime-flow',root/'exports/agurim-prime-24-raw.html')
    assert 'agurim-prime' in html.read_text()
    before=sha256_file(html)
    with pytest.raises(FileExistsError): export_dashboard(root,'fixture','prime-flow',html)
    assert sha256_file(html)==before
    with pytest.raises(FileExistsError): api.run_prime(root,'fixture','prime-flow',flows,binary,threshold=10)
    # A new run reuses the exact same immutable cache.
    reused=api.run_prime(root,'fixture','reuse',flows,binary,threshold=10)
    reuse_manifest=json.loads(reused.read_text())
    assert reuse_manifest['cache']['agurim_prime']==m['cache']['agurim_prime']
    assert {'name':'agurim_prime','status':'completed'} in m['stages']
    assert {'name':'agurim_prime','status':'reused'} in reuse_manifest['stages']


def test_cache_corruption_and_input_changes_fail_closed(canonical,binary):
    root,flows=canonical
    api=prime()
    path=api.run_prime(root,'fixture','initial',flows,binary)
    m=json.loads(path.read_text())
    candidate=Path(m['artifacts']['agurim_prime_candidates']['path'])
    candidate.write_text(candidate.read_text()+'broken\n')
    with pytest.raises(ValueError,match='cache|checksum'): api.run_prime(root,'fixture','corrupt',flows,binary)
    assert not (root/'results/fixture/corrupt').exists()
    # The canonical manifest is mandatory, not inferred from a bare CSV.
    (flows.parent/'flow_manifest.json').unlink()
    with pytest.raises((ValueError,FileNotFoundError)): api.run_prime(root,'fixture','unbound',flows,binary)


def test_run_lineage_tamper_is_not_mislabelled_as_agurim(canonical,binary):
    root,flows=canonical
    path=prime().run_prime(root,'fixture','prime',flows,binary)
    from mawi_global_analysis.normalized24 import analyze_agurim_run
    m=json.loads(path.read_text());m['selection']['basis']='packet';path.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='prime|selection|basis'): analyze_agurim_run(root,'fixture','prime')


def test_cli_generates_new_raw_html(canonical,binary):
    root,flows=canonical
    output=root/'exports/agurim-prime-24-raw.html'
    result=subprocess.run([sys.executable,'-m','mawi_global_analysis.agurim_prime','--root',str(root),
        '--dataset','fixture','--run','cli','--flows',str(flows),'--agurim',str(binary),'--output',str(output)],
        capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert output.is_file()


def test_raw_pcap_and_canonical_conditions_generate_comparable_raw_views(canonical,binary,tmp_path):
    """Changing input representation and changing weight are separate conditions."""
    import yaml
    from mawi_global_analysis import pipeline
    from mawi_global_analysis.normalized24 import analyze_agurim_run
    from mawi_global_analysis.normalized24.dashboard import export_dashboard
    root,flows=canonical
    source=binary.parent/'src'
    subprocess.run(['make','-C',str(source),'aguri3'],check=True,capture_output=True)
    cfg=load_config(ROOT/'configs/baseline.yaml').model_dump()
    cfg['aguri']['aguri3_executable']=str(source/'aguri3')
    cfg['aguri']['agurim_executable']=str(binary)
    cfgpath=tmp_path/'baseline.yaml';cfgpath.write_text(yaml.safe_dump(cfg))
    args=pipeline.build_parser().parse_args(['--input',str(PCAP),'--dataset-id','fixture',
        '--config',str(cfgpath),'--run-name','raw-pcap'])
    assert pipeline.run_pipeline(args)==0
    old=analyze_agurim_run(root,'fixture','raw-pcap')
    paths={mode:prime().run_prime(root,'fixture',f'canonical-{mode}',flows,binary,mode=mode)
           for mode in ('flow','byte','packet','unit-packet')}
    views={mode:analyze_agurim_run(root,'fixture',f'canonical-{mode}') for mode in paths}
    assert old['method']=='agurim'
    assert old['references'][1]==views['flow']['references'][1]
    assert old['histogram_spec']==views['flow']['histogram_spec']
    # Canonical CSV has six IPv4 flows, including both directions. Raw Aguri
    # represents packet directions separately and also observes the IPv6 flow.
    raw_candidates=pd.read_csv(root/'data/fixture/processed/aguri'/
        json.loads((root/'results/fixture/raw-pcap/run_manifest.json').read_text())['cache']['aguri']['fingerprint']/'aguri_candidates.csv')
    canonical_candidates=pd.read_csv(json.loads(paths['packet'].read_text())['artifacts']['agurim_prime_candidates']['path'])
    assert (raw_candidates.src_prefix.str.contains(':')|raw_candidates.dst_prefix.str.contains(':')).any()
    assert not (canonical_candidates.src_prefix.str.contains(':')|canonical_candidates.dst_prefix.str.contains(':')).any()
    assert raw_candidates.packets.astype(int).sum()>canonical_candidates.discounted_packets.astype(int).sum()
    assert views['flow']['provenance']['normalized_prefixes']==views['unit-packet']['provenance']['normalized_prefixes']
    assert export_dashboard(root,'fixture','raw-pcap',root/'views/agurim-24-raw.html').is_file()
    assert export_dashboard(root,'fixture','canonical-flow',root/'views/agurim-prime-24-raw.html').is_file()


def test_adapter_detects_reversed_tuple_and_allows_explicit_timeout_segments(canonical,tmp_path):
    _,flows=canonical
    rows=pd.read_csv(flows).astype(object)
    for a,b in [('src_ip','dst_ip'),('src_port','dst_port')]:
        rows.loc[1,a],rows.loc[1,b]=rows.loc[0,b],rows.loc[0,a]
    rows.loc[1,'protocol']=rows.loc[0,'protocol']
    altered=tmp_path/'reversed.csv';rows.to_csv(altered,index=False)
    with pytest.raises(ValueError,match='bidirectional'): prime().convert_flows(altered,tmp_path/'bad.bin')
    assert prime().convert_flows(altered,tmp_path/'segments.bin',allow_segments=True)['included_flows']==6


def test_incomplete_canonical_schema_cannot_publish_success(canonical,binary):
    root,flows=canonical
    frame=pd.read_csv(flows).drop(columns=['observed_tcp_pattern'])
    frame.to_csv(flows,index=False)
    with pytest.raises(ValueError,match='columns|header|schema|CSV'):
        prime().run_prime(root,'fixture','incomplete',flows,binary)
    assert not (root/'results/fixture/incomplete').exists()
    assert not (root/'data/fixture/processed/agurim-prime').exists()


def test_weight_change_isolated_from_input_representation(canonical,binary):
    """Same 101 canonical flows: elephant dominates packets; many flows dominate FLOW."""
    root,flows=canonical
    base=pd.read_csv(flows).iloc[0].to_dict()
    rows=[]
    for i in range(101):
        n=1000 if i==0 else 1
        row={**base,'flow_id':f'synthetic-{i}','ip_version':4,'protocol':6,
             'src_ip':'192.0.2.1' if i==0 else f'203.0.113.{i}',
             'dst_ip':'198.51.100.1' if i==0 else f'198.18.0.{i}',
             'src_port':10000+i,'dst_port':80,'packet_count':n,'byte_count':60*n,'frame_byte_count':60*n,
             'packets_from_src':n,'packets_from_dst':0,'bytes_from_src':60*n,'bytes_from_dst':0}
        rows.append(row)
    pd.DataFrame(rows).to_csv(flows,index=False)
    manifest_path=flows.parent/'flow_manifest.json'
    fm=json.loads(manifest_path.read_text());fm['row_count']=101;manifest_path.write_text(json.dumps(fm))
    from mawi_global_analysis.normalized24 import analyze_agurim_run
    selected={}
    for mode in ('flow','packet','byte','unit-packet'):
        prime().run_prime(root,'fixture',mode,flows,binary,mode=mode,threshold=20)
        view=analyze_agurim_run(root,'fixture',mode)
        selected[mode]=view['provenance']['normalized_prefixes']
    assert '203.0.113.0/24' in selected['flow'] and '192.0.2.0/24' not in selected['flow']
    assert '192.0.2.0/24' in selected['packet'] and '203.0.113.0/24' not in selected['packet']
    assert selected['byte']==selected['packet']
    assert selected['unit-packet']==selected['flow']
