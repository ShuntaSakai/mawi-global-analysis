"""Strict source-run validation, including authentic compiled synthetic runs."""
import csv
import importlib
import json
from ipaddress import IPv4Address
from pathlib import Path
import struct
import pytest
from test_aguri_two_stage_c import compiled_two
from test_random_prefix_population import write_flows
from mawi_global_analysis.aguri_two_stage.stage import run_two_stage
from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_stage import run_flow_stage
from mawi_global_analysis.models import InputContext
from mawi_global_analysis.hashing import sha256_file

ROOT = Path(__file__).resolve().parents[1]


def api():
    try: return importlib.import_module('mawi_global_analysis.random_prefix_selection.validation')
    except ModuleNotFoundError: pytest.fail('random validation module missing')


@pytest.fixture(scope='module')
def source_runs(tmp_path_factory, compiled_two):
    root = tmp_path_factory.mktemp('random-sources')
    flows = root/'canonical'/'flows.csv'; flows.parent.mkdir()
    rows = []
    for i in range(18):
        for j in range(10):
            rows.append(dict(src_ip=f'10.{i}.0.1', dst_ip=f'10.{i}.0.1', src_port=1000+j,
                             packet_count=1000 if i < 15 else 1,
                             byte_count=60000 if i < 15 else 60,
                             frame_byte_count=60000 if i < 15 else 60))
    for i in range(40):
        rows.append(dict(src_ip=f'172.16.{i}.1', dst_ip=f'172.16.{i}.2'))
    write_flows(flows, rows)
    pcap = root/'synthetic.pcap'
    with pcap.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for row in rows:
            n=row.get('packet_count',2)
            ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0,0,64,6,0,
                IPv4Address(row['src_ip']).packed,IPv4Address(row['dst_ip']).packed)
            tcp=struct.pack('!HHIIBBHHH',row.get('src_port',1000),80,0,0,0x50,0x10,0,0,0)
            frame=b'\0'*12+b'\x08\x00'+ip+tcp+b'\0'*6
            for j in range(n):
                stream.write(struct.pack('<IIII',1775624400+(j==n-1),0,60,60)+frame)
    cfg = load_config(ROOT/'configs/baseline.yaml'); capture = sha256_file(pcap)
    # Extract the actual canonical fixture from these bytes, rather than merely
    # assigning a PCAP checksum to handcrafted canonical rows.
    ctx = InputContext(dataset_id='fixture',path=pcap,sha256=capture,size_bytes=pcap.stat().st_size)
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(root)
        flows = run_flow_stage(ctx,cfg)
    for mode in ('flow', 'packet'):
        run_two_stage(root, 'fixture', mode, flows, compiled_two[0], mode=mode, chunksize=31)
    return root, flows


def test_real_synthetic_lineage_has_strict_18_and_15(source_runs):
    root, flows = source_runs
    v = api().validate_inputs(root, 'fixture', flows, 'flow', 'packet')
    assert len(v['runs']['flow']['selected_prefixes']) == 18
    assert len(v['runs']['packet']['selected_prefixes']) == 15
    assert v['source']['csv_sha256'] == sha256_file(flows)
    assert v['input_identity']['pcap_bytes_verified'] is False
    assert api().validate_inputs(root, 'fixture', None, 'flow', 'packet')['source'] == v['source']


@pytest.mark.parametrize('kind', ['count', 'flag', 'capture', 'csv', 'manifest', 'mode'])
def test_altered_source_rejected(source_runs, tmp_path, kind):
    # Copy sources but retain absolute cache/build paths: only the copied run is altered.
    import shutil
    root, flows = source_runs
    new = tmp_path/'root'; shutil.copytree(root/'results', new/'results')
    manifest = new/'results/fixture/flow/run_manifest.json'
    m = json.loads(manifest.read_text())
    if kind in ('count', 'flag'):
        ledger = tmp_path/'prefixes.csv'; ledger.write_bytes(Path(m['artifacts']['prefixes']['path']).read_bytes())
        with ledger.open(newline='') as f: reader=csv.DictReader(f); names=reader.fieldnames; rows=list(reader)
        chosen = next(r for r in rows if r['selected_for_analysis'] == 'True')
        chosen['selected_for_analysis'] = 'False' if kind == 'count' else 'maybe'
        with ledger.open('w', newline='') as f: w=csv.DictWriter(f, fieldnames=names);w.writeheader();w.writerows(rows)
        m['artifacts']['prefixes'].update(path=str(ledger), sha256=sha256_file(ledger))
    elif kind == 'capture': m['input']['sha256'] = 'b'*64
    elif kind == 'csv': m['artifacts']['flows']['sha256'] = 'b'*64
    elif kind == 'manifest': m['artifacts']['flows']['producer']['cache_manifest_sha256'] = 'b'*64
    else: m['selection']['basis'] = 'packet'
    manifest.write_text(json.dumps(m))
    with pytest.raises(ValueError): api().validate_inputs(new, 'fixture', flows, 'flow', 'packet')
