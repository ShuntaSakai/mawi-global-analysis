"""Synthetic populations; no MAWI evidence."""
import csv
import importlib
import ipaddress
import sqlite3

import pytest
from mawi_global_analysis.flow_stage import FLOW_COLUMNS


def api():
    try:
        return importlib.import_module('mawi_global_analysis.random_prefix_selection.population')
    except ModuleNotFoundError:
        pytest.fail('random population module missing')


def write_flows(path, rows):
    defaults = dict.fromkeys(FLOW_COLUMNS, '')
    defaults.update(ip_version=4, protocol=6, src_port=1000, dst_port=80,
                    packet_count=2, byte_count=120, frame_byte_count=120,
                    start_time='1775624400', end_time='1775624401')
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=FLOW_COLUMNS); w.writeheader()
        for i, row in enumerate(rows):
            w.writerow({**defaults, 'flow_id': str(i), **row})
    return path


@pytest.mark.parametrize('length', range(24, 33))
def test_parent24_contains_native(length):
    native = ipaddress.ip_network(f'192.0.2.128/{length}', strict=False)
    assert str(api().parent24(str(native))) == '192.0.2.0/24'


@pytest.mark.parametrize('prefix', ['192.0.2.1/24', '192.0.0.0/23', '::/128', 'bad'])
def test_parent_rejects_invalid_or_noncanonical(prefix):
    with pytest.raises(ValueError): api().parent24(prefix)


def test_selected_only_and_strict_flags_counts_duplicates(tmp_path):
    p = tmp_path/'prefixes.csv'
    p.write_text('prefix,selected_for_analysis\n192.0.2.128/25,True\n198.51.100.0/24,False\n')
    assert list(map(str, api().load_selected_prefixes(p, 1))) == ['192.0.2.128/25']
    for text in [p.read_text().replace('True', 'maybe'), p.read_text()+ '192.0.2.128/25,True\n']:
        p.write_text(text)
        with pytest.raises(ValueError): api().load_selected_prefixes(p, 1)
    p.write_text('prefix,selected_for_analysis\n192.0.2.0/24,True\n')
    with pytest.raises(ValueError, match='count'): api().load_selected_prefixes(p, 18)


def test_both_endpoints_deduplicated_ipv4_tcp_udp_only(tmp_path):
    p = write_flows(tmp_path/'flows.csv', [
        dict(src_ip='192.0.2.1', dst_ip='198.51.100.1'),
        dict(src_ip='192.0.2.2', dst_ip='192.0.2.3', protocol=17),
        dict(src_ip='203.0.113.1', dst_ip='203.0.114.1', protocol=1),
        dict(src_ip='2001:db8::1', dst_ip='2001:db8::2', ip_version=6),
    ])
    with sqlite3.connect(':memory:') as db:
        audit = api().build_population(p, db, chunksize=1)
        assert list(api().iter_population(db)) == [ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24')]
        assert audit['input_rows'] == 4 and audit['included_flows'] == 2
    assert str(api().address24('192.0.2.255')) == '192.0.2.0/24'
    assert api().exclusion_set(['192.0.2.128/25'], ['192.0.2.1/32', '198.51.100.0/24']) == (ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'))


@pytest.mark.parametrize('change', [dict(flow_id='0'), dict(src_ip='bad'), dict(byte_count=121), dict(packet_count=0)])
def test_invalid_flows_across_chunks_rejected(tmp_path, change):
    p = write_flows(tmp_path/'flows.csv', [dict(src_ip='192.0.2.1', dst_ip='198.51.100.1'), {'src_ip': '192.0.3.1', 'dst_ip': '198.51.100.2', **change}])
    with sqlite3.connect(':memory:') as db, pytest.raises(ValueError): api().build_population(p, db, chunksize=1)


def test_reversed_duplicate_tuple_rejected(tmp_path):
    p = write_flows(tmp_path/'flows.csv', [dict(src_ip='192.0.2.1', dst_ip='198.51.100.1'), dict(src_ip='198.51.100.1', dst_ip='192.0.2.1', src_port=80, dst_port=1000)])
    with sqlite3.connect(':memory:') as db, pytest.raises(ValueError, match='tuple'): api().build_population(p, db, chunksize=1)


def test_population_order_and_chunk_size_independent(tmp_path):
    rows=[dict(src_ip=f'10.0.{i}.1',dst_ip=f'10.1.{i}.2') for i in range(24)]
    outcomes=[]
    for i,(order,size) in enumerate([(rows,1),(list(reversed(rows)),7),(rows,100)]):
        p=write_flows(tmp_path/f'{i}.csv',order)
        with sqlite3.connect(':memory:') as db:
            api().build_population(p,db,chunksize=size)
            outcomes.append(list(api().iter_population(db)))
    assert outcomes[0]==outcomes[1]==outcomes[2] and len(outcomes[0])==48
