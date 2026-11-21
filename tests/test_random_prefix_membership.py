import csv
import importlib
from ipaddress import IPv4Network
from test_random_prefix_population import write_flows


def test_streamed_or_membership_and_exact_counts(tmp_path):
    import pytest
    try: api=importlib.import_module('mawi_global_analysis.random_prefix_selection.run')
    except ModuleNotFoundError: pytest.fail('random run module missing')
    flows=write_flows(tmp_path/'flows.csv', [dict(src_ip='192.0.2.1',dst_ip='192.0.2.2'),
                                           dict(src_ip='192.0.2.3',dst_ip='198.51.100.1'),
                                           dict(src_ip='203.0.113.1',dst_ip='198.51.100.2', protocol=17),
                                           dict(src_ip='192.0.2.9',dst_ip='198.51.100.9',protocol=1)])
    output=tmp_path/'membership.csv'
    audit=api.write_membership_and_counts(flows, (IPv4Network('192.0.2.0/24'),IPv4Network('198.51.100.0/24')), output, chunksize=1)
    assert audit['counts'] == {'192.0.2.0/24': [2,4,240], '198.51.100.0/24': [2,4,240]}
    with output.open() as f: rows=list(csv.DictReader(f))
    assert len(rows)==8 and len({(r['flow_id'],r['analysis_scope'],r['analysis_prefix']) for r in rows})==8
    assert rows[0]['src_match']==rows[0]['dst_match']=='True'
    assert {r['analysis_scope'] for r in rows}=={'native','normalized_24'}


def test_membership_rejects_global_duplicate_id(tmp_path):
    import pytest
    api=importlib.import_module('mawi_global_analysis.random_prefix_selection.run')
    flows=write_flows(tmp_path/'flows.csv', [dict(src_ip='192.0.2.1',dst_ip='192.0.2.2'),
        dict(src_ip='192.0.2.3',dst_ip='192.0.2.4',flow_id='0')])
    with pytest.raises(ValueError, match='duplicate'):
        api.write_membership_and_counts(flows,(IPv4Network('192.0.2.0/24'),),tmp_path/'m.csv',chunksize=1)
