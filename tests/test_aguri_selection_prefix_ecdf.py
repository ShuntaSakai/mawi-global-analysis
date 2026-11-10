"""Exact native-prefix sources and bounded, shared browser curves."""
import csv
import json
from itertools import accumulate

import pytest

from test_aguri_selection_comparison import api


KEYS = ('A', 'B', 'C-packet', 'C-flow')


def fixture(base, entries, frequencies):
    for key in KEYS:
        path = base / 'modes' / key
        path.mkdir(parents=True)
        with (path / 'frequencies.csv').open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(('distribution', 'packet_count', 'frequency'))
            writer.writerows(frequencies.get(key, []))
    return dict(dataset_id='fixture', validation_sha256='validated-inputs',
                selection_conditions={key: {'run_name': key + '-run'} for key in KEYS},
                prefixes=entries)


def entry(prefix, conditions, counts):
    total = sum(n for _, n in counts)
    return dict(prefix=prefix, conditions=conditions,
                stats=dict(flow_count=total, packet_total=sum(p*n for p, n in counts),
                           median=1 if total else None, p95=1 if total else None,
                           one_packet_rate=sum(n for p, n in counts if p==1)/total if total else None))


def test_native_shared_points_and_empty(tmp_path):
    shared, packet, flow, empty = ('192.0.2.1/32', '192.0.2.2/32', '198.51.100.4/30', '203.0.113.5/32')
    counts = [(1, 2), (2, 1), (2**53+1, 1)]
    shared_rows = [(shared, p, n) for p, n in counts]
    summary = fixture(tmp_path, [entry(shared, ['A','B'], counts), entry(packet, ['C-packet'], [(2,1)]),
                                entry(flow, ['C-flow'], [(1,1)]), entry(empty, ['A'], [])],
                      {'A':shared_rows, 'B':shared_rows, 'C-packet':[(packet,2,1)], 'C-flow':[(flow,1,1)]})
    data = api('prefix_ecdf').build_prefix_ecdf_payload(tmp_path, summary)
    assert data['schema_version']=='aguri-selection-prefix-ecdf-v1'
    assert data['dataset_id']=='fixture'
    assert data['conditions']['C-flow']['run_name']=='C-flow-run'
    assert data['conditions']['C-flow']['prefixes']==[flow]
    assert data['conditions']['C-packet']['prefixes']==[packet]
    assert set(data['curves'])=={shared,packet,flow,empty}
    assert data['prefixes'][shared]['conditions']==['A','B']
    assert data['prefixes'][shared]['stats']['one_packet_rate']==0.5
    points = json.loads(data['curves'][shared]['encoded_points'])
    assert [int(p['packet_count']) for p in points]==[p for p, _ in counts]
    assert [int(p['frequency']) for p in points]==[n for _, n in counts]
    assert [int(p['cumulative_count']) for p in points]==list(accumulate(n for _, n in counts))
    assert [p['cumulative_fraction'] for p in points]==[0.5, 0.75, 1]
    assert points[-1]['packet_count']==str(2**53+1)
    assert json.loads(data['curves'][empty]['encoded_points'])==[]
    assert data['curves'][empty]['error_bound'] is None
    assert data['prefixes'][empty]['stats']['median'] is None


@pytest.mark.parametrize(('counts', 'message'), [
    ([(2,2)], 'exact frequencies differ'),
    ([(1,1)], 'flow_count'),
    ([(1,1),(4,1)], 'packet_total'),
])
def test_rejects_inconsistent_frequencies(tmp_path, counts, message):
    p = '192.0.2.1/32'
    reference = [(1,1),(3,1)]
    summary = fixture(tmp_path, [entry(p, ['A','B'], reference)],
                      {'A':[(p,x,n) for x,n in reference], 'B':[(p,x,n) for x,n in counts]})
    with pytest.raises(ValueError, match=message):
        api('prefix_ecdf').build_prefix_ecdf_payload(tmp_path, summary)


def test_many_prefixes_bounded_and_full_frequency_unchanged(tmp_path):
    prefixes = [f'10.{i//256}.{i%256}.1/32' for i in range(1100)]
    sizes = [(i,1) for i in range(1,251)]
    summary = fixture(tmp_path, [entry(prefixes[0], ['A'], sizes), *[entry(p, ['A'], [(1,1)]) for p in prefixes[1:]]],
                      {'A':[(prefixes[0],i,n) for i,n in sizes]+[(p,1,1) for p in prefixes[1:]]})
    csv_file = tmp_path/'modes/A/frequencies.csv'
    original = csv_file.read_bytes()
    data = api('prefix_ecdf').build_prefix_ecdf_payload(tmp_path, summary)
    assert len(data['curves'])==1100
    assert data['displayed_point_count']<=data['point_upper_bound']
    curve = data['curves'][prefixes[0]]
    assert curve['simplified'] and curve['exact_point_count']==250
    points = json.loads(curve['encoded_points'])
    assert len(points)==data['max_points_per_prefix']<250
    assert [points[i]['packet_count'] for i in (0,-1)]==['1','250']
    for point in points:
        assert int(point['cumulative_count'])==int(point['packet_count'])
        assert point['cumulative_fraction']==int(point['cumulative_count'])/250
    width = max(int(b['cumulative_count'])-int(a['cumulative_count']) for a,b in zip(points,points[1:]))
    assert int(curve['error_bound_numerator'])==width and curve['error_bound']==width/250
    assert csv_file.read_bytes()==original



def test_unselected_native_frequency_rows_are_rejected(tmp_path):
    p = '192.0.2.1/32'
    summary = fixture(tmp_path, [entry(p, ['A'], [(1, 1)])],
                      {'A': [(p, 1, 1)], 'B': [(p, 1, 1)]})
    with pytest.raises(ValueError, match='B.*unselected prefix'):
        api('prefix_ecdf').build_prefix_ecdf_payload(tmp_path, summary)
