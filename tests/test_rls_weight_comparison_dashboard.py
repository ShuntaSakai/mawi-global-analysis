"""Offline rendering boundaries; all examples are explicitly synthetic."""
import base64
from copy import deepcopy
import hashlib
from html.parser import HTMLParser
import importlib
import json
import re

import pytest


class Document(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.scripts = []
        self.external = []
        self.csp = None
        self.current = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script':
            self.current = {'attrs': attrs, 'text': ''}
            self.scripts.append(self.current)
        for key in ('src', 'href'):
            if attrs.get(key, '').startswith(('http:', 'https:', '//')):
                self.external.append(attrs[key])
        if tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy':
            self.csp = attrs['content']

    def handle_data(self, text):
        if self.current is not None:
            self.current['text'] += text

    def handle_endtag(self, tag):
        if tag == 'script':
            self.current = None


def render(payload):
    try:
        module = importlib.import_module('mawi_global_analysis.rls_weight_comparison.dashboard')
    except ModuleNotFoundError:
        pytest.fail('comparison dashboard renderer is not implemented')
    return module.render_dashboard(payload)


@pytest.fixture
def sample():
    stats = dict(flow_count='9007199254740993', packet_total='18014398509481987',
                 byte_total='9007199254740993123', mean_packet_count=2.1,
                 median=1, p95=4, one_packet_rate=0.75)
    return {'schema_version': 'rls-weight-comparison-dashboard-v1',
            'dataset_id': 'synthetic-dashboard', 'evidence': 'synthetic fixture only',
            'conditions': {}, 'runs': {},
            'modes': {'packet': {'selected_native_prefix_count': 2,
                                 'normalized_prefix_count': 1, 'stats': stats,
                                 'coverage': {'flow': 0.75, 'packet': 0.5, 'byte': 0.25},
                                 'ks_distance': 0.125, 'ks_numerator': '1', 'ks_denominator': '8'}},
            'overall': {'stats': stats}, 'jaccard': [],
            'prefixes': [{'prefix_24': '192.0.2.0/24', 'modes': ['packet', 'flow'],
                          'native_prefixes': {'packet': ['192.0.2.0/25'], 'flow': ['192.0.2.0/24']},
                          'stats': stats}],
            'ecdf': {'packet': {'total_flow_count': '9007199254740993',
                               'exact_point_count': 3, 'displayed_point_count': 2,
                               'simplified': True, 'error_bound': 0.5,
                               'points': [{'packet_count': '1', 'frequency': '1',
                                           'cumulative_count': '1', 'cumulative_fraction': 0.25},
                                          {'packet_count': '9007199254740993', 'frequency': '2',
                                           'cumulative_count': '9007199254740993', 'cumulative_fraction': 1.0}]}},
            'provenance': {'validation': {}, 'inputs': {}, 'implementation': {},
                           'artifacts': {'ecdf_counts.csv': {'sha256': 'a' * 64, 'row_count': 3}},
                           'display': {}}}


def test_render_is_self_contained_and_exact_payload_is_unchanged(sample):
    before = deepcopy(sample)
    document = Document(render(sample))
    data = next(s for s in document.scripts if s['attrs'].get('id') == 'dashboard-data')
    assert json.loads(data['text']) == sample
    assert sample == before
    assert not document.external
    assert "connect-src 'none'" in document.csp
    assert "default-src 'none'" in document.csp
    executable = [s for s in document.scripts if s['attrs'].get('type') != 'application/json']
    assert len(executable) == 1
    digest = base64.b64encode(hashlib.sha256(executable[0]['text'].encode()).digest()).decode()
    assert "'sha256-" + digest + "'" in document.csp
    assert "'unsafe-inline'" not in document.csp.split('script-src ')[1].split(';')[0]


def test_untrusted_values_cannot_close_script_or_create_markup(sample):
    attack = '</script><script>alert("x")</script><img src=x onerror=alert(1)>&\u2028\u2029'
    sample['dataset_id'] = attack
    sample['prefixes'][0]['prefix_24'] = attack
    html = render(sample)
    document = Document(html)
    assert len(document.scripts) == 2
    assert attack not in html
    embedded = next(s for s in document.scripts if s['attrs'].get('id') == 'dashboard-data')
    assert json.loads(embedded['text'])['dataset_id'] == attack
    assert '\\u003c/script\\u003e' in embedded['text']


def test_payload_marker_in_untrusted_text_is_never_replaced(sample):
    sample['dataset_id'] = '__DASHBOARD_DATA__ __DASHBOARD_SCRIPT_HASH__'
    doc = Document(render(sample))
    embedded = next(s for s in doc.scripts if s['attrs'].get('id') == 'dashboard-data')
    assert json.loads(embedded['text'])['dataset_id'] == sample['dataset_id']


def test_missing_and_null_panels_have_valid_embedded_json():
    document = Document(render({'dataset_id': None, 'modes': None, 'ecdf': None,
                                'prefixes': None, 'provenance': None}))
    data = next(s for s in document.scripts if s['attrs'].get('id') == 'dashboard-data')
    assert json.loads(data['text'])['ecdf'] is None


@pytest.mark.parametrize('bad', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_values_are_rejected_instead_of_emitting_invalid_json(bad):
    with pytest.raises(ValueError):
        render({'stat': bad})


def test_unsafe_python_integers_become_exact_browser_strings_without_mutation(sample):
    sample['modes']['packet']['stats']['packet_total'] = 2**63 + 1
    sample['provenance']['inputs']['large_nested'] = [2**53, -2**63 - 1, 2**53 - 1, True]
    before = deepcopy(sample)
    document = Document(render(sample))
    embedded = next(s for s in document.scripts if s['attrs'].get('id') == 'dashboard-data')
    parsed = json.loads(embedded['text'])
    assert parsed['modes']['packet']['stats']['packet_total'] == '9223372036854775809'
    assert parsed['provenance']['inputs']['large_nested'] == [
        '9007199254740992', '-9223372036854775809', 9007199254740991, True]
    assert sample == before
