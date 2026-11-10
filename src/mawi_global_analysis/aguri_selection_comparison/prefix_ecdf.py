"""Prepare shared native-prefix display curves from a v2 comparison's exact CSVs."""
from ipaddress import IPv4Network, ip_network
from pathlib import Path

from mawi_global_analysis.rls_weight_comparison.prefix_ecdf import _build_frequency_curves
from .validation import CONDITIONS_V2


SCHEMA = 'aguri-selection-prefix-ecdf-v1'
ARTIFACT = 'prefix_ecdf.json'
DESCRIPTOR = {'path': ARTIFACT, 'schema_version': SCHEMA}


def _prefix_metadata(summary: dict) -> dict:
    selections = summary['selection_conditions']
    if set(selections) != set(CONDITIONS_V2):
        raise ValueError('prefix ECDF requires the four v2 selection conditions')
    conditions = {
        key: {**selections[key], 'prefixes': [],
              'frequencies': f'modes/{key}/frequencies.csv'}
        for key in CONDITIONS_V2
    }
    prefixes = {}
    for row in summary['prefixes']:
        cidr, selected = row['prefix'], row['conditions']
        network = ip_network(cidr)
        if not isinstance(network, IPv4Network) or network.prefixlen < 24 or str(network) != cidr:
            raise ValueError(f'{cidr}: expected a canonical native IPv4 CIDR /24..32')
        if cidr in prefixes:
            raise ValueError(f'{cidr}: duplicate prefix record')
        if not selected or len(set(selected)) != len(selected) or any(key not in conditions for key in selected):
            raise ValueError(f'{cidr}: invalid selection conditions')
        prefixes[cidr] = {'conditions': selected, 'stats': row['stats']}
        for key in selected:
            conditions[key]['prefixes'].append(cidr)

    return dict(
        schema_version=SCHEMA,
        dataset_id=summary['dataset_id'],
        conditions=conditions,
        prefixes=prefixes,
        evaluation=dict(scope='native', group='Raw', membership='src_ip OR dst_ip',
                        deduplication='flow_id per CIDR', x='packet_count',
                        y='cumulative flow fraction', ecdf='right-continuous'),
        provenance=dict(manifest='comparison_manifest.json',
                        validation_sha256=summary['validation_sha256']),
    )


def build_prefix_ecdf_payload(base: Path, summary: dict, *, scratch_dir: Path | None = None) -> dict:
    """Keep one bounded display curve per CIDR and leave exact frequency CSVs intact."""
    payload = _prefix_metadata(summary)
    cards = {
        cidr: {'modes': record['conditions'], 'stats': record['stats']}
        for cidr, record in payload['prefixes'].items()
    }
    display = _build_frequency_curves(base, cards, CONDITIONS_V2, scratch_dir=scratch_dir)
    return {
        **payload, **display,
        'encoding': 'Decode encoded_points as JSON only for the requested CIDR.',
        'sampling': 'Observed-size ranks, both endpoints retained; lower HV steps and next-point upper bound.',
    }


def verify_prefix_ecdf_binding(payload: dict, summary: dict, validation: dict) -> None:
    """Check the sidecar's identity against the verified bundle without decoding points."""
    expected = _prefix_metadata(summary)
    if any(payload.get(key) != value for key, value in expected.items()):
        raise ValueError('prefix ECDF metadata binding mismatch')
    for key, condition in expected['conditions'].items():
        if set(condition['prefixes']) != set(validation['runs'][key]['selected_native_prefixes']):
            raise ValueError(f'{key}: prefix ECDF selection binding mismatch')
    curves = payload.get('curves')
    if not isinstance(curves, dict) or set(curves) != set(expected['prefixes']):
        raise ValueError('prefix ECDF curve binding mismatch')
