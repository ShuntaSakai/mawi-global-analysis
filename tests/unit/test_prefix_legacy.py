from __future__ import annotations

import pandas as pd

from mawi_global_analysis.prefix import legacy_select_prefixes


LEGACY_CONFIG = {
    "prefix_len": 24,
    "min_flows": 100,
    "min_packets": 1000,
    "min_bytes": 100000,
    "max_short_flow_ratio": 0.8,
    "max_tiny_flow_ratio": 0.8,
    "max_syn_only_like_ratio": 0.5,
    "max_rst_observed_ratio": 0.8,
    "short_duration_threshold": 1.0,
    "tiny_packet_threshold": 3,
    "top_k": 10,
    "score_weights": {
        "flow_count": 0.20,
        "packet_count": 0.20,
        "byte_count": 0.20,
        "low_short_flow_ratio": 0.15,
        "low_tiny_flow_ratio": 0.15,
        "low_syn_only_like_ratio": 0.10,
    },
}


def _flows() -> pd.DataFrame:
    rows = [
        {
            "flow_id": flow_id,
            "src_ip": "198.51.100.10",
            "dst_ip": "192.0.2.10",
            "protocol": 6,
            "duration": 2.0,
            "packet_count": 10,
            "byte_count": 1000,
            "syn_from_initiator": 0,
            "synack_from_responder": 0,
            "rst_from_initiator": 0,
            "rst_from_responder": 0,
            "syn_count": 0,
            "ack_count": 0,
            "rst_count": 0,
        }
        for flow_id in range(100)
    ]
    rows.append(
        {
            "flow_id": 100,
            "src_ip": "192.0.2.99",
            "dst_ip": "203.0.113.99",
            "protocol": 6,
            "duration": 0.0,
            "packet_count": 1,
            "byte_count": 58,
            "syn_from_initiator": 1,
            "synack_from_responder": 0,
            "rst_from_initiator": 0,
            "rst_from_responder": 0,
            "syn_count": 1,
            "ack_count": 0,
            "rst_count": 0,
        }
    )
    return pd.DataFrame(rows)


def test_legacy_selection_uses_destination_membership_and_old_filters() -> None:
    """Source-side matches must not enter the destination-only legacy cohort."""
    aguri = pd.DataFrame(
        [
            {"aggregate_id": "1", "src_prefix": "*", "dst_prefix": "192.0.2.0/24"},
            {"aggregate_id": "2", "src_prefix": "*", "dst_prefix": "203.0.113.0/24"},
            {"aggregate_id": "3", "src_prefix": "*", "dst_prefix": "2001:db8::/32"},
            {"aggregate_id": "4", "src_prefix": "*", "dst_prefix": "198.51.0.0/16"},
        ]
    )

    selected = legacy_select_prefixes(aguri, _flows(), LEGACY_CONFIG)

    by_prefix = selected.set_index("normalized_dst_prefix")
    assert by_prefix.loc["192.0.2.0/24", "flow_count"] == 100
    assert by_prefix.loc["192.0.2.0/24", "packet_count"] == 1000
    assert by_prefix.loc["192.0.2.0/24", "byte_count"] == 100000
    assert by_prefix.loc["192.0.2.0/24", "short_flow_ratio"] == 0.0
    assert by_prefix.loc["192.0.2.0/24", "tiny_flow_ratio"] == 0.0
    assert by_prefix.loc["192.0.2.0/24", "syn_only_like_ratio"] == 0.0
    assert bool(by_prefix.loc["192.0.2.0/24", "passes_filters"])
    assert bool(by_prefix.loc["192.0.2.0/24", "selected"])

    assert by_prefix.loc["203.0.113.0/24", "flow_count"] == 1
    assert not bool(by_prefix.loc["203.0.113.0/24", "passes_filters"])
    assert not bool(by_prefix.loc["203.0.113.0/24", "selected"])
    assert by_prefix.loc["2001:db8::/32", "exclusion_reason"] == "no_matching_flows"
    assert by_prefix.loc["198.51.0.0/16", "exclusion_reason"] == "no_matching_flows"


def test_legacy_score_ranks_all_evaluated_prefixes_before_filtering() -> None:
    """Old percentile volumes include failed candidates before the filter is applied."""
    aguri = pd.DataFrame(
        [
            {"aggregate_id": "1", "src_prefix": "*", "dst_prefix": "192.0.2.0/24"},
            {"aggregate_id": "2", "src_prefix": "*", "dst_prefix": "203.0.113.0/24"},
        ]
    )
    flows = _flows()
    flows.loc[flows["dst_ip"] == "203.0.113.99", "packet_count"] = 2000
    flows.loc[flows["dst_ip"] == "203.0.113.99", "byte_count"] = 200000

    selected = legacy_select_prefixes(aguri, flows, LEGACY_CONFIG)

    by_prefix = selected.set_index("normalized_dst_prefix")
    assert by_prefix.loc["192.0.2.0/24", "score"] == 0.80
    assert by_prefix.loc["203.0.113.0/24", "score"] == 0.75


def test_legacy_skips_invalid_candidates_and_uses_numeric_tcp_protocol_only() -> None:
    """These are observable old-script behaviors, not corrected-mode choices."""
    aguri = pd.DataFrame(
        [
            {"aggregate_id": "1", "src_prefix": "*", "dst_prefix": "192.0.2.0/24"},
            {"aggregate_id": "2", "src_prefix": "*", "dst_prefix": "not-a-prefix"},
    ]
    )
    flows = _flows()
    flows["protocol"] = flows["protocol"].astype(object)
    flows.loc[flows["dst_ip"] == "192.0.2.10", "protocol"] = "TCP"
    flows.loc[flows["dst_ip"] == "192.0.2.10", "packet_count"] = 1
    flows.loc[flows["dst_ip"] == "192.0.2.10", "duration"] = 2.0
    flows.loc[flows["dst_ip"] == "192.0.2.10", "syn_count"] = 1

    selection = legacy_select_prefixes(aguri, flows, LEGACY_CONFIG)

    assert selection["normalized_dst_prefix"].tolist() == ["192.0.2.0/24"]
    assert selection.iloc[0]["syn_only_like_ratio"] == 0.0


def test_legacy_syn_only_like_uses_the_old_exact_protocol_text_comparison() -> None:
    """Only the old CSV spelling `6` qualifies; numeric coercion is not faithful."""
    aguri = pd.DataFrame(
        [{"aggregate_id": "1", "src_prefix": "*", "dst_prefix": "192.0.2.0/24"}]
    )
    flows = _flows().iloc[:4].copy()
    flows["protocol"] = ["6", "TCP", "6.0", "06"]
    flows["packet_count"] = 1
    flows["syn_count"] = 1
    flows["ack_count"] = 0

    selection = legacy_select_prefixes(aguri, flows, LEGACY_CONFIG)

    assert selection.iloc[0]["syn_only_like_ratio"] == 0.25
