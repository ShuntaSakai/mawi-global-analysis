from __future__ import annotations

import importlib
import importlib.util

import pandas as pd
import pytest


def _build_membership():
    """Load the public membership builder after making a missing module a RED failure."""
    module_name = "mawi_global_analysis.membership"
    assert importlib.util.find_spec(module_name) is not None, (
        "Task 10 membership module must provide build_membership"
    )
    return importlib.import_module(module_name).build_membership


def test_membership_records_source_destination_and_both_endpoint_matches() -> None:
    """Using either endpoint is required; canonical direction must remain observable."""
    flows = pd.DataFrame(
        [
            {"flow_id": "source", "src_ip": "203.0.113.10", "dst_ip": "198.51.100.1"},
            {"flow_id": "destination", "src_ip": "198.51.100.2", "dst_ip": "203.0.113.11"},
            {"flow_id": "both", "src_ip": "203.0.113.12", "dst_ip": "203.0.113.13"},
            {"flow_id": "neither", "src_ip": "198.51.100.3", "dst_ip": "198.51.100.4"},
        ]
    )
    prefixes = pd.DataFrame(
        [
            {
                "prefix": "203.0.113.0/24",
                "normalized_prefix_24": "203.0.113.0/24",
                "selected_for_analysis": True,
            }
        ]
    )

    membership = _build_membership()(flows, prefixes)

    assert list(membership.columns) == [
        "flow_id",
        "analysis_scope",
        "analysis_prefix",
        "src_match",
        "dst_match",
    ]
    assert membership.set_index(["flow_id", "analysis_scope"]).to_dict("index") == {
        ("source", "native"): {
            "analysis_prefix": "203.0.113.0/24",
            "src_match": True,
            "dst_match": False,
        },
        ("destination", "native"): {
            "analysis_prefix": "203.0.113.0/24",
            "src_match": False,
            "dst_match": True,
        },
        ("both", "native"): {
            "analysis_prefix": "203.0.113.0/24",
            "src_match": True,
            "dst_match": True,
        },
        ("source", "normalized_24"): {
            "analysis_prefix": "203.0.113.0/24",
            "src_match": True,
            "dst_match": False,
        },
        ("destination", "normalized_24"): {
            "analysis_prefix": "203.0.113.0/24",
            "src_match": False,
            "dst_match": True,
        },
        ("both", "normalized_24"): {
            "analysis_prefix": "203.0.113.0/24",
            "src_match": True,
            "dst_match": True,
        },
    }
    assert "neither" not in set(membership["flow_id"])
    assert not membership.duplicated(
        ["flow_id", "analysis_scope", "analysis_prefix"]
    ).any()


def test_normalized_24_recomputes_membership_beyond_native_subnet() -> None:
    """Relabeling a native /25 would wrongly omit addresses in its containing /24."""
    flows = pd.DataFrame(
        [
            {
                "flow_id": "outside-native-inside-24",
                "src_ip": "203.0.113.200",
                "dst_ip": "198.51.100.1",
            }
        ]
    )
    prefixes = pd.DataFrame(
        [
            {
                "prefix": "203.0.113.0/25",
                "normalized_prefix_24": "203.0.113.0/24",
                "selected_for_analysis": True,
            }
        ]
    )

    membership = _build_membership()(flows, prefixes)

    assert membership.to_dict("records") == [
        {
            "flow_id": "outside-native-inside-24",
            "analysis_scope": "normalized_24",
            "analysis_prefix": "203.0.113.0/24",
            "src_match": True,
            "dst_match": False,
        }
    ]


def test_normalized_24_scope_is_deduplicated_across_selected_native_prefixes() -> None:
    """Two selected /25s must not duplicate their shared full-/24 analysis scope."""
    flows = pd.DataFrame(
        [
            {
                "flow_id": "crosses-siblings",
                "src_ip": "203.0.113.10",
                "dst_ip": "203.0.113.200",
            }
        ]
    )
    prefixes = pd.DataFrame(
        [
            {
                "prefix": "203.0.113.0/25",
                "normalized_prefix_24": "203.0.113.0/24",
                "selected_for_analysis": True,
            },
            {
                "prefix": "203.0.113.128/25",
                "normalized_prefix_24": "203.0.113.0/24",
                "selected_for_analysis": True,
            },
        ]
    )

    membership = _build_membership()(flows, prefixes)

    assert membership.loc[
        membership["analysis_scope"] == "native", "analysis_prefix"
    ].tolist() == ["203.0.113.0/25", "203.0.113.128/25"]
    normalized = membership.loc[membership["analysis_scope"] == "normalized_24"]
    assert normalized.to_dict("records") == [
        {
            "flow_id": "crosses-siblings",
            "analysis_scope": "normalized_24",
            "analysis_prefix": "203.0.113.0/24",
            "src_match": True,
            "dst_match": True,
        }
    ]


def test_membership_rejects_duplicate_canonical_flow_ids() -> None:
    """Duplicate flow IDs would violate the documented membership uniqueness key."""
    flows = pd.DataFrame(
        [
            {"flow_id": "duplicate", "src_ip": "203.0.113.10", "dst_ip": "198.51.100.1"},
            {"flow_id": "duplicate", "src_ip": "198.51.100.2", "dst_ip": "203.0.113.11"},
        ]
    )
    prefixes = pd.DataFrame(
        [
            {
                "prefix": "203.0.113.0/24",
                "normalized_prefix_24": "203.0.113.0/24",
                "selected_for_analysis": True,
            }
        ]
    )

    with pytest.raises(ValueError, match="duplicate canonical flow_id"):
        _build_membership()(flows, prefixes)
