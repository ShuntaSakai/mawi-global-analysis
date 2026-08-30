from __future__ import annotations

import pandas as pd
import pytest

from mawi_global_analysis import prefix


CORRECTED_CONFIG = {
    "ip_version": 4,
    "candidate_sources": ["src_prefix", "dst_prefix"],
    "min_prefix_length": 24,
    "containment_strategy": "prefer_broader",
    "membership_mode": "src_or_dst",
    "normalized_24_enabled": True,
    "top_k": None,
}


@pytest.mark.parametrize("invalid_min_prefix_length", [23, 25])
def test_corrected_baseline_requires_minimum_prefix_length_24(
    invalid_min_prefix_length: int,
) -> None:
    """Allowing another minimum would change the fixed corrected-baseline cohort."""
    aguri = pd.DataFrame(
        [{"src_prefix": "198.51.100.0/23", "dst_prefix": "198.51.101.0/24"}]
    )

    with pytest.raises(
        ValueError, match="corrected baseline requires min_prefix_length=24"
    ):
        prefix.build_corrected_prefix_ledger(
            aguri, {**CORRECTED_CONFIG, "min_prefix_length": invalid_min_prefix_length}
        )


def test_corrected_ledger_unions_candidates_and_preserves_provenance() -> None:
    """Removing either Aguri side or counts would lose a concrete candidate fact."""
    aguri = pd.DataFrame(
        [
            {"src_prefix": "203.0.113.0/24", "dst_prefix": "203.0.113.0/24"},
            {"src_prefix": "203.0.113.0/24", "dst_prefix": "198.51.100.0/25"},
            {"src_prefix": "198.51.100.0/23", "dst_prefix": "*"},
            {"src_prefix": "not-a-prefix", "dst_prefix": "2001:db8::/48"},
        ]
    )

    ledger = prefix.build_corrected_prefix_ledger(aguri, CORRECTED_CONFIG).set_index("prefix")

    parent = ledger.loc["203.0.113.0/24"]
    assert bool(parent["seen_as_src_prefix"])
    assert bool(parent["seen_as_dst_prefix"])
    assert parent["aguri_src_occurrence_count"] == 2
    assert parent["aguri_dst_occurrence_count"] == 1
    assert parent["aguri_occurrence_count"] == 3
    assert parent["normalized_prefix_24"] == "203.0.113.0/24"

    broader = ledger.loc["198.51.100.0/23"]
    assert not bool(broader["selected_for_analysis"])
    assert broader["exclusion_reason"] == "broader_than_24"
    assert pd.isna(broader["normalized_prefix_24"])

    ipv6 = ledger.loc["2001:db8::/48"]
    assert not bool(ipv6["selected_for_analysis"])
    assert ipv6["exclusion_reason"] == "outside_ipv4_baseline"
    assert "*" not in ledger.index
    assert "not-a-prefix" not in ledger.index


def test_corrected_ledger_prefers_eligible_parent_and_keeps_non_overlapping_siblings() -> None:
    """Selecting a descendant beside its eligible parent would double-count its scope."""
    aguri = pd.DataFrame(
        [
            {"src_prefix": "192.0.2.0/24", "dst_prefix": "192.0.2.128/25"},
            {"src_prefix": "192.0.2.192/26", "dst_prefix": "198.51.100.0/25"},
            {"src_prefix": "198.51.100.128/25", "dst_prefix": "198.51.101.0/25"},
            {"src_prefix": "198.51.101.128/25", "dst_prefix": "*"},
        ]
    )

    ledger = prefix.build_corrected_prefix_ledger(aguri, CORRECTED_CONFIG).set_index("prefix")

    assert bool(ledger.loc["192.0.2.0/24", "selected_for_analysis"])
    for descendant in ("192.0.2.128/25", "192.0.2.192/26"):
        assert not bool(ledger.loc[descendant, "selected_for_analysis"])
        assert ledger.loc[descendant, "exclusion_reason"] == "covered_by_parent"
        assert ledger.loc[descendant, "covered_by_prefix"] == "192.0.2.0/24"

    for sibling in ("198.51.100.0/25", "198.51.100.128/25", "198.51.101.0/25", "198.51.101.128/25"):
        assert bool(ledger.loc[sibling, "selected_for_analysis"])


def test_corrected_ledger_ignores_top_k_and_flow_feature_settings() -> None:
    """A ranking/filter regression would improperly remove otherwise eligible prefixes."""
    aguri = pd.DataFrame(
        [
            {"src_prefix": "198.51.100.0/25", "dst_prefix": "198.51.100.128/25"},
            {"src_prefix": "203.0.113.0/25", "dst_prefix": "203.0.113.128/25"},
        ]
    )
    config_with_legacy_like_selection_values = {
        **CORRECTED_CONFIG,
        "top_k": 1,
        "short_flow_ratio": 1.0,
        "tiny_flow_ratio": 1.0,
        "scan_like_ratio": 1.0,
    }

    ledger = prefix.build_corrected_prefix_ledger(aguri, config_with_legacy_like_selection_values)

    assert ledger["selected_for_analysis"].sum() == 4
    assert not {"short_flow_ratio", "tiny_flow_ratio", "scan_like_ratio"} & set(ledger.columns)
