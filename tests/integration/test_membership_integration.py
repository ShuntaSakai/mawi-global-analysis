from __future__ import annotations

import importlib
import importlib.util

import pandas as pd

from mawi_global_analysis.prefix import build_corrected_prefix_ledger


CORRECTED_CONFIG = {"min_prefix_length": 24}


def _build_membership():
    """Load the public membership builder after making a missing module a RED failure."""
    module_name = "mawi_global_analysis.membership"
    assert importlib.util.find_spec(module_name) is not None, (
        "Task 10 membership module must provide build_membership"
    )
    return importlib.import_module(module_name).build_membership


def test_membership_uses_only_selected_corrected_prefixes_and_shared_normalized_scope() -> None:
    """Selection exclusions must not become traffic scopes, and sibling /25s share one /24."""
    ledger = build_corrected_prefix_ledger(
        pd.DataFrame(
            [
                {"src_prefix": "203.0.113.0/25", "dst_prefix": "203.0.113.128/25"},
                {"src_prefix": "198.51.100.0/23", "dst_prefix": "*"},
            ]
        ),
        CORRECTED_CONFIG,
    )
    flows = pd.DataFrame(
        [
            {
                "flow_id": "selected-scope",
                "src_ip": "203.0.113.10",
                "dst_ip": "203.0.113.200",
            },
            {
                "flow_id": "excluded-broader-scope",
                "src_ip": "198.51.100.10",
                "dst_ip": "198.51.101.10",
            },
        ]
    )

    membership = _build_membership()(flows, ledger)

    assert set(membership["flow_id"]) == {"selected-scope"}
    assert membership.loc[
        membership["analysis_scope"] == "normalized_24", "analysis_prefix"
    ].tolist() == ["203.0.113.0/24"]
