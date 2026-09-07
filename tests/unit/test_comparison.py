from __future__ import annotations

import pandas as pd
import pytest


def _flows() -> pd.DataFrame:
    return pd.DataFrame({"flow_id": [101, 102, 103, 104]})


def _labels() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "flow_id": [101, 102, 103, 104],
            "strict_removed": [False, True, False, True],
            "broad_removed": [False, True, True, True],
        }
    )


def test_comparison_inclusion_uses_m5_removal_flags() -> None:
    """A wrong removal-flag branch would produce incorrect survivor conditions."""
    from mawi_global_analysis.comparison import build_comparison_flow_inclusion

    inclusion = build_comparison_flow_inclusion(_flows(), _labels())

    assert inclusion.to_dict("list") == {
        "flow_id": [101, 102, 103, 104],
        "raw_included": [True, True, True, True],
        "strict_included": [True, False, True, False],
        "broad_included": [True, False, False, False],
    }


def test_broad_survivors_are_a_subset_of_strict_and_raw_survivors() -> None:
    """A reversed inclusion condition would violate the required nesting."""
    from mawi_global_analysis.comparison import build_comparison_flow_inclusion

    inclusion = build_comparison_flow_inclusion(_flows(), _labels())

    broad_ids = set(inclusion.loc[inclusion["broad_included"], "flow_id"])
    strict_ids = set(inclusion.loc[inclusion["strict_included"], "flow_id"])
    raw_ids = set(inclusion.loc[inclusion["raw_included"], "flow_id"])

    assert broad_ids <= strict_ids <= raw_ids


def test_rejects_m5_removal_invariant_violation() -> None:
    """A strict-only removal would make the comparison conditions invalid."""
    from mawi_global_analysis.comparison import build_comparison_flow_inclusion

    labels = _labels()
    labels.loc[1, "broad_removed"] = False

    with pytest.raises(ValueError, match="strict_removed.*broad_removed"):
        build_comparison_flow_inclusion(_flows(), labels)


def test_rejects_missing_m5_removal_decision() -> None:
    """An unknown removal flag cannot produce a Raw, Strict, or Broad cohort."""
    from mawi_global_analysis.comparison import build_comparison_flow_inclusion

    labels = _labels()
    labels["strict_removed"] = pd.Series(
        [False, pd.NA, False, True], dtype="boolean"
    )

    with pytest.raises(ValueError, match="must not contain missing values"):
        build_comparison_flow_inclusion(_flows(), labels)


def test_rejects_flow_id_mismatch_between_canonical_flows_and_labels() -> None:
    """Missing or extra M5 labels must not silently alter a comparison cohort."""
    from mawi_global_analysis.comparison import build_comparison_flow_inclusion

    labels = _labels()
    labels.loc[3, "flow_id"] = 999

    with pytest.raises(ValueError, match="flow_id sets do not match"):
        build_comparison_flow_inclusion(_flows(), labels)


@pytest.mark.parametrize(
    ("flows", "labels", "message"),
    [
        (
            pd.DataFrame({"flow_id": [101, 101]}),
            _labels(),
            "flows contain duplicate canonical flow_id values",
        ),
        (
            _flows(),
            pd.concat([_labels(), _labels().iloc[[0]]], ignore_index=True),
            "labels contain duplicate flow_id values",
        ),
    ],
)
def test_rejects_duplicate_flow_ids(
    flows: pd.DataFrame, labels: pd.DataFrame, message: str
) -> None:
    """Duplicate identifiers would make an inclusion decision ambiguous."""
    from mawi_global_analysis.comparison import build_comparison_flow_inclusion

    with pytest.raises(ValueError, match=message):
        build_comparison_flow_inclusion(flows, labels)
