"""Pure Raw, Strict, and Broad flow-inclusion decisions."""

from __future__ import annotations

import pandas as pd


COMPARISON_INCLUSION_COLUMNS = (
    "flow_id",
    "raw_included",
    "strict_included",
    "broad_included",
)

_LABEL_COLUMNS = {"flow_id", "strict_removed", "broad_removed"}


def build_comparison_flow_inclusion(
    flows: pd.DataFrame, labels: pd.DataFrame
) -> pd.DataFrame:
    """Return lightweight Raw, Strict, and Broad inclusion decisions by flow ID.

    The caller supplies the canonical flow set and M5-produced labels.  This
    function intentionally does not classify scans or inspect prefix artifacts.
    """
    _require_columns(flows, {"flow_id"}, "flows")
    _require_columns(labels, _LABEL_COLUMNS, "labels")
    if flows["flow_id"].duplicated().any():
        raise ValueError("flows contain duplicate canonical flow_id values")
    if labels["flow_id"].duplicated().any():
        raise ValueError("labels contain duplicate flow_id values")
    _require_boolean_columns(labels, {"strict_removed", "broad_removed"})

    flow_ids = set(flows["flow_id"])
    label_ids = set(labels["flow_id"])
    if flow_ids != label_ids:
        raise ValueError("flows and labels flow_id sets do not match")

    strict_removed = labels["strict_removed"]
    broad_removed = labels["broad_removed"]
    if (strict_removed & ~broad_removed).any():
        raise ValueError("strict_removed values must imply broad_removed values")

    labels_by_flow_id = labels.set_index("flow_id")
    ordered_labels = labels_by_flow_id.loc[flows["flow_id"]]
    inclusion = pd.DataFrame({"flow_id": flows["flow_id"].to_numpy(copy=True)})
    inclusion["raw_included"] = True
    inclusion["strict_included"] = ~ordered_labels["strict_removed"].to_numpy(dtype=bool)
    inclusion["broad_included"] = ~ordered_labels["broad_removed"].to_numpy(dtype=bool)
    return inclusion.loc[:, COMPARISON_INCLUSION_COLUMNS]


def _require_columns(frame: pd.DataFrame, required: set[str], label: str) -> None:
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"{label} missing required columns: {', '.join(missing)}")


def _require_boolean_columns(frame: pd.DataFrame, columns: set[str]) -> None:
    invalid = sorted(
        column
        for column in columns
        if not pd.api.types.is_bool_dtype(frame[column])
    )
    if invalid:
        raise ValueError(
            "labels removal columns must have boolean dtype: " + ", ".join(invalid)
        )
    missing = sorted(column for column in columns if frame[column].isna().any())
    if missing:
        raise ValueError(
            "labels removal columns must not contain missing values: "
            + ", ".join(missing)
        )
