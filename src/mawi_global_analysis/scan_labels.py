"""Pre-M5 neutral flow labels and the explicit threshold-approval gate."""

from __future__ import annotations

import pandas as pd

from mawi_global_analysis.config import ExperimentConfig


FLOW_LABEL_COLUMNS = (
    "flow_id",
    "strict_scan_like",
    "broad_scan_like",
    "strict_removed",
    "broad_removed",
)


class ScanThresholdApprovalRequiredError(RuntimeError):
    """Raised when M5-only thresholded scan behavior is requested too early."""


def ensure_pre_m5_labels_allowed(config: ExperimentConfig) -> None:
    """Reject M5 thresholded modes before labels can be reused or generated."""
    if config.scan.strict.enabled or config.scan.broad.enabled:
        raise ScanThresholdApprovalRequiredError(
            "strict/broad scan labels require M5 threshold approval; stop for M5 "
            "threshold approval before running scan classification or removal"
        )


def build_pre_m5_flow_labels(
    flows: pd.DataFrame, config: ExperimentConfig
) -> pd.DataFrame:
    """Return all-false labels, or require explicit M5 threshold approval.

    Thresholded classification and removal are intentionally outside M0--M4.
    """
    ensure_pre_m5_labels_allowed(config)
    if "flow_id" not in flows.columns:
        raise ValueError("flows missing required scan-label column: flow_id")
    if flows["flow_id"].duplicated().any():
        raise ValueError("flows contain duplicate canonical flow_id values")
    labels = pd.DataFrame({"flow_id": flows["flow_id"].tolist()})
    for column in FLOW_LABEL_COLUMNS[1:]:
        labels[column] = False
    return labels.loc[:, FLOW_LABEL_COLUMNS]
