"""Run-specific scan labels derived from threshold-free flow observations."""

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

_STRICT_WINDOW_COLUMNS = {
    "initial_syn_sender_ip",
    "high_confidence_probe_pattern_count",
    "unique_high_confidence_targets",
}
_FLOW_LABEL_INPUT_COLUMNS = {
    "flow_id",
    "initial_syn_sender_ip",
    "observed_tcp_pattern",
}
_STRICT_PATTERNS = {"syn_to_rst", "syn_synack_rst"}


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


def classify_strict_windows(
    source_scan_windows: pd.DataFrame, config: ExperimentConfig
) -> pd.DataFrame:
    """Add a strict-window decision using the configured positive evidence.

    The input remains the threshold-free source-window artifact.  A window is
    strict only when both configured comparisons are satisfied inclusively.
    """
    _require_columns(source_scan_windows, _STRICT_WINDOW_COLUMNS, "source windows")
    strict = config.scan.strict
    if not strict.enabled:
        raise ValueError("strict window classification requires scan.strict.enabled")
    if strict.min_pattern_count is None or strict.min_unique_targets is None:
        raise ValueError("strict window classification requires explicit thresholds")

    classified = source_scan_windows.copy()
    pattern_count = pd.to_numeric(
        classified["high_confidence_probe_pattern_count"], errors="raise"
    )
    unique_targets = pd.to_numeric(
        classified["unique_high_confidence_targets"], errors="raise"
    )
    classified["strict_window"] = (
        (pattern_count >= strict.min_pattern_count)
        & (unique_targets >= strict.min_unique_targets)
    )
    return classified


def derive_scan_like_sources(classified_windows: pd.DataFrame) -> set[str]:
    """Return SYN senders having at least one already-classified strict window."""
    _require_columns(
        classified_windows,
        {"initial_syn_sender_ip", "strict_window"},
        "classified source windows",
    )
    return {
        str(source)
        for source in classified_windows.loc[
            classified_windows["strict_window"].astype(bool), "initial_syn_sender_ip"
        ].dropna()
    }


def build_flow_labels(
    flows: pd.DataFrame,
    source_scan_windows: pd.DataFrame,
    config: ExperimentConfig,
) -> pd.DataFrame:
    """Label only strict/broad probe evidence from capture-wide scan-like sources.

    Source detection uses strict windows only.  Once a source is detected,
    strict patterns are labeled over the whole capture; optional broad
    expansion adds only ``syn_only_observed`` flows from that same source.
    """
    _require_columns(flows, _FLOW_LABEL_INPUT_COLUMNS, "flows")
    if flows["flow_id"].duplicated().any():
        raise ValueError("flows contain duplicate canonical flow_id values")

    strict_windows = classify_strict_windows(source_scan_windows, config)
    scan_like_sources = derive_scan_like_sources(strict_windows)
    source_is_scan_like = flows["initial_syn_sender_ip"].isin(scan_like_sources)
    observed_pattern = flows["observed_tcp_pattern"].fillna("none")
    strict_scan_like = source_is_scan_like & observed_pattern.isin(_STRICT_PATTERNS)
    broad_scan_like = strict_scan_like.copy()
    if config.scan.broad.enabled:
        broad_scan_like |= source_is_scan_like & observed_pattern.eq("syn_only_observed")

    labels = pd.DataFrame({"flow_id": flows["flow_id"].tolist()})
    labels["strict_scan_like"] = strict_scan_like.to_numpy(dtype=bool)
    labels["broad_scan_like"] = broad_scan_like.to_numpy(dtype=bool)
    labels["strict_removed"] = strict_scan_like.to_numpy(dtype=bool)
    labels["broad_removed"] = broad_scan_like.to_numpy(dtype=bool)
    return labels.loc[:, FLOW_LABEL_COLUMNS]


def _require_columns(
    frame: pd.DataFrame, required: set[str], label: str
) -> None:
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"{label} missing required columns: {', '.join(missing)}")
