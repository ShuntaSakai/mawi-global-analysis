from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.config import load_config


ROOT = Path(__file__).parents[2]


def test_pre_m5_labels_are_neutral_when_both_modes_are_disabled() -> None:
    from mawi_global_analysis.scan_labels import (
        FLOW_LABEL_COLUMNS,
        build_pre_m5_flow_labels,
    )

    config = load_config(ROOT / "configs" / "baseline.yaml")
    labels = build_pre_m5_flow_labels(pd.DataFrame({"flow_id": [11, 12]}), config)

    assert tuple(labels.columns) == FLOW_LABEL_COLUMNS
    assert labels["flow_id"].tolist() == [11, 12]
    assert labels.drop(columns="flow_id").eq(False).all().all()


def test_enabled_scan_modes_stop_at_the_m5_threshold_approval_gate() -> None:
    from mawi_global_analysis.scan_labels import (
        ScanThresholdApprovalRequiredError,
        build_pre_m5_flow_labels,
    )

    baseline = load_config(ROOT / "configs" / "baseline.yaml")
    config = baseline.model_copy(
        update={
            "scan": baseline.scan.model_copy(
                update={
                    "strict": baseline.scan.strict.model_copy(
                        update={"enabled": True, "min_pattern_count": 2, "min_unique_targets": 2}
                    )
                }
            )
        }
    )

    with pytest.raises(ScanThresholdApprovalRequiredError, match="M5 threshold approval"):
        build_pre_m5_flow_labels(pd.DataFrame({"flow_id": [11]}), config)


def test_broad_expansion_alone_stops_at_the_m5_threshold_approval_gate() -> None:
    """The threshold-free expansion toggle cannot activate M5 behavior at M4."""
    from mawi_global_analysis.scan_labels import (
        ScanThresholdApprovalRequiredError,
        build_pre_m5_flow_labels,
    )

    baseline = load_config(ROOT / "configs" / "baseline.yaml")
    config = baseline.model_copy(
        update={
            "scan": baseline.scan.model_copy(
                update={"broad": baseline.scan.broad.model_copy(update={"enabled": True})}
            )
        }
    )

    with pytest.raises(ScanThresholdApprovalRequiredError, match="M5 threshold approval"):
        build_pre_m5_flow_labels(pd.DataFrame({"flow_id": [11]}), config)


def test_strict_window_classification_uses_inclusive_configured_thresholds() -> None:
    from mawi_global_analysis.scan_labels import classify_strict_windows

    config = load_config(ROOT / "configs" / "scan_source_driven_removal.yaml")
    windows = pd.DataFrame(
        {
            "initial_syn_sender_ip": ["198.51.100.1"] * 4,
            "high_confidence_probe_pattern_count": [19, 20, 20, 21],
            "unique_high_confidence_targets": [10, 9, 10, 11],
        }
    )

    classified = classify_strict_windows(windows, config)

    assert classified["strict_window"].tolist() == [False, False, True, True]


def test_strict_thresholds_from_yaml_config_change_window_classification(
    tmp_path: Path,
) -> None:
    from mawi_global_analysis.scan_labels import classify_strict_windows

    config = load_config(ROOT / "configs" / "scan_source_driven_removal.yaml")
    windows = pd.DataFrame(
        {
            "initial_syn_sender_ip": ["198.51.100.1"],
            "high_confidence_probe_pattern_count": [20],
            "unique_high_confidence_targets": [10],
        }
    )
    adjusted_config_path = tmp_path / "raised_threshold.yaml"
    adjusted_config_path.write_text(
        (ROOT / "configs" / "scan_source_driven_removal.yaml")
        .read_text(encoding="utf-8")
        .replace("min_pattern_count: 20", "min_pattern_count: 21"),
        encoding="utf-8",
    )
    raised_count_threshold = load_config(adjusted_config_path)

    assert classify_strict_windows(windows, config)["strict_window"].tolist() == [
        True
    ]
    assert classify_strict_windows(windows, raised_count_threshold)[
        "strict_window"
    ].tolist() == [False]


def test_one_strict_window_is_enough_to_derive_a_scan_like_source() -> None:
    from mawi_global_analysis.scan_labels import derive_scan_like_sources

    classified_windows = pd.DataFrame(
        {
            "initial_syn_sender_ip": ["198.51.100.1", "198.51.100.2"],
            "strict_window": [True, False],
        }
    )

    assert derive_scan_like_sources(classified_windows) == {"198.51.100.1"}


def test_capture_wide_labels_remove_only_permitted_patterns_from_scan_like_sources() -> None:
    from mawi_global_analysis.scan_labels import build_flow_labels

    config = load_config(ROOT / "configs" / "scan_source_driven_removal.yaml")
    windows = pd.DataFrame(
        {
            "initial_syn_sender_ip": ["198.51.100.1"],
            "high_confidence_probe_pattern_count": [20],
            "unique_high_confidence_targets": [10],
        }
    )
    flows = pd.DataFrame(
        {
            "flow_id": [1, 2, 3, 4, 5, 6, 7, 8],
            "initial_syn_sender_ip": [
                "198.51.100.1",  # strict evidence outside the strict window
                "198.51.100.1",  # strict evidence outside the strict window
                "198.51.100.1",  # broad-only expansion
                "198.51.100.1",  # established/payload traffic
                "198.51.100.1",  # UDP
                None,  # mid-connection/no observed plain SYN
                "198.51.100.1",  # no probe-like observed pattern
                "198.51.100.2",  # non-scan source SYN-only
            ],
            "observed_tcp_pattern": [
                "syn_to_rst",
                "syn_synack_rst",
                "syn_only_observed",
                "none",
                "none",
                "none",
                "none",
                "syn_only_observed",
            ],
        }
    )

    labels = build_flow_labels(flows, windows, config)

    assert labels["flow_id"].tolist() == flows["flow_id"].tolist()
    assert labels["strict_removed"].tolist() == [
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
    ]
    assert labels["broad_removed"].tolist() == [
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
    ]
    assert labels["strict_scan_like"].tolist() == [
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
    ]
    assert labels["broad_scan_like"].tolist() == [
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
    ]
    assert not (labels["strict_removed"] & ~labels["broad_removed"]).any()
