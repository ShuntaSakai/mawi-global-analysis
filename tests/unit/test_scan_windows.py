from __future__ import annotations

import pandas as pd
import pytest


def _flows() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "flow_id": 1,
                "protocol": 6,
                "first_syn_time": 0.0,
                "initial_syn_sender_ip": "198.51.100.1",
                "initial_syn_receiver_ip": "192.0.2.1",
                "initial_syn_receiver_port": 80,
                "observed_tcp_pattern": "syn_to_rst",
            },
            {
                "flow_id": 2,
                "protocol": 6,
                "first_syn_time": 59.999,
                "initial_syn_sender_ip": "198.51.100.1",
                "initial_syn_receiver_ip": "192.0.2.1",
                "initial_syn_receiver_port": 80,
                "observed_tcp_pattern": "syn_only_observed",
            },
            {
                "flow_id": 3,
                "protocol": 6,
                "first_syn_time": 60.0,
                "initial_syn_sender_ip": "198.51.100.1",
                "initial_syn_receiver_ip": "192.0.2.2",
                "initial_syn_receiver_port": 443,
                "observed_tcp_pattern": "syn_synack_rst",
            },
            {
                "flow_id": 4,
                "protocol": 6,
                "first_syn_time": 20.0,
                "initial_syn_sender_ip": None,
                "initial_syn_receiver_ip": None,
                "initial_syn_receiver_port": None,
                "observed_tcp_pattern": "none",
            },
        ]
    )


def test_source_windows_are_capture_anchored_half_open_and_threshold_free() -> None:
    """A window includes its start, excludes its end, and records facts only."""
    from mawi_global_analysis.scan_windows import (
        SCAN_WINDOW_COLUMNS,
        build_source_scan_windows,
    )

    windows = build_source_scan_windows(
        _flows(),
        dataset_id="fixture",
        size_seconds=60,
        step_seconds=10,
        capture_start=0.0,
    )

    assert tuple(windows.columns) == SCAN_WINDOW_COLUMNS
    first = windows.loc[windows["window_start"] == 0.0].iloc[0]
    assert first["window_end"] == 60.0
    assert first["syn_initiated_flow_count"] == 2
    assert first["unique_targets"] == 1
    assert first["syn_to_rst_pattern_count"] == 1
    assert first["syn_synack_rst_pattern_count"] == 0
    assert first["high_confidence_probe_pattern_count"] == 1
    assert first["unique_high_confidence_targets"] == 1
    assert first["no_observed_response_count"] == 1

    at_sixty = windows.loc[windows["window_start"] == 60.0].iloc[0]
    assert at_sixty["syn_initiated_flow_count"] == 1
    assert at_sixty["unique_targets"] == 1
    assert at_sixty["syn_synack_rst_pattern_count"] == 1


def test_windows_count_endpoint_pairs_and_only_actual_plain_syn_initiators() -> None:
    """Repeated attempts differ from target diversity and no-SYN rows are absent."""
    from mawi_global_analysis.scan_windows import build_source_scan_windows

    flows = _flows().iloc[[0, 1, 3]].copy()
    flows.loc[4] = {
        "flow_id": 5,
        "protocol": 6,
        "first_syn_time": 5.0,
        "initial_syn_sender_ip": "198.51.100.1",
        "initial_syn_receiver_ip": "192.0.2.1",
        "initial_syn_receiver_port": 443,
        "observed_tcp_pattern": "syn_to_rst",
    }
    flows.loc[5] = {
        "flow_id": 6,
        "protocol": 17,
        "first_syn_time": 5.0,
        "initial_syn_sender_ip": "198.51.100.99",
        "initial_syn_receiver_ip": "192.0.2.99",
        "initial_syn_receiver_port": 53,
        "observed_tcp_pattern": "syn_to_rst",
    }

    windows = build_source_scan_windows(flows, "fixture", 60, 10, 0.0)
    first = windows.loc[windows["window_start"] == 0.0].iloc[0]

    assert first["syn_initiated_flow_count"] == 3
    assert first["unique_targets"] == 2
    assert first["unique_dst_ips"] == 1
    assert first["unique_dst_ports"] == 2
    assert set(windows["initial_syn_sender_ip"]) == {"198.51.100.1"}


def test_full_capture_summary_contains_observed_source_facts_only() -> None:
    """Summary totals are not window labels and do not add M5-only counts."""
    from mawi_global_analysis.scan_windows import (
        SCAN_SUMMARY_COLUMNS,
        build_source_scan_summary,
    )

    summary = build_source_scan_summary(_flows(), "fixture")

    assert tuple(summary.columns) == SCAN_SUMMARY_COLUMNS
    row = summary.iloc[0]
    assert row["initial_syn_sender_ip"] == "198.51.100.1"
    assert row["syn_initiated_flow_count"] == 3
    assert row["unique_targets"] == 2
    assert row["unique_dst_ips"] == 2
    assert row["unique_dst_ports"] == 2
    assert row["high_confidence_probe_pattern_count"] == 2
    assert not {"strict_scan_window_count", "behavioral_scan_window_count"} & set(
        summary.columns
    )


@pytest.mark.parametrize("size_seconds,step_seconds", [(0, 10), (60, 0), (60, -1)])
def test_window_geometry_must_be_positive(size_seconds: int, step_seconds: int) -> None:
    from mawi_global_analysis.scan_windows import build_source_scan_windows

    with pytest.raises(ValueError, match="positive"):
        build_source_scan_windows(_flows(), "fixture", size_seconds, step_seconds, 0.0)
