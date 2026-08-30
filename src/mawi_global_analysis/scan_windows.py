"""Threshold-free source-window statistics from observed TCP SYN facts."""

from __future__ import annotations

import math

import pandas as pd


SCAN_WINDOW_COLUMNS = (
    "dataset",
    "initial_syn_sender_ip",
    "window_start",
    "window_end",
    "syn_initiated_flow_count",
    "unique_targets",
    "unique_dst_ips",
    "unique_dst_ports",
    "syn_to_rst_pattern_count",
    "syn_synack_rst_pattern_count",
    "high_confidence_probe_pattern_count",
    "unique_high_confidence_targets",
    "no_observed_response_count",
)

SCAN_SUMMARY_COLUMNS = (
    "dataset",
    "initial_syn_sender_ip",
    "syn_initiated_flow_count",
    "unique_targets",
    "unique_dst_ips",
    "unique_dst_ports",
    "high_confidence_probe_pattern_count",
)

_REQUIRED_COLUMNS = {
    "protocol",
    "first_syn_time",
    "initial_syn_sender_ip",
    "initial_syn_receiver_ip",
    "initial_syn_receiver_port",
    "observed_tcp_pattern",
}
_HIGH_CONFIDENCE_PATTERNS = {"syn_to_rst", "syn_synack_rst"}


def build_source_scan_windows(
    flows: pd.DataFrame,
    dataset_id: str,
    size_seconds: int | float,
    step_seconds: int | float,
    capture_start: float,
) -> pd.DataFrame:
    """Build active capture-anchored source windows without assigning labels.

    A qualifying flow belongs to every non-negative anchored window whose
    half-open interval contains its observed initial plain-SYN timestamp.
    """
    _validate_geometry(size_seconds, step_seconds)
    qualifying = _qualifying_syn_initiated_flows(flows)
    if qualifying.empty:
        return pd.DataFrame(columns=SCAN_WINDOW_COLUMNS)

    capture_start = float(capture_start)
    size = float(size_seconds)
    step = float(step_seconds)
    rows: list[dict[str, object]] = []
    for sender_ip, source_flows in qualifying.groupby("initial_syn_sender_ip", sort=True):
        active: dict[float, list[pd.Series]] = {}
        for _, flow in source_flows.iterrows():
            timestamp = float(flow["first_syn_time"])
            if timestamp < capture_start:
                continue
            first_index = max(0, math.floor((timestamp - size - capture_start) / step) + 1)
            last_index = math.floor((timestamp - capture_start) / step)
            for index in range(first_index, last_index + 1):
                start = capture_start + index * step
                if start <= timestamp < start + size:
                    active.setdefault(start, []).append(flow)
        for start in sorted(active):
            rows.append(
                _window_row(dataset_id, str(sender_ip), start, size, active[start])
            )
    return pd.DataFrame(rows, columns=SCAN_WINDOW_COLUMNS)


def build_source_scan_summary(flows: pd.DataFrame, dataset_id: str) -> pd.DataFrame:
    """Build full-capture supporting observations per actual SYN sender."""
    qualifying = _qualifying_syn_initiated_flows(flows)
    rows: list[dict[str, object]] = []
    for sender_ip, source_flows in qualifying.groupby("initial_syn_sender_ip", sort=True):
        rows.append(_summary_row(dataset_id, str(sender_ip), list(source_flows.iterrows())))
    return pd.DataFrame(rows, columns=SCAN_SUMMARY_COLUMNS)


def _window_row(
    dataset_id: str, sender_ip: str, start: float, size: float, flows: list[pd.Series]
) -> dict[str, object]:
    facts = _facts(flows)
    return {
        "dataset": dataset_id,
        "initial_syn_sender_ip": sender_ip,
        "window_start": start,
        "window_end": start + size,
        **facts,
    }


def _summary_row(
    dataset_id: str, sender_ip: str, indexed_flows: list[tuple[object, pd.Series]]
) -> dict[str, object]:
    facts = _facts([flow for _, flow in indexed_flows])
    return {
        "dataset": dataset_id,
        "initial_syn_sender_ip": sender_ip,
        "syn_initiated_flow_count": facts["syn_initiated_flow_count"],
        "unique_targets": facts["unique_targets"],
        "unique_dst_ips": facts["unique_dst_ips"],
        "unique_dst_ports": facts["unique_dst_ports"],
        "high_confidence_probe_pattern_count": facts[
            "high_confidence_probe_pattern_count"
        ],
    }


def _facts(flows: list[pd.Series]) -> dict[str, int]:
    targets = {
        (str(flow["initial_syn_receiver_ip"]), int(flow["initial_syn_receiver_port"]))
        for flow in flows
    }
    high_confidence = [
        flow for flow in flows if flow["observed_tcp_pattern"] in _HIGH_CONFIDENCE_PATTERNS
    ]
    high_confidence_targets = {
        (str(flow["initial_syn_receiver_ip"]), int(flow["initial_syn_receiver_port"]))
        for flow in high_confidence
    }
    patterns = [str(flow["observed_tcp_pattern"]) for flow in flows]
    return {
        "syn_initiated_flow_count": len(flows),
        "unique_targets": len(targets),
        "unique_dst_ips": len({target[0] for target in targets}),
        "unique_dst_ports": len({target[1] for target in targets}),
        "syn_to_rst_pattern_count": patterns.count("syn_to_rst"),
        "syn_synack_rst_pattern_count": patterns.count("syn_synack_rst"),
        "high_confidence_probe_pattern_count": len(high_confidence),
        "unique_high_confidence_targets": len(high_confidence_targets),
        "no_observed_response_count": patterns.count("syn_only_observed"),
    }


def _qualifying_syn_initiated_flows(flows: pd.DataFrame) -> pd.DataFrame:
    missing = sorted(_REQUIRED_COLUMNS - set(flows.columns))
    if missing:
        raise ValueError("flows missing required scan-stat columns: " + ", ".join(missing))
    initial = flows.loc[
        (flows["initial_syn_sender_ip"].notna())
        & (flows["initial_syn_receiver_ip"].notna())
        & (flows["initial_syn_receiver_port"].notna())
        & (flows["first_syn_time"].notna())
        & _is_tcp(flows["protocol"])
    ].copy()
    if initial.empty:
        return initial
    initial["first_syn_time"] = pd.to_numeric(initial["first_syn_time"], errors="raise")
    return initial


def _is_tcp(protocol: pd.Series) -> pd.Series:
    return protocol.astype(str).isin({"6", "6.0", "tcp"})


def _validate_geometry(size_seconds: int | float, step_seconds: int | float) -> None:
    if float(size_seconds) <= 0 or float(step_seconds) <= 0:
        raise ValueError("scan window size and step must be positive")
