"""Streaming observations for Broad-remaining one-packet source-run flows.

This module records capture facts and temporal context only.  It deliberately
does not interpret observed traffic as malicious or benign, create artifacts,
or aggregate the full capture into canonical flows.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Iterable
from typing import Any

import dpkt
import pandas as pd

from mawi_global_analysis.flow import (
    FlowKey,
    PcapParseError,
    TCP_PROTOCOL,
    UDP_PROTOCOL,
    iter_capture_packet_records,
)
from mawi_global_analysis.io import RunData, load_run


ONE_PACKET_COHORT_COLUMNS = (
    "source_flow_id", "target_timestamp", "ip_version", "protocol",
    "src_ip", "src_port", "dst_ip", "dst_port", "observed_tcp_pattern",
    "initial_syn_sender_ip", "initial_syn_sender_port",
    "initial_syn_receiver_ip", "initial_syn_receiver_port",
    "strict_removed", "broad_removed",
)

_THRESHOLDS = (1, 10, 60, 300)
ONE_PACKET_CONTEXT_COLUMNS = (
    "source_flow_id", "target_timestamp",
    "packet_src_ip", "packet_src_port", "packet_dst_ip", "packet_dst_port",
    "captured_frame_length", "original_frame_length", "ip_total_length",
    "transport_payload_length", "tcp_flags_raw", "tcp_flags_text",
    "same_5tuple_packet_count_24h", "same_5tuple_before_count",
    "same_5tuple_after_count", "forward_packet_count_24h",
    "reverse_packet_count_24h", "previous_same_5tuple_timestamp",
    "previous_same_5tuple_gap_seconds", "next_same_5tuple_timestamp",
    "next_same_5tuple_gap_seconds", "nearest_reverse_before_gap_seconds",
    "nearest_reverse_after_gap_seconds",
    *tuple(f"same_5tuple_before_{seconds}s" for seconds in _THRESHOLDS),
    *tuple(f"same_5tuple_after_{seconds}s" for seconds in _THRESHOLDS),
)

_SOURCE_WINDOWS = (("5m", 5 * 60), ("15m", 15 * 60), ("1h", 60 * 60))
ONE_PACKET_SOURCE_CONTEXT_COLUMNS = (
    "source_flow_id", "target_timestamp", "source_context_applicable",
    "context_source_ip",
    *(f"plain_syn_packet_count_{name}" for name, _ in _SOURCE_WINDOWS),
    *(f"unique_target_count_{name}" for name, _ in _SOURCE_WINDOWS),
    *(f"unique_dst_ip_count_{name}" for name, _ in _SOURCE_WINDOWS),
    *(f"unique_dst_port_count_{name}" for name, _ in _SOURCE_WINDOWS),
    "plain_syn_packet_count_24h", "unique_target_count_24h",
    "unique_dst_ip_count_24h", "unique_dst_port_count_24h",
)


@dataclass(frozen=True, slots=True)
class _Packet:
    timestamp: float
    key: FlowKey
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ip_total_length: int
    transport_payload_length: int
    tcp_flags_raw: int | None


@dataclass(frozen=True, slots=True)
class _SourceObservation:
    timestamp: float
    dst_ip: str
    dst_port: int


@dataclass(slots=True)
class _TargetSummary:
    source_flow_id: Any
    target_timestamp: float
    key: FlowKey
    target_match_count: int = 0
    target: _Packet | None = None
    captured_frame_length: int | None = None
    original_frame_length: int | None = None
    total_count: int = 0
    before_count: int = 0
    after_count: int = 0
    endpoint_a_to_b_count: int = 0
    endpoint_b_to_a_count: int = 0
    previous_timestamp: float | None = None
    next_timestamp: float | None = None
    nearest_a_to_b_before_gap: float | None = None
    nearest_a_to_b_after_gap: float | None = None
    nearest_b_to_a_before_gap: float | None = None
    nearest_b_to_a_after_gap: float | None = None
    before_local: dict[int, int] = field(default_factory=lambda: {n: 0 for n in _THRESHOLDS})
    after_local: dict[int, int] = field(default_factory=lambda: {n: 0 for n in _THRESHOLDS})


def build_one_packet_cohort(
    dataset_id: str, run_name: str, root: Path = Path(".")
) -> pd.DataFrame:
    """Load a successful run and return its Broad-remaining one-packet cohort."""
    return build_one_packet_cohort_from_run(load_run(dataset_id, run_name, root=root))


def build_one_packet_cohort_from_run(run: RunData) -> pd.DataFrame:
    """Join canonical flows and labels, retaining deterministic target facts."""
    flows = run.flows.copy()
    labels = run.labels.copy()
    if flows["flow_id"].duplicated().any():
        raise ValueError("flows contain duplicate flow_id identities")
    if labels["flow_id"].duplicated().any():
        raise ValueError("flow labels contain duplicate flow_id identities")
    flow_ids = set(flows["flow_id"])
    label_ids = set(labels["flow_id"])
    if flow_ids != label_ids:
        missing = sorted(flow_ids - label_ids)
        extra = sorted(label_ids - flow_ids)
        raise ValueError(
            "flow labels do not match flow identities: "
            f"missing={missing}, extra={extra}"
        )
    merged = flows.merge(labels, on="flow_id", how="inner", validate="one_to_one")
    selected = merged.loc[
        (merged["packet_count"] == 1) & ~merged["broad_removed"].astype(bool)
    ].copy()
    selected = selected.rename(columns={"flow_id": "source_flow_id", "start_time": "target_timestamp"})
    return selected.loc[:, ONE_PACKET_COHORT_COLUMNS].sort_values(
        "source_flow_id", kind="stable"
    ).reset_index(drop=True)


def scan_one_packet_context(
    full_capture_path: Path, one_packet_cohort: pd.DataFrame
) -> pd.DataFrame:
    """Return tuple context while retaining the Phase 2 public interface."""
    context, _ = scan_one_packet_contexts(full_capture_path, one_packet_cohort)
    return context


def scan_one_packet_contexts(
    full_capture_path: Path, one_packet_cohort: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stream one capture and summarize only the cohort's bidirectional tuples.

    ``transport_payload_length`` is the decoded payload byte count present in
    the captured record.  It is never inferred from a declared wire length, so
    snaplen truncation cannot silently become a claimed wire-payload size.

    Source context retains plain-SYN observations only for addresses that are
    endpoints of cohort tuples.  Applicability is decided from the exact
    matched target packet: only ``SYN=1, ACK=0`` targets receive source facts.
    Bounded source windows are inclusive intervals around that target time.
    """
    _require_cohort_columns(one_packet_cohort)
    target_keys = {
        FlowKey.from_packet(str(row.src_ip), int(row.src_port), str(row.dst_ip), int(row.dst_port), int(row.protocol))
        for row in one_packet_cohort.itertuples(index=False)
    }
    candidate_source_ips = {endpoint.ip for key in target_keys for endpoint in (key.endpoint_a, key.endpoint_b)}
    target_rows: list[dict[str, object]] = []
    source_rows: list[dict[str, object]] = []
    for packet_index, (timestamp, frame, captured_length, original_length) in enumerate(
        iter_capture_packet_records(Path(full_capture_path)), start=1
    ):
        packet = _decode_context_packet(frame, packet_index, timestamp)
        if packet is None:
            continue
        if _is_plain_syn(packet) and packet.src_ip in candidate_source_ips:
            source_rows.append({"timestamp": packet.timestamp, "src_ip": packet.src_ip, "dst_ip": packet.dst_ip, "dst_port": packet.dst_port})
        if packet.key in target_keys:
            target_rows.append({
                "timestamp": packet.timestamp, "src_ip": packet.src_ip, "src_port": packet.src_port,
                "dst_ip": packet.dst_ip, "dst_port": packet.dst_port, "protocol": packet.key.protocol,
                "captured_frame_length": captured_length, "original_frame_length": original_length,
                "ip_total_length": packet.ip_total_length, "transport_payload_length": packet.transport_payload_length,
                "tcp_flags_raw": packet.tcp_flags_raw,
            })
    return aggregate_one_packet_context_observations(
        one_packet_cohort, pd.DataFrame(target_rows), pd.DataFrame(source_rows)
    )


def aggregate_one_packet_context_chunks(
    one_packet_cohort: pd.DataFrame, chunks: Iterable[Any]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Aggregate validated chunk observations without relying on chunk order."""
    chunk_list = list(chunks)
    target_frames = [chunk.target_packets for chunk in chunk_list]
    source_frames = [chunk.source_syn_packets for chunk in chunk_list]
    return aggregate_one_packet_context_observations(
        one_packet_cohort,
        pd.concat(target_frames, ignore_index=True) if target_frames else pd.DataFrame(),
        pd.concat(source_frames, ignore_index=True) if source_frames else pd.DataFrame(),
    )


def aggregate_one_packet_context_observations(
    one_packet_cohort: pd.DataFrame,
    target_observations: pd.DataFrame,
    source_syn_observations: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Compute public context tables from timestamped, observational rows only."""
    _require_cohort_columns(one_packet_cohort)
    summaries = [_summary_from_row(row) for _, row in one_packet_cohort.iterrows()]
    if len({summary.source_flow_id for summary in summaries}) != len(summaries):
        raise ValueError("one-packet cohort contains duplicate source_flow_id values")
    target_index: dict[tuple[FlowKey, float], list[_TargetSummary]] = {}
    key_index: dict[FlowKey, list[_TargetSummary]] = {}
    for summary in summaries:
        target_index.setdefault((summary.key, summary.target_timestamp), []).append(summary)
        key_index.setdefault(summary.key, []).append(summary)
    for row in _timestamp_ordered_records(target_observations):
        packet = _packet_from_observation(row)
        for summary in key_index.get(packet.key, []):
            _observe_context(summary, packet)
        for summary in target_index.get((packet.key, packet.timestamp), []):
            summary.target_match_count += 1
            summary.target = packet
            summary.captured_frame_length = int(row["captured_frame_length"])
            summary.original_frame_length = int(row["original_frame_length"])
    source_observations: dict[str, list[_SourceObservation]] = {}
    for row in _timestamp_ordered_records(source_syn_observations):
        source_observations.setdefault(str(row["src_ip"]), []).append(
            _SourceObservation(float(row["timestamp"]), str(row["dst_ip"]), int(row["dst_port"]))
        )
    invalid = [summary for summary in summaries if summary.target_match_count != 1]
    if invalid:
        missing = [str(summary.source_flow_id) for summary in invalid if summary.target_match_count == 0]
        ambiguous = [str(summary.source_flow_id) for summary in invalid if summary.target_match_count > 1]
        parts = []
        if missing:
            parts.append("missing target matches for source_flow_id=" + ", ".join(missing))
        if ambiguous:
            parts.append("ambiguous target matches for source_flow_id=" + ", ".join(ambiguous))
        raise ValueError("; ".join(parts))
    context = pd.DataFrame([_context_row(summary) for summary in summaries], columns=ONE_PACKET_CONTEXT_COLUMNS)
    source_context = pd.DataFrame([_source_context_row(summary, source_observations) for summary in summaries], columns=ONE_PACKET_SOURCE_CONTEXT_COLUMNS)
    return context, source_context


def _timestamp_ordered_records(frame: pd.DataFrame) -> list[dict[str, object]]:
    if frame.empty:
        return []
    if "timestamp" not in frame.columns:
        raise ValueError("observation frame missing timestamp")
    return frame.sort_values(list(frame.columns), kind="stable", na_position="last").to_dict("records")


def _packet_from_observation(row: dict[str, object]) -> _Packet:
    raw_flags = row["tcp_flags_raw"]
    flags = None if pd.isna(raw_flags) else int(raw_flags)
    src_ip, dst_ip = str(row["src_ip"]), str(row["dst_ip"])
    src_port, dst_port, protocol = int(row["src_port"]), int(row["dst_port"]), int(row["protocol"])
    return _Packet(
        timestamp=float(row["timestamp"]), key=FlowKey.from_packet(src_ip, src_port, dst_ip, dst_port, protocol),
        src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
        ip_total_length=int(row["ip_total_length"]), transport_payload_length=int(row["transport_payload_length"]),
        tcp_flags_raw=flags,
    )


def _require_cohort_columns(cohort: pd.DataFrame) -> None:
    required = {"source_flow_id", "target_timestamp", "protocol", "src_ip", "src_port", "dst_ip", "dst_port"}
    missing = sorted(required - set(cohort.columns))
    if missing:
        raise ValueError("one-packet cohort missing required columns: " + ", ".join(missing))


def _summary_from_row(row: pd.Series) -> _TargetSummary:
    protocol = int(row["protocol"])
    return _TargetSummary(
        source_flow_id=row["source_flow_id"], target_timestamp=float(row["target_timestamp"]),
        key=FlowKey.from_packet(str(row["src_ip"]), int(row["src_port"]), str(row["dst_ip"]), int(row["dst_port"]), protocol),
    )


def _decode_context_packet(
    frame: bytes, packet_index: int, timestamp: float
) -> _Packet | None:
    try:
        ethernet = dpkt.ethernet.Ethernet(frame)
    except (dpkt.dpkt.Error, ValueError, IndexError) as exc:
        raise PcapParseError(f"malformed Ethernet frame at packet {packet_index}") from exc
    network = ethernet.data
    if not isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None
    transport = network.data
    if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        return None
    protocol = TCP_PROTOCOL if isinstance(transport, dpkt.tcp.TCP) else UDP_PROTOCOL
    family = socket.AF_INET if isinstance(network, dpkt.ip.IP) else socket.AF_INET6
    try:
        src_ip = socket.inet_ntop(family, network.src)
        dst_ip = socket.inet_ntop(family, network.dst)
    except (OSError, ValueError) as exc:
        raise PcapParseError(f"malformed IP address at packet {packet_index}") from exc
    ip_total_length = int(network.len) if isinstance(network, dpkt.ip.IP) else 40 + int(network.plen)
    return _Packet(
        timestamp=timestamp,
        key=FlowKey.from_packet(
            src_ip, int(transport.sport), dst_ip, int(transport.dport), protocol
        ),
        src_ip=src_ip, src_port=int(transport.sport), dst_ip=dst_ip, dst_port=int(transport.dport),
        ip_total_length=ip_total_length, transport_payload_length=len(transport.data),
        tcp_flags_raw=int(transport.flags) if isinstance(transport, dpkt.tcp.TCP) else None,
    )


def _observe_context(summary: _TargetSummary, packet: _Packet) -> None:
    summary.total_count += 1
    is_a_to_b = (packet.src_ip, packet.src_port) == (
        summary.key.endpoint_a.ip,
        summary.key.endpoint_a.port,
    )
    if is_a_to_b:
        summary.endpoint_a_to_b_count += 1
    else:
        summary.endpoint_b_to_a_count += 1

    gap = packet.timestamp - summary.target_timestamp
    if gap < 0:
        positive_gap = -gap
        summary.before_count += 1
        if summary.previous_timestamp is None or packet.timestamp > summary.previous_timestamp:
            summary.previous_timestamp = packet.timestamp
        for threshold in _THRESHOLDS:
            if positive_gap <= threshold:
                summary.before_local[threshold] += 1
    elif gap > 0:
        summary.after_count += 1
        if summary.next_timestamp is None or packet.timestamp < summary.next_timestamp:
            summary.next_timestamp = packet.timestamp
        for threshold in _THRESHOLDS:
            if gap <= threshold:
                summary.after_local[threshold] += 1

    if gap < 0:
        reverse_gap = -gap
        attribute = (
            "nearest_a_to_b_before_gap" if is_a_to_b else "nearest_b_to_a_before_gap"
        )
        existing = getattr(summary, attribute)
        if existing is None or reverse_gap < existing:
            setattr(summary, attribute, reverse_gap)
    elif gap > 0:
        attribute = (
            "nearest_a_to_b_after_gap" if is_a_to_b else "nearest_b_to_a_after_gap"
        )
        existing = getattr(summary, attribute)
        if existing is None or gap < existing:
            setattr(summary, attribute, gap)


def _is_plain_syn(packet: _Packet) -> bool:
    return (
        packet.tcp_flags_raw is not None
        and bool(packet.tcp_flags_raw & dpkt.tcp.TH_SYN)
        and not bool(packet.tcp_flags_raw & dpkt.tcp.TH_ACK)
    )


def _source_context_row(
    summary: _TargetSummary,
    source_observations: dict[str, list[_SourceObservation]],
) -> dict[str, object]:
    assert summary.target is not None
    row: dict[str, object] = {
        "source_flow_id": summary.source_flow_id,
        "target_timestamp": summary.target_timestamp,
        "source_context_applicable": _is_plain_syn(summary.target),
        "context_source_ip": None,
    }
    statistic_columns = [
        column for column in ONE_PACKET_SOURCE_CONTEXT_COLUMNS
        if column.startswith(("plain_syn_", "unique_"))
    ]
    if not row["source_context_applicable"]:
        row.update({column: None for column in statistic_columns})
        return row

    source_ip = summary.target.src_ip
    row["context_source_ip"] = source_ip
    observations = source_observations.get(source_ip, [])
    for name, seconds in _SOURCE_WINDOWS:
        selected = [
            event for event in observations
            if abs(event.timestamp - summary.target_timestamp) <= seconds
        ]
        row.update(_source_statistics(selected, suffix=name))
    row.update(_source_statistics(observations, suffix="24h"))
    return row


def _source_statistics(
    observations: list[_SourceObservation], *, suffix: str
) -> dict[str, int]:
    targets = {(event.dst_ip, event.dst_port) for event in observations}
    return {
        f"plain_syn_packet_count_{suffix}": len(observations),
        f"unique_target_count_{suffix}": len(targets),
        f"unique_dst_ip_count_{suffix}": len({event.dst_ip for event in observations}),
        f"unique_dst_port_count_{suffix}": len({event.dst_port for event in observations}),
    }


def _tcp_flags_text(flags: int | None) -> str | None:
    if flags is None:
        return None
    ordered_flags = (
        (dpkt.tcp.TH_FIN, "F"), (dpkt.tcp.TH_SYN, "S"),
        (dpkt.tcp.TH_RST, "R"), (dpkt.tcp.TH_PUSH, "P"),
        (dpkt.tcp.TH_ACK, "A"), (dpkt.tcp.TH_URG, "U"),
        (dpkt.tcp.TH_ECE, "E"), (dpkt.tcp.TH_CWR, "C"),
    )
    return "".join(text for bit, text in ordered_flags if flags & bit)


def _context_row(summary: _TargetSummary) -> dict[str, object]:
    assert summary.target is not None
    assert summary.captured_frame_length is not None
    assert summary.original_frame_length is not None
    target_is_a_to_b = (summary.target.src_ip, summary.target.src_port) == (
        summary.key.endpoint_a.ip,
        summary.key.endpoint_a.port,
    )
    forward_count = (
        summary.endpoint_a_to_b_count if target_is_a_to_b else summary.endpoint_b_to_a_count
    )
    reverse_count = (
        summary.endpoint_b_to_a_count if target_is_a_to_b else summary.endpoint_a_to_b_count
    )
    reverse_before_gap = (
        summary.nearest_b_to_a_before_gap
        if target_is_a_to_b else summary.nearest_a_to_b_before_gap
    )
    reverse_after_gap = (
        summary.nearest_b_to_a_after_gap
        if target_is_a_to_b else summary.nearest_a_to_b_after_gap
    )
    previous_gap = (
        summary.target_timestamp - summary.previous_timestamp
        if summary.previous_timestamp is not None else None
    )
    next_gap = (
        summary.next_timestamp - summary.target_timestamp
        if summary.next_timestamp is not None else None
    )
    row: dict[str, object] = {
        "source_flow_id": summary.source_flow_id,
        "target_timestamp": summary.target_timestamp,
        "packet_src_ip": summary.target.src_ip,
        "packet_src_port": summary.target.src_port,
        "packet_dst_ip": summary.target.dst_ip,
        "packet_dst_port": summary.target.dst_port,
        "captured_frame_length": summary.captured_frame_length,
        "original_frame_length": summary.original_frame_length,
        "ip_total_length": summary.target.ip_total_length,
        "transport_payload_length": summary.target.transport_payload_length,
        "tcp_flags_raw": summary.target.tcp_flags_raw,
        "tcp_flags_text": _tcp_flags_text(summary.target.tcp_flags_raw),
        "same_5tuple_packet_count_24h": summary.total_count,
        "same_5tuple_before_count": summary.before_count,
        "same_5tuple_after_count": summary.after_count,
        "forward_packet_count_24h": forward_count,
        "reverse_packet_count_24h": reverse_count,
        "previous_same_5tuple_timestamp": summary.previous_timestamp,
        "previous_same_5tuple_gap_seconds": previous_gap,
        "next_same_5tuple_timestamp": summary.next_timestamp,
        "next_same_5tuple_gap_seconds": next_gap,
        "nearest_reverse_before_gap_seconds": reverse_before_gap,
        "nearest_reverse_after_gap_seconds": reverse_after_gap,
    }
    for threshold in _THRESHOLDS:
        row[f"same_5tuple_before_{threshold}s"] = summary.before_local[threshold]
        row[f"same_5tuple_after_{threshold}s"] = summary.after_local[threshold]
    return row
