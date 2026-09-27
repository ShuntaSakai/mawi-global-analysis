"""Tests for Broad-remaining one-packet context observations."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import dpkt
import pandas as pd
import pytest

from mawi_global_analysis.flow import FlowKey
from mawi_global_analysis.flow_stage import FLOW_COLUMNS
from mawi_global_analysis.io import RunData
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS


def _flow(
    flow_id: int,
    *,
    start_time: float,
    packet_count: int = 1,
    src_ip: str = "198.51.100.1",
    src_port: int = 40000,
    dst_ip: str = "192.0.2.1",
    dst_port: int = 443,
    protocol: int = 6,
) -> dict[str, object]:
    row = {column: None for column in FLOW_COLUMNS}
    row.update(
        flow_id=flow_id,
        ip_version=4,
        protocol=protocol,
        start_time=start_time,
        end_time=start_time,
        duration=0.0,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        packet_count=packet_count,
        observed_tcp_pattern="syn_only_observed" if protocol == 6 else "none",
        initial_syn_sender_ip=src_ip if protocol == 6 else None,
        initial_syn_sender_port=src_port if protocol == 6 else None,
        initial_syn_receiver_ip=dst_ip if protocol == 6 else None,
        initial_syn_receiver_port=dst_port if protocol == 6 else None,
    )
    return row


def _labels(*pairs: tuple[int, bool]) -> pd.DataFrame:
    rows = []
    for flow_id, broad_removed in pairs:
        rows.append(
            {
                "flow_id": flow_id,
                "strict_scan_like": broad_removed,
                "broad_scan_like": broad_removed,
                "strict_removed": broad_removed,
                "broad_removed": broad_removed,
            }
        )
    return pd.DataFrame(rows, columns=FLOW_LABEL_COLUMNS)


def _run(flows: list[dict[str, object]], labels: pd.DataFrame) -> RunData:
    return RunData(
        flows=pd.DataFrame(flows, columns=FLOW_COLUMNS),
        labels=labels,
        prefixes=pd.DataFrame(),
        membership=pd.DataFrame(),
        scan_windows=None,
        scan_summary=None,
        manifest={"status": "success"},
    )


def _cohort(flow: dict[str, object]) -> pd.DataFrame:
    from mawi_global_analysis.one_packet_context import build_one_packet_cohort_from_run

    return build_one_packet_cohort_from_run(_run([flow], _labels((int(flow["flow_id"]), False))))


def _tcp_frame(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, flags: int, payload: bytes = b""
) -> bytes:
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, seq=1, ack=1, flags=flags, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, src_ip), dst=socket.inet_pton(socket.AF_INET, dst_ip),
        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp,
    )
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _udp_frame() -> bytes:
    udp = dpkt.udp.UDP(sport=50000, dport=53, data=b"payload")
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton("198.51.100.2"), dst=socket.inet_aton("192.0.2.2"), p=17, ttl=64, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _udp6_frame() -> bytes:
    udp = dpkt.udp.UDP(sport=50001, dport=53, data=b"v6")
    udp.ulen = len(udp)
    ip = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        nxt=17, hlim=64, data=udp,
    )
    ip.plen = len(udp)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip))


def _pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        for timestamp, frame in packets:
            writer.writepkt(frame, ts=timestamp)
        writer.close()


def test_build_cohort_filters_labels_and_keeps_deterministic_flow_order() -> None:
    from mawi_global_analysis.one_packet_context import build_one_packet_cohort_from_run

    cohort = build_one_packet_cohort_from_run(
        _run([_flow(3, start_time=3), _flow(1, start_time=1), _flow(2, start_time=2, packet_count=2)], _labels((1, False), (2, False), (3, True)))
    )

    assert cohort["source_flow_id"].tolist() == [1]
    assert cohort.loc[0, "target_timestamp"] == 1
    assert cohort.loc[0, "broad_removed"] == False


def test_build_cohort_loads_the_successful_run_through_the_run_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    import mawi_global_analysis.one_packet_context as context

    run = _run([_flow(1, start_time=1)], _labels((1, False)))
    monkeypatch.setattr(context, "load_run", lambda dataset_id, run_name, root: run)
    assert context.build_one_packet_cohort("fixture", "approved", root=Path("/tmp"))["source_flow_id"].tolist() == [1]


@pytest.mark.parametrize("labels, message", [(_labels((1, False)), "missing"), (_labels((1, False), (1, False)), "duplicate")])
def test_build_cohort_rejects_non_one_to_one_labels(labels: pd.DataFrame, message: str) -> None:
    from mawi_global_analysis.one_packet_context import build_one_packet_cohort_from_run

    with pytest.raises(ValueError, match=message):
        build_one_packet_cohort_from_run(_run([_flow(1, start_time=1), _flow(2, start_time=2)], labels))


def test_scanner_collects_packet_facts_context_and_ignores_unrelated_packets(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import scan_one_packet_context

    target = _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN)
    full_capture = tmp_path / "full.pcap"
    _pcap(full_capture, [
        (90.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_ACK)),
        (100.0, target),
        (101.0, _tcp_frame("192.0.2.1", 443, "198.51.100.1", 40000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)),
        (160.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_ACK)),
        (100.5, _tcp_frame("203.0.113.1", 12345, "203.0.113.2", 80, dpkt.tcp.TH_ACK)),
    ])
    cohort = _cohort(_flow(7, start_time=100))

    context = scan_one_packet_context(full_capture, cohort)
    row = context.iloc[0]
    assert FlowKey.from_packet("198.51.100.1", 40000, "192.0.2.1", 443, 6) == FlowKey.from_packet("192.0.2.1", 443, "198.51.100.1", 40000, 6)
    assert row["tcp_flags_raw"] == dpkt.tcp.TH_SYN
    assert row["tcp_flags_text"] == "S"
    assert row["same_5tuple_packet_count_24h"] == 4
    assert row["same_5tuple_before_count"] == 1
    assert row["same_5tuple_after_count"] == 2
    assert row["forward_packet_count_24h"] == 3
    assert row["reverse_packet_count_24h"] == 1
    assert row["previous_same_5tuple_timestamp"] == 90.0
    assert row["previous_same_5tuple_gap_seconds"] == 10.0
    assert row["next_same_5tuple_timestamp"] == 101.0
    assert row["next_same_5tuple_gap_seconds"] == 1.0
    assert row["nearest_reverse_before_gap_seconds"] is None
    assert row["nearest_reverse_after_gap_seconds"] == 1.0
    assert [row[f"same_5tuple_before_{seconds}s"] for seconds in (1, 10, 60, 300)] == [0, 1, 1, 1]
    assert [row[f"same_5tuple_after_{seconds}s"] for seconds in (1, 10, 60, 300)] == [1, 1, 2, 2]
    assert "unrelated_packets" not in context.columns


@pytest.mark.parametrize(
    ("flags", "text"),
    [
        (dpkt.tcp.TH_SYN, "S"),
        (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, "SA"),
        (dpkt.tcp.TH_ACK, "A"),
        (dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, "RA"),
        (dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, "FA"),
        (dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, "PA"),
    ],
)
def test_scanner_uses_fixed_tcp_flag_text_order(tmp_path: Path, flags: int, text: str) -> None:
    from mawi_global_analysis.one_packet_context import scan_one_packet_context

    capture = tmp_path / "flags.pcap"
    _pcap(capture, [(10.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, flags))])
    cohort = _cohort(_flow(1, start_time=10))
    assert scan_one_packet_context(capture, cohort).iloc[0]["tcp_flags_text"] == text


def test_scanner_keeps_capture_and_original_lengths_distinct_and_udp_flags_null(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import scan_one_packet_context

    capture = tmp_path / "lengths.pcap"
    frame = _udp_frame()
    _pcap(capture, [(10.0, frame)])
    raw = bytearray(capture.read_bytes())
    struct.pack_into("<I", raw, 24 + 12, len(frame) + 50)
    capture.write_bytes(raw)
    cohort = _cohort(_flow(1, start_time=10, src_ip="198.51.100.2", src_port=50000, dst_ip="192.0.2.2", dst_port=53, protocol=17))

    row = scan_one_packet_context(capture, cohort).iloc[0]
    assert row["captured_frame_length"] == len(frame)
    assert row["original_frame_length"] == len(frame) + 50
    assert row["ip_total_length"] == len(frame) - 14
    assert row["transport_payload_length"] == len(b"payload")
    assert row["tcp_flags_raw"] is None
    assert row["tcp_flags_text"] is None


def test_scanner_uses_ipv6_header_plus_declared_payload_for_ip_total_length(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import scan_one_packet_context

    capture = tmp_path / "ipv6-lengths.pcap"
    frame = _udp6_frame()
    _pcap(capture, [(10.0, frame)])
    flow = _flow(1, start_time=10, src_ip="2001:db8::1", src_port=50001, dst_ip="2001:db8::2", dst_port=53, protocol=17)
    flow["ip_version"] = 6

    row = scan_one_packet_context(capture, _cohort(flow)).iloc[0]
    assert row["ip_total_length"] == 40 + 8 + len(b"v6")
    assert row["transport_payload_length"] == len(b"v6")


@pytest.mark.parametrize("packets, message", [([], "missing target"), ([(10.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN)), (10.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))], "ambiguous target")])
def test_scanner_requires_exactly_one_target_match(tmp_path: Path, packets: list[tuple[float, bytes]], message: str) -> None:
    from mawi_global_analysis.one_packet_context import scan_one_packet_context

    capture = tmp_path / "matches.pcap"
    _pcap(capture, packets)
    cohort = _cohort(_flow(1, start_time=10))
    with pytest.raises(ValueError, match=message):
        scan_one_packet_context(capture, cohort)
