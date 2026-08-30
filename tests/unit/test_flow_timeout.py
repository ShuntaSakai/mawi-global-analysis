from __future__ import annotations

import socket
from pathlib import Path

import dpkt
import pytest

from mawi_global_analysis.flow import parse_pcap


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "pcaps"
PCAP_PATH = FIXTURE_DIR / "tcp_patterns.pcap"


def _timeout_fixture_flows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [row for row in rows if 110 in {row["src_port"], row["dst_port"]}]


def _tcp_ack_frame(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=src_port,
        dport=dst_port,
        seq=1,
        ack=1,
        flags=dpkt.tcp.TH_ACK,
    )
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, src_ip),
        dst=socket.inet_pton(socket.AF_INET, dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
    )


def test_inactive_timeout_does_not_split_a_gap_equal_to_threshold(tmp_path: Path) -> None:
    """A 60.0-second gap remains one flow when the timeout is 60 seconds."""
    boundary_capture = tmp_path / "exact-timeout-boundary.pcap"
    with boundary_capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(
            _tcp_ack_frame("198.51.100.70", 40006, "192.0.2.70", 111),
            ts=10.0,
        )
        writer.writepkt(
            _tcp_ack_frame("192.0.2.70", 111, "198.51.100.70", 40006),
            ts=70.0,
        )
        writer.close()

    rows = parse_pcap(boundary_capture, timeout=60.0)

    assert len(rows) == 1
    assert rows[0]["packet_count"] == 2
    assert rows[0]["duration"] == pytest.approx(60.0)


def test_inactive_timeout_splits_only_gaps_strictly_greater_than_threshold() -> None:
    """The F tuple is retained without timeout and split after its 60.001s gap."""
    no_timeout = _timeout_fixture_flows(parse_pcap(PCAP_PATH, timeout=None))
    with_timeout = _timeout_fixture_flows(parse_pcap(PCAP_PATH, timeout=60.0))

    assert len(no_timeout) == 1
    assert no_timeout[0]["packet_count"] == 2
    assert no_timeout[0]["duration"] == pytest.approx(60.001)

    assert len(with_timeout) == 2
    assert [row["packet_count"] for row in with_timeout] == [1, 1]
    assert [row["start_time"] for row in with_timeout] == [6.0, 66.001]
    assert [row["flow_id"] for row in with_timeout] == sorted(
        row["flow_id"] for row in with_timeout
    )
