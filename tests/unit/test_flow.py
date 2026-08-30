from __future__ import annotations

import gzip
import struct
from pathlib import Path

import dpkt
import pytest

from mawi_global_analysis.dataset import resolve_local_input
from mawi_global_analysis.flow import FlowKey, PcapParseError, parse_pcap


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "pcaps"
PCAP_PATH = FIXTURE_DIR / "tcp_patterns.pcap"
GZIP_PATH = FIXTURE_DIR / "tcp_patterns.pcap.gz"


def _write_pcapng(source: Path, destination: Path) -> None:
    with source.open("rb") as input_file, destination.open("wb") as output_file:
        reader = dpkt.pcap.Reader(input_file)
        writer = dpkt.pcapng.Writer(output_file, linktype=reader.datalink())
        for timestamp, frame in reader:
            writer.writepkt(frame, ts=timestamp)


def _write_pcapng_with_oversized_epb_caplen(source: Path, destination: Path) -> None:
    """Create an EPB whose caplen exceeds its unchanged original packet length."""
    _write_pcapng(source, destination)
    capture = bytearray(destination.read_bytes())
    byte_order = "<" if capture[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    offset = 0

    while offset < len(capture):
        block_type, block_length = struct.unpack_from(f"{byte_order}II", capture, offset)
        if block_type == dpkt.pcapng.PCAPNG_BT_EPB:
            caplen_offset = offset + 20
            caplen = struct.unpack_from(f"{byte_order}I", capture, caplen_offset)[0]
            struct.pack_into(f"{byte_order}I", capture, caplen_offset, caplen + 4)
            destination.write_bytes(capture)
            return
        offset += block_length

    raise AssertionError("test capture did not contain an enhanced packet block")


def test_resolved_pcapng_capture_parses_to_canonical_flows(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    _write_pcapng(PCAP_PATH, capture)

    context = resolve_local_input(capture, dataset_id="pcapng-capture")

    assert parse_pcap(context.path, timeout=None) == parse_pcap(PCAP_PATH, timeout=None)


def test_resolved_gzip_magic_without_gz_suffix_parses_to_canonical_flows(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(gzip.compress(PCAP_PATH.read_bytes()))

    context = resolve_local_input(capture, dataset_id="gzip-magic-capture")

    assert parse_pcap(context.path, timeout=None) == parse_pcap(PCAP_PATH, timeout=None)


def test_pcapng_packet_caplen_exceeding_original_length_is_fatal(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "oversized-caplen.pcapng"
    _write_pcapng_with_oversized_epb_caplen(PCAP_PATH, capture)

    with pytest.raises(PcapParseError, match="caplen"):
        parse_pcap(capture, timeout=None)


def test_reverse_packets_share_one_bidirectional_flow_key() -> None:
    forward = FlowKey.from_packet(
        src_ip="198.51.100.10",
        src_port=40000,
        dst_ip="192.0.2.10",
        dst_port=80,
        protocol=6,
    )
    reverse = FlowKey.from_packet(
        src_ip="192.0.2.10",
        src_port=80,
        dst_ip="198.51.100.10",
        dst_port=40000,
        protocol=6,
    )

    assert forward == reverse


def test_canonical_direction_is_the_first_observed_packet_direction() -> None:
    rows = parse_pcap(PCAP_PATH, timeout=None)
    flow = next(row for row in rows if row["dst_port"] == 80)

    assert flow["src_ip"] == "198.51.100.10"
    assert flow["src_port"] == 40000
    assert flow["dst_ip"] == "192.0.2.10"
    assert flow["dst_port"] == 80
    assert flow["packets_from_src"] == 1
    assert flow["packets_from_dst"] == 1


def test_frame_ip_and_transport_payload_bytes_are_accounted_separately() -> None:
    rows = parse_pcap(PCAP_PATH, timeout=None)
    payload_flow = next(row for row in rows if row["dst_port"] == 8080)

    assert payload_flow["transport_payload_byte_count"] == 5
    assert payload_flow["ip_byte_count"] == 165
    assert payload_flow["frame_byte_count"] == 221
    assert payload_flow["byte_count"] == payload_flow["frame_byte_count"]

    for row in rows:
        assert (
            row["byte_count"]
            == row["frame_byte_count"]
            >= row["ip_byte_count"]
            >= row["transport_payload_byte_count"]
        )
        assert row["bytes_from_src"] + row["bytes_from_dst"] == row["byte_count"]


def test_parser_covers_ipv4_ipv6_tcp_and_udp() -> None:
    rows = parse_pcap(PCAP_PATH, timeout=None)

    assert {(row["ip_version"], row["protocol"]) for row in rows} == {
        (4, 6),
        (6, 17),
    }
    udp_flow = next(row for row in rows if row["protocol"] == 17)
    assert udp_flow["src_ip"] == "2001:db8::1"
    assert udp_flow["packet_count"] == 2
    assert udp_flow["transport_payload_byte_count"] == 11


def test_parser_honors_selected_transport_protocols() -> None:
    """A TCP-only flow profile must not write UDP rows into its cache."""
    rows = parse_pcap(PCAP_PATH, timeout=None, protocols=(6,))

    assert rows
    assert {row["protocol"] for row in rows} == {6}


def test_gzip_and_uncompressed_captures_produce_identical_flows() -> None:
    assert parse_pcap(GZIP_PATH, timeout=None) == parse_pcap(PCAP_PATH, timeout=None)


def test_malformed_capture_is_fatal(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.pcap"
    malformed.write_bytes(b"not a pcap")

    with pytest.raises(PcapParseError, match="malformed|unreadable"):
        parse_pcap(malformed, timeout=None)


def test_capture_truncated_inside_packet_record_is_fatal(tmp_path: Path) -> None:
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(PCAP_PATH.read_bytes()[:-1])

    with pytest.raises(PcapParseError, match="truncated"):
        parse_pcap(truncated, timeout=None)
