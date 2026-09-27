"""Tests for durable observational caches used by multi-chunk context analysis."""

from __future__ import annotations

import socket
import json
import struct
import gzip
from pathlib import Path

import dpkt
import pandas as pd
import pytest

from mawi_global_analysis.one_packet_context import ONE_PACKET_COHORT_COLUMNS


def _tcp_frame(src: str, sport: int, dst: str, dport: int, flags: int) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=b"payload")
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP,
        ttl=64, data=tcp,
    )
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    ))


def _udp_frame(src: str, sport: int, dst: str, dport: int) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=b"udp")
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_UDP,
        ttl=64, data=udp,
    )
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    ))


def _pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        for timestamp, frame in packets:
            writer.writepkt(frame, ts=timestamp)
        writer.close()


def _cohort() -> pd.DataFrame:
    row = {column: None for column in ONE_PACKET_COHORT_COLUMNS}
    row.update(
        source_flow_id=1, target_timestamp=100.0, protocol=6,
        src_ip="198.51.100.1", src_port=40000,
        dst_ip="192.0.2.1", dst_port=443,
    )
    return pd.DataFrame([row], columns=ONE_PACKET_COHORT_COLUMNS)


def _target_observation(flags: object) -> pd.DataFrame:
    from mawi_global_analysis.one_packet_context_chunks import TARGET_OBSERVATION_COLUMNS

    return pd.DataFrame([{
        "timestamp": 100.0, "src_ip": "198.51.100.1", "src_port": 40000,
        "dst_ip": "192.0.2.1", "dst_port": 443, "protocol": 6,
        "captured_frame_length": 54, "original_frame_length": 54,
        "ip_total_length": 40, "transport_payload_length": 0,
        "tcp_flags_raw": flags,
    }], columns=TARGET_OBSERVATION_COLUMNS)


@pytest.mark.parametrize("flags", [0, 255, 256, 319, 386, 450, 511])
def test_chunk_observation_validator_accepts_representable_9_bit_tcp_flags(flags: int) -> None:
    from mawi_global_analysis.one_packet_context_chunks import _validate_observation_values

    _validate_observation_values(_target_observation(flags), is_target=True)


@pytest.mark.parametrize("flags", [-1, 512, 1.5])
def test_chunk_observation_validator_rejects_invalid_tcp_flags(flags: object) -> None:
    from mawi_global_analysis.one_packet_context_chunks import ChunkCacheConflictError, _validate_observation_values

    with pytest.raises(ChunkCacheConflictError, match="invalid TCP flags"):
        _validate_observation_values(_target_observation(flags), is_target=True)


def test_chunk_cache_preserves_raw_ninth_bit_tcp_flags(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    capture = tmp_path / "ns.pcap"
    flags = 319
    _pcap(capture, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, flags))])
    cache = tmp_path / "cache"

    extract_one_packet_chunk_observations(capture, _cohort(), cache, "ns")
    assert load_completed_chunk_observations(cache, "ns", _cohort()).target_packets.iloc[0]["tcp_flags_raw"] == flags


def test_extracts_only_relevant_observations_and_reloads_after_source_deletion(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import (
        SOURCE_SYN_OBSERVATION_COLUMNS,
        TARGET_OBSERVATION_COLUMNS,
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    capture = tmp_path / "chunk.pcap"
    _pcap(capture, [
        (90.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_ACK)),
        (100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN)),
        (101.0, _udp_frame("198.51.100.1", 40000, "192.0.2.1", 443)),
        (102.0, _tcp_frame("198.51.100.1", 40001, "192.0.2.2", 80, dpkt.tcp.TH_SYN)),
        (103.0, _tcp_frame("203.0.113.1", 40002, "192.0.2.3", 53, dpkt.tcp.TH_SYN)),
    ])
    cache = tmp_path / "cache"

    metadata = extract_one_packet_chunk_observations(capture, _cohort(), cache, "target")

    assert metadata["status"] == "success"
    assert metadata["source"]["size_bytes"] == capture.stat().st_size
    assert metadata["target_observation_row_count"] == 2
    assert metadata["source_syn_observation_row_count"] == 2
    loaded = load_completed_chunk_observations(cache, "target", _cohort())
    assert tuple(loaded.target_packets.columns) == TARGET_OBSERVATION_COLUMNS
    assert tuple(loaded.source_syn_packets.columns) == SOURCE_SYN_OBSERVATION_COLUMNS
    assert loaded.target_packets["timestamp"].tolist() == [90.0, 100.0]
    assert loaded.target_packets["protocol"].tolist() == [6, 6]
    assert loaded.target_packets["captured_frame_length"].tolist() == [
        len(_tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_ACK)),
    ] * 2
    assert loaded.source_syn_packets["src_ip"].tolist() == ["198.51.100.1", "198.51.100.1"]
    capture.unlink()
    reloaded = load_completed_chunk_observations(cache, "target", _cohort())
    assert reloaded.metadata["status"] == "success"
    from mawi_global_analysis.one_packet_context import aggregate_one_packet_context_chunks
    context, source_context = aggregate_one_packet_context_chunks(_cohort(), [reloaded])
    assert context.iloc[0]["same_5tuple_packet_count_24h"] == 2
    assert source_context.iloc[0]["plain_syn_packet_count_24h"] == 2


def test_disk_revalidated_phase5a_checkpoint_permits_owned_raw_deletion(tmp_path: Path) -> None:
    from mawi_global_analysis.ditl_downloader import delete_owned_raw_after_checkpoint, write_ownership_record
    from mawi_global_analysis.one_packet_context_chunks import extract_one_packet_chunk_observations, load_completed_chunk_observations

    spool = tmp_path / "spool"; spool.mkdir()
    unpacked = spool / "temporary.pcap"
    _pcap(unpacked, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    capture = spool / "202604081400.pcap.gz"
    capture.write_bytes(gzip.compress(unpacked.read_bytes()))
    write_ownership_record(capture, "202604081400", "https://example.test/202604081400.pcap.gz")
    cache = tmp_path / "cache"
    extract_one_packet_chunk_observations(capture, _cohort(), cache, "202604081400", source_url="https://example.test/202604081400.pcap.gz")
    checkpoint = load_completed_chunk_observations(cache, "202604081400", _cohort())

    from mawi_global_analysis.one_packet_context_chunks import cohort_identity
    assert delete_owned_raw_after_checkpoint(capture, spool, checkpoint,
        expected_cohort_identity=cohort_identity(_cohort()), expected_chunk_id="202604081400",
        expected_source_url="https://example.test/202604081400.pcap.gz")
    assert not capture.exists()


def test_completed_cache_rejects_corruption_changed_source_and_changed_cohort(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import (
        ChunkCacheConflictError,
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    capture = tmp_path / "same-name.pcap"
    _pcap(capture, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    cache = tmp_path / "cache"
    extract_one_packet_chunk_observations(capture, _cohort(), cache, "chunk")
    target_csv = cache / "chunk" / "target_observations.csv"
    target_csv.write_text("corrupt\n", encoding="utf-8")
    with pytest.raises(ChunkCacheConflictError, match="checksum|schema"):
        load_completed_chunk_observations(cache, "chunk", _cohort())

    extract_one_packet_chunk_observations(capture, _cohort(), cache, "other")
    _pcap(capture, [(101.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    with pytest.raises(ChunkCacheConflictError, match="source identity"):
        extract_one_packet_chunk_observations(capture, _cohort(), cache, "other")
    changed = _cohort().copy()
    changed.loc[0, "src_port"] = 40001
    with pytest.raises(ChunkCacheConflictError, match="cohort identity"):
        load_completed_chunk_observations(cache, "other", changed)


def test_completed_cache_reuses_identical_capture_after_path_changes(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import extract_one_packet_chunk_observations

    original = tmp_path / "original.pcap"
    _pcap(original, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    cache = tmp_path / "cache"
    first = extract_one_packet_chunk_observations(original, _cohort(), cache, "chunk")
    relocated = tmp_path / "relocated.pcap"
    relocated.write_bytes(original.read_bytes())
    second = extract_one_packet_chunk_observations(relocated, _cohort(), cache, "chunk")
    assert second == first


def test_completed_cache_round_trips_exact_packet_timestamp_and_relative_cache_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mawi_global_analysis.flow import iter_capture_packet_records
    from mawi_global_analysis.one_packet_context_chunks import (
        enumerate_completed_chunk_metadata,
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    capture = tmp_path / "precise.pcap"
    timestamp = 100 + 23339 / 1_000_000
    _pcap(capture, [(timestamp, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    raw_timestamp = next(iter_capture_packet_records(capture))[0]
    cache = tmp_path / "cache"
    extract_one_packet_chunk_observations(capture, _cohort(), cache, "precise")
    assert load_completed_chunk_observations(cache, "precise", _cohort()).target_packets.iloc[0]["timestamp"] == raw_timestamp

    monkeypatch.chdir(tmp_path)
    metadata = enumerate_completed_chunk_metadata(Path("cache"), _cohort())
    assert [record["chunk_id"] for record in metadata] == ["precise"]


def test_extraction_failure_never_publishes_success_metadata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import mawi_global_analysis.one_packet_context_chunks as chunks

    capture = tmp_path / "chunk.pcap"
    _pcap(capture, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    calls = 0
    original = chunks._write_dataframe_atomically

    def fail_on_second_write(frame: pd.DataFrame, path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated output failure")
        original(frame, path)

    monkeypatch.setattr(chunks, "_write_dataframe_atomically", fail_on_second_write)
    with pytest.raises(OSError, match="simulated"):
        chunks.extract_one_packet_chunk_observations(capture, _cohort(), tmp_path / "cache", "failed")
    assert not (tmp_path / "cache" / "failed" / "chunk_metadata.json").exists()


@pytest.mark.parametrize("field", ["source", "observation_code_identity"])
def test_completed_cache_rejects_incomplete_or_wrong_identity_metadata(tmp_path: Path, field: str) -> None:
    from mawi_global_analysis.one_packet_context_chunks import (
        ChunkCacheConflictError,
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    capture = tmp_path / "chunk.pcap"
    _pcap(capture, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
    cache = tmp_path / "cache"
    extract_one_packet_chunk_observations(capture, _cohort(), cache, "chunk")
    metadata_path = cache / "chunk" / "chunk_metadata.json"
    metadata = json.loads(metadata_path.read_text())
    if field == "source":
        del metadata[field]
    else:
        metadata[field] = "wrong"
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ChunkCacheConflictError, match="source identity|code identity"):
        load_completed_chunk_observations(cache, "chunk", _cohort())


def test_chunk_aggregation_matches_single_capture_and_is_order_independent(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import (
        aggregate_one_packet_context_chunks,
        scan_one_packet_contexts,
    )
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    packets = [
        (99.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_ACK)),
        (100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN)),
        (101.0, _tcp_frame("192.0.2.1", 443, "198.51.100.1", 40000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)),
        (400.0, _tcp_frame("198.51.100.1", 40001, "192.0.2.2", 80, dpkt.tcp.TH_SYN)),
        (100.0, _tcp_frame("203.0.113.9", 40002, "192.0.2.9", 53, dpkt.tcp.TH_SYN)),
    ]
    combined = tmp_path / "combined.pcap"
    _pcap(combined, packets)
    chunk_paths = []
    cache = tmp_path / "cache"
    for chunk_id, records in (("late", packets[2:]), ("early", packets[:2])):
        capture = tmp_path / f"{chunk_id}.pcap"
        _pcap(capture, records)
        extract_one_packet_chunk_observations(capture, _cohort(), cache, chunk_id)
        chunk_paths.append(load_completed_chunk_observations(cache, chunk_id, _cohort()))

    expected_context, expected_source = scan_one_packet_contexts(combined, _cohort())
    actual_context, actual_source = aggregate_one_packet_context_chunks(_cohort(), chunk_paths)
    reverse_context, reverse_source = aggregate_one_packet_context_chunks(_cohort(), list(reversed(chunk_paths)))
    pd.testing.assert_frame_equal(actual_context, expected_context)
    pd.testing.assert_frame_equal(actual_source, expected_source)
    pd.testing.assert_frame_equal(reverse_context, expected_context)
    pd.testing.assert_frame_equal(reverse_source, expected_source)
    assert actual_context.iloc[0]["previous_same_5tuple_timestamp"] == 99.0
    assert actual_context.iloc[0]["nearest_reverse_after_gap_seconds"] == 1.0
    assert actual_source.iloc[0]["plain_syn_packet_count_5m"] == 2
    assert actual_source.iloc[0]["plain_syn_packet_count_24h"] == 2


def test_chunk_aggregation_rejects_duplicate_target_matches_across_chunks(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import aggregate_one_packet_context_chunks
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    cache = tmp_path / "cache"
    chunks = []
    for chunk_id in ("one", "two"):
        capture = tmp_path / f"{chunk_id}.pcap"
        _pcap(capture, [(100.0, _tcp_frame("198.51.100.1", 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))])
        extract_one_packet_chunk_observations(capture, _cohort(), cache, chunk_id)
        chunks.append(load_completed_chunk_observations(cache, chunk_id, _cohort()))
    with pytest.raises(ValueError, match="ambiguous target"):
        aggregate_one_packet_context_chunks(_cohort(), chunks)


def test_five_chunks_target_first_preserve_boundaries_and_full_day_uniqueness(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import (
        aggregate_one_packet_context_chunks,
        scan_one_packet_contexts,
    )
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    source = "198.51.100.1"
    captures = {
        "00": [(0.0, _tcp_frame(source, 40100, "192.0.2.10", 80, dpkt.tcp.TH_SYN))],
        "1345": [
            (49500.0, _tcp_frame(source, 40000, "192.0.2.1", 443, dpkt.tcp.TH_ACK)),
            (49500.0, _tcp_frame(source, 40101, "192.0.2.11", 81, dpkt.tcp.TH_SYN)),
        ],
        "1400": [(50400.0, _tcp_frame(source, 40000, "192.0.2.1", 443, dpkt.tcp.TH_SYN))],
        "1415": [
            (51300.0, _tcp_frame("192.0.2.1", 443, source, 40000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)),
            (51300.0, _tcp_frame(source, 40102, "192.0.2.12", 82, dpkt.tcp.TH_SYN)),
        ],
        "2345": [(85500.0, _tcp_frame(source, 40103, "192.0.2.12", 82, dpkt.tcp.TH_SYN))],
    }
    cache = tmp_path / "cache"
    combined_records = [record for records in captures.values() for record in records]
    combined = tmp_path / "combined.pcap"
    _pcap(combined, combined_records)
    for chunk_id, records in captures.items():
        capture = tmp_path / f"{chunk_id}.pcap"
        _pcap(capture, records)
        extract_one_packet_chunk_observations(capture, _cohort().assign(target_timestamp=50400.0), cache, chunk_id)
    cohort = _cohort().assign(target_timestamp=50400.0)
    target_first = ["1400", "00", "2345", "1345", "1415"]
    chunks = [load_completed_chunk_observations(cache, chunk_id, cohort) for chunk_id in target_first]
    actual_context, actual_source = aggregate_one_packet_context_chunks(cohort, chunks)
    expected_context, expected_source = scan_one_packet_contexts(combined, cohort)
    pd.testing.assert_frame_equal(actual_context, expected_context)
    pd.testing.assert_frame_equal(actual_source, expected_source)
    source_row = actual_source.iloc[0]
    assert source_row["plain_syn_packet_count_5m"] == 1
    assert source_row["plain_syn_packet_count_15m"] == 3
    assert source_row["plain_syn_packet_count_1h"] == 3
    assert source_row["plain_syn_packet_count_24h"] == 5
    assert source_row["unique_target_count_24h"] == 4
    assert source_row["unique_dst_ip_count_24h"] == 4
    assert source_row["unique_dst_port_count_24h"] == 4


def test_chunk_cache_preserves_udp_and_distinct_original_frame_length(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )

    cohort = _cohort().copy()
    cohort.loc[0, ["protocol", "src_ip", "src_port", "dst_ip", "dst_port"]] = [17, "198.51.100.2", 50000, "192.0.2.2", 53]
    frame = _udp_frame("198.51.100.2", 50000, "192.0.2.2", 53)
    capture = tmp_path / "udp.pcap"
    _pcap(capture, [(100.0, frame)])
    raw = bytearray(capture.read_bytes())
    struct.pack_into("<I", raw, 24 + 12, len(frame) + 50)
    capture.write_bytes(raw)
    cache = tmp_path / "cache"
    extract_one_packet_chunk_observations(capture, cohort, cache, "udp")
    row = load_completed_chunk_observations(cache, "udp", cohort).target_packets.iloc[0]
    assert row["protocol"] == 17
    assert row["captured_frame_length"] == len(frame)
    assert row["original_frame_length"] == len(frame) + 50
    assert pd.isna(row["tcp_flags_raw"])
