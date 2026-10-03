"""Public semantic equivalence between in-memory and SQLite DITL context paths."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pandas as pd
import pytest


def _cohort_row(
    flow_id: int,
    timestamp: float,
    *,
    protocol: int = 6,
    src_ip: str = "198.51.100.1",
    src_port: int = 40_000,
    dst_ip: str = "192.0.2.1",
    dst_port: int = 443,
) -> dict[str, object]:
    return {
        "source_flow_id": flow_id,
        "target_timestamp": timestamp,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }


def _packet(
    timestamp: float,
    *,
    src_ip: str = "198.51.100.1",
    src_port: int = 40_000,
    dst_ip: str = "192.0.2.1",
    dst_port: int = 443,
    protocol: int = 6,
    flags: int | None = 2,
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "captured_frame_length": 60,
        "original_frame_length": 64,
        "ip_total_length": 40,
        "transport_payload_length": 0,
        "tcp_flags_raw": flags,
    }


def _syn(
    timestamp: float,
    dst_ip: str,
    dst_port: int,
    *,
    src_ip: str = "198.51.100.1",
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }


def _public_frame(rows: Any, columns: tuple[str, ...]) -> pd.DataFrame:
    """Make exact public ordering visible even for empty results."""
    return pd.DataFrame(list(rows), columns=columns)


def _value(value: object) -> object:
    """Only bridge public null representations; never coerce real values."""
    if value is pd.NA or value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    if hasattr(value, "item") and not isinstance(value, (str, bytes)):
        return value.item()
    return value


def _assert_public_equal(expected: pd.DataFrame, actual: pd.DataFrame) -> None:
    assert tuple(actual.columns) == tuple(expected.columns)
    assert len(actual) == len(expected)
    for row_index, (expected_row, actual_row) in enumerate(zip(
        expected.to_dict("records"), actual.to_dict("records"), strict=True,
    )):
        for column in expected.columns:
            expected_value = _value(expected_row[column])
            actual_value = _value(actual_row[column])
            assert actual_value == expected_value, (
                "public semantic mismatch: "
                f"source_flow_id={expected_row['source_flow_id']!r}, "
                f"target_timestamp={expected_row['target_timestamp']!r}, "
                f"row={row_index}, column={column!r}, "
                f"expected={expected_value!r}, actual={actual_value!r}"
            )


def _reference(
    cohort: pd.DataFrame,
    target_packets: pd.DataFrame,
    source_syn_packets: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    from mawi_global_analysis.one_packet_context import (
        aggregate_one_packet_context_observations,
    )

    return aggregate_one_packet_context_observations(
        cohort, target_packets, source_syn_packets,
    )


def _reference_chunks(
    cohort: pd.DataFrame,
    chunks: list[tuple[pd.DataFrame, pd.DataFrame]],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    from mawi_global_analysis.one_packet_context import aggregate_one_packet_context_chunks

    return aggregate_one_packet_context_chunks(
        cohort,
        [
            SimpleNamespace(target_packets=targets, source_syn_packets=syns)
            for targets, syns in chunks
        ],
    )


def _sqlite(
    tmp_path,
    cohort: pd.DataFrame,
    chunks: list[tuple[pd.DataFrame, pd.DataFrame]],
    *,
    active_state_limit: int = 10_000,
):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    from mawi_global_analysis.one_packet_context import (
        ONE_PACKET_CONTEXT_COLUMNS,
        ONE_PACKET_SOURCE_CONTEXT_COLUMNS,
    )

    tmp_path.mkdir(parents=True, exist_ok=True)
    aggregator = SQLiteContextAggregator(
        tmp_path / "aggregation.sqlite3",
        cohort,
        active_state_limit=active_state_limit,
        spill_batch_size=2,
    )
    for index, (targets, syns) in enumerate(chunks):
        aggregator.ingest_frames(
            targets, syns, chunk_id=f"chunk-{index}", chunk_identity=str(index),
        )
    aggregator.compute()
    context = _public_frame(aggregator.iter_context_rows(), ONE_PACKET_CONTEXT_COLUMNS)
    source = _public_frame(
        aggregator.iter_source_context_rows(), ONE_PACKET_SOURCE_CONTEXT_COLUMNS,
    )
    return aggregator, context, source


def _rich_fixture() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """One fixture exercises tuple, source, TCP, UDP, and null semantics."""
    cohort = pd.DataFrame([
        _cohort_row(20, 100.0),
        _cohort_row(
            10, 50.0, protocol=17, src_ip="203.0.113.1", src_port=50_000,
            dst_ip="203.0.113.2", dst_port=53,
        ),
        _cohort_row(30, 200.0, src_port=40_001),
        _cohort_row(40, 300.0, src_port=40_002),
        _cohort_row(50, 350.0, src_port=40_003),
        _cohort_row(60, 500.0, src_port=40_004),
    ])
    targets = pd.DataFrame([
        _packet(-200.0001),
        _packet(-200.0),
        _packet(40.0),
        _packet(90.0, src_ip="192.0.2.1", src_port=443, dst_ip="198.51.100.1", dst_port=40_000, flags=18),
        _packet(99.0, src_ip="192.0.2.1", src_port=443, dst_ip="198.51.100.1", dst_port=40_000, flags=18),
        _packet(100.0, flags=0x102),
        _packet(101.0, flags=16),
        _packet(101.0, src_ip="192.0.2.1", src_port=443, dst_ip="198.51.100.1", dst_port=40_000, flags=18),
        _packet(110.0, flags=16),
        _packet(160.0, flags=16),
        _packet(400.0, flags=16),
        _packet(400.0001, flags=16),
        _packet(50.0, protocol=17, src_ip="203.0.113.1", src_port=50_000, dst_ip="203.0.113.2", dst_port=53, flags=None),
        _packet(200.0, src_port=40_001, flags=18),
        _packet(300.0, src_port=40_002, flags=16),
        _packet(350.0, src_port=40_003, flags=1),
        _packet(500.0, src_port=40_004, flags=2),
    ])
    source = pd.DataFrame([
        _syn(-3_500.0, "192.0.2.10", 80),
        _syn(-800.0, "192.0.2.10", 80),
        _syn(-200.0, "192.0.2.10", 80),
        _syn(100.0, "192.0.2.10", 81),
        _syn(400.0, "192.0.2.11", 80),
        _syn(1_000.0, "192.0.2.12", 82),
        _syn(3_700.0, "192.0.2.13", 83),
        _syn(-3_500.0001, "192.0.2.14", 84),
        _syn(-800.0001, "192.0.2.15", 85),
        _syn(-200.0001, "192.0.2.16", 86),
        _syn(400.0001, "192.0.2.17", 87),
        _syn(1_000.0001, "192.0.2.18", 88),
        _syn(3_700.0001, "192.0.2.19", 89),
        _syn(200.0, "192.0.2.20", 443, src_ip="203.0.113.1"),
    ])
    return cohort, targets, source


def test_public_tuple_and_source_outputs_match_established_reference(tmp_path) -> None:
    cohort, targets, syns = _rich_fixture()
    expected_context, expected_source = _reference(cohort, targets, syns)
    aggregator, actual_context, actual_source = _sqlite(
        tmp_path, cohort, [(targets, syns)], active_state_limit=10_000,
    )

    _assert_public_equal(expected_context, actual_context)
    _assert_public_equal(expected_source, actual_source)
    assert tuple(actual_context.columns) == tuple(expected_context.columns)
    assert tuple(actual_source.columns) == tuple(expected_source.columns)
    assert actual_context["source_flow_id"].tolist() == cohort["source_flow_id"].tolist()
    assert actual_source["source_flow_id"].tolist() == cohort["source_flow_id"].tolist()
    assert actual_context["target_timestamp"].tolist() == cohort["target_timestamp"].tolist()
    assert actual_source["target_timestamp"].tolist() == cohort["target_timestamp"].tolist()
    assert aggregator.spill_used is False


def test_reference_equivalence_covers_flags_nulls_boundaries_and_public_types(tmp_path) -> None:
    cohort, targets, syns = _rich_fixture()
    expected_context, expected_source = _reference(cohort, targets, syns)
    aggregator, actual_context, actual_source = _sqlite(tmp_path, cohort, [(targets, syns)])

    _assert_public_equal(expected_context, actual_context)
    _assert_public_equal(expected_source, actual_source)

    plain = actual_context.loc[actual_context["source_flow_id"] == 20].iloc[0]
    assert plain["tcp_flags_raw"] == 0x102
    assert plain["tcp_flags_text"] == "NS"
    assert plain["packet_src_ip"] == "198.51.100.1"
    assert plain["packet_dst_ip"] == "192.0.2.1"
    assert plain["same_5tuple_packet_count_24h"] == 12
    assert plain["same_5tuple_before_count"] == 5
    assert plain["same_5tuple_after_count"] == 6
    assert plain["forward_packet_count_24h"] == 9
    assert plain["reverse_packet_count_24h"] == 3
    assert plain["previous_same_5tuple_timestamp"] == 99.0
    assert plain["previous_same_5tuple_gap_seconds"] == 1.0
    assert plain["next_same_5tuple_timestamp"] == 101.0
    assert plain["next_same_5tuple_gap_seconds"] == 1.0
    assert plain["nearest_reverse_before_gap_seconds"] == 1.0
    assert plain["nearest_reverse_after_gap_seconds"] == 1.0
    assert plain["same_5tuple_before_1s"] == 1
    assert plain["same_5tuple_after_1s"] == 2
    assert plain["same_5tuple_before_10s"] == 2
    assert plain["same_5tuple_after_10s"] == 3
    assert plain["same_5tuple_before_60s"] == 3
    assert plain["same_5tuple_after_60s"] == 4
    assert plain["same_5tuple_before_300s"] == 4
    assert plain["same_5tuple_after_300s"] == 5

    plain_source = actual_source.loc[actual_source["source_flow_id"] == 20].iloc[0]
    assert plain_source["plain_syn_packet_count_5m"] == 3
    assert plain_source["plain_syn_packet_count_15m"] == 7
    assert plain_source["plain_syn_packet_count_1h"] == 11
    assert plain_source["plain_syn_packet_count_24h"] == 13
    assert plain_source["unique_target_count_24h"] == 11
    assert plain_source["unique_dst_ip_count_24h"] == 10
    assert plain_source["unique_dst_port_count_24h"] == 10
    raw_context = {row["source_flow_id"]: row for row in aggregator.iter_context_rows()}
    raw_source = {row["source_flow_id"]: row for row in aggregator.iter_source_context_rows()}
    for flow_id in (10, 30, 40, 50):
        row = raw_source[flow_id]
        assert row["source_context_applicable"] is False
        assert row["context_source_ip"] is None
        assert all(
            row[column] is None
            for column in actual_source.columns
            if column.startswith(("plain_syn_", "unique_"))
        )
    udp = raw_context[10]
    assert udp["tcp_flags_raw"] is None
    assert udp["tcp_flags_text"] is None
    isolated = raw_context[40]
    assert isolated["previous_same_5tuple_timestamp"] is None
    assert isolated["previous_same_5tuple_gap_seconds"] is None
    assert isolated["next_same_5tuple_timestamp"] is None
    assert isolated["next_same_5tuple_gap_seconds"] is None
    assert isolated["nearest_reverse_before_gap_seconds"] is None
    assert isolated["nearest_reverse_after_gap_seconds"] is None
    assert [type(raw_context[20][column]) for column in ("source_flow_id", "target_timestamp", "tcp_flags_raw")] == [int, float, int]
    assert all(type(row["source_context_applicable"]) is bool for row in raw_source.values())


@pytest.mark.parametrize(
    "target_packets",
    [
        pd.DataFrame(columns=(
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "captured_frame_length", "original_frame_length", "ip_total_length",
            "transport_payload_length", "tcp_flags_raw",
        )),
        pd.DataFrame([_packet(100.00000000000001)]),
        pd.DataFrame([_packet(100.0, src_port=40_001)]),
        pd.DataFrame([_packet(100.0), _packet(100.0)]),
    ],
    ids=["missing_exact", "nearby_timestamp", "same_timestamp_different_flow_key", "duplicate_exact"],
)
def test_exact_target_match_failures_match_established_reference(tmp_path, target_packets) -> None:
    cohort = pd.DataFrame([_cohort_row(1, 100.0)])
    empty_syn = pd.DataFrame(columns=("timestamp", "src_ip", "dst_ip", "dst_port"))
    with pytest.raises(ValueError):
        _reference(cohort, target_packets, empty_syn)
    with pytest.raises(ValueError):
        _sqlite(tmp_path, cohort, [(target_packets, empty_syn)])


@pytest.mark.parametrize("timestamp", [100.0, 100.00000000000001])
def test_exact_ieee_float_target_timestamp_matches_only_the_same_value(tmp_path, timestamp: float) -> None:
    cohort = pd.DataFrame([_cohort_row(1, timestamp)])
    targets = pd.DataFrame([_packet(timestamp)])
    syns = pd.DataFrame(columns=("timestamp", "src_ip", "dst_ip", "dst_port"))
    expected_context, expected_source = _reference(cohort, targets, syns)
    _, actual_context, actual_source = _sqlite(tmp_path, cohort, [(targets, syns)])

    _assert_public_equal(expected_context, actual_context)
    _assert_public_equal(expected_source, actual_source)


def test_chunk_ingestion_order_and_spill_match_reference(tmp_path) -> None:
    cohort, targets, syns = _rich_fixture()
    chunks = [
        (targets.iloc[:5].reset_index(drop=True), syns.iloc[:3].reset_index(drop=True)),
        (targets.iloc[5:10].reset_index(drop=True), syns.iloc[3:6].reset_index(drop=True)),
        (targets.iloc[10:].reset_index(drop=True), syns.iloc[6:].reset_index(drop=True)),
    ]
    expected_context, expected_source = _reference_chunks(cohort, chunks)
    nonspill, nonspill_context, nonspill_source = _sqlite(
        tmp_path / "nonspill", cohort, chunks, active_state_limit=10_000,
    )
    spill, spill_context, spill_source = _sqlite(
        tmp_path / "spill", cohort, list(reversed(chunks)), active_state_limit=2,
    )

    assert nonspill.spill_used is False
    assert spill.spill_used is True
    _assert_public_equal(expected_context, nonspill_context)
    _assert_public_equal(expected_source, nonspill_source)
    _assert_public_equal(expected_context, spill_context)
    _assert_public_equal(expected_source, spill_source)


def test_sparse_targets_with_day_history_and_gaps_match_reference_under_spill(tmp_path):
    timestamps = (10_000.0, 30_000.0)
    sources = ("198.51.100.1", "198.51.100.2")
    cohort = pd.DataFrame([
        _cohort_row(index, ts, src_ip=src)
        for index, (src, ts) in enumerate(
            ((src, ts) for src in sources for ts in timestamps), start=1,
        )
    ])
    targets = pd.DataFrame([_packet(ts, src_ip=src) for src in sources for ts in timestamps])
    syns = pd.DataFrame([
        _syn(ts, f"192.0.2.{index % 20 + 2}", 80 + index % 3, src_ip=src)
        for src in sources
        for index, ts in enumerate((
            0.0, 1.0, 2.0, 15_000.0, 15_001.0,
            *[t + offset for t in timestamps for offset in (-3600, -900, -300, 0, 300, 900, 3600)],
        ))
    ])
    expected_context, expected_source = _reference(cohort, targets, syns)
    memory, memory_context, memory_source = _sqlite(
        tmp_path / "memory", cohort, [(targets, syns)], active_state_limit=100,
    )
    spill, spill_context, spill_source = _sqlite(
        tmp_path / "spill", cohort, [(targets, syns)], active_state_limit=1,
    )
    assert not memory.spill_used
    assert spill.spill_used
    _assert_public_equal(expected_context, memory_context)
    _assert_public_equal(expected_source, memory_source)
    _assert_public_equal(expected_context, spill_context)
    _assert_public_equal(expected_source, spill_source)
    for table in ("spill_event", "spill_pair", "spill_ip", "spill_port"):
        assert spill.connection.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)
