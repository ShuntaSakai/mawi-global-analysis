from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest


def _cohort() -> pd.DataFrame:
    return pd.DataFrame([{
        "source_flow_id": 1, "target_timestamp": 100.0, "protocol": 6,
        "src_ip": "198.51.100.1", "src_port": 40000,
        "dst_ip": "192.0.2.1", "dst_port": 443,
    }])


def _target(timestamp: float, src: str = "198.51.100.1", sport: int = 40000) -> dict[str, object]:
    return {"timestamp": timestamp, "src_ip": src, "src_port": sport,
            "dst_ip": "192.0.2.1", "dst_port": 443, "protocol": 6,
            "captured_frame_length": 60, "original_frame_length": 60,
            "ip_total_length": 40, "transport_payload_length": 0,
            "tcp_flags_raw": 2}


def _cohort_row(
    source_flow_id: int,
    timestamp: float,
    source_ip: str = "198.51.100.1",
    source_port: int = 40000,
) -> dict[str, object]:
    return {
        "source_flow_id": source_flow_id,
        "target_timestamp": timestamp,
        "protocol": 6,
        "src_ip": source_ip,
        "src_port": source_port,
        "dst_ip": "192.0.2.1",
        "dst_port": 443,
    }


def _syn(timestamp: float, dst: str, port: int, source: str = "198.51.100.1") -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "src_ip": source,
        "dst_ip": dst,
        "dst_port": port,
    }


def _disk_metadata(
    tmp_path: Path,
    *,
    chunk_id: str = "chunk",
    target_rows: int = 10,
    source_rows: int = 5,
    target_bytes: int = 1_000,
    source_bytes: int = 500,
) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    target_path = tmp_path / f"{chunk_id}-targets.csv"
    source_path = tmp_path / f"{chunk_id}-syns.csv"
    target_path.write_bytes(b"t" * target_bytes)
    source_path.write_bytes(b"s" * source_bytes)
    return {
        "chunk_id": chunk_id,
        "target_observation_row_count": target_rows,
        "source_syn_observation_row_count": source_rows,
        "artifacts": {
            "target_observations": {"path": str(target_path), "row_count": target_rows},
            "source_syn_observations": {"path": str(source_path), "row_count": source_rows},
        },
    }


def test_disk_estimate_has_explainable_nonzero_components(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import estimate_aggregation_disk_space

    estimate = estimate_aggregation_disk_space(
        [_disk_metadata(tmp_path)], cohort_row_count=100,
        available_bytes=10**15,
    )
    assert estimate.cache_observation_bytes == 1_500
    assert estimate.sqlite_raw_bytes > 0
    assert estimate.sqlite_index_bytes > 0
    assert estimate.derived_bytes > 0
    assert estimate.spill_headroom_bytes > 0
    assert estimate.sqlite_temp_journal_bytes > 0
    assert estimate.publication_bytes > 0
    assert estimate.safety_margin_bytes > 0
    assert estimate.required_bytes == sum((
        estimate.cache_observation_bytes,
        estimate.sqlite_raw_bytes,
        estimate.sqlite_index_bytes,
        estimate.derived_bytes,
        estimate.spill_headroom_bytes,
        estimate.sqlite_temp_journal_bytes,
        estimate.publication_bytes,
        estimate.safety_margin_bytes,
    ))


@pytest.mark.parametrize(
    ("target_rows", "source_rows", "cohort_rows", "component"),
    [
        (20, 5, 100, "sqlite_raw_bytes"),
        (10, 20, 100, "spill_headroom_bytes"),
        (10, 5, 200, "publication_bytes"),
    ],
)
def test_disk_estimate_increases_with_observation_and_cohort_evidence(
    tmp_path, target_rows, source_rows, cohort_rows, component,
):
    from mawi_global_analysis.ditl_context_sqlite import estimate_aggregation_disk_space

    baseline = estimate_aggregation_disk_space(
        [_disk_metadata(tmp_path / "baseline")], cohort_row_count=100,
        available_bytes=10**15,
    )
    changed = estimate_aggregation_disk_space(
        [_disk_metadata(
            tmp_path / "changed", target_rows=target_rows, source_rows=source_rows,
        )], cohort_row_count=cohort_rows, available_bytes=10**15,
    )
    assert getattr(changed, component) > getattr(baseline, component)
    assert changed.required_bytes > baseline.required_bytes


def test_disk_estimate_handles_96_metadata_records_without_loading_frames(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import estimate_aggregation_disk_space

    metadata = [
        _disk_metadata(tmp_path / str(index), chunk_id=str(index), target_rows=1, source_rows=1)
        for index in range(96)
    ]
    estimate = estimate_aggregation_disk_space(metadata, cohort_row_count=96, available_bytes=10**15)
    assert estimate.cache_observation_bytes == 96 * 1_500
    assert estimate.required_bytes > estimate.cache_observation_bytes


def test_disk_estimate_rejects_negative_or_invalid_metadata(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import estimate_aggregation_disk_space

    bad = _disk_metadata(tmp_path, target_rows=-1)
    with pytest.raises(ValueError, match="non-negative"):
        estimate_aggregation_disk_space([bad], cohort_row_count=1, available_bytes=10**15)
    with pytest.raises(ValueError, match="non-negative"):
        estimate_aggregation_disk_space([], cohort_row_count=-1, available_bytes=10**15)


def test_disk_preflight_rejects_insufficient_space_before_aggregation(tmp_path, monkeypatch):
    import mawi_global_analysis.ditl_context_sqlite as sqlite_context

    metadata = [_disk_metadata(tmp_path)]
    monkeypatch.setattr(
        sqlite_context.shutil, "disk_usage",
        lambda _: type("Usage", (), {"free": 1})(),
    )
    with pytest.raises(sqlite_context.InsufficientAggregationDiskSpace, match="required"):
        sqlite_context.require_aggregation_disk_space(
            tmp_path, metadata, cohort_row_count=100,
        )


def test_sqlite_aggregator_requires_exact_timestamp_and_streams_source_windows(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    aggregator = SQLiteContextAggregator(tmp_path / "aggregation.sqlite3", _cohort())
    aggregator.ingest_frames(pd.DataFrame([_target(100.0), _target(101.0)]), pd.DataFrame([
        {"timestamp": -200.0, "src_ip": "198.51.100.1", "dst_ip": "192.0.2.2", "dst_port": 80},
        {"timestamp": 400.0, "src_ip": "198.51.100.1", "dst_ip": "192.0.2.3", "dst_port": 81},
    ]))
    aggregator.compute()
    context = pd.DataFrame(aggregator.iter_context_rows())
    source = pd.DataFrame(aggregator.iter_source_context_rows())
    assert context.iloc[0]["same_5tuple_packet_count_24h"] == 2
    assert context.iloc[0]["same_5tuple_after_count"] == 1
    assert source.iloc[0]["plain_syn_packet_count_5m"] == 2
    assert source.iloc[0]["plain_syn_packet_count_15m"] == 2
    aggregator.close(delete=True)


def test_sqlite_aggregator_rejects_nearby_timestamp_not_exact(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    aggregator = SQLiteContextAggregator(tmp_path / "aggregation.sqlite3", _cohort())
    aggregator.ingest_frames(pd.DataFrame([_target(100.00000000000001)]), pd.DataFrame())
    with pytest.raises(ValueError, match="missing target"):
        aggregator.compute()
    aggregator.close(delete=False)


def test_udp_target_gets_one_non_applicable_null_source_context_row(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    cohort = _cohort(); cohort.loc[0, ["protocol", "src_ip", "src_port", "dst_ip", "dst_port"]] = [17, "198.51.100.2", 50000, "192.0.2.2", 53]
    target = _target(100.0, "198.51.100.2", 50000); target.update({"protocol": 17, "dst_ip": "192.0.2.2", "dst_port": 53, "tcp_flags_raw": None})
    aggregator = SQLiteContextAggregator(tmp_path / "aggregation.sqlite3", cohort)
    aggregator.ingest_frames(pd.DataFrame([target]), pd.DataFrame())
    aggregator.compute()
    row = next(aggregator.iter_source_context_rows())
    assert row["source_context_applicable"] is False
    assert row["context_source_ip"] is None
    assert all(row[column] is None for column in row if column.startswith(("plain_syn_", "unique_")))
    aggregator.close(delete=True)


def test_committed_ledger_survives_missing_external_checkpoint(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    path = tmp_path / "aggregation.sqlite3"
    first = SQLiteContextAggregator(path, _cohort(), identity={"cohort_identity": "cohort"})
    first.ingest_frames(pd.DataFrame([_target(100.0)]), pd.DataFrame(), chunk_id="chunk", chunk_identity="digest")
    first.close(delete=False)
    path.with_suffix(".checkpoint.json").unlink()

    resumed = SQLiteContextAggregator(path, _cohort(), identity={"cohort_identity": "cohort"})
    assert resumed.ingested_chunks == ["chunk"]
    resumed.close(delete=True)


def test_compute_rebuilds_partial_derived_tables_without_reingestion(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    path = tmp_path / "aggregation.sqlite3"
    first = SQLiteContextAggregator(path, _cohort(), identity={"cohort_identity": "cohort"})
    first.ingest_frames(pd.DataFrame([_target(100.0)]), pd.DataFrame(), chunk_id="chunk", chunk_identity="digest")
    first.connection.execute("CREATE TABLE m (partial INTEGER)")
    first.connection.commit(); first.close(delete=False)
    resumed = SQLiteContextAggregator(path, _cohort(), identity={"cohort_identity": "cohort"})
    resumed.compute()
    assert len(list(resumed.iter_context_rows())) == 1
    resumed.close(delete=True)


def _ledger_expectation(
    *, identity: str = "digest", target_rows: int = 1, source_rows: int = 0,
) -> dict[str, tuple[str, int, int]]:
    return {"chunk": (identity, target_rows, source_rows)}


def _committed_aggregator(tmp_path, *, identity: dict[str, object] | None = None):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    path = tmp_path / "aggregation.sqlite3"
    aggregator = SQLiteContextAggregator(path, _cohort(), identity=identity or {"run": "one"})
    aggregator.ingest_frames(
        pd.DataFrame([_target(100.0)]), pd.DataFrame(),
        chunk_id="chunk", chunk_identity="digest",
    )
    return aggregator


@pytest.mark.parametrize(
    ("expected", "reason"),
    [
        (_ledger_expectation(identity="other"), "metadata"),
        (_ledger_expectation(target_rows=2), "target rows"),
        (_ledger_expectation(source_rows=1), "source rows"),
        ({"different": ("digest", 1, 0)}, "unknown chunk"),
    ],
)
def test_incompatible_ledger_is_rejected_before_it_can_be_reused(tmp_path, expected, reason):
    aggregator = _committed_aggregator(tmp_path)

    with pytest.raises(ValueError, match="ledger"):
        aggregator.validate_ingestion_ledger(expected)

    aggregator.quarantine()
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    rebuilt = SQLiteContextAggregator(
        tmp_path / "aggregation.sqlite3", _cohort(), identity={"run": "one"},
    )
    assert rebuilt.ingested_chunks == [], reason
    assert (tmp_path / "aggregation.sqlite3.stale.1").exists()
    rebuilt.close(delete=True)


def test_incomplete_ledger_cannot_start_compute(tmp_path):
    aggregator = _committed_aggregator(tmp_path)

    with pytest.raises(ValueError, match="all expected DITL chunk caches"):
        aggregator.require_complete_ledger({
            **_ledger_expectation(),
            "missing": ("other", 1, 0),
        })
    aggregator.close(delete=True)


def test_identity_mismatch_quarantines_temporary_state_and_rebuilds(tmp_path):
    first = _committed_aggregator(tmp_path, identity={"run": "one"})
    first.close(delete=False)

    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    rebuilt = SQLiteContextAggregator(
        tmp_path / "aggregation.sqlite3", _cohort(), identity={"run": "two"},
    )
    assert rebuilt.ingested_chunks == []
    assert (tmp_path / "aggregation.sqlite3.stale.1").exists()
    rebuilt.close(delete=True)


def test_aggregation_code_identity_mismatch_quarantines_temporary_state(monkeypatch, tmp_path):
    import mawi_global_analysis.ditl_context_sqlite as sqlite_context

    monkeypatch.setattr(sqlite_context, "aggregation_code_identity", lambda: "code-one")
    first = _committed_aggregator(tmp_path)
    first.close(delete=False)
    monkeypatch.setattr(sqlite_context, "aggregation_code_identity", lambda: "code-two")

    rebuilt = sqlite_context.SQLiteContextAggregator(
        tmp_path / "aggregation.sqlite3", _cohort(), identity={"run": "one"},
    )
    assert rebuilt.ingested_chunks == []
    assert (tmp_path / "aggregation.sqlite3.stale.1").exists()
    rebuilt.close(delete=True)


def test_corrupt_database_is_quarantined_before_rebuild(tmp_path):
    path = tmp_path / "aggregation.sqlite3"
    path.write_bytes(b"not a sqlite database")

    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    rebuilt = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    assert rebuilt.ingested_chunks == []
    assert (tmp_path / "aggregation.sqlite3.stale.1").read_bytes() == b"not a sqlite database"
    rebuilt.close(delete=True)


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm", ".checkpoint.tmp"])
def test_orphaned_temporary_state_is_quarantined_before_database_rebuild(tmp_path, suffix):
    path = tmp_path / "aggregation.sqlite3"
    orphan = (
        path.with_suffix(".checkpoint.tmp")
        if suffix == ".checkpoint.tmp"
        else path.with_name(f"{path.name}{suffix}")
    )
    orphan.write_bytes(b"orphan")

    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    rebuilt = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    assert rebuilt.ingested_chunks == []
    assert orphan.with_name(f"{orphan.name}.stale.1").read_bytes() == b"orphan"
    rebuilt.close(delete=True)


def test_quarantine_uses_next_unique_diagnostic_suffix(tmp_path):
    path = tmp_path / "aggregation.sqlite3"
    path.write_bytes(b"not a sqlite database")
    (tmp_path / "aggregation.sqlite3.stale.1").write_bytes(b"older evidence")

    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    rebuilt = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    assert (tmp_path / "aggregation.sqlite3.stale.1").read_bytes() == b"older evidence"
    assert (tmp_path / "aggregation.sqlite3.stale.2").read_bytes() == b"not a sqlite database"
    rebuilt.close(delete=True)


def test_sqlite_ledger_overrides_stale_external_checkpoint(tmp_path):
    first = _committed_aggregator(tmp_path)
    path = first.path
    first.close(delete=False)
    path.with_suffix(".checkpoint.json").write_text(
        '{"identity": "wrong", "ingested": []}', encoding="utf-8",
    )

    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator
    resumed = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    assert resumed.ingested_chunks == ["chunk"]
    assert resumed.connection.execute("SELECT COUNT(*) FROM ingestion_ledger").fetchone() == (1,)
    resumed.close(delete=True)


def test_ingestion_before_commit_rolls_back_rows_and_ledger(tmp_path, monkeypatch):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    path = tmp_path / "aggregation.sqlite3"
    first = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    original_insert = first._insert

    def fail_after_observation_inserts(sql, rows):
        original_insert(sql, rows)
        if "INSERT INTO syn" in sql:
            raise RuntimeError("before commit")

    monkeypatch.setattr(first, "_insert", fail_after_observation_inserts)
    with pytest.raises(RuntimeError, match="before commit"):
        first.ingest_frames(
            pd.DataFrame([_target(100.0)]), pd.DataFrame(),
            chunk_id="chunk", chunk_identity="digest",
        )
    assert first.connection.execute("SELECT COUNT(*) FROM o").fetchone() == (0,)
    assert first.connection.execute("SELECT COUNT(*) FROM ingestion_ledger").fetchone() == (0,)
    first.close(delete=False)

    resumed = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    assert resumed.ingested_chunks == []
    assert resumed.connection.execute("SELECT COUNT(*) FROM o").fetchone() == (0,)
    assert resumed.connection.execute("SELECT COUNT(*) FROM ingestion_ledger").fetchone() == (0,)
    resumed.ingest_frames(
        pd.DataFrame([_target(100.0)]), pd.DataFrame(),
        chunk_id="chunk", chunk_identity="digest",
    )
    assert resumed.ingested_chunks == ["chunk"]
    resumed.close(delete=True)


def test_ingestion_after_commit_before_checkpoint_reuses_ledger(tmp_path, monkeypatch):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    path = tmp_path / "aggregation.sqlite3"
    first = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    monkeypatch.setattr(first, "_write_checkpoint", lambda _: (_ for _ in ()).throw(RuntimeError("after commit")))
    with pytest.raises(RuntimeError, match="after commit"):
        first.ingest_frames(
            pd.DataFrame([_target(100.0)]), pd.DataFrame(),
            chunk_id="chunk", chunk_identity="digest",
        )
    first.close(delete=False)

    resumed = SQLiteContextAggregator(path, _cohort(), identity={"run": "one"})
    assert resumed.ingested_chunks == ["chunk"]
    assert resumed.connection.execute("SELECT COUNT(*) FROM o").fetchone() == (1,)
    resumed.close(delete=True)


def test_prolific_source_uses_spill_and_preserves_inclusive_windows(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    syns = pd.DataFrame([
        {"timestamp": float(index - 250), "src_ip": "198.51.100.1", "dst_ip": f"192.0.2.{index % 20 + 2}", "dst_port": 80 + index % 7}
        for index in range(500)
    ])
    ordinary = SQLiteContextAggregator(tmp_path / "ordinary.sqlite3", _cohort(), active_state_limit=1_000)
    ordinary.ingest_frames(pd.DataFrame([_target(100.0)]), syns); ordinary.compute()
    expected = list(ordinary.iter_source_context_rows())
    assert ordinary.spill_used is False
    assert ordinary.spill_count == 0
    spilled = SQLiteContextAggregator(tmp_path / "spilled.sqlite3", _cohort(), active_state_limit=10, spill_batch_size=17)
    spilled.ingest_frames(pd.DataFrame([_target(100.0)]), syns); spilled.compute()
    assert spilled.spill_used is True
    assert spilled.spill_count >= 1
    assert all(spilled.spill_count_by_window[window] >= 1 for window in (300, 900, 3600))
    assert spilled.max_python_active_events <= 10
    assert spilled.max_spill_batch_rows <= 17
    assert spilled.max_post_spill_python_state == (0, 0, 0, 0)
    assert spilled.spill_migration_batches_by_table["event"] > 1
    assert spilled.spill_migration_batches_by_table["pair"] > 1
    assert list(spilled.iter_source_context_rows()) == expected


@pytest.mark.parametrize("kwargs", [{"batch_size": 0}, {"active_state_limit": 0}, {"spill_batch_size": 0}])
def test_sqlite_aggregator_rejects_non_positive_limits(tmp_path, kwargs):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    with pytest.raises(ValueError, match="positive"):
        SQLiteContextAggregator(tmp_path / "aggregation.sqlite3", _cohort(), **kwargs)


def test_spilled_window_slides_across_multiple_targets_like_memory(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    cohort = pd.concat([_cohort().assign(source_flow_id=index, target_timestamp=float(timestamp)) for index, timestamp in enumerate((0, 100, 200), 1)], ignore_index=True)
    targets = pd.DataFrame([_target(float(timestamp)) for timestamp in (0, 100, 200)])
    syns = pd.DataFrame([
        {"timestamp": float(timestamp), "src_ip": "198.51.100.1", "dst_ip": f"192.0.2.{index % 3 + 2}", "dst_port": 80 + index % 2}
        for index, timestamp in enumerate(range(-400, 701, 10))
    ])
    memory = SQLiteContextAggregator(tmp_path / "memory.sqlite3", cohort, active_state_limit=10_000)
    memory.ingest_frames(targets, syns); memory.compute(); expected = list(memory.iter_source_context_rows())
    spill = SQLiteContextAggregator(tmp_path / "spill.sqlite3", cohort, active_state_limit=10, spill_batch_size=7)
    spill.ingest_frames(targets, syns); spill.compute()
    assert memory.spill_used is False
    assert spill.spill_used is True
    assert list(spill.iter_source_context_rows()) == expected


def test_spill_keeps_exact_inclusive_source_window_boundaries(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    boundary = [
        -3600.0, -900.0, -300.0, 0.0, 300.0, 900.0, 3600.0,
        -3600.1, -900.1, -300.1, 300.1, 900.1, 3600.1,
    ]
    syns = pd.DataFrame([
        {"timestamp": value, "src_ip": "198.51.100.1", "dst_ip": f"198.18.0.{index + 1}", "dst_port": 1000 + index}
        for index, value in enumerate(boundary + [0.0] * 20)
    ])
    cohort = _cohort().assign(target_timestamp=0.0)
    reference = SQLiteContextAggregator(tmp_path / "reference.sqlite3", cohort, active_state_limit=1_000)
    reference.ingest_frames(pd.DataFrame([_target(0.0)]), syns); reference.compute(); expected = next(reference.iter_source_context_rows())
    spilled = SQLiteContextAggregator(tmp_path / "spill.sqlite3", cohort, active_state_limit=10, spill_batch_size=5)
    spilled.ingest_frames(pd.DataFrame([_target(0.0)]), syns); spilled.compute(); actual = next(spilled.iter_source_context_rows())
    assert reference.spill_used is False and reference.spill_count == 0
    assert spilled.spill_used is True
    assert actual == expected
    assert actual["plain_syn_packet_count_5m"] == 23
    assert actual["plain_syn_packet_count_15m"] == 27
    assert actual["plain_syn_packet_count_1h"] == 31
    assert actual["unique_target_count_5m"] == 23
    assert actual["unique_target_count_15m"] == 27
    assert actual["unique_target_count_1h"] == 31
    assert actual["unique_dst_ip_count_5m"] == 23
    assert actual["unique_dst_ip_count_15m"] == 27
    assert actual["unique_dst_ip_count_1h"] == 31
    assert actual["unique_dst_port_count_5m"] == 23
    assert actual["unique_dst_port_count_15m"] == 27
    assert actual["unique_dst_port_count_1h"] == 31


def test_spill_expiration_query_uses_indexed_bounded_search(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    aggregator = SQLiteContextAggregator(tmp_path / "spill.sqlite3", _cohort(), active_state_limit=1)
    aggregator.ingest_frames(pd.DataFrame([_target(100.0)]), pd.DataFrame([
        {"timestamp": 0.0, "src_ip": "198.51.100.1", "dst_ip": "192.0.2.2", "dst_port": 80},
        {"timestamp": 1.0, "src_ip": "198.51.100.1", "dst_ip": "192.0.2.3", "dst_port": 81},
    ])); aggregator.compute()
    plan = " ".join(row[-1] for row in aggregator.connection.execute("EXPLAIN QUERY PLAN SELECT seq,ts,dst,dp FROM spill_event WHERE window=? AND src=? AND ts<? ORDER BY ts,seq LIMIT ?", (300, "198.51.100.1", 100.0, 10)))
    assert "spill_expiry" in plan and "SEARCH" in plan and "TEMP B-TREE" not in plan


def test_spill_migration_batches_every_state_table_without_full_copy(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    # The first 100 events are simultaneously active and have unique pair,
    # IP, and port keys.  Thus every migration structure needs more than one
    # bounded batch; no full ``list(active)``/``list(counter.items())`` copy is
    # permitted by the migration implementation.
    syns = pd.DataFrame([
        _syn(
            float(index - 50),
            f"203.0.{index // 254}.{index % 254 + 1}",
            10_000 + index,
        )
        for index in range(300)
    ])
    spilled = SQLiteContextAggregator(
        tmp_path / "spill.sqlite3",
        _cohort().assign(target_timestamp=100.0),
        active_state_limit=100,
        spill_batch_size=17,
    )
    spilled.ingest_frames(pd.DataFrame([_target(100.0)]), syns)
    spilled.compute()

    assert spilled.spill_used is True
    assert spilled.max_python_active_events <= 100
    assert spilled.max_spill_batch_rows <= 17
    assert all(
        spilled.spill_migration_batches_by_table[name] > 1
        for name in ("event", "pair", "ip", "port")
    )
    assert spilled.max_post_spill_python_state == (0, 0, 0, 0)


def test_spill_reference_counts_slide_and_remove_keys_like_memory(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    timestamps = (0.0, 400.0, 800.0, 1_200.0)
    cohort = pd.DataFrame([
        _cohort_row(index, timestamp)
        for index, timestamp in enumerate(timestamps, start=1)
    ])
    targets = pd.DataFrame([_target(timestamp) for timestamp in timestamps])
    # ``203.0.113.2:80`` is deliberately repeated.  The other observations
    # share just an IP or just a port, so each sliding result tests pair/IP/
    # port reference counts independently as events enter and leave.
    syns = pd.DataFrame([
        _syn(-100.0, "203.0.113.2", 80),
        _syn(0.0, "203.0.113.2", 80),
        _syn(1.0, "203.0.113.2", 80),
        _syn(100.0, "203.0.113.2", 81),
        _syn(200.0, "203.0.113.3", 80),
        _syn(400.0, "203.0.113.2", 80),
        _syn(700.0, "203.0.113.2", 81),
        _syn(800.0, "203.0.113.3", 80),
        _syn(1_100.0, "203.0.113.4", 82),
        _syn(1_200.0, "203.0.113.2", 80),
    ])
    memory = SQLiteContextAggregator(
        tmp_path / "memory.sqlite3", cohort, active_state_limit=10_000,
    )
    memory.ingest_frames(targets, syns)
    memory.compute()
    expected = list(memory.iter_source_context_rows())

    spilled = SQLiteContextAggregator(
        tmp_path / "spill.sqlite3", cohort, active_state_limit=2,
        spill_batch_size=2,
    )
    spilled.ingest_frames(targets, syns)
    spilled.compute()

    assert memory.spill_used is False
    assert spilled.spill_used is True
    assert all(spilled.spill_count_by_window[window] >= 1 for window in (300, 900, 3600))
    assert list(spilled.iter_source_context_rows()) == expected
    assert [
        (
            row["plain_syn_packet_count_5m"],
            row["unique_target_count_5m"],
            row["unique_dst_ip_count_5m"],
            row["unique_dst_port_count_5m"],
        )
        for row in expected
    ] == [
        (5, 3, 2, 2),
        (4, 3, 2, 2),
        (3, 3, 3, 3),
        (2, 2, 2, 2),
    ]
    # At the final target, the ±5 minute window contains exactly the two
    # newest observations: two pairs, two IPs, and two ports.  Earlier
    # rows include the repeated pair and catch incorrect 2→1→0 decrements.
    final = expected[-1]
    assert final["plain_syn_packet_count_5m"] == 2
    assert final["unique_target_count_5m"] == 2
    assert final["unique_dst_ip_count_5m"] == 2
    assert final["unique_dst_port_count_5m"] == 2
    assert spilled.max_post_spill_python_state == (0, 0, 0, 0)


@pytest.mark.parametrize("reverse_sources", [False, True])
def test_spill_state_isolated_between_prolific_and_ordinary_sources(tmp_path, reverse_sources):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    prolific_source = "198.51.100.1"
    ordinary_source = "203.0.113.9"
    source_rows = [
        _cohort_row(1, 0.0, prolific_source),
        _cohort_row(2, 0.0, ordinary_source),
    ]
    if reverse_sources:
        source_rows.reverse()
    cohort = pd.DataFrame(source_rows)
    targets = pd.DataFrame([
        _target(0.0, prolific_source),
        _target(0.0, ordinary_source),
    ])
    syns = pd.DataFrame([
        *[
            _syn(float(index - 100), f"192.0.2.{index % 20 + 2}", 8000 + index, prolific_source)
            for index in range(250)
        ],
        _syn(-1.0, "192.0.2.200", 53, ordinary_source),
        _syn(0.0, "192.0.2.201", 54, ordinary_source),
        _syn(1.0, "192.0.2.202", 55, ordinary_source),
    ])
    memory = SQLiteContextAggregator(
        tmp_path / f"memory-{reverse_sources}.sqlite3", cohort,
        active_state_limit=10_000,
    )
    memory.ingest_frames(targets, syns)
    memory.compute()
    expected = list(memory.iter_source_context_rows())
    spilled = SQLiteContextAggregator(
        tmp_path / f"spill-{reverse_sources}.sqlite3", cohort,
        active_state_limit=10, spill_batch_size=5,
    )
    spilled.ingest_frames(targets, syns)
    spilled.compute()

    assert memory.spill_used is False
    assert spilled.spill_used is True
    assert list(spilled.iter_source_context_rows()) == expected
    ordinary = next(row for row in expected if row["source_flow_id"] == 2)
    assert ordinary["plain_syn_packet_count_5m"] == 3
    assert ordinary["unique_target_count_5m"] == 3


def test_compute_rebuilds_populated_spill_state_without_reingestion(tmp_path):
    from mawi_global_analysis.ditl_context_sqlite import SQLiteContextAggregator

    path = tmp_path / "spill-restart.sqlite3"
    syns = pd.DataFrame([
        _syn(float(index - 100), f"192.0.2.{index % 20 + 2}", 9000 + index)
        for index in range(250)
    ])
    first = SQLiteContextAggregator(path, _cohort().assign(target_timestamp=0.0), active_state_limit=10)
    first.ingest_frames(pd.DataFrame([_target(0.0)]), syns, chunk_id="chunk", chunk_identity="digest")
    first.compute()
    expected = list(first.iter_source_context_rows())
    raw_o = list(first.connection.execute("SELECT * FROM o ORDER BY rowid"))
    raw_syn = list(first.connection.execute("SELECT * FROM syn ORDER BY rowid"))
    ledger = list(first.connection.execute("SELECT * FROM ingestion_ledger"))
    # Simulate a process dying after it has populated derived spill tables.
    first.connection.execute(
        "INSERT INTO spill_event VALUES(?,?,?,?,?,?)",
        (300, "debug-source", 999_999, 0.0, "192.0.2.250", 1),
    )
    first.connection.commit()
    first.close(delete=False)

    resumed = SQLiteContextAggregator(path, _cohort().assign(target_timestamp=0.0), active_state_limit=10)
    assert resumed.ingested_chunks == ["chunk"]
    assert list(resumed.connection.execute("SELECT * FROM o ORDER BY rowid")) == raw_o
    assert list(resumed.connection.execute("SELECT * FROM syn ORDER BY rowid")) == raw_syn
    assert list(resumed.connection.execute("SELECT * FROM ingestion_ledger")) == ledger
    resumed.compute()

    assert resumed.spill_used is True
    assert list(resumed.iter_source_context_rows()) == expected
    assert resumed.connection.execute(
        "SELECT COUNT(*) FROM spill_event WHERE src = 'debug-source'"
    ).fetchone() == (0,)
    assert all(
        resumed.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone() is not None
        for table in ("spill_event", "spill_pair", "spill_ip", "spill_port")
    )
    assert resumed.connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'spill_expiry'"
    ).fetchone() == ("spill_expiry",)
