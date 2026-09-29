from __future__ import annotations

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
