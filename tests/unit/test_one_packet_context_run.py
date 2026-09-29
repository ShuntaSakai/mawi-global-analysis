"""Tests for deterministic one-packet context run artifacts."""

from __future__ import annotations

import json
import socket
import csv
from pathlib import Path

import dpkt
import pandas as pd
import pytest


class _StreamingAggregator:
    """Small cursor-like fixture; production receives SQLite iterators."""

    def __init__(self, context: pd.DataFrame, source_context: pd.DataFrame) -> None:
        self.context = context
        self.source_context = source_context

    def iter_context_rows(self):
        yield from self.context.to_dict("records")

    def iter_source_context_rows(self):
        yield from self.source_context.to_dict("records")


def _streaming_inputs(tmp_path: Path):
    from mawi_global_analysis.one_packet_context_chunks import cohort_identity

    tmp_path.mkdir(parents=True, exist_ok=True)
    _, source, _ = _provenance(tmp_path)
    cohort, context, source_context = _frames()
    cohort.loc[0, ["protocol", "src_ip", "src_port", "dst_ip", "dst_port"]] = [
        6, "198.51.100.1", 40000, "192.0.2.1", 443,
    ]
    source_manifest = json.loads(source.read_text())
    metadata = [{
        "status": "success",
        "chunk_id": "target",
        "cohort_identity": cohort_identity(cohort),
        "observation_code_identity": "fixture-observation-code",
        "source": {
            "sha256": source_manifest["input"]["sha256"],
            "filename": "target.pcap.gz",
            "size_bytes": 1,
            "url": "https://example.test/target.pcap.gz",
        },
        "target_observation_row_count": len(context),
        "source_syn_observation_row_count": 0,
        "artifacts": {},
    }]
    return source, cohort, context, source_context, metadata


def _write_streaming_fixture(tmp_path: Path, aggregator=None, *, context_run_name: str = "streaming") -> Path:
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_chunk_run_streaming

    source, cohort, context, source_context, metadata = _streaming_inputs(tmp_path)
    return write_one_packet_context_chunk_run_streaming(
        "fixture", "source", metadata, "target", context_run_name, cohort,
        aggregator or _StreamingAggregator(context, source_context), source,
        root=tmp_path,
    )


def _provenance(tmp_path: Path) -> tuple[Path, Path, Path]:
    extracted = tmp_path / "window.pcap"
    extracted.write_bytes(b"extracted")
    full = tmp_path / "full.pcap.gz"
    full.write_bytes(b"full")
    window = tmp_path / "window_manifest.json"
    window.write_text(json.dumps({
        "window_start": "2026-04-08T05:00:00+00:00",
        "window_end": "2026-04-08T05:15:00+00:00",
        "output_path": str(extracted),
        "output_sha256": __import__("hashlib").sha256(extracted.read_bytes()).hexdigest(),
        "source_sha256": __import__("hashlib").sha256(full.read_bytes()).hexdigest(),
    }))
    source = tmp_path / "run_manifest.json"
    source.write_text(json.dumps({
        "status": "success", "dataset_id": "fixture", "input": {
            "path": str(extracted), "sha256": __import__("hashlib").sha256(extracted.read_bytes()).hexdigest(),
        }, "config": {"path": "configs/scan_source_driven_removal.yaml", "hash": "config-hash", "text": "scan: {}"},
    }))
    return full, source, window


def _frames() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    from mawi_global_analysis.one_packet_context import (
        ONE_PACKET_COHORT_COLUMNS, ONE_PACKET_CONTEXT_COLUMNS,
        ONE_PACKET_SOURCE_CONTEXT_COLUMNS,
    )

    cohort_row = {column: None for column in ONE_PACKET_COHORT_COLUMNS}
    context_row = {column: None for column in ONE_PACKET_CONTEXT_COLUMNS}
    source_row = {column: None for column in ONE_PACKET_SOURCE_CONTEXT_COLUMNS}
    cohort_row.update(source_flow_id=2, target_timestamp=10.0)
    context_row.update(source_flow_id=2, target_timestamp=10.0, packet_src_ip="198.51.100.1")
    source_row.update(source_flow_id=2, target_timestamp=10.0, source_context_applicable=True)
    cohort = pd.DataFrame([cohort_row], columns=ONE_PACKET_COHORT_COLUMNS)
    context = pd.DataFrame([context_row], columns=ONE_PACKET_CONTEXT_COLUMNS)
    source_context = pd.DataFrame([source_row], columns=ONE_PACKET_SOURCE_CONTEXT_COLUMNS)
    return cohort, context, source_context


def test_writer_records_deterministic_artifacts_and_provenance(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_run

    full, source, window = _provenance(tmp_path)
    cohort, context, source_context = _frames()
    run_dir = write_one_packet_context_run(
        dataset_id="fixture", source_run_name="source", full_capture_path=full,
        context_run_name="context", cohort=cohort, context=context,
        source_context=source_context, source_run_manifest_path=source,
        window_manifest_path=window, root=tmp_path,
    )

    manifest = json.loads((run_dir / "context_manifest.json").read_text())
    assert manifest["status"] == "success"
    assert manifest["source_run"]["run_name"] == "source"
    assert manifest["full_capture"]["sha256"]
    assert manifest["source_capture_window"]["window_start"] == "2026-04-08T05:00:00+00:00"
    assert set(manifest["artifacts"]) == {"one_packet_cohort", "one_packet_context", "one_packet_source_context"}
    assert list(pd.read_csv(run_dir / "one_packet_cohort.csv").columns) == list(cohort.columns)


def test_writer_rejects_existing_context_run_with_different_identity(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import ContextRunConflictError, write_one_packet_context_run

    full, source, window = _provenance(tmp_path)
    cohort, context, source_context = _frames()
    write_one_packet_context_run("fixture", "source", full, "context", cohort, context, source_context, source, window, root=tmp_path)
    source_data = json.loads(source.read_text())
    source_data["config"]["hash"] = "changed-config-hash"
    source.write_text(json.dumps(source_data))
    with pytest.raises(ContextRunConflictError, match="identity"):
        write_one_packet_context_run("fixture", "source", full, "context", cohort, context, source_context, source, window, root=tmp_path)


def test_writer_rejects_full_capture_that_does_not_match_window_ancestry(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_run

    full, source, window = _provenance(tmp_path)
    cohort, context, source_context = _frames()
    substitute = tmp_path / "substitute.pcap.gz"
    substitute.write_bytes(b"substitute")
    with pytest.raises(ValueError, match="full capture"):
        write_one_packet_context_run("fixture", "source", substitute, "context", cohort, context, source_context, source, window, root=tmp_path)


def test_writer_does_not_reuse_a_success_manifest_with_missing_artifact(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import ContextRunConflictError, write_one_packet_context_run

    full, source, window = _provenance(tmp_path)
    cohort, context, source_context = _frames()
    run_dir = write_one_packet_context_run("fixture", "source", full, "context", cohort, context, source_context, source, window, root=tmp_path)
    (run_dir / "one_packet_context.csv").unlink()
    with pytest.raises(ContextRunConflictError, match="artifact"):
        write_one_packet_context_run("fixture", "source", full, "context", cohort, context, source_context, source, window, root=tmp_path)


def test_writer_identity_changes_with_context_code_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import mawi_global_analysis.one_packet_context_run as context_run

    full, source, window = _provenance(tmp_path)
    cohort, context, source_context = _frames()
    context_run.write_one_packet_context_run("fixture", "source", full, "context", cohort, context, source_context, source, window, root=tmp_path)
    monkeypatch.setattr(context_run, "_code_identity", lambda: {"source_hash": "different", "git_commit": None, "dirty": True})
    with pytest.raises(context_run.ContextRunConflictError, match="identity"):
        context_run.write_one_packet_context_run("fixture", "source", full, "context", cohort, context, source_context, source, window, root=tmp_path)


def test_ditl_chunk_writer_validates_direct_target_input_and_loader_survives_raw_deletion(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_chunk_run
    from mawi_global_analysis.io import load_one_packet_context
    from mawi_global_analysis.one_packet_context import ONE_PACKET_COHORT_COLUMNS, aggregate_one_packet_context_chunks

    target_row = {column: None for column in ONE_PACKET_COHORT_COLUMNS}
    target_row.update(source_flow_id=1, target_timestamp=100.0, protocol=6, src_ip="198.51.100.1", src_port=40000, dst_ip="192.0.2.1", dst_port=443)
    target_cohort = pd.DataFrame([target_row], columns=ONE_PACKET_COHORT_COLUMNS)
    tcp = dpkt.tcp.TCP(sport=40000, dport=443, flags=dpkt.tcp.TH_SYN, data=b"payload")
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton("198.51.100.1"), dst=socket.inet_aton("192.0.2.1"), p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    frame = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))

    capture = tmp_path / "target.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(frame, ts=100.0)
        writer.close()
    cache = tmp_path / "data" / "fixture" / "processed" / "one_packet_context_chunks" / "cohort"
    extract_one_packet_chunk_observations(capture, target_cohort, cache, "target")
    chunks = [load_completed_chunk_observations(cache, "target", target_cohort)]
    context, source_context = aggregate_one_packet_context_chunks(target_cohort, chunks)
    source = tmp_path / "source_run_manifest.json"
    source.write_text(json.dumps({
        "status": "success", "dataset_id": "fixture",
        "input": {"path": str(capture), "sha256": chunks[0].metadata["source"]["sha256"]},
        "config": {"path": "configs/scan_source_driven_removal.yaml", "hash": "config-hash", "text": "scan: {}"},
    }))
    capture.unlink()

    run_dir = write_one_packet_context_chunk_run(
        "fixture", "source", chunks, "target", "context", target_cohort, context, source_context,
        source, root=tmp_path,
    )

    manifest = json.loads((run_dir / "context_manifest.json").read_text())
    assert manifest["input_mode"] == "ditl_chunks"
    assert manifest["ditl_chunks"][0]["chunk_id"] == "target"
    assert manifest["ditl_chunks"][0]["source"]["filename"] == "target.pcap"
    assert load_one_packet_context("fixture", "context", root=tmp_path).manifest["status"] == "success"


def test_ditl_chunk_writer_rejects_source_run_checksum_mismatch(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context import (
        ONE_PACKET_COHORT_COLUMNS,
        aggregate_one_packet_context_chunks,
    )
    from mawi_global_analysis.one_packet_context_chunks import (
        extract_one_packet_chunk_observations,
        load_completed_chunk_observations,
    )
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_chunk_run

    row = {column: None for column in ONE_PACKET_COHORT_COLUMNS}
    row.update(source_flow_id=1, target_timestamp=100.0, protocol=6, src_ip="198.51.100.1", src_port=40000, dst_ip="192.0.2.1", dst_port=443)
    cohort = pd.DataFrame([row], columns=ONE_PACKET_COHORT_COLUMNS)
    tcp = dpkt.tcp.TCP(sport=40000, dport=443, flags=dpkt.tcp.TH_SYN)
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton("198.51.100.1"), dst=socket.inet_aton("192.0.2.1"), p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    capture = tmp_path / "target.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)), ts=100.0)
        writer.close()
    cache = tmp_path / "cache"
    extract_one_packet_chunk_observations(capture, cohort, cache, "target")
    chunks = [load_completed_chunk_observations(cache, "target", cohort)]
    context, source_context = aggregate_one_packet_context_chunks(cohort, chunks)
    source = tmp_path / "source.json"
    source.write_text(json.dumps({
        "status": "success", "dataset_id": "fixture",
        "input": {"path": "/gone/target.pcap", "sha256": "wrong"},
        "config": {"path": "config.yaml", "hash": "hash", "text": "scan: {}"},
    }))
    with pytest.raises(ValueError, match="checksum"):
        write_one_packet_context_chunk_run("fixture", "source", chunks, "target", "context", cohort, context, source_context, source, root=tmp_path)


def test_ditl_chunk_writer_requires_disk_validated_chunk_matching_output_cohort(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_chunks import ChunkCacheConflictError, ChunkObservations
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_chunk_run

    cohort, context, source_context = _frames()
    cohort.loc[0, ["protocol", "src_ip", "src_port", "dst_ip", "dst_port"]] = [6, "198.51.100.1", 40000, "192.0.2.1", 443]
    source = tmp_path / "source.json"
    source.write_text(json.dumps({
        "status": "success", "dataset_id": "fixture",
        "input": {"path": "/gone/target.pcap", "sha256": "right"},
        "config": {"path": "config.yaml", "hash": "hash", "text": "scan: {}"},
    }))
    unvalidated = ChunkObservations(pd.DataFrame(), pd.DataFrame(), {
        "status": "success", "chunk_id": "target", "cohort_identity": "different-cohort",
        "observation_code_identity": "code", "source": {"path": "/gone/target.pcap", "filename": "target.pcap", "sha256": "right", "size_bytes": 1, "url": None},
        "first_observed_packet_timestamp": 1.0, "last_observed_packet_timestamp": 2.0,
        "target_observation_row_count": 0, "source_syn_observation_row_count": 0, "artifacts": {},
    })
    with pytest.raises(ChunkCacheConflictError, match="artifact|cohort"):
        write_one_packet_context_chunk_run("fixture", "source", [unvalidated], "target", "context", cohort, context, source_context, source, root=tmp_path)


@pytest.mark.parametrize("failure_point", ["cohort", "context", "source", "validation"])
def test_streaming_publication_failure_never_creates_final_run(tmp_path: Path, monkeypatch, failure_point: str) -> None:
    import mawi_global_analysis.one_packet_context_run as context_run

    source, cohort, context, source_context, _ = _streaming_inputs(tmp_path)
    if failure_point == "cohort":
        monkeypatch.setattr(
            context_run, "_write_dataframe_atomically",
            lambda *_: (_ for _ in ()).throw(RuntimeError("cohort write failure")),
        )
        aggregator = _StreamingAggregator(context, source_context)
    elif failure_point == "context":
        class FailingContext(_StreamingAggregator):
            def iter_context_rows(self):
                raise RuntimeError("context write failure")
        aggregator = FailingContext(context, source_context)
    elif failure_point == "source":
        class FailingSource(_StreamingAggregator):
            def iter_source_context_rows(self):
                raise RuntimeError("source write failure")
        aggregator = FailingSource(context, source_context)
    else:
        monkeypatch.setattr(
            context_run, "_validate_staged_context_artifacts",
            lambda *_: (_ for _ in ()).throw(ValueError("validation failure")),
        )
        aggregator = _StreamingAggregator(context, source_context)

    with pytest.raises((RuntimeError, ValueError)):
        _write_streaming_fixture(tmp_path, aggregator)

    final_dir = tmp_path / "results" / "fixture" / "streaming"
    assert not final_dir.exists()
    staging = list(final_dir.parent.glob(".streaming.staging.*"))
    assert len(staging) == 1
    assert not (staging[0] / "context_manifest.json").exists() or failure_point == "validation"


def test_streaming_publication_reuses_valid_final_run_without_regeneration(tmp_path: Path) -> None:
    run_dir = _write_streaming_fixture(tmp_path)
    original_mtimes = {
        path.name: path.stat().st_mtime_ns
        for path in run_dir.glob("*.csv")
    }

    class MustNotWrite:
        def iter_context_rows(self):
            raise AssertionError("published context CSV must be reused")

        def iter_source_context_rows(self):
            raise AssertionError("published source CSV must be reused")

    assert _write_streaming_fixture(tmp_path, MustNotWrite()) == run_dir
    assert {
        path.name: path.stat().st_mtime_ns
        for path in run_dir.glob("*.csv")
    } == original_mtimes


def test_post_rename_interruption_reuses_valid_publication_without_regeneration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mawi_global_analysis.one_packet_context_run as context_run

    original_fsync_directory = context_run._fsync_directory
    fsync_calls = 0

    def fail_after_rename(directory: Path) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise RuntimeError("interrupted after rename")
        original_fsync_directory(directory)

    monkeypatch.setattr(context_run, "_fsync_directory", fail_after_rename)
    with pytest.raises(RuntimeError, match="after rename"):
        _write_streaming_fixture(tmp_path)
    run_dir = tmp_path / "results" / "fixture" / "streaming"
    assert (run_dir / "context_manifest.json").is_file()
    original_mtimes = {path.name: path.stat().st_mtime_ns for path in run_dir.glob("*.csv")}
    monkeypatch.setattr(context_run, "_fsync_directory", original_fsync_directory)

    class MustNotWrite:
        def iter_context_rows(self):
            raise AssertionError("post-rename retry must not regenerate CSVs")

        def iter_source_context_rows(self):
            raise AssertionError("post-rename retry must not regenerate CSVs")

    assert _write_streaming_fixture(tmp_path, MustNotWrite()) == run_dir
    assert {path.name: path.stat().st_mtime_ns for path in run_dir.glob("*.csv")} == original_mtimes


def test_streaming_published_run_rejects_checksum_and_manifest_count_mismatch(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import ContextRunConflictError

    run_dir = _write_streaming_fixture(tmp_path)
    context_path = run_dir / "one_packet_context.csv"
    context_path.write_text(context_path.read_text() + "tampered\n")
    with pytest.raises(ContextRunConflictError, match="invalid artifacts"):
        _write_streaming_fixture(tmp_path)

    # Restore a clean final run, then prove manifest counts independently gate
    # reuse even when the CSV bytes still have their original checksum.
    clean_root = tmp_path / "clean"
    clean_run = _write_streaming_fixture(clean_root)
    manifest_path = clean_run / "context_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["one_packet_context"]["row_count"] = 999
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ContextRunConflictError, match="invalid artifacts"):
        _write_streaming_fixture(clean_root)


def test_streaming_published_run_rejects_manifest_checksum_and_identity_mismatch(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import ContextRunConflictError

    run_dir = _write_streaming_fixture(tmp_path)
    manifest_path = run_dir / "context_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["one_packet_context"]["sha256"] = "not-the-file"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ContextRunConflictError, match="invalid artifacts"):
        _write_streaming_fixture(tmp_path)

    identity_root = tmp_path / "identity"
    identity_run = _write_streaming_fixture(identity_root)
    identity_manifest_path = identity_run / "context_manifest.json"
    identity_manifest = json.loads(identity_manifest_path.read_text())
    identity_manifest["identity"] = "different"
    identity_manifest_path.write_text(json.dumps(identity_manifest))
    with pytest.raises(ContextRunConflictError, match="prevents streaming publication"):
        _write_streaming_fixture(identity_root)


def test_streaming_reuse_wraps_validated_header_and_linkage_failures_as_conflicts(tmp_path: Path) -> None:
    from mawi_global_analysis.hashing import sha256_file
    from mawi_global_analysis.one_packet_context_run import ContextRunConflictError

    run_dir = _write_streaming_fixture(tmp_path)
    context_path = run_dir / "one_packet_context.csv"
    rows = list(csv.reader(context_path.open(newline="", encoding="utf-8")))
    rows[0] = ["wrong-header"]
    with context_path.open("w", newline="", encoding="utf-8") as output:
        csv.writer(output).writerows(rows)
    manifest_path = run_dir / "context_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["one_packet_context"]["sha256"] = sha256_file(context_path)
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ContextRunConflictError, match="invalid artifacts"):
        _write_streaming_fixture(tmp_path)

    linkage_root = tmp_path / "linkage"
    linkage_run = _write_streaming_fixture(linkage_root)
    linkage_path = linkage_run / "one_packet_context.csv"
    linkage_rows = list(csv.reader(linkage_path.open(newline="", encoding="utf-8")))
    linkage_rows[1][linkage_rows[0].index("source_flow_id")] = "wrong"
    with linkage_path.open("w", newline="", encoding="utf-8") as output:
        csv.writer(output).writerows(linkage_rows)
    linkage_manifest_path = linkage_run / "context_manifest.json"
    linkage_manifest = json.loads(linkage_manifest_path.read_text())
    linkage_manifest["artifacts"]["one_packet_context"]["sha256"] = sha256_file(linkage_path)
    linkage_manifest_path.write_text(json.dumps(linkage_manifest))
    with pytest.raises(ContextRunConflictError, match="invalid artifacts"):
        _write_streaming_fixture(linkage_root)


@pytest.mark.parametrize(
    ("artifact", "replacement"),
    [
        ("one_packet_cohort.csv", ("bad",)),
        ("one_packet_context.csv", ("bad",)),
        ("one_packet_source_context.csv", ("bad",)),
    ],
)
def test_staged_streaming_validation_rejects_each_header(tmp_path: Path, artifact: str, replacement: tuple[str, ...]) -> None:
    from mawi_global_analysis.one_packet_context_run import _validate_staged_context_artifacts

    run_dir = _write_streaming_fixture(tmp_path)
    path = run_dir / artifact
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    rows[0] = list(replacement)
    with path.open("w", newline="", encoding="utf-8") as output:
        csv.writer(output).writerows(rows)
    with pytest.raises(ValueError, match="schema"):
        _validate_staged_context_artifacts(
            run_dir / "one_packet_cohort.csv",
            run_dir / "one_packet_context.csv",
            run_dir / "one_packet_source_context.csv",
        )


@pytest.mark.parametrize(
    "mutation",
    ["source_flow_id", "target_timestamp", "extra", "missing"],
)
@pytest.mark.parametrize("artifact", ["one_packet_context.csv", "one_packet_source_context.csv"])
def test_staged_streaming_validation_rejects_linkage_order_and_row_count_errors(tmp_path: Path, artifact: str, mutation: str) -> None:
    from mawi_global_analysis.one_packet_context_run import _validate_staged_context_artifacts

    run_dir = _write_streaming_fixture(tmp_path)
    path = run_dir / artifact
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    header = rows[0]
    if mutation == "source_flow_id":
        rows[1][header.index("source_flow_id")] = "wrong"
    elif mutation == "target_timestamp":
        rows[1][header.index("target_timestamp")] = "wrong"
    elif mutation == "extra":
        rows.append(rows[1].copy())
    else:
        rows.pop()
    with path.open("w", newline="", encoding="utf-8") as output:
        csv.writer(output).writerows(rows)
    with pytest.raises(ValueError, match="linkage|longer|shorter"):
        _validate_staged_context_artifacts(
            run_dir / "one_packet_cohort.csv",
            run_dir / "one_packet_context.csv",
            run_dir / "one_packet_source_context.csv",
        )


def test_staged_streaming_validation_rejects_correct_ids_in_wrong_cohort_order(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import _validate_staged_context_artifacts

    run_dir = _write_streaming_fixture(tmp_path)
    cohort_path = run_dir / "one_packet_cohort.csv"
    context_path = run_dir / "one_packet_context.csv"
    source_path = run_dir / "one_packet_source_context.csv"
    cohort_rows = list(csv.reader(cohort_path.open(newline="", encoding="utf-8")))
    context_rows = list(csv.reader(context_path.open(newline="", encoding="utf-8")))
    source_rows = list(csv.reader(source_path.open(newline="", encoding="utf-8")))
    for rows in (cohort_rows, context_rows, source_rows):
        rows.append(rows[1].copy())
        rows[-1][rows[0].index("source_flow_id")] = "3"
        rows[-1][rows[0].index("target_timestamp")] = "20.0"
    # Context has the same two linkage pairs but deliberately reversed.
    context_rows[1], context_rows[2] = context_rows[2], context_rows[1]
    for path, rows in ((cohort_path, cohort_rows), (context_path, context_rows), (source_path, source_rows)):
        with path.open("w", newline="", encoding="utf-8") as output:
            csv.writer(output).writerows(rows)

    with pytest.raises(ValueError, match="linkage/order"):
        _validate_staged_context_artifacts(cohort_path, context_path, source_path)


def test_staged_streaming_validation_rejects_cohort_row_count_mismatch(tmp_path: Path) -> None:
    from mawi_global_analysis.one_packet_context_run import _validate_staged_context_artifacts

    run_dir = _write_streaming_fixture(tmp_path)
    cohort_path = run_dir / "one_packet_cohort.csv"
    rows = list(csv.reader(cohort_path.open(newline="", encoding="utf-8")))
    rows.append(rows[1].copy())
    with cohort_path.open("w", newline="", encoding="utf-8") as output:
        csv.writer(output).writerows(rows)

    with pytest.raises(ValueError, match="longer|shorter"):
        _validate_staged_context_artifacts(
            cohort_path,
            run_dir / "one_packet_context.csv",
            run_dir / "one_packet_source_context.csv",
        )


def test_failed_streaming_attempts_have_unique_staging_directories(tmp_path: Path) -> None:
    source, cohort, context, source_context, _ = _streaming_inputs(tmp_path)

    class FailingContext(_StreamingAggregator):
        def iter_context_rows(self):
            raise RuntimeError("context write failure")

    for _ in range(2):
        with pytest.raises(RuntimeError, match="context write failure"):
            _write_streaming_fixture(tmp_path, FailingContext(context, source_context))
    parent = tmp_path / "results" / "fixture"
    assert len(list(parent.glob(".streaming.staging.*"))) == 2
