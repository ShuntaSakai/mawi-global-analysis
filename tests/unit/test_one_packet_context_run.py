"""Tests for deterministic one-packet context run artifacts."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import dpkt
import pandas as pd
import pytest


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
