"""Tests for deterministic one-packet context run artifacts."""

from __future__ import annotations

import json
from pathlib import Path

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
