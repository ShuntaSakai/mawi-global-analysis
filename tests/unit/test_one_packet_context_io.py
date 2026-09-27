"""Tests for manifest-driven one-packet context loading."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.one_packet_context import (
    ONE_PACKET_COHORT_COLUMNS, ONE_PACKET_CONTEXT_COLUMNS,
    ONE_PACKET_SOURCE_CONTEXT_COLUMNS,
)


def _context_run(tmp_path: Path) -> Path:
    from mawi_global_analysis.one_packet_context_run import write_one_packet_context_run

    extracted = tmp_path / "window.pcap"
    extracted.write_bytes(b"window")
    full = tmp_path / "full.pcap"
    full.write_bytes(b"full")
    import hashlib
    window = tmp_path / "window_manifest.json"
    window.write_text(json.dumps({"window_start": "start", "window_end": "end", "output_path": str(extracted), "output_sha256": hashlib.sha256(extracted.read_bytes()).hexdigest(), "source_sha256": hashlib.sha256(full.read_bytes()).hexdigest()}))
    source = tmp_path / "source_manifest.json"
    source.write_text(json.dumps({"status": "success", "dataset_id": "fixture", "input": {"path": str(extracted), "sha256": hashlib.sha256(extracted.read_bytes()).hexdigest()}, "config": {"path": "config.yaml", "hash": "hash", "text": "scan: {}"}}))
    def frame(columns: tuple[str, ...]) -> pd.DataFrame:
        row = {column: None for column in columns}
        row.update(source_flow_id=1, target_timestamp=10.0)
        return pd.DataFrame([row], columns=columns)
    return write_one_packet_context_run("fixture", "source", full, "context", frame(ONE_PACKET_COHORT_COLUMNS), frame(ONE_PACKET_CONTEXT_COLUMNS), frame(ONE_PACKET_SOURCE_CONTEXT_COLUMNS), source, window, root=tmp_path)


def test_load_one_packet_context_uses_manifest_artifact_paths(tmp_path: Path) -> None:
    from mawi_global_analysis.io import load_one_packet_context

    run_dir = _context_run(tmp_path)
    data = load_one_packet_context("fixture", "context", root=tmp_path)
    assert data.cohort["source_flow_id"].tolist() == [1]
    manifest = json.loads((run_dir / "context_manifest.json").read_text())
    assert data.manifest == manifest


def test_load_one_packet_context_rejects_missing_artifact_and_failed_manifest(tmp_path: Path) -> None:
    from mawi_global_analysis.io import load_one_packet_context

    run_dir = _context_run(tmp_path)
    (run_dir / "one_packet_context.csv").unlink()
    with pytest.raises(FileNotFoundError, match="artifact"):
        load_one_packet_context("fixture", "context", root=tmp_path)
    manifest_path = run_dir / "context_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["status"] = "failed"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="not successful"):
        load_one_packet_context("fixture", "context", root=tmp_path)
