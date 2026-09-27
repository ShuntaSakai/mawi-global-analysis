"""Run-specific writers and orchestration for one-packet context analysis."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.manifests import write_json_atomically
from mawi_global_analysis.one_packet_context import (
    ONE_PACKET_COHORT_COLUMNS,
    ONE_PACKET_CONTEXT_COLUMNS,
    ONE_PACKET_SOURCE_CONTEXT_COLUMNS,
    build_one_packet_cohort_from_run,
    scan_one_packet_contexts,
)
from mawi_global_analysis.io import load_run
from mawi_global_analysis.pipeline import _code_identity


class ContextRunConflictError(ValueError):
    """Raised when an existing context run cannot safely be reused."""


def run_one_packet_context_analysis(
    dataset_id: str,
    source_run_name: str,
    full_capture_path: Path,
    context_run_name: str,
    *,
    root: Path = Path("."),
) -> Path:
    """Build cohort/context observations and publish their provenance-bearing run."""
    root = Path(root).resolve()
    source_manifest_path = root / "results" / dataset_id / source_run_name / "run_manifest.json"
    run = load_run(dataset_id, source_run_name, root=root)
    source_input = run.manifest.get("input")
    if not isinstance(source_input, dict) or not isinstance(source_input.get("path"), str):
        raise ValueError("source run manifest has no usable input provenance")
    extracted_capture = Path(source_input["path"])
    window_manifest_path = extracted_capture.parent / "window_manifest.json"
    cohort = build_one_packet_cohort_from_run(run)
    context, source_context = scan_one_packet_contexts(Path(full_capture_path), cohort)
    return write_one_packet_context_run(
        dataset_id, source_run_name, Path(full_capture_path), context_run_name,
        cohort, context, source_context, source_manifest_path, window_manifest_path,
        root=root,
    )


def write_one_packet_context_run(
    dataset_id: str,
    source_run_name: str,
    full_capture_path: Path,
    context_run_name: str,
    cohort: pd.DataFrame,
    context: pd.DataFrame,
    source_context: pd.DataFrame,
    source_run_manifest_path: Path,
    window_manifest_path: Path,
    *,
    root: Path = Path("."),
) -> Path:
    """Publish deterministic context CSVs and a successful manifest atomically.

    A successful manifest is written only after all three CSVs are published.
    Existing context runs may be reused only when their identity is identical.
    """
    root = Path(root).resolve()
    full_capture_path = Path(full_capture_path).resolve()
    source_run_manifest_path = Path(source_run_manifest_path).resolve()
    window_manifest_path = Path(window_manifest_path).resolve()
    source_manifest = _read_json(source_run_manifest_path, "source run manifest")
    window_manifest = _read_json(window_manifest_path, "window manifest")
    provenance = _validated_provenance(
        dataset_id, source_run_name, full_capture_path, source_run_manifest_path,
        source_manifest, window_manifest_path, window_manifest,
    )
    _validate_frames(cohort, context, source_context)
    code_identity = _code_identity()
    run_dir = root / "results" / dataset_id / context_run_name
    manifest_path = run_dir / "context_manifest.json"
    identity = stable_json_hash({
        "dataset_id": dataset_id, "context_run_name": context_run_name,
        "full_capture_sha256": provenance["full_capture"]["sha256"],
        "source_run_manifest_sha256": provenance["source_run"]["run_manifest_sha256"],
        "window_manifest_sha256": provenance["source_capture_window"]["window_manifest_sha256"],
        "context_code_source_hash": code_identity.get("source_hash"),
    })
    if manifest_path.exists():
        existing = _read_json(manifest_path, "context manifest")
        if existing.get("identity") != identity:
            raise ContextRunConflictError("existing context run has a different identity")
        if existing.get("status") != "success":
            raise ContextRunConflictError("existing context run is not successful")
        try:
            from mawi_global_analysis.io import load_one_packet_context
            load_one_packet_context(dataset_id, context_run_name, root=root)
        except (OSError, ValueError, FileNotFoundError) as error:
            raise ContextRunConflictError(
                f"existing context run has invalid artifact provenance: {error}"
            ) from error
        return run_dir

    run_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "one_packet_cohort": (cohort, run_dir / "one_packet_cohort.csv"),
        "one_packet_context": (context, run_dir / "one_packet_context.csv"),
        "one_packet_source_context": (source_context, run_dir / "one_packet_source_context.csv"),
    }
    try:
        artifacts: dict[str, dict[str, object]] = {}
        for name, (frame, path) in outputs.items():
            if path.exists():
                raise ContextRunConflictError(f"context artifact already exists: {path}")
            _write_dataframe_atomically(frame, path)
            artifacts[name] = {"path": str(path), "sha256": sha256_file(path), "row_count": len(frame)}
        manifest = {
            "status": "success", "analysis_name": "one_packet_context",
            "dataset_id": dataset_id, "context_run_name": context_run_name,
            "identity": identity, **provenance, "code_identity": code_identity,
            "artifacts": artifacts,
        }
        write_json_atomically(manifest_path, manifest)
    except BaseException as error:
        if not manifest_path.exists():
            write_json_atomically(manifest_path, {
                "status": "failed", "analysis_name": "one_packet_context",
                "dataset_id": dataset_id, "context_run_name": context_run_name,
                "identity": identity, "error": {"type": type(error).__name__, "message": str(error)},
            })
        raise
    return run_dir


def _validated_provenance(
    dataset_id: str, source_run_name: str, full_capture: Path, source_manifest_path: Path,
    source_manifest: dict[str, Any], window_manifest_path: Path, window_manifest: dict[str, Any],
) -> dict[str, Any]:
    if source_manifest.get("status") != "success" or source_manifest.get("dataset_id") != dataset_id:
        raise ValueError("source run manifest is not a successful matching dataset run")
    source_input = source_manifest.get("input")
    if not isinstance(source_input, dict):
        raise ValueError("source run manifest has invalid input provenance")
    extracted = Path(str(window_manifest.get("output_path", ""))).resolve()
    if not extracted.is_file() or source_input.get("path") != str(extracted):
        raise ValueError("source run input does not match extraction window provenance")
    extracted_hash = sha256_file(extracted)
    if source_input.get("sha256") != extracted_hash or window_manifest.get("output_sha256") != extracted_hash:
        raise ValueError("extracted capture checksum disagrees with provenance")
    full_capture_hash = sha256_file(full_capture)
    if window_manifest.get("source_sha256") != full_capture_hash:
        raise ValueError("full capture checksum does not match extraction window provenance")
    config = source_manifest.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("path"), str) or not isinstance(config.get("hash"), str):
        raise ValueError("source run manifest has invalid scan configuration provenance")
    thresholds: dict[str, object] = {}
    try:
        scan = yaml.safe_load(config.get("text", "")) or {}
        strict = scan.get("scan", {}).get("strict", {})
        for key in ("min_pattern_count", "min_unique_targets"):
            if key in strict:
                thresholds[key] = strict[key]
    except yaml.YAMLError:
        pass
    return {
        "full_capture": {"path": str(full_capture), "sha256": full_capture_hash, "size_bytes": full_capture.stat().st_size},
        "source_run": {"dataset_id": dataset_id, "run_name": source_run_name, "run_manifest_path": str(source_manifest_path), "run_manifest_sha256": sha256_file(source_manifest_path)},
        "source_capture_window": {"window_start": window_manifest.get("window_start"), "window_end": window_manifest.get("window_end"), "extracted_capture_path": str(extracted), "extracted_capture_sha256": extracted_hash, "window_manifest_path": str(window_manifest_path), "window_manifest_sha256": sha256_file(window_manifest_path)},
        "scan_configuration": {"path": config["path"], "hash": config["hash"], "effective_strict_thresholds": thresholds},
    }


def _validate_frames(cohort: pd.DataFrame, context: pd.DataFrame, source_context: pd.DataFrame) -> None:
    for name, frame, columns in (("cohort", cohort, ONE_PACKET_COHORT_COLUMNS), ("context", context, ONE_PACKET_CONTEXT_COLUMNS), ("source context", source_context, ONE_PACKET_SOURCE_CONTEXT_COLUMNS)):
        if tuple(frame.columns) != columns:
            raise ValueError(f"{name} schema does not match its explicit schema")
        if frame.duplicated(["source_flow_id", "target_timestamp"]).any():
            raise ValueError(f"{name} has duplicate source-flow linkage")
    linkage = set(zip(cohort.source_flow_id, cohort.target_timestamp))
    if set(zip(context.source_flow_id, context.target_timestamp)) != linkage or set(zip(source_context.source_flow_id, source_context.target_timestamp)) != linkage:
        raise ValueError("context artifacts do not preserve cohort source_flow_id linkage")


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"unreadable {description}: {path}") from error
    if not isinstance(data, dict):
        raise ValueError(f"{description} is not an object: {path}")
    return data


def _write_dataframe_atomically(frame: pd.DataFrame, path: Path) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            frame.to_csv(output, index=False)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
