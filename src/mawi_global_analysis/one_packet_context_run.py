"""Run-specific writers and orchestration for one-packet context analysis."""

from __future__ import annotations

import json
import os
import tempfile
import csv
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
    aggregate_one_packet_context_chunks,
    build_one_packet_cohort_from_run,
    scan_one_packet_contexts,
)
from mawi_global_analysis.io import load_run
from mawi_global_analysis.pipeline import _code_identity


class ContextRunConflictError(ValueError):
    """Raised when an existing context run cannot safely be reused."""


def write_one_packet_context_chunk_run_streaming(
    dataset_id: str,
    source_run_name: str,
    metadata: list[dict[str, Any]],
    target_chunk_id: str,
    context_run_name: str,
    cohort: pd.DataFrame,
    aggregator: Any,
    source_run_manifest_path: Path,
    *,
    root: Path = Path("."),
) -> Path:
    """Publish SQLite cursor output without materialising final context frames."""
    from types import SimpleNamespace

    root = Path(root).resolve()
    source_run_manifest_path = Path(source_run_manifest_path).resolve()
    provenance = _validated_ditl_provenance(
        dataset_id, source_run_name, [SimpleNamespace(metadata=item) for item in metadata],
        target_chunk_id, source_run_manifest_path, _read_json(source_run_manifest_path, "source run manifest"),
    )
    run_dir = root / "results" / dataset_id / context_run_name
    manifest_path = run_dir / "context_manifest.json"
    identity = stable_json_hash({
        "dataset_id": dataset_id, "context_run_name": context_run_name,
        "input_mode": provenance["input_mode"], "input_identity": provenance["input_identity"],
        "source_run_manifest_sha256": provenance["source_run"]["run_manifest_sha256"],
        "context_code_source_hash": _code_identity().get("source_hash"),
    })
    if manifest_path.exists():
        raise ContextRunConflictError("existing context run prevents streaming publication")
    run_dir.mkdir(parents=True, exist_ok=True)
    try:
        cohort_path = run_dir / "one_packet_cohort.csv"
        _write_dataframe_atomically(cohort, cohort_path)
        context_path = run_dir / "one_packet_context.csv"
        source_path = run_dir / "one_packet_source_context.csv"
        context_rows = _write_rows_atomically(context_path, ONE_PACKET_CONTEXT_COLUMNS, aggregator.iter_context_rows())
        source_rows = _write_rows_atomically(source_path, ONE_PACKET_SOURCE_CONTEXT_COLUMNS, aggregator.iter_source_context_rows())
        if context_rows != len(cohort) or source_rows != len(cohort):
            raise ValueError("streaming context rows do not preserve cohort linkage")
        artifacts = {
            "one_packet_cohort": _stream_artifact(cohort_path, len(cohort)),
            "one_packet_context": _stream_artifact(context_path, context_rows),
            "one_packet_source_context": _stream_artifact(source_path, source_rows),
        }
        write_json_atomically(manifest_path, {"status": "success", "analysis_name": "one_packet_context", "dataset_id": dataset_id, "context_run_name": context_run_name, "identity": identity, **provenance, "code_identity": _code_identity(), "artifacts": artifacts})
    except BaseException as error:
        if not manifest_path.exists(): write_json_atomically(manifest_path, {"status": "failed", "analysis_name": "one_packet_context", "dataset_id": dataset_id, "context_run_name": context_run_name, "identity": identity, "error": {"type": type(error).__name__, "message": str(error)}})
        raise
    return run_dir


def _write_rows_atomically(path: Path, columns: tuple[str, ...], rows: Any) -> int:
    temporary: Path | None = None
    count = 0
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name); writer = csv.DictWriter(output, fieldnames=columns); writer.writeheader()
            for row in rows:
                if tuple(row) != columns: raise ValueError("streaming context schema mismatch")
                writer.writerow(row); count += 1
            output.flush(); os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()
    return count


def _stream_artifact(path: Path, row_count: int) -> dict[str, object]:
    return {"path": str(path), "sha256": sha256_file(path), "row_count": row_count}


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
    return _write_context_artifacts(
        dataset_id, source_run_name, context_run_name, cohort, context, source_context,
        provenance, root=root,
    )


def run_one_packet_context_chunk_analysis(
    dataset_id: str,
    source_run_name: str,
    chunk_cache_directory: Path,
    target_chunk_id: str,
    context_run_name: str,
    *,
    root: Path = Path("."),
) -> Path:
    """Publish context from validated local DITL chunk observations."""
    from mawi_global_analysis.one_packet_context_chunks import (
        enumerate_completed_chunk_metadata,
        load_completed_chunk_observations,
    )

    root = Path(root).resolve()
    source_manifest_path = root / "results" / dataset_id / source_run_name / "run_manifest.json"
    run = load_run(dataset_id, source_run_name, root=root)
    cohort = build_one_packet_cohort_from_run(run)
    metadata = enumerate_completed_chunk_metadata(chunk_cache_directory, cohort)
    chunks = [load_completed_chunk_observations(chunk_cache_directory, record["chunk_id"], cohort) for record in metadata]
    context, source_context = aggregate_one_packet_context_chunks(cohort, chunks)
    return write_one_packet_context_chunk_run(
        dataset_id, source_run_name, chunks, target_chunk_id, context_run_name,
        cohort, context, source_context, source_manifest_path, root=root,
    )


def write_one_packet_context_chunk_run(
    dataset_id: str,
    source_run_name: str,
    chunks: list[Any],
    target_chunk_id: str,
    context_run_name: str,
    cohort: pd.DataFrame,
    context: pd.DataFrame,
    source_context: pd.DataFrame,
    source_run_manifest_path: Path,
    *,
    root: Path = Path("."),
) -> Path:
    """Publish a context run with direct DITL-target-chunk provenance."""
    source_run_manifest_path = Path(source_run_manifest_path).resolve()
    source_manifest = _read_json(source_run_manifest_path, "source run manifest")
    chunks = _reload_chunks_for_final(chunks, cohort)
    provenance = _validated_ditl_provenance(
        dataset_id, source_run_name, chunks, target_chunk_id, source_run_manifest_path, source_manifest,
    )
    _validate_frames(cohort, context, source_context)
    return _write_context_artifacts(
        dataset_id, source_run_name, context_run_name, cohort, context, source_context,
        provenance, root=Path(root).resolve(),
    )


def _reload_chunks_for_final(chunks: list[Any], cohort: pd.DataFrame) -> list[Any]:
    """Require disk-backed cache validation before final provenance is published."""
    from mawi_global_analysis.one_packet_context_chunks import (
        ChunkCacheConflictError,
        _load_chunk,
        cohort_identity,
    )

    expected_cohort_identity = cohort_identity(cohort)
    validated: list[Any] = []
    for chunk in chunks:
        metadata = getattr(chunk, "metadata", None)
        artifacts = metadata.get("artifacts") if isinstance(metadata, dict) else None
        if not isinstance(artifacts, dict):
            raise ChunkCacheConflictError("chunk metadata has invalid artifacts")
        paths = []
        for name in ("target_observations", "source_syn_observations"):
            record = artifacts.get(name)
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise ChunkCacheConflictError("chunk metadata has invalid artifact record")
            paths.append(Path(record["path"]))
        if not all(path.is_absolute() for path in paths) or paths[0].parent != paths[1].parent:
            raise ChunkCacheConflictError("chunk artifacts do not share a cache directory")
        validated.append(_load_chunk(paths[0].parent, expected_cohort_identity, require_success=True))
    return validated


def _write_context_artifacts(
    dataset_id: str,
    source_run_name: str,
    context_run_name: str,
    cohort: pd.DataFrame,
    context: pd.DataFrame,
    source_context: pd.DataFrame,
    provenance: dict[str, Any],
    *,
    root: Path,
) -> Path:
    """Write final schemas after either legacy or DITL input provenance validates."""
    code_identity = _code_identity()
    run_dir = root / "results" / dataset_id / context_run_name
    manifest_path = run_dir / "context_manifest.json"
    identity = stable_json_hash({
        "dataset_id": dataset_id, "context_run_name": context_run_name,
        "input_mode": provenance["input_mode"],
        "input_identity": provenance["input_identity"],
        "source_run_manifest_sha256": provenance["source_run"]["run_manifest_sha256"],
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
    window_hash = sha256_file(window_manifest_path)
    return {
        "input_mode": "full_capture",
        "input_identity": stable_json_hash({"full_capture_sha256": full_capture_hash, "window_manifest_sha256": window_hash}),
        "full_capture": {"path": str(full_capture), "sha256": full_capture_hash, "size_bytes": full_capture.stat().st_size},
        "source_run": {"dataset_id": dataset_id, "run_name": source_run_name, "run_manifest_path": str(source_manifest_path), "run_manifest_sha256": sha256_file(source_manifest_path)},
        "source_capture_window": {"window_start": window_manifest.get("window_start"), "window_end": window_manifest.get("window_end"), "extracted_capture_path": str(extracted), "extracted_capture_sha256": extracted_hash, "window_manifest_path": str(window_manifest_path), "window_manifest_sha256": window_hash},
        "scan_configuration": {"path": config["path"], "hash": config["hash"], "effective_strict_thresholds": thresholds},
    }


def _validated_ditl_provenance(
    dataset_id: str,
    source_run_name: str,
    chunks: list[Any],
    target_chunk_id: str,
    source_manifest_path: Path,
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    if source_manifest.get("status") != "success" or source_manifest.get("dataset_id") != dataset_id:
        raise ValueError("source run manifest is not a successful matching dataset run")
    source_input = source_manifest.get("input")
    if not isinstance(source_input, dict) or not isinstance(source_input.get("path"), str) or not isinstance(source_input.get("sha256"), str):
        raise ValueError("source run manifest has invalid input provenance")
    config = source_manifest.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("path"), str) or not isinstance(config.get("hash"), str):
        raise ValueError("source run manifest has invalid scan configuration provenance")
    if not chunks:
        raise ValueError("DITL context run requires at least one completed chunk")
    records: list[dict[str, Any]] = []
    for chunk in chunks:
        metadata = getattr(chunk, "metadata", None)
        if not isinstance(metadata, dict) or metadata.get("status") != "success":
            raise ValueError("DITL context run requires validated successful chunk metadata")
        required = ("chunk_id", "cohort_identity", "observation_code_identity", "source", "artifacts")
        if any(key not in metadata for key in required) or not isinstance(metadata["source"], dict):
            raise ValueError("DITL chunk metadata is incomplete")
        source = metadata["source"]
        if not isinstance(source.get("sha256"), str) or not isinstance(source.get("filename"), str) or not isinstance(source.get("size_bytes"), int):
            raise ValueError("DITL chunk source provenance is incomplete")
        record = {
            "chunk_id": metadata["chunk_id"], "cohort_identity": metadata["cohort_identity"],
            "observation_code_identity": metadata["observation_code_identity"], "source": source,
            "first_observed_packet_timestamp": metadata.get("first_observed_packet_timestamp"),
            "last_observed_packet_timestamp": metadata.get("last_observed_packet_timestamp"),
            "target_observation_row_count": metadata.get("target_observation_row_count"),
            "source_syn_observation_row_count": metadata.get("source_syn_observation_row_count"),
            "artifacts": metadata["artifacts"],
        }
        record["identity"] = stable_json_hash(record)
        records.append(record)
    if len({record["chunk_id"] for record in records}) != len(records):
        raise ValueError("DITL chunk metadata contains duplicate chunk_id values")
    records.sort(key=lambda record: record["identity"])
    target = next((record for record in records if record["chunk_id"] == target_chunk_id), None)
    if target is None:
        raise ValueError("target DITL chunk is not among completed chunks")
    if source_input["sha256"] != target["source"]["sha256"]:
        raise ValueError("source run input checksum does not match target DITL chunk checksum")
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
        "input_mode": "ditl_chunks",
        "raw_retention_policy": "delete_after_validated_checkpoint",
        "input_identity": stable_json_hash({"chunk_identities": [record["identity"] for record in records]}),
        "ditl_chunks": records,
        "source_target_chunk_id": target_chunk_id,
        "source_run": {"dataset_id": dataset_id, "run_name": source_run_name, "run_manifest_path": str(source_manifest_path), "run_manifest_sha256": sha256_file(source_manifest_path)},
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
