"""Durable, observational per-capture inputs for one-packet context analysis."""

from __future__ import annotations

import json
import ipaddress
import math
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from mawi_global_analysis.flow import FlowKey, iter_capture_packet_records
from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.manifests import write_json_atomically
from mawi_global_analysis.one_packet_context import _decode_context_packet, _is_plain_syn, _require_cohort_columns


CHUNK_SCHEMA_VERSION = "one-packet-context-chunk-observations-v1"
TARGET_OBSERVATION_COLUMNS = (
    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "captured_frame_length", "original_frame_length", "ip_total_length",
    "transport_payload_length", "tcp_flags_raw",
)
SOURCE_SYN_OBSERVATION_COLUMNS = ("timestamp", "src_ip", "dst_ip", "dst_port")


class ChunkCacheConflictError(ValueError):
    """Raised when a durable chunk cache cannot safely be reused."""


@dataclass(frozen=True)
class ChunkObservations:
    """Validated observational rows and their provenance metadata."""

    target_packets: pd.DataFrame
    source_syn_packets: pd.DataFrame
    metadata: dict[str, Any]


def cohort_identity(cohort: pd.DataFrame) -> str:
    """Hash exactly the cohort facts that determine retained observations."""
    _require_cohort_columns(cohort)
    keys = sorted({
        (str(row.src_ip), int(row.src_port), str(row.dst_ip), int(row.dst_port), int(row.protocol))
        for row in cohort.itertuples(index=False)
    })
    candidate_source_ips = sorted({endpoint for key in keys for endpoint in (key[0], key[2])})
    return stable_json_hash({
        "schema_version": CHUNK_SCHEMA_VERSION,
        "target_flow_keys": keys,
        "candidate_source_ips": candidate_source_ips,
    })


def extract_one_packet_chunk_observations(
    capture_path: Path,
    cohort: pd.DataFrame,
    output_directory: Path,
    chunk_id: str,
    *,
    source_url: str | None = None,
) -> dict[str, Any]:
    """Stream one capture into validated durable observational artifacts.

    This function never deletes ``capture_path``.  A returned success record has
    been reloaded from disk and checksum/schema validated, so a later caller can
    use it as the prerequisite for any source-retention policy.
    """
    capture_path = Path(capture_path).resolve()
    if not capture_path.is_file():
        raise FileNotFoundError(f"capture not found: {capture_path}")
    directory = _chunk_directory(output_directory, chunk_id)
    expected_cohort_identity = cohort_identity(cohort)
    source = {
        "path": str(capture_path),
        "filename": capture_path.name,
        "sha256": sha256_file(capture_path),
        "size_bytes": capture_path.stat().st_size,
        "url": source_url,
    }
    metadata_path = directory / "chunk_metadata.json"
    if metadata_path.exists():
        existing = load_completed_chunk_observations(output_directory, chunk_id, cohort).metadata
        existing_source = existing.get("source", {})
        if (
            existing_source.get("sha256") != source["sha256"]
            or existing_source.get("size_bytes") != source["size_bytes"]
        ):
            raise ChunkCacheConflictError("existing completed chunk has different source identity")
        return existing

    target_keys = {
        FlowKey.from_packet(str(row.src_ip), int(row.src_port), str(row.dst_ip), int(row.dst_port), int(row.protocol))
        for row in cohort.itertuples(index=False)
    }
    candidate_source_ips = {endpoint.ip for key in target_keys for endpoint in (key.endpoint_a, key.endpoint_b)}
    target_rows: list[dict[str, object]] = []
    source_rows: list[dict[str, object]] = []
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    for packet_index, (timestamp, frame, captured_length, original_length) in enumerate(
        iter_capture_packet_records(capture_path), start=1
    ):
        first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
        last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
        packet = _decode_context_packet(frame, packet_index, timestamp)
        if packet is None:
            continue
        if packet.key in target_keys:
            target_rows.append({
                "timestamp": packet.timestamp, "src_ip": packet.src_ip, "src_port": packet.src_port,
                "dst_ip": packet.dst_ip, "dst_port": packet.dst_port, "protocol": packet.key.protocol,
                "captured_frame_length": captured_length, "original_frame_length": original_length,
                "ip_total_length": packet.ip_total_length,
                "transport_payload_length": packet.transport_payload_length,
                "tcp_flags_raw": packet.tcp_flags_raw,
            })
        if _is_plain_syn(packet) and packet.src_ip in candidate_source_ips:
            source_rows.append({
                "timestamp": packet.timestamp, "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip, "dst_port": packet.dst_port,
            })

    target_frame = _ordered_frame(target_rows, TARGET_OBSERVATION_COLUMNS)
    source_frame = _ordered_frame(source_rows, SOURCE_SYN_OBSERVATION_COLUMNS)
    directory.mkdir(parents=True, exist_ok=True)
    target_path = directory / "target_observations.csv"
    source_path = directory / "source_syn_observations.csv"
    if target_path.exists() or source_path.exists():
        raise ChunkCacheConflictError(f"incomplete or unmanifested chunk artifacts exist: {directory}")
    _write_dataframe_atomically(target_frame, target_path)
    _write_dataframe_atomically(source_frame, source_path)
    metadata = {
        "status": "validating",
        "schema_version": CHUNK_SCHEMA_VERSION,
        "observation_code_identity": _observation_code_identity(),
        "chunk_id": chunk_id,
        "cohort_identity": expected_cohort_identity,
        "source": source,
        "first_observed_packet_timestamp": first_timestamp,
        "last_observed_packet_timestamp": last_timestamp,
        "target_observation_row_count": len(target_frame),
        "source_syn_observation_row_count": len(source_frame),
        "artifacts": {
            "target_observations": _artifact_record(target_path, len(target_frame)),
            "source_syn_observations": _artifact_record(source_path, len(source_frame)),
        },
    }
    write_json_atomically(metadata_path, metadata)
    _load_chunk(directory, expected_cohort_identity, require_success=False)
    metadata["status"] = "success"
    write_json_atomically(metadata_path, metadata)
    return _load_chunk(directory, expected_cohort_identity, require_success=True).metadata


def load_completed_chunk_observations(
    output_directory: Path, chunk_id: str, cohort: pd.DataFrame
) -> ChunkObservations:
    """Reload a successful chunk cache without requiring its raw capture."""
    return _load_chunk(_chunk_directory(output_directory, chunk_id), cohort_identity(cohort), require_success=True)


def enumerate_completed_chunk_metadata(output_directory: Path, cohort: pd.DataFrame) -> tuple[dict[str, Any], ...]:
    """Return fully validated successful metadata in deterministic chunk-ID order."""
    root = Path(output_directory).resolve()
    if not root.exists():
        return ()
    metadata = [
        _load_chunk(path.parent, cohort_identity(cohort), require_success=True).metadata
        for path in sorted(root.glob("*/chunk_metadata.json"))
    ]
    return tuple(sorted(metadata, key=lambda record: record["chunk_id"]))


def _chunk_directory(output_directory: Path, chunk_id: str) -> Path:
    if not chunk_id or Path(chunk_id).name != chunk_id or chunk_id in {".", ".."}:
        raise ValueError("chunk_id must be a single non-empty path component")
    return Path(output_directory).resolve() / chunk_id


def _ordered_frame(rows: list[dict[str, object]], columns: tuple[str, ...]) -> pd.DataFrame:
    frame = pd.DataFrame(rows, columns=columns)
    return frame.sort_values(list(columns), kind="stable", na_position="last").reset_index(drop=True)


def _artifact_record(path: Path, row_count: int) -> dict[str, object]:
    return {"path": str(path.resolve()), "sha256": sha256_file(path), "row_count": row_count}


def _observation_code_identity() -> str:
    return stable_json_hash({
        "schema_version": CHUNK_SCHEMA_VERSION,
        "chunk_module_sha256": sha256_file(Path(__file__)),
        "flow_module_sha256": sha256_file(Path(__file__).with_name("flow.py")),
        "context_decoder_sha256": sha256_file(Path(__file__).with_name("one_packet_context.py")),
    })


def _load_chunk(directory: Path, expected_cohort_identity: str, *, require_success: bool) -> ChunkObservations:
    metadata_path = directory / "chunk_metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ChunkCacheConflictError(f"unreadable chunk metadata: {metadata_path}") from error
    if not isinstance(metadata, dict):
        raise ChunkCacheConflictError(f"chunk metadata is not an object: {metadata_path}")
    if require_success and metadata.get("status") != "success":
        raise ChunkCacheConflictError("chunk cache is not successfully completed")
    if metadata.get("schema_version") != CHUNK_SCHEMA_VERSION:
        raise ChunkCacheConflictError("chunk cache has different schema identity")
    if metadata.get("observation_code_identity") != _observation_code_identity():
        raise ChunkCacheConflictError("chunk cache has different code identity")
    if metadata.get("cohort_identity") != expected_cohort_identity:
        raise ChunkCacheConflictError("chunk cache has different cohort identity")
    if not isinstance(metadata.get("chunk_id"), str) or _chunk_directory(directory.parent, metadata["chunk_id"]) != directory:
        raise ChunkCacheConflictError("chunk metadata chunk_id does not match its directory")
    _validate_metadata_fields(metadata)
    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ChunkCacheConflictError("chunk metadata has invalid artifacts")
    target = _load_artifact(directory, artifacts.get("target_observations"), TARGET_OBSERVATION_COLUMNS)
    source = _load_artifact(directory, artifacts.get("source_syn_observations"), SOURCE_SYN_OBSERVATION_COLUMNS)
    if metadata.get("target_observation_row_count") != len(target):
        raise ChunkCacheConflictError("target observation row count disagrees with metadata")
    if metadata.get("source_syn_observation_row_count") != len(source):
        raise ChunkCacheConflictError("source SYN observation row count disagrees with metadata")
    _validate_observation_values(target, is_target=True)
    _validate_observation_values(source, is_target=False)
    return ChunkObservations(target, source, metadata)


def _load_artifact(directory: Path, record: Any, columns: tuple[str, ...]) -> pd.DataFrame:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise ChunkCacheConflictError("chunk metadata has invalid artifact record")
    path = Path(record["path"])
    if not path.is_absolute() or path.parent != directory or not path.is_file():
        raise ChunkCacheConflictError("chunk artifact is missing or outside its cache directory")
    if record.get("sha256") != sha256_file(path):
        raise ChunkCacheConflictError(f"chunk artifact checksum mismatch: {path}")
    try:
        frame = pd.read_csv(path, float_precision="round_trip")
    except (OSError, pd.errors.ParserError) as error:
        raise ChunkCacheConflictError(f"unreadable chunk artifact: {path}") from error
    if tuple(frame.columns) != columns:
        raise ChunkCacheConflictError(f"chunk artifact schema mismatch: {path}")
    if record.get("row_count") != len(frame):
        raise ChunkCacheConflictError(f"chunk artifact row count mismatch: {path}")
    return frame


def _validate_metadata_fields(metadata: dict[str, Any]) -> None:
    source = metadata.get("source")
    if not isinstance(source, dict):
        raise ChunkCacheConflictError("chunk metadata has invalid source identity")
    if (
        not isinstance(source.get("path"), str)
        or not isinstance(source.get("filename"), str)
        or not isinstance(source.get("sha256"), str)
        or len(source["sha256"]) != 64
        or not isinstance(source.get("size_bytes"), int)
        or source["size_bytes"] < 0
        or source.get("url") is not None and not isinstance(source.get("url"), str)
    ):
        raise ChunkCacheConflictError("chunk metadata has invalid source identity")
    first, last = metadata.get("first_observed_packet_timestamp"), metadata.get("last_observed_packet_timestamp")
    if (first is None) != (last is None):
        raise ChunkCacheConflictError("chunk metadata has incomplete observed timestamp range")
    if first is not None and (not _finite_number(first) or not _finite_number(last) or float(first) > float(last)):
        raise ChunkCacheConflictError("chunk metadata has invalid observed timestamp range")
    for name in ("target_observation_row_count", "source_syn_observation_row_count"):
        if not isinstance(metadata.get(name), int) or metadata[name] < 0:
            raise ChunkCacheConflictError("chunk metadata has invalid observation row count")


def _validate_observation_values(frame: pd.DataFrame, *, is_target: bool) -> None:
    required = TARGET_OBSERVATION_COLUMNS if is_target else SOURCE_SYN_OBSERVATION_COLUMNS
    for row in frame.loc[:, required].itertuples(index=False, name=None):
        values = dict(zip(required, row, strict=True))
        if not _finite_number(values["timestamp"]):
            raise ChunkCacheConflictError("chunk artifact has invalid timestamp")
        for field in ("src_ip", "dst_ip"):
            try:
                ipaddress.ip_address(values[field])
            except ValueError as error:
                raise ChunkCacheConflictError("chunk artifact has invalid IP address") from error
        for field in ("dst_port",) + (("src_port",) if is_target else ()):
            if not _port_number(values[field]):
                raise ChunkCacheConflictError("chunk artifact has invalid port")
        if is_target:
            if not _integer_number(values["protocol"]) or int(values["protocol"]) not in {6, 17}:
                raise ChunkCacheConflictError("chunk artifact has invalid protocol")
            for field in ("captured_frame_length", "original_frame_length", "ip_total_length", "transport_payload_length"):
                if not _integer_number(values[field]) or int(values[field]) < 0:
                    raise ChunkCacheConflictError("chunk artifact has invalid length")
            flags = values["tcp_flags_raw"]
            if not pd.isna(flags) and (not _integer_number(flags) or not 0 <= int(flags) <= 255):
                raise ChunkCacheConflictError("chunk artifact has invalid TCP flags")


def _finite_number(value: object) -> bool:
    try:
        return not pd.isna(value) and math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def _integer_number(value: object) -> bool:
    return _finite_number(value) and float(value).is_integer()


def _port_number(value: object) -> bool:
    return _integer_number(value) and 0 <= int(value) <= 65535


def _write_dataframe_atomically(frame: pd.DataFrame, path: Path) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary = Path(output.name)
            frame.to_csv(output, index=False, float_format="%.17g")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
