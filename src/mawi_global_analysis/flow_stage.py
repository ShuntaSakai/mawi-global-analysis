"""Dataset-common canonical-flow cache generation and validation."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from mawi_global_analysis.config import ExperimentConfig
from mawi_global_analysis.flow import TCP_PROTOCOL, parse_pcap_with_provenance
from mawi_global_analysis.hashing import flow_fingerprint, flow_generation_config
from mawi_global_analysis.models import InputContext
from mawi_global_analysis.scan_patterns import classify_observed_tcp_pattern


FLOW_SCHEMA_VERSION = "flows-v3"
FLOW_COLUMNS = (
    "flow_id",
    "ip_version",
    "protocol",
    "start_time",
    "end_time",
    "duration",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "packet_count",
    "byte_count",
    "frame_byte_count",
    "ip_byte_count",
    "transport_payload_byte_count",
    "packets_from_src",
    "packets_from_dst",
    "bytes_from_src",
    "bytes_from_dst",
    "initial_syn_sender_ip",
    "initial_syn_sender_port",
    "initial_syn_receiver_ip",
    "initial_syn_receiver_port",
    "first_syn_time",
    "syn_from_initiator",
    "syn_from_responder",
    "synack_from_initiator",
    "synack_from_responder",
    "rst_from_initiator",
    "rst_from_responder",
    "first_responder_synack_time",
    "first_responder_rst_time",
    "first_initiator_rst_time",
    "ack_after_synack_observed",
    "non_syn_response_observed",
    "transport_payload_observed",
    "syn_count",
    "syn_ack_count",
    "ack_count",
    "rst_count",
    "observed_tcp_pattern",
)
_PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17}


class FlowCacheValidationError(ValueError):
    """Raised when an existing flow cache does not prove its own identity."""


def run_flow_stage(
    ctx: InputContext, cfg: ExperimentConfig, force: bool = False
) -> Path:
    """Reuse or produce dataset-common canonical flows for one semantic profile."""
    fingerprint = flow_fingerprint(ctx.sha256, cfg, FLOW_SCHEMA_VERSION)
    flow_config = flow_generation_config(cfg)
    stage_dir = (
        Path.cwd()
        / "data"
        / ctx.dataset_id
        / "processed"
        / "flows"
        / f"{_flow_profile(flow_config)}-{fingerprint[:10]}"
    )
    flows_path = stage_dir / "flows.csv"
    manifest_path = stage_dir / "flow_manifest.json"

    if not force and (flows_path.exists() or manifest_path.exists()):
        if not flows_path.exists() or not manifest_path.exists():
            raise FlowCacheValidationError(
                f"incomplete flow cache at {stage_dir}; use force=True to rebuild it"
            )
        expected_row_count = _validate_cache_manifest(
            manifest_path,
            input_sha256=ctx.sha256,
            fingerprint=fingerprint,
            flow_config=flow_config,
        )
        _validate_cached_flows(flows_path, expected_row_count)
        return flows_path

    parse_result = parse_pcap_with_provenance(
        ctx.path,
        timeout=cfg.flow.inactive_timeout_seconds,
        protocols=tuple(_PROTOCOL_NUMBERS[name] for name in flow_config["protocols"]),
    )
    rows_with_patterns = [_add_observed_pattern(row) for row in parse_result.rows]
    stage_dir.mkdir(parents=True, exist_ok=True)
    _write_csv_atomically(flows_path, rows_with_patterns)
    _write_json_atomically(
        manifest_path,
        {
            "input_sha256": ctx.sha256,
            "fingerprint": fingerprint,
            "row_count": len(rows_with_patterns),
            "skipped_packet_counts": parse_result.skipped_packet_counts,
            "flow_config": flow_config,
            "schema_version": FLOW_SCHEMA_VERSION,
        },
    )
    return flows_path


def _flow_profile(flow_config: dict[str, Any]) -> str:
    timeout = flow_config["inactive_timeout_seconds"]
    timeout_name = "no-timeout" if timeout is None else f"timeout-{timeout:g}s"
    return "-".join([*flow_config["protocols"], timeout_name])


def _add_observed_pattern(row: dict[str, object]) -> dict[str, object]:
    completed_row = dict(row)
    completed_row["observed_tcp_pattern"] = (
        classify_observed_tcp_pattern(completed_row)
        if completed_row["protocol"] == TCP_PROTOCOL
        else "none"
    )
    return completed_row


def _validate_cache_manifest(
    manifest_path: Path,
    *,
    input_sha256: str,
    fingerprint: str,
    flow_config: dict[str, Any],
) -> int:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FlowCacheValidationError(
            f"unreadable flow manifest: {manifest_path}"
        ) from error

    expected = {
        "input_sha256": input_sha256,
        "fingerprint": fingerprint,
        "flow_config": flow_config,
        "schema_version": FLOW_SCHEMA_VERSION,
    }
    mismatched = [key for key, value in expected.items() if manifest.get(key) != value]
    if mismatched:
        raise FlowCacheValidationError(
            f"flow cache manifest identity mismatch for {manifest_path}: "
            + ", ".join(mismatched)
        )
    row_count = manifest.get("row_count")
    if not isinstance(row_count, int) or row_count < 0:
        raise FlowCacheValidationError(
            f"flow cache manifest has invalid row_count: {manifest_path}"
        )
    skipped_packet_counts = manifest.get("skipped_packet_counts")
    if not isinstance(skipped_packet_counts, dict) or any(
        not isinstance(reason, str)
        or not isinstance(count, int)
        or count < 0
        for reason, count in skipped_packet_counts.items()
    ):
        raise FlowCacheValidationError(
            f"flow cache manifest has invalid skip provenance: {manifest_path}"
        )
    return row_count


def _validate_cached_flows(path: Path, expected_row_count: int) -> None:
    """Reject a cached CSV that is unreadable or disagrees with its manifest."""
    try:
        with path.open(encoding="utf-8", newline="") as input_file:
            reader = csv.reader(input_file, strict=True)
            header = next(reader, None)
            if tuple(header or ()) != FLOW_COLUMNS:
                raise FlowCacheValidationError(
                    f"flow cache CSV has an invalid canonical header: {path}"
                )

            row_count = 0
            for line_number, row in enumerate(reader, start=2):
                if len(row) != len(FLOW_COLUMNS):
                    raise FlowCacheValidationError(
                        f"flow cache CSV has {len(row)} columns at line "
                        f"{line_number}; expected {len(FLOW_COLUMNS)}: {path}"
                    )
                row_count += 1
    except FlowCacheValidationError:
        raise
    except (OSError, UnicodeError, csv.Error) as error:
        raise FlowCacheValidationError(f"unreadable flow cache CSV: {path}") from error

    if row_count != expected_row_count:
        raise FlowCacheValidationError(
            f"flow cache CSV row count mismatch for {path}: "
            f"expected {expected_row_count}, got {row_count}"
        )


def _write_csv_atomically(path: Path, rows: list[dict[str, object]]) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            writer = csv.DictWriter(output, fieldnames=FLOW_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _write_json_atomically(path: Path, data: dict[str, Any]) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(data, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
