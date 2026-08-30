"""Deterministic hashes used to identify reproducible pipeline inputs."""

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mawi_global_analysis.config import ExperimentConfig


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        while chunk := input_file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json_hash(mapping: Mapping[str, Any]) -> str:
    """Hash a mapping using canonical, compact JSON serialization."""
    encoded = json.dumps(
        mapping,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def flow_generation_config(cfg: ExperimentConfig) -> dict[str, Any]:
    """Return only settings that change canonical flow rows."""
    return {
        "protocols": sorted(cfg.flow.protocols),
        "inactive_timeout_seconds": cfg.flow.inactive_timeout_seconds,
    }


def flow_fingerprint(
    input_sha256: str, cfg: ExperimentConfig, schema_version: str = "flows-v1"
) -> str:
    """Identify a canonical-flow cache without including run interpretation."""
    return stable_json_hash(
        {
            "input_sha256": input_sha256,
            "flow_config": flow_generation_config(cfg),
            "schema_version": schema_version,
        }
    )
