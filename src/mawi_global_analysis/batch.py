"""Pure planning helpers for future multi-dataset batch execution."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from mawi_global_analysis.config import load_config
from mawi_global_analysis.dataset import MawiResolver


@dataclass(frozen=True)
class BatchJob:
    """One ordered dataset/config pair for a future batch controller."""

    dataset_id: str
    config_path: Path


def load_dataset_ids(path: Path) -> list[str]:
    """Load ordered MAWI dataset IDs from a UTF-8 text file."""
    if not path.is_file():
        raise FileNotFoundError(f"dataset list file not found: {path}")

    resolver = MawiResolver()
    dataset_ids: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        dataset_id = line.strip()
        if not dataset_id:
            continue
        if dataset_id in seen:
            raise ValueError(f"duplicate dataset ID: {dataset_id}")
        resolver.resolve(dataset_id)
        seen.add(dataset_id)
        dataset_ids.append(dataset_id)
    return dataset_ids


def normalize_config_paths(paths: Iterable[Path]) -> list[Path]:
    """Validate and normalize an ordered list of experiment configuration paths."""
    normalized_paths: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        normalized_path = path.resolve()
        if not normalized_path.is_file():
            raise FileNotFoundError(f"config file not found: {path}")
        if normalized_path in seen:
            raise ValueError(f"duplicate config path: {normalized_path}")
        load_config(normalized_path)
        seen.add(normalized_path)
        normalized_paths.append(normalized_path)

    if not normalized_paths:
        raise ValueError("at least one config path is required")
    return normalized_paths


def build_batch_jobs(
    dataset_ids: Sequence[str], config_paths: Sequence[Path]
) -> list[BatchJob]:
    """Build the deterministic dataset-major Cartesian product of batch inputs."""
    return [
        BatchJob(dataset_id=dataset_id, config_path=config_path)
        for dataset_id in dataset_ids
        for config_path in config_paths
    ]
