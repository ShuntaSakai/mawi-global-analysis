"""Pure planning helpers for future multi-dataset batch execution."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mawi_global_analysis.config import load_config
from mawi_global_analysis.dataset import MawiResolver
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.manifests import write_json_atomically
from mawi_global_analysis.pipeline import run_pipeline


@dataclass(frozen=True)
class BatchJob:
    """One ordered dataset/config pair for a future batch controller."""

    dataset_id: str
    config_path: Path


@dataclass(frozen=True)
class BatchJobResult:
    """The outcome of one executed batch job."""

    job: BatchJob
    status: Literal["succeeded", "failed"]
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class BatchExecutionResult:
    """Ordered batch job outcomes and their aggregate success state."""

    results: tuple[BatchJobResult, ...]

    @property
    def succeeded(self) -> bool:
        """Return whether every executed job succeeded."""
        return not self.failed

    @property
    def failed(self) -> bool:
        """Return whether any executed job failed."""
        return any(result.status == "failed" for result in self.results)


class BatchManifest:
    """Persist batch provenance without coupling it to batch execution."""

    def __init__(self, path: Path, data: dict[str, object]) -> None:
        self.path = path
        self.data = data

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        batch_name: str,
        dataset_list_path: Path,
        dataset_ids: Sequence[str],
        config_paths: Sequence[Path],
        jobs: Sequence[BatchJob],
        started_at: str,
    ) -> "BatchManifest":
        """Create a new batch manifest without overwriting existing provenance."""
        if path.exists():
            raise FileExistsError(f"batch manifest already exists: {path}")

        config_hashes = {config_path: sha256_file(config_path) for config_path in config_paths}
        job_records: list[dict[str, object]] = []
        for job in jobs:
            try:
                config_hash = config_hashes[job.config_path]
            except KeyError as error:
                raise ValueError(f"job config path is not a batch config: {job.config_path}") from error
            job_records.append(
                {
                    "dataset_id": job.dataset_id,
                    "config_path": str(job.config_path),
                    "config_hash": config_hash,
                    "status": "pending",
                    "started_at": None,
                    "finished_at": None,
                    "duration_seconds": None,
                    "linked_run_manifest": None,
                    "error": None,
                }
            )

        manifest = cls(
            path,
            {
                "batch_name": batch_name,
                "status": "running",
                "dataset_list": {
                    "path": str(dataset_list_path),
                    "hash": sha256_file(dataset_list_path),
                    "dataset_ids": list(dataset_ids),
                },
                "configs": [
                    {"path": str(config_path), "hash": config_hashes[config_path]}
                    for config_path in config_paths
                ],
                "jobs": job_records,
                "started_at": started_at,
                "finished_at": None,
                "total_jobs": len(job_records),
                "succeeded_jobs": 0,
                "failed_jobs": 0,
            },
        )
        manifest._write()
        return manifest

    def mark_running(self, job: BatchJob, *, started_at: str) -> None:
        """Record the start of one pending job."""
        record = self._transition(job, expected="pending", target="running")
        record["started_at"] = started_at
        self._write()

    def mark_succeeded(
        self,
        job: BatchJob,
        *,
        linked_run_manifest: Path,
        finished_at: str,
        duration_seconds: float,
    ) -> None:
        """Record successful completion and linked single-run provenance."""
        record = self._transition(job, expected="running", target="succeeded")
        record.update(
            {
                "linked_run_manifest": str(linked_run_manifest),
                "finished_at": finished_at,
                "duration_seconds": duration_seconds,
                "error": None,
            }
        )
        self._write()

    def mark_failed(
        self,
        job: BatchJob,
        error: Exception,
        *,
        finished_at: str,
        duration_seconds: float,
    ) -> None:
        """Record failed completion while retaining serializable error details."""
        record = self._transition(job, expected="running", target="failed")
        record.update(
            {
                "finished_at": finished_at,
                "duration_seconds": duration_seconds,
                "error": {"type": type(error).__name__, "message": str(error)},
            }
        )
        self._write()

    def finalize(self, *, finished_at: str) -> None:
        """Finalize a fully completed batch as succeeded or failed."""
        if self.data["status"] != "running":
            raise ValueError(f"cannot finalize batch with status {self.data['status']!r}")
        incomplete = [
            record for record in self._job_records() if record["status"] not in {"succeeded", "failed"}
        ]
        if incomplete:
            raise ValueError("cannot finalize batch with incomplete jobs")
        self._refresh_counts()
        self.data["status"] = "failed" if self.data["failed_jobs"] else "succeeded"
        self.data["finished_at"] = finished_at
        self._write()

    def _transition(
        self, job: BatchJob, *, expected: str, target: str
    ) -> dict[str, object]:
        record = self._job_record(job)
        current = record["status"]
        if current != expected:
            raise ValueError(
                f"cannot transition job {job.dataset_id}/{job.config_path} "
                f"from {current!r} to {target!r}"
            )
        record["status"] = target
        return record

    def _job_record(self, job: BatchJob) -> dict[str, object]:
        for record in self._job_records():
            if (
                record["dataset_id"] == job.dataset_id
                and record["config_path"] == str(job.config_path)
            ):
                return record
        raise ValueError(f"job is not part of this batch: {job.dataset_id}/{job.config_path}")

    def _job_records(self) -> list[dict[str, object]]:
        return self.data["jobs"]  # type: ignore[return-value]

    def _refresh_counts(self) -> None:
        records = self._job_records()
        self.data["total_jobs"] = len(records)
        self.data["succeeded_jobs"] = sum(record["status"] == "succeeded" for record in records)
        self.data["failed_jobs"] = sum(record["status"] == "failed" for record in records)

    def _write(self) -> None:
        self._refresh_counts()
        write_json_atomically(self.path, self.data)


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


def execute_batch_jobs(
    jobs: Iterable[BatchJob],
    runner: Callable[[BatchJob], None],
    *,
    fail_fast: bool = False,
) -> BatchExecutionResult:
    """Run planned jobs sequentially, recording failures for the caller."""
    if not callable(runner):
        raise TypeError("runner must be callable")
    if not isinstance(fail_fast, bool):
        raise TypeError("fail_fast must be a bool")

    results: list[BatchJobResult] = []
    for job in jobs:
        if not isinstance(job, BatchJob):
            raise TypeError("jobs must contain BatchJob instances")
        try:
            runner(job)
        except Exception as error:
            results.append(
                BatchJobResult(
                    job=job,
                    status="failed",
                    error_type=type(error).__name__,
                    error_message=str(error),
                )
            )
            if fail_fast:
                break
        else:
            results.append(BatchJobResult(job=job, status="succeeded"))

    return BatchExecutionResult(results=tuple(results))


def build_batch_parser() -> argparse.ArgumentParser:
    """Build the batch CLI parser without starting any pipeline jobs."""
    parser = argparse.ArgumentParser(description="Run MAWI analysis jobs as a batch.")
    parser.add_argument(
        "--datasets", type=Path, required=True, help="UTF-8 dataset ID list"
    )
    config_mode = parser.add_mutually_exclusive_group(required=True)
    config_mode.add_argument("--config", type=Path, help="One experiment configuration")
    config_mode.add_argument(
        "--configs", type=Path, nargs="+", help="Ordered experiment configurations"
    )
    parser.add_argument("--batch-name", help="Batch name reserved for provenance output")
    parser.add_argument("--fail-fast", action="store_true")
    return parser


def pipeline_args_for_job(job: BatchJob) -> argparse.Namespace:
    """Build the current single-dataset pipeline argument contract for one job."""
    return argparse.Namespace(
        dataset=job.dataset_id,
        input=None,
        dataset_id=None,
        config=job.config_path,
        run_name=None,
        from_stage=None,
        to_stage=None,
        force=None,
        dry_run=False,
        redownload=False,
    )


def run_pipeline_job(
    job: BatchJob, pipeline_runner: Callable[[argparse.Namespace], int] = run_pipeline
) -> None:
    """Run one job through the existing single-dataset pipeline boundary."""
    status = pipeline_runner(pipeline_args_for_job(job))
    if status != 0:
        raise RuntimeError(
            f"pipeline returned non-zero status {status} for dataset {job.dataset_id}"
        )


def run_batch(
    args: argparse.Namespace,
    *,
    pipeline_runner: Callable[[argparse.Namespace], int] = run_pipeline,
) -> int:
    """Plan and execute batch jobs with the existing sequential controller."""
    config_inputs = [args.config] if args.config is not None else args.configs
    config_paths = normalize_config_paths(config_inputs)
    jobs = build_batch_jobs(load_dataset_ids(args.datasets), config_paths)
    result = execute_batch_jobs(
        jobs,
        lambda job: run_pipeline_job(job, pipeline_runner),
        fail_fast=args.fail_fast,
    )
    return 0 if result.succeeded else 1
