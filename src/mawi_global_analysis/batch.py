"""Pure planning helpers for future multi-dataset batch execution."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from mawi_global_analysis.config import load_config
from mawi_global_analysis.dataset import MawiResolver
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.manifests import write_json_atomically
from mawi_global_analysis.pipeline import run_manifest_path, run_pipeline


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

    def finalize(
        self,
        *,
        finished_at: str,
        allow_incomplete: bool = False,
        force_failed: bool = False,
    ) -> None:
        """Finalize a fully completed batch as succeeded or failed."""
        if self.data["status"] != "running":
            raise ValueError(f"cannot finalize batch with status {self.data['status']!r}")
        incomplete = [
            record for record in self._job_records() if record["status"] not in {"succeeded", "failed"}
        ]
        if incomplete and not allow_incomplete:
            raise ValueError("cannot finalize batch with incomplete jobs")
        self._refresh_counts()
        self.data["status"] = (
            "failed"
            if force_failed or self.data["failed_jobs"] or incomplete
            else "succeeded"
        )
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


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _batch_name(value: str | None) -> str:
    name = "batch" if value is None else value
    candidate = Path(name)
    if (
        not name
        or name in {".", ".."}
        or candidate.is_absolute()
        or candidate.name != name
        or "/" in name
        or "\\" in name
    ):
        raise ValueError("batch name must be a safe single path component")
    return name


def _batch_output_paths(analysis_root: Path, batch_name: str) -> tuple[Path, Path]:
    output_dir = analysis_root / "results" / "batches" / batch_name
    return output_dir / "batch_manifest.json", output_dir / "batch.log"


def _linked_run_manifest_path(job: BatchJob, analysis_root: Path) -> Path:
    run_name = load_config(job.config_path).experiment.name
    return run_manifest_path(job.dataset_id, run_name, root=analysis_root)


def _validate_successful_linked_run_manifest(path: Path, job: BatchJob) -> None:
    """Require a successful single-run manifest with matching provenance."""
    if not path.is_file():
        raise FileNotFoundError(f"expected linked run manifest is missing: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"linked run manifest is unreadable: {path}") from error
    if not isinstance(manifest, dict):
        raise ValueError(f"linked run manifest is not an object: {path}")
    if manifest.get("status") != "success":
        raise ValueError(f"linked run manifest is not successful: {path}")
    if manifest.get("dataset_id") != job.dataset_id:
        raise ValueError(f"linked run manifest dataset_id does not match batch job: {path}")
    config = manifest.get("config")
    if not isinstance(config, dict) or config.get("hash") != sha256_file(job.config_path):
        raise ValueError(f"linked run manifest config hash does not match batch job: {path}")


def _append_batch_log(path: Path, timestamp: str, message: str) -> None:
    with path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")
        log_file.flush()
        os.fsync(log_file.fileno())


def run_batch(
    args: argparse.Namespace,
    *,
    pipeline_runner: Callable[[argparse.Namespace], int] = run_pipeline,
    analysis_root: Path | None = None,
    timestamp: Callable[[], str] = _timestamp,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> int:
    """Plan, execute, and persist one sequential batch run."""
    config_inputs = [args.config] if args.config is not None else args.configs
    config_paths = normalize_config_paths(config_inputs)
    dataset_ids = load_dataset_ids(args.datasets)
    jobs = build_batch_jobs(dataset_ids, config_paths)
    root = (analysis_root or Path.cwd()).resolve()
    batch_name = _batch_name(args.batch_name)
    manifest_path, log_path = _batch_output_paths(root, batch_name)
    if manifest_path.exists() or log_path.exists():
        raise FileExistsError(f"batch output already exists: {manifest_path.parent}")

    manifest = BatchManifest.create(
        manifest_path,
        batch_name=batch_name,
        dataset_list_path=args.datasets,
        dataset_ids=dataset_ids,
        config_paths=config_paths,
        jobs=jobs,
        started_at=timestamp(),
    )
    try:
        with log_path.open("x", encoding="utf-8"):
            pass
        _append_batch_log(
            log_path,
            timestamp(),
            f"[BATCH START] {batch_name}: {len(dataset_ids)} datasets, {len(config_paths)} configs, {len(jobs)} jobs",
        )

        def runner(job: BatchJob) -> None:
            started_at = timestamp()
            started_monotonic = monotonic_clock()
            manifest.mark_running(job, started_at=started_at)
            _append_batch_log(
                log_path, started_at, f"[START] {job.dataset_id} {job.config_path}"
            )
            try:
                run_pipeline_job(job, pipeline_runner)
                linked_manifest = _linked_run_manifest_path(job, root)
                _validate_successful_linked_run_manifest(linked_manifest, job)
            except Exception as error:
                finished_at = timestamp()
                duration = monotonic_clock() - started_monotonic
                manifest.mark_failed(
                    job,
                    error,
                    finished_at=finished_at,
                    duration_seconds=duration,
                )
                _append_batch_log(
                    log_path,
                    finished_at,
                    f"[FAIL] {job.dataset_id} {job.config_path}: {type(error).__name__}: {error}",
                )
                raise
            else:
                finished_at = timestamp()
                duration = monotonic_clock() - started_monotonic
                manifest.mark_succeeded(
                    job,
                    linked_run_manifest=linked_manifest,
                    finished_at=finished_at,
                    duration_seconds=duration,
                )
                _append_batch_log(
                    log_path, finished_at, f"[DONE] {job.dataset_id} {job.config_path}"
                )

        result = execute_batch_jobs(jobs, runner, fail_fast=args.fail_fast)
        if args.fail_fast and result.failed:
            _append_batch_log(log_path, timestamp(), "[FAIL-FAST] remaining jobs were not run")
        status = "SUCCEEDED" if result.succeeded else "FAILED"
        _append_batch_log(
            log_path,
            timestamp(),
            f"[BATCH {status}] {manifest.data['succeeded_jobs']} succeeded, {manifest.data['failed_jobs']} failed",
        )
        manifest.finalize(
            finished_at=timestamp(), allow_incomplete=args.fail_fast and result.failed
        )
        return 0 if result.succeeded else 1
    except Exception:
        if log_path.exists():
            _append_batch_log(log_path, timestamp(), "[BATCH FAILED] unexpected orchestration error")
        if manifest.data["status"] == "running":
            manifest.finalize(
                finished_at=timestamp(), allow_incomplete=True, force_failed=True
            )
        raise
