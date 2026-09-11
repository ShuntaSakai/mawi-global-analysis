"""Manifest-driven convenience loading for analysis notebooks.

This module intentionally performs only provenance-aware I/O and basic table
validation. Statistical aggregation remains explicit in notebooks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from mawi_global_analysis.flow_stage import FLOW_COLUMNS
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS
from mawi_global_analysis.scan_windows import SCAN_SUMMARY_COLUMNS, SCAN_WINDOW_COLUMNS


@dataclass(frozen=True)
class RunData:
    """Canonical and run-local tables recorded by one successful analysis run."""

    flows: pd.DataFrame
    labels: pd.DataFrame
    prefixes: pd.DataFrame
    membership: pd.DataFrame
    scan_windows: pd.DataFrame | None
    scan_summary: pd.DataFrame | None
    manifest: dict[str, Any]


@dataclass(frozen=True)
class BatchJobData:
    """One manifest-ordered batch job and its recorded provenance metadata."""

    dataset_id: str
    config_path: str
    config_hash: str
    status: str
    linked_run_manifest: Path | None
    metadata: dict[str, Any]


@dataclass(frozen=True)
class BatchData:
    """Batch provenance with lazy access to successful single-dataset runs."""

    manifest: dict[str, Any]
    jobs: tuple[BatchJobData, ...]
    root: Path

    @property
    def batch_name(self) -> str:
        return self.manifest["batch_name"]

    @property
    def status(self) -> str:
        return self.manifest["status"]

    @property
    def dataset_list(self) -> dict[str, Any]:
        return self.manifest["dataset_list"]

    @property
    def configs(self) -> list[dict[str, Any]]:
        return self.manifest["configs"]

    @property
    def successful_jobs(self) -> tuple[BatchJobData, ...]:
        return tuple(job for job in self.jobs if job.status == "succeeded")

    def load_job_run(self, job: BatchJobData) -> RunData:
        """Load one successful job through the canonical single-run loader."""
        if job not in self.jobs:
            raise ValueError("batch job does not belong to this batch")
        if job.status != "succeeded":
            raise ValueError(f"batch job is not succeeded: {job.status!r}")
        linked_manifest = _validate_linked_run_manifest(job, root=self.root)
        return load_run(job.dataset_id, linked_manifest.parent.name, root=self.root)


def load_batch(path: Path) -> BatchData:
    """Load batch provenance without eagerly loading any run CSV artifacts."""
    manifest_path = Path(path).resolve()
    root = _batch_root(manifest_path)
    manifest = _read_batch_manifest(manifest_path)
    _validate_batch_manifest(manifest, manifest_path)
    jobs = tuple(_batch_job(record, root=root) for record in manifest["jobs"])
    return BatchData(manifest=manifest, jobs=jobs, root=root)


def load_run(dataset_id: str, run_name: str, root: Path = Path(".")) -> RunData:
    """Load one run exclusively from its recorded manifest provenance.

    Required artifacts are canonical flows plus run-local labels, prefix ledger,
    and membership. Source-window tables are optional, because a caller may
    intentionally load a run that ended before the M4 scan-stat stage.
    """
    root = Path(root).resolve()
    run_dir = root / "results" / dataset_id / run_name
    manifest_path = run_dir / "run_manifest.json"
    manifest = _read_manifest(manifest_path)
    _validate_manifest_identity(manifest, dataset_id, manifest_path)
    if manifest.get("status") != "success":
        raise ValueError(
            "run manifest is not successful: "
            f"{manifest.get('status')!s} ({manifest_path})"
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError(f"run manifest has invalid artifacts object: {manifest_path}")

    flows = _read_required_csv(
        artifacts,
        artifact_name="flows",
        compatible_names=("flows_csv",),
        expected_columns=FLOW_COLUMNS,
        root=root,
    )
    labels = _read_required_csv(
        artifacts,
        artifact_name="flow_labels",
        expected_columns=FLOW_LABEL_COLUMNS,
        root=root,
    )
    prefixes = _read_required_csv(
        artifacts,
        artifact_name="prefixes",
        expected_columns=CORRECTED_LEDGER_COLUMNS,
        root=root,
    )
    membership = _read_required_csv(
        artifacts,
        artifact_name="flow_prefix_membership",
        expected_columns=MEMBERSHIP_COLUMNS,
        root=root,
    )
    scan_windows = _read_optional_csv(
        artifacts,
        artifact_name="source_scan_windows",
        expected_columns=SCAN_WINDOW_COLUMNS,
        root=root,
    )
    scan_summary = _read_optional_csv(
        artifacts,
        artifact_name="source_scan_summary",
        expected_columns=SCAN_SUMMARY_COLUMNS,
        root=root,
    )
    return RunData(
        flows=flows,
        labels=labels,
        prefixes=prefixes,
        membership=membership,
        scan_windows=scan_windows,
        scan_summary=scan_summary,
        manifest=manifest,
    )


def _batch_root(manifest_path: Path) -> Path:
    if (
        manifest_path.name != "batch_manifest.json"
        or manifest_path.parent.parent.name != "batches"
        or manifest_path.parent.parent.parent.name != "results"
    ):
        raise ValueError(
            "batch manifest must be located at "
            f"results/batches/<batch-name>/batch_manifest.json: {manifest_path}"
        )
    return manifest_path.parent.parent.parent.parent


def _read_batch_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"batch manifest not found: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"unreadable batch manifest: {path}") from error
    if not isinstance(manifest, dict):
        raise ValueError(f"batch manifest is not an object: {path}")
    return manifest


def _validate_batch_manifest(manifest: dict[str, Any], path: Path) -> None:
    for name in ("batch_name", "status"):
        if not isinstance(manifest.get(name), str) or not manifest[name]:
            raise ValueError(f"batch manifest missing valid {name}: {path}")
    if not isinstance(manifest.get("dataset_list"), dict):
        raise ValueError(f"batch manifest has invalid dataset_list: {path}")
    if not isinstance(manifest.get("configs"), list):
        raise ValueError(f"batch manifest has invalid configs: {path}")
    if not isinstance(manifest.get("jobs"), list):
        raise ValueError(f"batch manifest has invalid jobs: {path}")


def _batch_job(record: Any, *, root: Path) -> BatchJobData:
    if not isinstance(record, dict):
        raise ValueError("batch manifest job is not an object")
    required = ("dataset_id", "config_path", "config_hash", "status")
    invalid = [name for name in required if not isinstance(record.get(name), str) or not record[name]]
    if invalid:
        raise ValueError("batch manifest job missing valid " + ", ".join(invalid))
    linked_value = record.get("linked_run_manifest")
    linked_manifest: Path | None = None
    if record["status"] == "succeeded":
        if not isinstance(linked_value, str) or not linked_value:
            raise ValueError(
                f"succeeded batch job missing linked_run_manifest: {record['dataset_id']}"
            )
        linked_manifest = Path(linked_value)
        if not linked_manifest.is_absolute():
            raise ValueError(
                "succeeded batch job linked_run_manifest must be an absolute path: "
                f"{linked_value}"
            )
    elif linked_value is not None and not isinstance(linked_value, str):
        raise ValueError(
            "batch job linked_run_manifest must be a string or null: "
            f"{record['dataset_id']}"
        )
    job = BatchJobData(
        dataset_id=record["dataset_id"],
        config_path=record["config_path"],
        config_hash=record["config_hash"],
        status=record["status"],
        linked_run_manifest=linked_manifest,
        metadata=record,
    )
    if job.status == "succeeded":
        _validate_linked_run_manifest(job, root=root)
    return job


def _validate_linked_run_manifest(job: BatchJobData, *, root: Path) -> Path:
    linked_manifest = job.linked_run_manifest
    assert linked_manifest is not None
    linked_manifest = linked_manifest.resolve()
    if linked_manifest.name != "run_manifest.json":
        raise ValueError(f"linked run manifest must name run_manifest.json: {linked_manifest}")
    if not linked_manifest.is_file():
        raise FileNotFoundError(f"linked run manifest not found: {linked_manifest}")
    manifest = _read_manifest(linked_manifest)
    recorded_dataset = manifest.get("dataset_id")
    if recorded_dataset != job.dataset_id:
        raise ValueError(
            "linked run manifest dataset_id does not match batch job: "
            f"job {job.dataset_id!r}, recorded {recorded_dataset!r} in {linked_manifest}"
        )
    config = manifest.get("config")
    recorded_config_hash = config.get("hash") if isinstance(config, dict) else None
    if recorded_config_hash != job.config_hash:
        raise ValueError(
            "linked run manifest config hash does not match batch job: "
            f"job {job.config_hash!r}, recorded {recorded_config_hash!r} in {linked_manifest}"
        )
    expected = root / "results" / job.dataset_id / linked_manifest.parent.name / "run_manifest.json"
    if linked_manifest != expected:
        raise ValueError(
            "linked run manifest is not in the canonical run location: "
            f"{linked_manifest}"
        )
    return linked_manifest


def _read_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"run manifest not found: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"unreadable run manifest: {path}") from error
    if not isinstance(manifest, dict):
        raise ValueError(f"run manifest is not an object: {path}")
    return manifest


def _validate_manifest_identity(
    manifest: dict[str, Any], dataset_id: str, manifest_path: Path
) -> None:
    recorded_dataset = manifest.get("dataset_id")
    if recorded_dataset != dataset_id:
        raise ValueError(
            "run manifest dataset_id does not match requested dataset: "
            f"requested {dataset_id!r}, recorded {recorded_dataset!r} in {manifest_path}"
        )


def _read_required_csv(
    artifacts: dict[str, Any],
    *,
    artifact_name: str,
    expected_columns: tuple[str, ...],
    root: Path,
    compatible_names: tuple[str, ...] = (),
) -> pd.DataFrame:
    entry_name, entry = _artifact_entry(
        artifacts, artifact_name, compatible_names, required=True
    )
    assert entry_name is not None and entry is not None
    return _read_csv(entry_name, entry, expected_columns, root)


def _read_optional_csv(
    artifacts: dict[str, Any],
    *,
    artifact_name: str,
    expected_columns: tuple[str, ...],
    root: Path,
) -> pd.DataFrame | None:
    entry_name, entry = _artifact_entry(artifacts, artifact_name, (), required=False)
    if entry is None:
        return None
    assert entry_name is not None
    return _read_csv(entry_name, entry, expected_columns, root)


def _artifact_entry(
    artifacts: dict[str, Any],
    artifact_name: str,
    compatible_names: tuple[str, ...],
    *,
    required: bool,
) -> tuple[str | None, dict[str, Any] | None]:
    names = (artifact_name, *compatible_names)
    found = [(name, artifacts[name]) for name in names if name in artifacts]
    if not found:
        if required:
            raise FileNotFoundError(f"missing required artifact entry: {artifact_name}")
        return None, None
    if len(found) > 1:
        raise ValueError(
            f"ambiguous artifact entries for {artifact_name}: "
            + ", ".join(name for name, _ in found)
        )
    entry_name, entry = found[0]
    if not isinstance(entry, dict):
        raise ValueError(f"artifact entry is not an object: {entry_name}")
    return entry_name, entry


def _read_csv(
    artifact_name: str,
    entry: dict[str, Any],
    expected_columns: tuple[str, ...],
    root: Path,
) -> pd.DataFrame:
    value = entry.get("path")
    if not isinstance(value, str) or not value:
        raise ValueError(f"artifact entry missing path: {artifact_name}")
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    if not path.is_file():
        raise FileNotFoundError(f"artifact file not found for {artifact_name}: {path}")
    try:
        frame = pd.read_csv(path)
    except (OSError, UnicodeError, pd.errors.ParserError) as error:
        raise ValueError(f"unreadable CSV artifact {artifact_name}: {path}") from error
    missing = [column for column in expected_columns if column not in frame.columns]
    if missing:
        raise ValueError(
            f"{artifact_name} missing required columns: {', '.join(missing)}"
        )
    expected_row_count = entry.get("row_count")
    if expected_row_count is not None:
        if not isinstance(expected_row_count, int) or expected_row_count < 0:
            raise ValueError(f"artifact entry has invalid row_count: {artifact_name}")
        if len(frame) != expected_row_count:
            raise ValueError(
                f"{artifact_name} row count disagrees with manifest: "
                f"expected {expected_row_count}, got {len(frame)}"
            )
    return frame
