import json
from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.flow_stage import FLOW_COLUMNS
from mawi_global_analysis.io import load_batch
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS


def _write_run_manifest(
    root: Path,
    *,
    dataset_id: str,
    run_name: str,
    config_hash: str,
) -> Path:
    run_dir = root / "results" / dataset_id / run_name
    run_dir.mkdir(parents=True)
    artifacts = {}
    for name, columns in (
        ("flows", FLOW_COLUMNS),
        ("flow_labels", FLOW_LABEL_COLUMNS),
        ("prefixes", CORRECTED_LEDGER_COLUMNS),
        ("flow_prefix_membership", MEMBERSHIP_COLUMNS),
    ):
        artifact_path = run_dir / f"{name}.csv"
        pd.DataFrame(columns=columns).to_csv(artifact_path, index=False)
        artifacts[name] = {"path": str(artifact_path), "row_count": 0}
    manifest_path = run_dir / "run_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "status": "success",
                "dataset_id": dataset_id,
                "config": {"hash": config_hash},
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def _write_batch_manifest(root: Path, jobs: list[dict[str, object]]) -> Path:
    path = root / "results" / "batches" / "synthetic" / "batch_manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "batch_name": "synthetic",
                "status": "failed",
                "dataset_list": {
                    "path": "/synthetic/datasets.txt",
                    "hash": "datasets-hash",
                    "dataset_ids": ["202604081400", "202604091400"],
                },
                "configs": [
                    {"path": "/synthetic/first.yaml", "hash": "first-hash"},
                    {"path": "/synthetic/second.yaml", "hash": "second-hash"},
                ],
                "jobs": jobs,
            }
        ),
        encoding="utf-8",
    )
    return path


def _job(
    dataset_id: str,
    *,
    config_hash: str,
    status: str,
    linked_run_manifest: Path | None = None,
) -> dict[str, object]:
    return {
        "dataset_id": dataset_id,
        "config_path": f"/synthetic/{config_hash}.yaml",
        "config_hash": config_hash,
        "status": status,
        "linked_run_manifest": (
            str(linked_run_manifest) if linked_run_manifest is not None else None
        ),
        "error": {"type": "SyntheticError", "message": "expected"}
        if status == "failed"
        else None,
    }


def test_load_batch_preserves_manifest_order_and_non_successful_metadata(tmp_path: Path) -> None:
    first = _write_run_manifest(
        tmp_path,
        dataset_id="202604081400",
        run_name="first",
        config_hash="first-hash",
    )
    second = _write_run_manifest(
        tmp_path,
        dataset_id="202604091400",
        run_name="second",
        config_hash="second-hash",
    )
    batch_manifest = _write_batch_manifest(
        tmp_path,
        [
            _job("202604091400", config_hash="second-hash", status="succeeded", linked_run_manifest=second),
            _job("202604081400", config_hash="first-hash", status="failed"),
            _job("202604091400", config_hash="first-hash", status="pending"),
            _job("202604081400", config_hash="first-hash", status="succeeded", linked_run_manifest=first),
        ],
    )

    batch = load_batch(batch_manifest)

    assert batch.batch_name == "synthetic"
    assert batch.status == "failed"
    assert batch.dataset_list["hash"] == "datasets-hash"
    assert [config["hash"] for config in batch.configs] == ["first-hash", "second-hash"]
    assert [(job.dataset_id, job.status) for job in batch.jobs] == [
        ("202604091400", "succeeded"),
        ("202604081400", "failed"),
        ("202604091400", "pending"),
        ("202604081400", "succeeded"),
    ]
    assert [job.dataset_id for job in batch.successful_jobs] == [
        "202604091400",
        "202604081400",
    ]
    assert batch.jobs[1].metadata["error"] == {
        "type": "SyntheticError",
        "message": "expected",
    }
    assert batch.jobs[1].linked_run_manifest is None
    assert batch.jobs[2].linked_run_manifest is None


def test_load_batch_defers_artifact_reads_until_a_successful_job_is_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    linked_manifest = _write_run_manifest(
        tmp_path,
        dataset_id="202604081400",
        run_name="first",
        config_hash="first-hash",
    )
    batch_manifest = _write_batch_manifest(
        tmp_path,
        [_job("202604081400", config_hash="first-hash", status="succeeded", linked_run_manifest=linked_manifest)],
    )
    calls = 0
    original_read_csv = pd.read_csv

    def count_read_csv(*args: object, **kwargs: object) -> pd.DataFrame:
        nonlocal calls
        calls += 1
        return original_read_csv(*args, **kwargs)

    monkeypatch.setattr("mawi_global_analysis.io.pd.read_csv", count_read_csv)

    batch = load_batch(batch_manifest)

    assert calls == 0
    run = batch.load_job_run(batch.successful_jobs[0])
    assert calls == 4
    assert run.manifest["dataset_id"] == "202604081400"


def test_load_batch_rejects_succeeded_job_without_linked_manifest(tmp_path: Path) -> None:
    batch_manifest = _write_batch_manifest(
        tmp_path, [_job("202604081400", config_hash="first-hash", status="succeeded")]
    )

    with pytest.raises(ValueError, match="missing linked_run_manifest"):
        load_batch(batch_manifest)


def test_load_batch_rejects_missing_linked_manifest_file(tmp_path: Path) -> None:
    batch_manifest = _write_batch_manifest(
        tmp_path,
        [
            _job(
                "202604081400",
                config_hash="first-hash",
                status="succeeded",
                linked_run_manifest=tmp_path / "results" / "202604081400" / "first" / "run_manifest.json",
            )
        ],
    )

    with pytest.raises(FileNotFoundError, match="linked run manifest not found"):
        load_batch(batch_manifest)


def test_load_batch_rejects_linked_path_that_is_not_a_run_manifest(tmp_path: Path) -> None:
    other_file = tmp_path / "results" / "202604081400" / "first" / "other.json"
    other_file.parent.mkdir(parents=True)
    other_file.write_text("{}", encoding="utf-8")
    batch_manifest = _write_batch_manifest(
        tmp_path,
        [_job("202604081400", config_hash="first-hash", status="succeeded", linked_run_manifest=other_file)],
    )

    with pytest.raises(ValueError, match="must name run_manifest.json"):
        load_batch(batch_manifest)


def test_load_batch_rejects_linked_run_dataset_identity_mismatch(tmp_path: Path) -> None:
    linked_manifest = _write_run_manifest(
        tmp_path,
        dataset_id="202604091400",
        run_name="first",
        config_hash="first-hash",
    )
    batch_manifest = _write_batch_manifest(
        tmp_path,
        [_job("202604081400", config_hash="first-hash", status="succeeded", linked_run_manifest=linked_manifest)],
    )

    with pytest.raises(ValueError, match="dataset_id does not match batch job"):
        load_batch(batch_manifest)


def test_load_batch_rejects_linked_run_config_hash_mismatch(tmp_path: Path) -> None:
    linked_manifest = _write_run_manifest(
        tmp_path,
        dataset_id="202604081400",
        run_name="first",
        config_hash="other-hash",
    )
    batch_manifest = _write_batch_manifest(
        tmp_path,
        [_job("202604081400", config_hash="first-hash", status="succeeded", linked_run_manifest=linked_manifest)],
    )

    with pytest.raises(ValueError, match="config hash does not match batch job"):
        load_batch(batch_manifest)
