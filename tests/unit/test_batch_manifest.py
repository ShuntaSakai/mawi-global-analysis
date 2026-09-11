import json
from pathlib import Path

import pytest

from mawi_global_analysis.batch import BatchJob, BatchManifest
from mawi_global_analysis.hashing import sha256_file


def _inputs(tmp_path: Path) -> tuple[Path, list[Path], list[BatchJob]]:
    dataset_list = tmp_path / "datasets.txt"
    dataset_list.write_text("202604081400\n202604091400\n", encoding="utf-8")
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text("first config\n", encoding="utf-8")
    second.write_text("second config\n", encoding="utf-8")
    jobs = [
        BatchJob("202604081400", first),
        BatchJob("202604081400", second),
        BatchJob("202604091400", first),
        BatchJob("202604091400", second),
    ]
    return dataset_list, [first, second], jobs


def _create_manifest(tmp_path: Path) -> tuple[BatchManifest, list[BatchJob]]:
    dataset_list, config_paths, jobs = _inputs(tmp_path)
    manifest = BatchManifest.create(
        tmp_path / "batch_manifest.json",
        batch_name="multi-day",
        dataset_list_path=dataset_list,
        dataset_ids=["202604081400", "202604091400"],
        config_paths=config_paths,
        jobs=jobs,
        started_at="2026-09-11T00:00:00+00:00",
    )
    return manifest, jobs


def test_initial_manifest_persists_ordered_inputs_pending_jobs_and_hashes(
    tmp_path: Path,
) -> None:
    manifest, jobs = _create_manifest(tmp_path)
    dataset_list, config_paths, _ = _inputs(tmp_path)

    persisted = json.loads(manifest.path.read_text(encoding="utf-8"))

    assert persisted["batch_name"] == "multi-day"
    assert persisted["dataset_list"] == {
        "path": str(dataset_list),
        "hash": sha256_file(dataset_list),
        "dataset_ids": ["202604081400", "202604091400"],
    }
    assert persisted["configs"] == [
        {"path": str(path), "hash": sha256_file(path)} for path in config_paths
    ]
    assert persisted["jobs"] == [
        {
            "dataset_id": job.dataset_id,
            "config_path": str(job.config_path),
            "config_hash": sha256_file(job.config_path),
            "status": "pending",
            "started_at": None,
            "finished_at": None,
            "duration_seconds": None,
            "linked_run_manifest": None,
            "error": None,
        }
        for job in jobs
    ]
    assert persisted["status"] == "running"


def test_manifest_records_running_then_success_with_link_and_timing(tmp_path: Path) -> None:
    manifest, jobs = _create_manifest(tmp_path)

    manifest.mark_running(jobs[0], started_at="2026-09-11T00:01:00+00:00")
    manifest.mark_succeeded(
        jobs[0],
        linked_run_manifest=Path("results/202604081400/baseline/run_manifest.json"),
        finished_at="2026-09-11T00:01:05+00:00",
        duration_seconds=5.0,
    )

    job = manifest.data["jobs"][0]
    assert job["status"] == "succeeded"
    assert job["linked_run_manifest"] == "results/202604081400/baseline/run_manifest.json"
    assert job["started_at"] == "2026-09-11T00:01:00+00:00"
    assert job["finished_at"] == "2026-09-11T00:01:05+00:00"
    assert job["duration_seconds"] == 5.0


def test_manifest_records_running_then_failure_details(tmp_path: Path) -> None:
    manifest, jobs = _create_manifest(tmp_path)

    manifest.mark_running(jobs[1], started_at="2026-09-11T00:01:00+00:00")
    manifest.mark_failed(
        jobs[1],
        ValueError("invalid input"),
        finished_at="2026-09-11T00:01:03+00:00",
        duration_seconds=3.0,
    )

    job = manifest.data["jobs"][1]
    assert job["status"] == "failed"
    assert job["error"] == {"type": "ValueError", "message": "invalid input"}
    assert job["finished_at"] == "2026-09-11T00:01:03+00:00"
    assert job["duration_seconds"] == 3.0


def test_manifest_rejects_transition_from_a_terminal_job(tmp_path: Path) -> None:
    manifest, jobs = _create_manifest(tmp_path)
    manifest.mark_running(jobs[0], started_at="2026-09-11T00:01:00+00:00")
    manifest.mark_succeeded(
        jobs[0],
        linked_run_manifest=Path("run_manifest.json"),
        finished_at="2026-09-11T00:01:01+00:00",
        duration_seconds=1.0,
    )

    with pytest.raises(ValueError, match="cannot transition job"):
        manifest.mark_running(jobs[0], started_at="2026-09-11T00:02:00+00:00")


def test_manifest_finalizes_success_with_correct_counts(tmp_path: Path) -> None:
    manifest, jobs = _create_manifest(tmp_path)
    for job in jobs:
        manifest.mark_running(job, started_at="2026-09-11T00:01:00+00:00")
        manifest.mark_succeeded(
            job,
            linked_run_manifest=Path("run_manifest.json"),
            finished_at="2026-09-11T00:01:01+00:00",
            duration_seconds=1.0,
        )

    manifest.finalize(finished_at="2026-09-11T00:02:00+00:00")

    assert manifest.data["status"] == "succeeded"
    assert manifest.data["total_jobs"] == 4
    assert manifest.data["succeeded_jobs"] == 4
    assert manifest.data["failed_jobs"] == 0


def test_manifest_finalizes_failed_when_any_job_failed(tmp_path: Path) -> None:
    manifest, jobs = _create_manifest(tmp_path)
    for index, job in enumerate(jobs):
        manifest.mark_running(job, started_at="2026-09-11T00:01:00+00:00")
        if index == 0:
            manifest.mark_failed(
                job,
                RuntimeError("pipeline failure"),
                finished_at="2026-09-11T00:01:01+00:00",
                duration_seconds=1.0,
            )
        else:
            manifest.mark_succeeded(
                job,
                linked_run_manifest=Path("run_manifest.json"),
                finished_at="2026-09-11T00:01:01+00:00",
                duration_seconds=1.0,
            )

    manifest.finalize(finished_at="2026-09-11T00:02:00+00:00")

    assert manifest.data["status"] == "failed"
    assert manifest.data["total_jobs"] == 4
    assert manifest.data["succeeded_jobs"] == 3
    assert manifest.data["failed_jobs"] == 1


def test_manifest_creation_rejects_an_existing_output_path(tmp_path: Path) -> None:
    manifest, _ = _create_manifest(tmp_path)
    dataset_list, config_paths, jobs = _inputs(tmp_path)

    with pytest.raises(FileExistsError, match="batch manifest already exists"):
        BatchManifest.create(
            manifest.path,
            batch_name="multi-day",
            dataset_list_path=dataset_list,
            dataset_ids=["202604081400", "202604091400"],
            config_paths=config_paths,
            jobs=jobs,
            started_at="2026-09-11T00:00:00+00:00",
        )


def test_manifest_atomic_writes_leave_no_temporary_artifacts(tmp_path: Path) -> None:
    manifest, jobs = _create_manifest(tmp_path)
    manifest.mark_running(jobs[0], started_at="2026-09-11T00:01:00+00:00")

    assert list(tmp_path.glob(".batch_manifest.json.*.tmp")) == []
