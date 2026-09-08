from pathlib import Path

import pytest

from mawi_global_analysis.batch import (
    BatchJob,
    build_batch_jobs,
    execute_batch_jobs,
    load_dataset_ids,
    normalize_config_paths,
)


def _write_valid_config(path: Path, name: str) -> None:
    path.write_text(
        f"""
experiment: {{name: {name}, description: Synthetic batch config}}
flow: {{inactive_timeout_seconds: null}}
prefix: {{ip_version: 4, candidate_sources: [src_prefix, dst_prefix], min_prefix_length: 24, containment_strategy: prefer_broader, membership_mode: src_or_dst, normalized_24_enabled: true, top_k: null}}
scan:
  window_size_seconds: 60
  window_step_seconds: 10
  strict: {{enabled: false}}
  broad: {{enabled: false}}
aguri: {{aguri3_executable: null, agurim_executable: null, options: []}}
analysis: {{overall_ip_scope: ipv4}}
""",
        encoding="utf-8",
    )


def test_load_dataset_ids_preserves_order_and_ignores_blank_lines(tmp_path: Path) -> None:
    dataset_list = tmp_path / "datasets.txt"
    dataset_list.write_text("202604081400\n\n202604091400\n", encoding="utf-8")

    assert load_dataset_ids(dataset_list) == ["202604081400", "202604091400"]


def test_load_dataset_ids_rejects_duplicates(tmp_path: Path) -> None:
    dataset_list = tmp_path / "datasets.txt"
    dataset_list.write_text("202604081400\n202604081400\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate dataset ID"):
        load_dataset_ids(dataset_list)


def test_load_dataset_ids_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="dataset list file not found"):
        load_dataset_ids(tmp_path / "missing.txt")


def test_normalize_config_paths_preserves_order(tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    _write_valid_config(first, "first")
    _write_valid_config(second, "second")

    assert normalize_config_paths([first, second]) == [first.resolve(), second.resolve()]


def test_normalize_config_paths_rejects_duplicates(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    _write_valid_config(config, "config")

    with pytest.raises(ValueError, match="duplicate config path"):
        normalize_config_paths([config, config])


def test_normalize_config_paths_rejects_an_empty_list() -> None:
    with pytest.raises(ValueError, match="at least one config path"):
        normalize_config_paths([])


def test_normalize_config_paths_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="config file not found"):
        normalize_config_paths([tmp_path / "missing.yaml"])


def test_build_batch_jobs_returns_dataset_by_config_matrix() -> None:
    jobs = build_batch_jobs(
        ["202604081400", "202604091400"],
        [Path("first.yaml"), Path("second.yaml")],
    )

    assert [(job.dataset_id, job.config_path) for job in jobs] == [
        ("202604081400", Path("first.yaml")),
        ("202604081400", Path("second.yaml")),
        ("202604091400", Path("first.yaml")),
        ("202604091400", Path("second.yaml")),
    ]


def _jobs() -> list[BatchJob]:
    return [
        BatchJob("202604081400", Path("first.yaml")),
        BatchJob("202604091400", Path("first.yaml")),
        BatchJob("202604101400", Path("first.yaml")),
    ]


def test_execute_batch_jobs_runs_all_successful_jobs_in_input_order() -> None:
    jobs = _jobs()
    executed: list[BatchJob] = []

    result = execute_batch_jobs(jobs, lambda job: executed.append(job))

    assert executed == jobs
    assert result.succeeded is True
    assert result.failed is False
    assert [job_result.status for job_result in result.results] == [
        "succeeded",
        "succeeded",
        "succeeded",
    ]


def test_execute_batch_jobs_continues_after_a_failed_job() -> None:
    jobs = _jobs()
    executed: list[BatchJob] = []

    def runner(job: BatchJob) -> None:
        executed.append(job)
        if job == jobs[1]:
            raise RuntimeError("middle job failed")

    result = execute_batch_jobs(jobs, runner)

    assert executed == jobs
    assert result.succeeded is False
    assert result.failed is True
    assert result.results[1].status == "failed"
    assert result.results[1].error_type == "RuntimeError"
    assert result.results[1].error_message == "middle job failed"


def test_execute_batch_jobs_stops_after_failure_when_fail_fast_is_enabled() -> None:
    jobs = _jobs()
    executed: list[BatchJob] = []

    def runner(job: BatchJob) -> None:
        executed.append(job)
        if job == jobs[1]:
            raise RuntimeError("middle job failed")

    result = execute_batch_jobs(jobs, runner, fail_fast=True)

    assert executed == jobs[:2]
    assert [job_result.job for job_result in result.results] == jobs[:2]
    assert result.succeeded is False


def test_execute_batch_jobs_records_multiple_failures_when_continuing() -> None:
    jobs = _jobs()

    def runner(job: BatchJob) -> None:
        if job in (jobs[0], jobs[2]):
            raise ValueError(f"failed {job.dataset_id}")

    result = execute_batch_jobs(jobs, runner)

    assert [job_result.status for job_result in result.results] == [
        "failed",
        "succeeded",
        "failed",
    ]
    assert [job_result.error_message for job_result in result.results] == [
        "failed 202604081400",
        None,
        "failed 202604101400",
    ]
    assert result.failed is True


def test_execute_batch_jobs_preserves_executed_result_order() -> None:
    jobs = _jobs()

    def runner(job: BatchJob) -> None:
        if job == jobs[1]:
            raise RuntimeError("middle job failed")

    result = execute_batch_jobs(jobs, runner)

    assert [job_result.job for job_result in result.results] == jobs
