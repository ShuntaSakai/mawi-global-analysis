import json
from pathlib import Path

import pytest

from mawi_global_analysis.batch import build_batch_parser, run_batch
from mawi_global_analysis.hashing import sha256_file


def _write_config(path: Path, name: str = "batch_test") -> None:
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


def _parsed_args(tmp_path: Path, *, batch_name: str | None = None):
    dataset_list = tmp_path / "datasets.txt"
    dataset_list.write_text(
        "202604081400\n202604091400\n202604101400\n", encoding="utf-8"
    )
    config = tmp_path / "config.yaml"
    _write_config(config)
    arguments = ["--datasets", str(dataset_list), "--config", str(config)]
    if batch_name is not None:
        arguments.extend(["--batch-name", batch_name])
    return build_batch_parser().parse_args(arguments), dataset_list, config


def _manifest_path(root: Path, batch_name: str = "batch") -> Path:
    return root / "results" / "batches" / batch_name / "batch_manifest.json"


def test_successful_batch_persists_manifest_log_and_linked_run_manifests(
    tmp_path: Path,
) -> None:
    args, dataset_list, config = _parsed_args(tmp_path)
    executed: list[str] = []

    def runner(pipeline_args) -> int:
        executed.append(pipeline_args.dataset)
        path = (
            tmp_path
            / "results"
            / pipeline_args.dataset
            / "batch_test"
            / "run_manifest.json"
        )
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
        return 0

    assert run_batch(args, pipeline_runner=runner, analysis_root=tmp_path) == 0

    manifest_path = _manifest_path(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert executed == ["202604081400", "202604091400", "202604101400"]
    assert manifest["status"] == "succeeded"
    assert manifest["succeeded_jobs"] == 3
    assert manifest["failed_jobs"] == 0
    assert manifest["dataset_list"]["hash"] == sha256_file(dataset_list)
    assert manifest["configs"] == [{"path": str(config.resolve()), "hash": sha256_file(config)}]
    assert [job["dataset_id"] for job in manifest["jobs"]] == executed
    assert manifest["jobs"][0]["linked_run_manifest"] == str(
        tmp_path / "results" / "202604081400" / "batch_test" / "run_manifest.json"
    )
    assert (_manifest_path(tmp_path).parent / "batch.log").is_file()


def test_batch_continues_after_job_failure_and_records_log_details(tmp_path: Path) -> None:
    args, _, _ = _parsed_args(tmp_path)
    executed: list[str] = []

    def runner(pipeline_args) -> int:
        executed.append(pipeline_args.dataset)
        if pipeline_args.dataset == "202604091400":
            raise ValueError("synthetic failure")
        path = (
            tmp_path
            / "results"
            / pipeline_args.dataset
            / "batch_test"
            / "run_manifest.json"
        )
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
        return 0

    assert run_batch(args, pipeline_runner=runner, analysis_root=tmp_path) == 1

    manifest = json.loads(_manifest_path(tmp_path).read_text(encoding="utf-8"))
    assert executed == ["202604081400", "202604091400", "202604101400"]
    assert [job["status"] for job in manifest["jobs"]] == [
        "succeeded",
        "failed",
        "succeeded",
    ]
    assert manifest["status"] == "failed"
    assert manifest["jobs"][1]["error"] == {
        "type": "ValueError",
        "message": "synthetic failure",
    }
    log = (_manifest_path(tmp_path).parent / "batch.log").read_text(encoding="utf-8")
    assert "[START]" in log
    assert "[DONE]" in log
    assert "[FAIL]" in log
    assert "ValueError: synthetic failure" in log
    assert "[BATCH FAILED] 2 succeeded, 1 failed" in log


def test_fail_fast_leaves_unexecuted_jobs_pending_and_finalizes_failed(tmp_path: Path) -> None:
    args, _, _ = _parsed_args(tmp_path)
    args.fail_fast = True
    executed: list[str] = []

    def runner(pipeline_args) -> int:
        executed.append(pipeline_args.dataset)
        if pipeline_args.dataset == "202604091400":
            raise ValueError("synthetic failure")
        path = (
            tmp_path
            / "results"
            / pipeline_args.dataset
            / "batch_test"
            / "run_manifest.json"
        )
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
        return 0

    assert run_batch(args, pipeline_runner=runner, analysis_root=tmp_path) == 1

    manifest = json.loads(_manifest_path(tmp_path).read_text(encoding="utf-8"))
    assert executed == ["202604081400", "202604091400"]
    assert [job["status"] for job in manifest["jobs"]] == [
        "succeeded",
        "failed",
        "pending",
    ]
    assert manifest["status"] == "failed"
    assert "[FAIL-FAST]" in (
        _manifest_path(tmp_path).parent / "batch.log"
    ).read_text(encoding="utf-8")


def test_missing_linked_run_manifest_converts_pipeline_success_to_job_failure(
    tmp_path: Path,
) -> None:
    args, _, _ = _parsed_args(tmp_path)

    assert run_batch(args, pipeline_runner=lambda pipeline_args: 0, analysis_root=tmp_path) == 1

    manifest = json.loads(_manifest_path(tmp_path).read_text(encoding="utf-8"))
    assert [job["status"] for job in manifest["jobs"]] == ["failed", "failed", "failed"]
    assert manifest["jobs"][0]["error"]["type"] == "FileNotFoundError"


def test_batch_output_conflicts_do_not_run_or_overwrite(tmp_path: Path) -> None:
    args, _, _ = _parsed_args(tmp_path)
    conflict = _manifest_path(tmp_path)
    conflict.parent.mkdir(parents=True)
    conflict.write_text('{"existing": true}\n', encoding="utf-8")
    executed = False

    def runner(pipeline_args) -> int:
        nonlocal executed
        executed = True
        return 0

    with pytest.raises(FileExistsError, match="batch output already exists"):
        run_batch(args, pipeline_runner=runner, analysis_root=tmp_path)

    assert executed is False
    assert conflict.read_text(encoding="utf-8") == '{"existing": true}\n'


@pytest.mark.parametrize("batch_name", ["", ".", "..", "../foo", "foo/bar", "/tmp/batch"])
def test_batch_rejects_unsafe_output_names(tmp_path: Path, batch_name: str) -> None:
    args, _, _ = _parsed_args(tmp_path, batch_name=batch_name)

    with pytest.raises(ValueError, match="batch name"):
        run_batch(args, pipeline_runner=lambda pipeline_args: 0, analysis_root=tmp_path)
