import json
from pathlib import Path

from mawi_global_analysis.manifests import RunManifest


def test_failure_manifest_keeps_completed_stages_and_error_details(tmp_path: Path) -> None:
    """A fatal error must retain evidence recorded before it occurred."""
    manifest_path = tmp_path / "run_manifest.json"
    manifest = RunManifest.start(
        manifest_path,
        dataset_id="202604081400",
        config_path=Path("configs/baseline.yaml"),
        config_text="experiment: {name: baseline}\n",
        config_hash="config-sha",
        git_commit="abc123",
    )
    manifest.record_stage("input", "completed")
    manifest.record_artifact("input_pcap", Path("data/input.pcap.gz"), row_count=1)
    manifest.finalize_failure(ValueError("unreadable input"))

    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert persisted["status"] == "failed"
    assert persisted["error"] == {
        "type": "ValueError",
        "message": "unreadable input",
    }
    assert persisted["stages"] == [{"name": "input", "status": "completed"}]
    assert persisted["artifacts"] == {
        "input_pcap": {"path": "data/input.pcap.gz", "row_count": 1}
    }
