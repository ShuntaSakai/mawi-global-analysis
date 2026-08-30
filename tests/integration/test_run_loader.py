from __future__ import annotations

import importlib
import json
from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis import pipeline


ROOT = Path(__file__).parents[2]
PCAP_PATH = ROOT / "tests" / "fixtures" / "pcaps" / "tcp_patterns.pcap"
CONFIG_PATH = ROOT / "configs" / "baseline.yaml"
CANDIDATES_PATH = ROOT / "tests" / "fixtures" / "aguri" / "sample_candidates.csv"


def _load_run():
    """Import the Task 13 public loader with an actionable RED failure."""
    try:
        module = importlib.import_module("mawi_global_analysis.io")
    except ModuleNotFoundError as error:
        pytest.fail("Task 13 loader module must provide load_run")
        raise AssertionError("unreachable") from error
    return module.load_run


def _args() -> object:
    return pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "fixture",
            "--config",
            str(CONFIG_PATH),
        ]
    )


def _stub_aguri(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    def copy_candidates(ctx, cfg, force=False):
        target = root / "data" / ctx.dataset_id / "processed" / "aguri" / "stub"
        target.mkdir(parents=True, exist_ok=True)
        candidates = target / "aguri_candidates.csv"
        candidates.write_bytes(CANDIDATES_PATH.read_bytes())
        return candidates

    monkeypatch.setattr("mawi_global_analysis.pipeline.run_aguri_stage", copy_candidates)


def _fixture_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    return tmp_path / "results" / "fixture" / "baseline"


def test_load_run_uses_manifest_flows_csv_and_run_local_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loader follows recorded provenance, including legacy flows_csv naming."""
    run_dir = _fixture_run(tmp_path, monkeypatch)
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["flows_csv"] = manifest["artifacts"].pop("flows")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    run = _load_run()("fixture", "baseline", root=tmp_path)

    assert run.manifest["dataset_id"] == "fixture"
    assert not run.flows.empty
    assert not run.labels.empty
    assert not run.prefixes.empty
    assert not run.membership.empty
    assert run.scan_windows is not None
    assert run.scan_summary is not None
    assert set(run.labels["flow_id"]) == set(run.flows["flow_id"])
    assert set(run.membership["flow_id"]).issubset(set(run.flows["flow_id"]))


def test_load_run_rejects_missing_required_artifact_and_invalid_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Notebook I/O must fail explicitly rather than guessing missing tables."""
    run_dir = _fixture_run(tmp_path, monkeypatch)
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"].pop("flow_labels")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="missing required artifact entry: flow_labels"):
        _load_run()("fixture", "baseline", root=tmp_path)

    manifest["artifacts"]["flow_labels"] = {
        "path": str(run_dir / "flow_labels.csv"),
        "row_count": len(pd.read_csv(run_dir / "flow_labels.csv")),
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    pd.DataFrame({"flow_id": [1]}).to_csv(run_dir / "flow_labels.csv", index=False)

    with pytest.raises(ValueError, match="flow_labels missing required columns"):
        _load_run()("fixture", "baseline", root=tmp_path)


@pytest.mark.parametrize("status", ["failed", "running"])
def test_load_run_rejects_manifest_that_is_not_successful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    """Partially completed provenance must never be presented as an analysis run."""
    run_dir = _fixture_run(tmp_path, monkeypatch)
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = status
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match=f"run manifest is not successful: {status}"):
        _load_run()("fixture", "baseline", root=tmp_path)
