"""Read-only operational disk report, using synthetic metadata and file sizes."""

import importlib.util
import json
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "report_ditl_disk_preflight.py"


def _module():
    spec = importlib.util.spec_from_file_location("disk_report", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cache(tmp_path):
    from mawi_global_analysis.ditl_chunks import expected_chunk_ids

    root = tmp_path / "cache"
    records = []
    for index, chunk_id in enumerate(expected_chunk_ids("20260408")):
        directory = root / "cohort-hash" / chunk_id
        directory.mkdir(parents=True)
        artifacts = {}
        for name in ("target_observations", "source_syn_observations"):
            path = directory / f"{name}.csv"
            path.write_bytes(b"not a CSV; only stat is allowed")
            artifacts[name] = {"path": str(path)}
        record = {"chunk_id": chunk_id, "status": "success",
                  "cohort_identity": "cohort-hash", "observation_code_identity": "code-hash",
                  "target_observation_row_count": 1,
                  "source_syn_observation_row_count": 10 if 40 <= index < 49 else 1,
                  "artifacts": artifacts}
        (directory / "chunk_metadata.json").write_text(json.dumps(record))
        records.append(record)
    return root, records


def test_report_only_reads_metadata_and_stats_and_prints_exact_estimate(tmp_path, monkeypatch, capsys):
    from mawi_global_analysis.ditl_context_sqlite import estimate_aggregation_disk_space, SQLiteContextAggregator

    root, records = _cache(tmp_path)
    before = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in root.rglob("*")}
    report = _module()
    monkeypatch.setattr(report.shutil, "disk_usage", lambda _: type("Usage", (), {"free": 10**15})())
    monkeypatch.setattr(pd, "read_csv", lambda *a, **k: pytest.fail("loaded frame"))
    monkeypatch.setattr(SQLiteContextAggregator, "__init__", lambda *a, **k: pytest.fail("started aggregation"))
    original_open = Path.open

    def metadata_only(path, *args, **kwargs):
        assert path.name == "chunk_metadata.json"
        assert not args or args[0] == "r"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", metadata_only)
    assert report.main(["--cache-root", str(root), "--spool", str(tmp_path),
                        "--day", "20260408", "--cohort-row-count", "12"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["disk_estimate"] == asdict(estimate_aggregation_disk_space(records, cohort_row_count=12, available_bytes=10**15))
    assert result["max_rolling_source_syn_rows"] == {"300": 20, "900": 30, "3600": 90}
    assert result["successful_chunks"] == 96
    assert result["preflight_passes"] is True
    assert before == {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in root.rglob("*")}


@pytest.mark.parametrize("problem", ["missing", "duplicate", "failed", "mixed_cohort", "mixed_code", "outside_artifact"])
def test_report_rejects_incomplete_or_ambiguous_cache_sets(tmp_path, problem):
    root, records = _cache(tmp_path)
    report = _module()
    first = root / "cohort-hash" / records[0]["chunk_id"] / "chunk_metadata.json"
    if problem == "missing":
        first.unlink()
    elif problem == "duplicate":
        (root / "chunk_metadata.json").write_text(first.read_text())
    else:
        record = records[0]
        if problem == "failed":
            record["status"] = "failed"
        elif problem == "mixed_cohort":
            record["cohort_identity"] = "different"
        elif problem == "mixed_code":
            record["observation_code_identity"] = "different"
        else:
            record["artifacts"]["source_syn_observations"]["path"] = str(tmp_path / "outside.csv")
        first.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        report.load_metadata(root, "20260408")
