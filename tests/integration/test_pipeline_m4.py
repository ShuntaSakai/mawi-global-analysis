from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest
import dpkt

from mawi_global_analysis import pipeline


ROOT = Path(__file__).parents[2]
PCAP_PATH = ROOT / "tests" / "fixtures" / "pcaps" / "tcp_patterns.pcap"
CONFIG_PATH = ROOT / "configs" / "baseline.yaml"
CANDIDATES_PATH = ROOT / "tests" / "fixtures" / "aguri" / "sample_candidates.csv"


def _args(*arguments: str):
    return pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "fixture",
            "--config",
            str(CONFIG_PATH),
            *arguments,
        ]
    )


def _stub_aguri(monkeypatch, tmp_path: Path) -> None:
    def copy_candidates(ctx, cfg, force=False):
        target = tmp_path / "data" / ctx.dataset_id / "processed" / "aguri" / "stub"
        target.mkdir(parents=True, exist_ok=True)
        candidates = target / "aguri_candidates.csv"
        candidates.write_bytes(CANDIDATES_PATH.read_bytes())
        return candidates

    monkeypatch.setattr("mawi_global_analysis.pipeline.run_aguri_stage", copy_candidates)


def test_pipeline_writes_threshold_free_stats_and_neutral_labels(
    tmp_path: Path, monkeypatch
) -> None:
    """M4 artifacts are manifest-backed and independent of Aguri/prefix stages."""
    monkeypatch.chdir(tmp_path)

    _stub_aguri(monkeypatch, tmp_path)

    assert pipeline.run_pipeline(_args("--to", "scan-labels")) == 0

    run_dir = tmp_path / "results" / "fixture" / "baseline"
    windows = pd.read_csv(run_dir / "source_scan_windows.csv")
    summary = pd.read_csv(run_dir / "source_scan_summary.csv")
    labels = pd.read_csv(run_dir / "flow_labels.csv")
    manifest = json.loads((run_dir / "run_manifest.json").read_text())

    assert not windows.empty
    assert not summary.empty
    assert labels.drop(columns="flow_id").eq(False).all().all()
    assert set(manifest["artifacts"]) >= {
        "flows",
        "source_scan_windows",
        "source_scan_summary",
        "flow_labels",
    }
    assert [stage["status"] for stage in manifest["stages"] if stage["name"] == "scan-stats"][-1] == "completed"
    assert [stage["status"] for stage in manifest["stages"] if stage["name"] == "scan-labels"][-1] == "completed"


def test_scan_labels_partial_run_requires_prior_scan_statistics(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)

    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="scan-labels requires"):
        pipeline.run_pipeline(_args("--from", "scan-labels", "--to", "scan-labels"))


def test_pipeline_stops_at_m5_gate_when_thresholded_modes_are_enabled(
    tmp_path: Path, monkeypatch
) -> None:
    """Configured numeric thresholds must not activate M5 behavior during M4."""
    monkeypatch.chdir(tmp_path)
    configured = tmp_path / "thresholded.yaml"
    configured.write_text(
        CONFIG_PATH.read_text(encoding="utf-8").replace(
            "strict:\n    enabled: false",
            "strict:\n    enabled: true\n    min_pattern_count: 2\n    min_unique_targets: 2",
        ),
        encoding="utf-8",
    )

    _stub_aguri(monkeypatch, tmp_path)
    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "thresholded-fixture",
            "--config",
            str(configured),
            "--to",
            "scan-labels",
        ]
    )

    with pytest.raises(RuntimeError, match="M5 threshold approval"):
        pipeline.run_pipeline(args)

    assert not (tmp_path / "results" / "thresholded-fixture").exists()


def test_scan_windows_anchor_to_the_first_raw_packet_not_first_retained_flow(
    tmp_path: Path, monkeypatch
) -> None:
    """An earlier non-IP frame must establish the capture-start window grid."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    capture = tmp_path / "raw-anchor.pcap"
    with capture.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(
            bytes(
                dpkt.ethernet.Ethernet(
                    src=b"\x00\x01\x02\x03\x04\x05",
                    dst=b"\x06\x07\x08\x09\x0a\x0b",
                    type=dpkt.ethernet.ETH_TYPE_ARP,
                    data=b"ignored",
                )
            ),
            ts=0.0,
        )
        with PCAP_PATH.open("rb") as source:
            for timestamp, frame in dpkt.pcap.Reader(source):
                writer.writepkt(frame, ts=timestamp)
        writer.close()

    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(capture),
            "--dataset-id",
            "raw-anchor",
            "--config",
            str(CONFIG_PATH),
            "--to",
            "scan-labels",
        ]
    )
    assert pipeline.run_pipeline(args) == 0

    windows = pd.read_csv(
        tmp_path / "results" / "raw-anchor" / "baseline" / "source_scan_windows.csv"
    )
    assert 0.0 in set(windows["window_start"])
    assert 1.0 not in set(windows["window_start"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda labels: labels.assign(flow_id=labels["flow_id"].replace(labels.iloc[0]["flow_id"], 999)),
        lambda labels: labels.assign(strict_removed=[True, *([False] * (len(labels) - 1))]),
    ],
)
def test_neutral_label_reuse_rejects_same_shape_corruption(
    tmp_path: Path, monkeypatch, mutate
) -> None:
    """A header and row count cannot prove neutral labels match canonical flows."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args("--to", "scan-labels")) == 0
    labels_path = tmp_path / "results" / "fixture" / "baseline" / "flow_labels.csv"
    mutate(pd.read_csv(labels_path)).to_csv(labels_path, index=False)

    assert pipeline.run_pipeline(
        _args("--from", "scan-labels", "--to", "scan-labels")
    ) == 0

    restored = pd.read_csv(labels_path)
    flows_path = next((tmp_path / "data" / "fixture" / "processed" / "flows").glob("*/flows.csv"))
    assert restored["flow_id"].tolist() == pd.read_csv(flows_path)["flow_id"].tolist()
    assert restored.drop(columns="flow_id").eq(False).all().all()


def test_enabled_mode_rejects_even_a_reusable_neutral_label_artifact(
    tmp_path: Path, monkeypatch
) -> None:
    """The M5 gate precedes scan-label reuse validation and execution."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    configured = tmp_path / "thresholded.yaml"
    configured.write_text(
        CONFIG_PATH.read_text(encoding="utf-8").replace(
            "strict:\n    enabled: false",
            "strict:\n    enabled: true\n    min_pattern_count: 2\n    min_unique_targets: 2",
        ),
        encoding="utf-8",
    )
    assert pipeline.run_pipeline(_args("--to", "scan-labels")) == 0

    with pytest.raises(RuntimeError, match="M5 threshold approval"):
        pipeline.run_pipeline(
            pipeline.build_parser().parse_args(
                [
                    "--input",
                    str(PCAP_PATH),
                    "--dataset-id",
                    "fixture",
                    "--config",
                    str(configured),
                    "--from",
                    "scan-labels",
                    "--to",
                    "scan-labels",
                ]
        )
    )


@pytest.mark.parametrize("provenance", ["missing", "mismatched"])
def test_scan_stats_rejects_old_or_mismatched_semantic_provenance(
    tmp_path: Path, monkeypatch, provenance: str
) -> None:
    """Pre-anchor-fix source statistics cannot be reused by shape alone."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args("--to", "scan-labels")) == 0
    run_dir = tmp_path / "results" / "fixture" / "baseline"
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if provenance == "missing":
        manifest["cache"].pop("scan-stats", None)
    else:
        manifest["cache"]["scan-stats"]["fingerprint"] = "old-anchor-fingerprint"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert pipeline.run_pipeline(_args("--to", "scan-labels")) == 0

    refreshed = json.loads(manifest_path.read_text())
    assert refreshed["cache"]["scan-stats"]["capture_anchor"] == "raw_first_packet_timestamp"
    assert refreshed["cache"]["scan-stats"]["fingerprint"] != "old-anchor-fingerprint"
    assert [
        stage["status"]
        for stage in refreshed["stages"]
        if stage["name"] == "scan-stats"
    ][-1] == "completed"
    assert [
        stage["status"]
        for stage in refreshed["stages"]
        if stage["name"] == "scan-labels"
    ][-1] == "completed"


def test_split_label_run_rejects_labels_without_current_scan_stat_provenance(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A scan-stat rebuild invalidates legacy neutral labels in later runs."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args("--to", "scan-labels")) == 0
    run_dir = tmp_path / "results" / "fixture" / "baseline"
    manifest_path = run_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["cache"].pop("scan-labels", None)
    manifest["cache"]["scan-stats"]["fingerprint"] = "old-anchor-fingerprint"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert pipeline.run_pipeline(_args("--to", "scan-stats")) == 0
    capsys.readouterr()
    assert pipeline.run_pipeline(
        _args("--from", "scan-labels", "--to", "scan-labels", "--dry-run")
    ) == 0
    assert "[EXECUTE] scan-labels" in capsys.readouterr().out

    assert pipeline.run_pipeline(
        _args("--from", "scan-labels", "--to", "scan-labels")
    ) == 0
    refreshed = json.loads(manifest_path.read_text())
    assert refreshed["cache"]["scan-labels"]["scan_stats_fingerprint"] == refreshed[
        "cache"
    ]["scan-stats"]["fingerprint"]
    assert [
        stage["status"]
        for stage in refreshed["stages"]
        if stage["name"] == "scan-labels"
    ][-1] == "completed"


def test_dry_run_validates_partial_dependencies_without_writing(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="scan-labels requires"):
        pipeline.run_pipeline(
            _args("--from", "scan-labels", "--to", "scan-labels", "--dry-run")
        )

    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "results").exists()


def test_dry_run_enforces_m5_gate_without_writing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    configured = tmp_path / "thresholded.yaml"
    configured.write_text(
        CONFIG_PATH.read_text(encoding="utf-8").replace(
            "strict:\n    enabled: false",
            "strict:\n    enabled: true\n    min_pattern_count: 2\n    min_unique_targets: 2",
        ),
        encoding="utf-8",
    )
    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "dry-thresholded",
            "--config",
            str(configured),
            "--to",
            "scan-labels",
            "--dry-run",
        ]
    )

    with pytest.raises(RuntimeError, match="M5 threshold approval"):
        pipeline.run_pipeline(args)

    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize("dry_run", [False, True])
def test_m5_gate_applies_to_ranges_that_omit_scan_labels(
    tmp_path: Path, monkeypatch, dry_run: bool
) -> None:
    """No M0--M4 range may proceed once a thresholded mode is configured."""
    monkeypatch.chdir(tmp_path)
    configured = tmp_path / "thresholded.yaml"
    configured.write_text(
        CONFIG_PATH.read_text(encoding="utf-8").replace(
            "strict:\n    enabled: false",
            "strict:\n    enabled: true\n    min_pattern_count: 2\n    min_unique_targets: 2",
        ),
        encoding="utf-8",
    )
    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "range-thresholded",
            "--config",
            str(configured),
            "--from",
            "prefixes",
            "--to",
            "membership",
            *(["--dry-run"] if dry_run else []),
        ]
    )

    with pytest.raises(RuntimeError, match="M5 threshold approval"):
        pipeline.run_pipeline(args)

    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "results").exists()
