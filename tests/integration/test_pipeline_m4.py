from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest
import dpkt

from mawi_global_analysis import pipeline
from mawi_global_analysis.hashing import sha256_file


ROOT = Path(__file__).parents[2]
PCAP_PATH = ROOT / "tests" / "fixtures" / "pcaps" / "tcp_patterns.pcap"
CONFIG_PATH = ROOT / "configs" / "baseline.yaml"
M5_CONFIG_PATH = ROOT / "configs" / "scan_source_driven_removal.yaml"
THRESHOLD_EXPLORATION_CONFIG_PATH = ROOT / "configs" / "threshold_exploration.yaml"
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


def _stub_m5_flows(monkeypatch, tmp_path: Path) -> None:
    def write_flows(ctx, cfg, force=False):
        target = (
            tmp_path
            / "data"
            / ctx.dataset_id
            / "processed"
            / "flows"
            / "synthetic"
            / "flows.csv"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        strict_rows = [
            {
                "flow_id": flow_id,
                "protocol": "tcp",
                "first_syn_time": 1.0,
                "initial_syn_sender_ip": "198.51.100.1",
                "initial_syn_receiver_ip": "203.0.113.1",
                "initial_syn_receiver_port": 10000 + flow_id,
                "observed_tcp_pattern": "syn_to_rst",
            }
            for flow_id in range(1, 21)
        ]
        pd.DataFrame(
            [
                *strict_rows,
                {
                    "flow_id": 21,
                    "protocol": "tcp",
                    "first_syn_time": 120.0,
                    "initial_syn_sender_ip": "198.51.100.1",
                    "initial_syn_receiver_ip": "203.0.113.2",
                    "initial_syn_receiver_port": 443,
                    "observed_tcp_pattern": "syn_synack_rst",
                },
                {
                    "flow_id": 22,
                    "protocol": "tcp",
                    "first_syn_time": 120.0,
                    "initial_syn_sender_ip": "198.51.100.1",
                    "initial_syn_receiver_ip": "203.0.113.3",
                    "initial_syn_receiver_port": 80,
                    "observed_tcp_pattern": "syn_only_observed",
                },
                {
                    "flow_id": 23,
                    "protocol": "udp",
                    "first_syn_time": None,
                    "initial_syn_sender_ip": "198.51.100.1",
                    "initial_syn_receiver_ip": None,
                    "initial_syn_receiver_port": None,
                    "observed_tcp_pattern": "none",
                },
                {
                    "flow_id": 24,
                    "protocol": "tcp",
                    "first_syn_time": 120.0,
                    "initial_syn_sender_ip": "198.51.100.2",
                    "initial_syn_receiver_ip": "203.0.113.4",
                    "initial_syn_receiver_port": 22,
                    "observed_tcp_pattern": "syn_only_observed",
                },
            ]
        ).to_csv(target, index=False)
        return target

    monkeypatch.setattr("mawi_global_analysis.pipeline.run_flow_stage", write_flows)


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


def test_pipeline_integrates_m5_source_driven_labels_capture_wide(
    tmp_path: Path, monkeypatch
) -> None:
    """M5 consumes threshold-free windows and labels only permitted source flows."""
    monkeypatch.chdir(tmp_path)
    _stub_m5_flows(monkeypatch, tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "m5-fixture",
            "--config",
            str(M5_CONFIG_PATH),
            "--to",
            "scan-labels",
        ]
    )

    assert pipeline.run_pipeline(args) == 0

    labels = pd.read_csv(
        tmp_path
        / "results"
        / "m5-fixture"
        / "scan_source_driven_removal"
        / "flow_labels.csv"
    )
    manifest = json.loads(
        (
            tmp_path
            / "results"
            / "m5-fixture"
            / "scan_source_driven_removal"
            / "run_manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert labels.loc[labels["flow_id"] <= 21, "strict_removed"].all()
    assert labels.loc[labels["flow_id"] == 22, "broad_removed"].item() is True
    assert not labels.loc[labels["flow_id"] == 22, "strict_removed"].item()
    assert not labels.loc[labels["flow_id"].isin([23, 24]), "broad_removed"].any()
    assert not (labels["strict_removed"] & ~labels["broad_removed"]).any()
    assert manifest["config"]["text"] == M5_CONFIG_PATH.read_text(encoding="utf-8")
    assert manifest["config"]["hash"] == sha256_file(M5_CONFIG_PATH)
    assert manifest["cache"]["scan-labels"]["schema_version"] == (
        pipeline.SCAN_LABEL_SCHEMA_VERSION
    )
    assert manifest["cache"]["scan-labels"]["fingerprint"]


def test_threshold_change_reuses_scan_stats_but_reclassifies_labels(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_m5_flows(monkeypatch, tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    stricter_config = tmp_path / "stricter.yaml"
    stricter_config.write_text(
        M5_CONFIG_PATH.read_text(encoding="utf-8")
        .replace("name: scan_source_driven_removal", "name: scan_source_driven_removal_30_15")
        .replace("min_pattern_count: 20", "min_pattern_count: 30")
        .replace("min_unique_targets: 10", "min_unique_targets: 15"),
        encoding="utf-8",
    )
    initial = pipeline.build_parser().parse_args(
        ["--input", str(PCAP_PATH), "--dataset-id", "rerun-fixture", "--config", str(M5_CONFIG_PATH), "--to", "scan-labels"]
    )
    rerun = pipeline.build_parser().parse_args(
        ["--input", str(PCAP_PATH), "--dataset-id", "rerun-fixture", "--config", str(stricter_config), "--to", "scan-labels"]
    )

    assert pipeline.run_pipeline(initial) == 0
    assert pipeline.run_pipeline(rerun) == 0

    manifest = json.loads(
        (tmp_path / "results" / "rerun-fixture" / "scan_source_driven_removal_30_15" / "run_manifest.json").read_text()
    )
    labels = pd.read_csv(
        tmp_path / "results" / "rerun-fixture" / "scan_source_driven_removal_30_15" / "flow_labels.csv"
    )
    assert [stage["status"] for stage in manifest["stages"] if stage["name"] == "scan-stats"][-1] == "reused"
    assert labels.drop(columns="flow_id").eq(False).all().all()


@pytest.mark.parametrize(
    ("config_path", "run_name"),
    [
        (CONFIG_PATH, "baseline"),
        (THRESHOLD_EXPLORATION_CONFIG_PATH, "threshold_exploration"),
    ],
)
def test_scan_disabled_configs_continue_to_write_neutral_labels(
    tmp_path: Path, monkeypatch, config_path: Path, run_name: str
) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "neutral-fixture",
            "--config",
            str(config_path),
            "--to",
            "scan-labels",
        ]
    )

    assert pipeline.run_pipeline(args) == 0

    labels = pd.read_csv(
        tmp_path / "results" / "neutral-fixture" / run_name / "flow_labels.csv"
    )
    assert labels.drop(columns="flow_id").eq(False).all().all()


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
