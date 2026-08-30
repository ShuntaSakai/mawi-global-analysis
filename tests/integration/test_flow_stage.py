from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from mawi_global_analysis.config import load_config
from mawi_global_analysis.hashing import flow_fingerprint, sha256_file
from mawi_global_analysis.models import InputContext


ROOT = Path(__file__).parents[2]
PCAP_PATH = ROOT / "tests" / "fixtures" / "pcaps" / "tcp_patterns.pcap"


def test_flow_stage_reuses_semantic_cache_and_records_canonical_provenance(
    tmp_path: Path, monkeypatch
) -> None:
    """A repeated run reuses one cache whose manifest describes its stable facts."""
    from mawi_global_analysis.flow_stage import run_flow_stage

    monkeypatch.chdir(tmp_path)
    context = InputContext(
        dataset_id="fixture",
        path=PCAP_PATH,
        sha256=sha256_file(PCAP_PATH),
        size_bytes=PCAP_PATH.stat().st_size,
    )
    config = load_config(ROOT / "configs" / "baseline.yaml")

    first_path = run_flow_stage(context, config)
    second_path = run_flow_stage(context, config)

    assert first_path == second_path
    assert first_path == (
        tmp_path
        / "data"
        / "fixture"
        / "processed"
        / "flows"
        / f"tcp-udp-no-timeout-{flow_fingerprint(context.sha256, config)[:10]}"
        / "flows.csv"
    )

    manifest = json.loads((first_path.parent / "flow_manifest.json").read_text())
    assert manifest["input_sha256"] == context.sha256
    assert manifest["fingerprint"] == flow_fingerprint(context.sha256, config)
    assert manifest["row_count"] == 7
    assert manifest["flow_config"] == {
        "inactive_timeout_seconds": None,
        "protocols": ["tcp", "udp"],
    }
    assert manifest["schema_version"] == "flows-v2"

    with first_path.open(newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert {row["observed_tcp_pattern"] for row in rows} >= {
        "none",
        "syn_to_rst",
        "syn_synack_rst",
        "syn_only_observed",
    }
    assert next(row for row in rows if row["protocol"] == "17")[
        "observed_tcp_pattern"
    ] == "none"
    assert all(row["byte_count"] == row["frame_byte_count"] for row in rows)


def test_flow_stage_rejects_a_corrupted_cached_csv(
    tmp_path: Path, monkeypatch
) -> None:
    """A manifest cannot make a replaced flow artifact safe to reuse."""
    from mawi_global_analysis.flow_stage import (
        FlowCacheValidationError,
        run_flow_stage,
    )

    monkeypatch.chdir(tmp_path)
    context = InputContext(
        dataset_id="fixture",
        path=PCAP_PATH,
        sha256=sha256_file(PCAP_PATH),
        size_bytes=PCAP_PATH.stat().st_size,
    )
    config = load_config(ROOT / "configs" / "baseline.yaml")
    flows_path = run_flow_stage(context, config)
    flows_path.write_text("corrupt\n", encoding="utf-8")

    with pytest.raises(FlowCacheValidationError, match="CSV"):
        run_flow_stage(context, config)
