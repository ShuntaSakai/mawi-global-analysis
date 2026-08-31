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
TRUNCATED_IPV6_FRAGMENT_PATH = (
    ROOT / "tests" / "fixtures" / "pcaps" / "capture_truncated_ipv6_fragment.pcap"
)


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
    assert manifest["schema_version"] == "flows-v3"

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


def test_flow_stage_records_capture_truncated_packet_skip_provenance(
    tmp_path: Path, monkeypatch
) -> None:
    """Flow-cache provenance distinguishes skipped snaplen truncation from flow rows."""
    from mawi_global_analysis.flow_stage import run_flow_stage

    monkeypatch.chdir(tmp_path)
    context = InputContext(
        dataset_id="truncated-fixture",
        path=TRUNCATED_IPV6_FRAGMENT_PATH,
        sha256=sha256_file(TRUNCATED_IPV6_FRAGMENT_PATH),
        size_bytes=TRUNCATED_IPV6_FRAGMENT_PATH.stat().st_size,
    )

    flows_path = run_flow_stage(context, load_config(ROOT / "configs" / "baseline.yaml"))
    manifest = json.loads((flows_path.parent / "flow_manifest.json").read_text())

    assert manifest["row_count"] == 1
    assert manifest["skipped_packet_counts"] == {
        "capture_truncated_undecodable": 1,
    }


def test_flow_stage_rejects_cached_manifest_without_skip_provenance(
    tmp_path: Path, monkeypatch
) -> None:
    """A v3 flow cache must retain packet-skip provenance when reused."""
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
    manifest_path = flows_path.parent / "flow_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("skipped_packet_counts")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(FlowCacheValidationError, match="skip provenance"):
        run_flow_stage(context, config)
