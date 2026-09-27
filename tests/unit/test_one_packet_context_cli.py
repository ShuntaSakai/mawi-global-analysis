"""Tests for the thin one-packet context orchestration CLI."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import socket
from pathlib import Path

import dpkt
import pandas as pd

from mawi_global_analysis.flow_stage import FLOW_COLUMNS
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS
from mawi_global_analysis.prefix import CORRECTED_LEDGER_COLUMNS
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS


def test_cli_delegates_all_context_work(monkeypatch, tmp_path: Path) -> None:
    script = Path(__file__).resolve().parents[2] / "run_one_packet_context.py"
    spec = importlib.util.spec_from_file_location("run_one_packet_context", script)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    received = {}
    def fake_run(dataset_id, source_run_name, full_capture_path, context_run_name, *, root):
        received.update(dataset_id=dataset_id, source_run_name=source_run_name, full_capture_path=full_capture_path, context_run_name=context_run_name, root=root)
        return tmp_path / "result"

    monkeypatch.setattr(cli, "run_one_packet_context_analysis", fake_run)
    assert cli.main(["--dataset", "fixture", "--source-run", "source", "--full-capture", "full.pcap.gz", "--context-run-name", "context", "--root", str(tmp_path)]) == 0
    assert received == {"dataset_id": "fixture", "source_run_name": "source", "full_capture_path": Path("full.pcap.gz"), "context_run_name": "context", "root": tmp_path}


def test_cli_creates_manifest_loadable_context_run_from_synthetic_source_run(tmp_path: Path) -> None:
    from mawi_global_analysis.io import load_one_packet_context

    script = Path(__file__).resolve().parents[2] / "run_one_packet_context.py"
    spec = importlib.util.spec_from_file_location("run_one_packet_context_integration", script)
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    source_ip, destination_ip = "198.51.100.1", "192.0.2.1"
    tcp = dpkt.tcp.TCP(sport=40000, dport=443, flags=dpkt.tcp.TH_SYN)
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton(source_ip), dst=socket.inet_aton(destination_ip), p=6, data=tcp)
    ip.len = len(ip)
    frame = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
    full = tmp_path / "full.pcap"
    with full.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        writer.writepkt(frame, ts=10.0)
        writer.close()
    extracted = tmp_path / "window.pcap"
    extracted.write_bytes(full.read_bytes())
    run_dir = tmp_path / "results" / "fixture" / "source"
    run_dir.mkdir(parents=True)
    flow = {column: None for column in FLOW_COLUMNS}
    flow.update(flow_id=1, ip_version=4, protocol=6, start_time=10.0, end_time=10.0, duration=0.0, src_ip=source_ip, src_port=40000, dst_ip=destination_ip, dst_port=443, packet_count=1)
    labels = {column: False for column in FLOW_LABEL_COLUMNS}
    labels["flow_id"] = 1
    artifacts = {
        "flows": (pd.DataFrame([flow], columns=FLOW_COLUMNS), "flows.csv"),
        "flow_labels": (pd.DataFrame([labels], columns=FLOW_LABEL_COLUMNS), "flow_labels.csv"),
        "prefixes": (pd.DataFrame(columns=CORRECTED_LEDGER_COLUMNS), "prefixes.csv"),
        "flow_prefix_membership": (pd.DataFrame(columns=MEMBERSHIP_COLUMNS), "flow_prefix_membership.csv"),
    }
    manifest_artifacts = {}
    for name, (table, filename) in artifacts.items():
        path = run_dir / filename
        table.to_csv(path, index=False)
        manifest_artifacts[name] = {"path": str(path), "row_count": len(table)}
    extracted_hash = hashlib.sha256(extracted.read_bytes()).hexdigest()
    (extracted.parent / "window_manifest.json").write_text(json.dumps({"window_start": "start", "window_end": "end", "output_path": str(extracted), "output_sha256": extracted_hash, "source_sha256": hashlib.sha256(full.read_bytes()).hexdigest()}))
    (run_dir / "run_manifest.json").write_text(json.dumps({"status": "success", "dataset_id": "fixture", "input": {"path": str(extracted), "sha256": extracted_hash}, "config": {"path": "config.yaml", "hash": "config-hash", "text": "scan:\n  strict:\n    min_pattern_count: 3\n    min_unique_targets: 2"}, "artifacts": manifest_artifacts}))

    assert cli.main(["--dataset", "fixture", "--source-run", "source", "--full-capture", str(full), "--context-run-name", "context", "--root", str(tmp_path)]) == 0
    loaded = load_one_packet_context("fixture", "context", root=tmp_path)
    assert len(loaded.cohort) == len(loaded.context) == len(loaded.source_context) == 1
