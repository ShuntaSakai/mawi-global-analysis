import json
from pathlib import Path


NOTEBOOK_PATH = Path(__file__).parents[2] / "notebooks" / "03_prefix_deep_dive.ipynb"


def _notebook_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_prefix_deep_dive_uses_manifest_driven_native_target_flow_construction() -> None:
    source = _notebook_source()

    assert "TARGET_PREFIX =" in source
    assert "load_run(DATASET_ID, RUN_NAME, root=root)" in source
    assert "build_comparison_flow_inclusion(run.flows, run.labels)" in source
    assert "run.membership['analysis_scope'].eq('native')" in source
    assert "run.membership['analysis_prefix'].eq(TARGET_PREFIX)" in source
    assert "validate='one_to_one'" in source
    assert "Broad removed + Broad remaining == Raw" in source
    assert "scan.broad.enabled" in source


def test_prefix_deep_dive_preserves_observation_facts_and_removed_flow_audit() -> None:
    source = _notebook_source()

    assert "broad_removed" in source
    assert "initial_syn_receiver_ip" in source
    assert "initial_syn_receiver_port" in source
    assert "initial_syn_sender_ip" in source
    assert "Removed-flow audit" in source
    assert "Service candidate" in source
    assert "port番号だけでは用途不明" in source
    assert "dst_port" not in source
    assert "利用可能なselected native Prefix" in source
    assert "TARGET_PREFIXES" not in source


def test_prefix_deep_dive_adds_broad_removed_sender_diversity_without_canonical_endpoint_proxies() -> None:
    source = _notebook_source()

    assert "Broad removedの送信元・port多様性" in source
    assert "initial_syn_sender_ip'].notna()" in source
    assert "sender_diversity_by_sender" in source
    assert "unique_receiver_ports" in source
    assert "unique_receiver_endpoints" in source
    assert "dominant_observed_tcp_pattern" in source
    assert "sort_values(['unique_receiver_ports', 'flow_count', 'initial_syn_sender_ip']" in source
    assert "dst_port" not in source


def test_prefix_deep_dive_reports_receiver_port_ties_without_selecting_sorted_first_port() -> None:
    source = _notebook_source()

    assert "removed_receiver_port_counts" in source
    assert "unique removed receiver ports" in source
    assert "max removed flows per receiver port" in source
    assert "number of receiver ports tied for max" in source
    assert "なし（同率）" in source
    assert "removed_ports.iloc[0]['receiver port']" not in source
