import json
from pathlib import Path


NOTEBOOK_PATH = (
    Path(__file__).parents[2] / "notebooks" / "02_main_prefix_comparison_3_2.ipynb"
)


def _notebook_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_detailed_broad_removal_section_uses_canonical_join_facts() -> None:
    """Keep the detailed analysis tied to flow_id and SYN receiver facts."""
    source = _notebook_source()

    assert "## Broad除外によるpacket_count中央値変化が大きいprefixの詳細分析" in source
    for prefix in (
        "163.29.158.43/32",
        "173.218.110.3/32",
        "202.3.204.0/24",
        "131.142.238.168/32",
    ):
        assert prefix in source
    assert "validate='one_to_one'" in source
    assert "validate='many_to_one'" in source
    assert "run.membership['analysis_scope'] == 'native'" in source
    assert "missing_targets" in source
    assert "Broad removed + Broad remaining = Raw" in source
    assert "initial_syn_receiver_port" in source
    assert "initial_syn_receiver_ip" in source
    assert "broad_removed" in source
    assert "observed_tcp_pattern" in source
    assert "protocol_comparison" in source
    assert "removed_tcp =" in source


def test_detailed_broad_removal_section_keeps_service_wording_cautious() -> None:
    """Ports are service candidates, not application attribution evidence."""
    source = _notebook_source()

    assert "Service candidate" in source
    assert "port番号だけからapplicationを断定しない" in source
    assert "display_detail_table" in source
