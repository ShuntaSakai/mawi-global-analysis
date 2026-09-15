import json
from pathlib import Path


NOTEBOOK_PATH = Path(__file__).parents[2] / "notebooks" / "02_main_prefix_comparison.ipynb"


def _notebook_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_main_prefix_notebook_presents_only_raw_and_broad_comparisons() -> None:
    """Prevent Strict from returning to user-facing comparison tables or plots."""
    source = _notebook_source()

    assert "conditions = pd.DataFrame({'condition': ['Raw', 'Broad']" in source
    assert "condition_order = ['Raw', 'Broad']" in source
    assert "for condition in ['Broad']:" in source
    assert "reindex(['Broad'])" in source
    assert "Raw / Strict / Broad" not in source
    assert "Strict removal" not in source
    assert "strict_table_prefix_count" not in source
    assert "strict_zero_surviving_prefix_count" not in source
    assert "strict_overall_flow_count" not in source


def test_main_prefix_notebook_keeps_only_ecdf_descriptive_distribution_plots() -> None:
    """Prevent CCDF plots from returning to the Raw baseline descriptive views."""
    source = _notebook_source()

    assert "Packet-count ECDF" in source
    assert "Flow-duration ECDF" in source
    assert "Packet-count CCDF" not in source
    assert "Flow-duration CCDF" not in source
