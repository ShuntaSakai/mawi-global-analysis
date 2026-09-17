import json
from pathlib import Path


NOTEBOOK_PATH = (
    Path(__file__).parents[2] / "notebooks" / "02_main_prefix_comparison_3_2.ipynb"
)


def _notebook_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_main_notebook_delegates_detailed_broad_removal_to_prefix_deep_dive() -> None:
    """Keep the main notebook focused on all-prefix discovery and comparison."""
    source = _notebook_source()

    assert "# メインプレフィックス比較" in source
    assert "### Broad除外によるプレフィックス別中央値の変化" in source
    assert "## Broad除外によるpacket_count中央値変化が大きいprefixの詳細分析" not in source
    for prefix in (
        "163.29.158.43/32",
        "173.218.110.3/32",
        "202.3.204.0/24",
        "131.142.238.168/32",
    ):
        assert prefix not in source
