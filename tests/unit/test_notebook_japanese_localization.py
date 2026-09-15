import json
from pathlib import Path


NOTEBOOKS = Path(__file__).parents[2] / "notebooks"


def _source(name: str) -> str:
    notebook = json.loads((NOTEBOOKS / name).read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_legacy_notebook_uses_japanese_headings() -> None:
    source = _source("00_paper_legacy_reproduction.ipynb")

    assert "# 論文レガシー再現" in source
    assert "再現ビュー" in source


def test_threshold_notebook_uses_japanese_plot_text() -> None:
    source = _source("01_scan_threshold_exploration.ipynb")

    assert "# scan-like閾値の探索" in source
    assert "60秒ウィンドウあたりのSYN開始フロー数" in source
    assert "Broad scan-like source-window activity" not in source


def test_multi_dataset_notebook_uses_japanese_plot_text() -> None:
    source = _source("04_multi_dataset_validation.ipynb")

    assert "# 複数データセット検証の要約" in source
    assert "データセット別の除外量" in source
    assert "Removal volume across datasets" not in source
