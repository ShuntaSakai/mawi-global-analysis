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

    assert "パケット数のECDF" in source
    assert "フロー継続時間のECDF" in source
    assert "Packet-count CCDF" not in source
    assert "Flow-duration CCDF" not in source


def test_main_prefix_notebook_compares_raw_and_broad_packet_distributions() -> None:
    """Keep the fixed-native-prefix Raw/Broad packet-count comparison available."""
    source = _notebook_source()

    assert "### Broad除外後のパケット数分布" in source
    assert "broad_included" in source
    assert "common_packet_bin_edges" in source
    assert "median_packet_count" in source
    assert "one_packet_flow_ratio" in source
    assert "q99_packet_count" in source


def test_main_prefix_notebook_uses_japanese_user_facing_plot_text() -> None:
    """Keep notebook headings, plot labels, and legends accessible to Japanese readers."""
    source = _notebook_source()

    assert "# メインプレフィックス比較" in source
    assert "パケット数ヒストグラム" in source
    assert "全体IPv4トラフィックに対する除外量" in source
    assert "選択済みnativeプレフィックス" in source


def test_main_prefix_notebook_resolves_the_repository_root_from_notebooks_directory() -> None:
    """Prevent a notebook-local working directory from redirecting artifact lookup."""
    source = _notebook_source()

    assert "def resolve_analysis_root()" in source
    assert "for candidate in (Path.cwd(), *Path.cwd().parents):" in source
    assert "(candidate / 'pyproject.toml').is_file()" in source
    assert "(candidate / 'src' / 'mawi_global_analysis').is_dir()" in source
    assert "os.environ.get('MAWI_ANALYSIS_ROOT', resolve_analysis_root())" in source
