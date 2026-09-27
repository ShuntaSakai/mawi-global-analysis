import json
from pathlib import Path


NOTEBOOK_PATH = Path(__file__).parents[2] / "notebooks" / "02_main_prefix_comparison.ipynb"


def _notebook_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_main_prefix_notebook_presents_only_raw_and_broad_comparisons() -> None:
    """Keep user-facing comparison conditions limited to Raw and Broad."""
    source = _notebook_source()

    assert "conditions = pd.DataFrame({'condition': ['Raw', 'Broad']" in source
    assert "condition_order = ['Raw', 'Broad']" in source
    assert "condition_display_names = {'Raw': 'Raw（除外前）', 'Broad': 'Broad（除外後）'}" in source
    assert "Raw / Strict / Broad" not in source
    assert "Strict removal" not in source


def test_main_prefix_notebook_preserves_fixed_native_prefix_raw_broad_analysis() -> None:
    """Keep the Raw-derived native prefix population fixed across conditions."""
    source = _notebook_source()

    assert "build_comparison_flow_inclusion(run.flows, run.labels)" in source
    assert "pd.to_numeric(flow_metrics['ip_version']) == 4" in source
    assert "run.prefixes['selected_for_analysis'] == True" in source
    assert "run.membership['analysis_scope'] == 'native'" in source
    assert "'raw_included', 'strict_included', 'broad_included'" in source
    assert "比較条件が固定Raw由来プレフィックス集合を変更しています" in source


def test_main_prefix_notebook_keeps_detailed_broad_removal_in_the_deep_dive() -> None:
    """Keep the main notebook focused on all-prefix comparison."""
    source = _notebook_source()

    assert "### Broad除外によるプレフィックス別中央値の変化" in source
    assert "## Broad除外によるpacket_count中央値変化が大きいprefixの詳細分析" not in source


def test_main_prefix_notebook_compares_raw_and_broad_distributions() -> None:
    """Keep packet, frame-byte, and duration comparisons available."""
    source = _notebook_source()

    assert "def packet_cdf_series(condition):" in source
    assert "plot_packet_distribution(raw_packet_cdf_series, '除外前')" in source
    assert "plot_packet_distribution(broad_packet_cdf_series, '除外後', reference_series=raw_packet_cdf_series)" in source
    assert "def frame_byte_distribution_series(condition):" in source
    assert "def plot_duration_distribution(series_keys, title_prefix):" in source
    assert "plot_duration_distribution(['overall_raw', 'overall_broad', 'native_raw', 'native_broad'], 'Raw vs Broad')" in source


def test_main_prefix_notebook_reports_packet_and_duration_statistics() -> None:
    """Keep the current descriptive statistics tied to the plotted populations."""
    source = _notebook_source()

    assert "def slide_packet_stats(condition):" in source
    assert "series = packet_cdf_series(condition)" in source
    assert "'中央値': item['packets'].median()" in source
    assert "'95パーセンタイル': item['packets'].quantile(0.95)" in source
    assert "'q90_duration': values.quantile(0.90)" in source
    assert "'q99_duration': values.quantile(0.99)" in source


def test_main_prefix_notebook_uses_explicit_dataset_and_run_selection() -> None:
    """Avoid silently analysing fixture artifacts in the thesis notebook."""
    source = _notebook_source()

    assert "os.environ.get('MAWI_DATASET_ID')" in source
    assert "os.environ.get('MAWI_RUN_NAME')" in source
    assert "MAWI_DATASET_ID と MAWI_RUN_NAME を明示指定してください" in source
    assert "os.environ.get('MAWI_DATASET_ID', 'fixture')" not in source
    assert "os.environ.get('MAWI_RUN_NAME', 'baseline')" not in source


def test_main_prefix_notebook_uses_japanese_user_facing_plot_text() -> None:
    """Keep notebook headings and plot labels accessible to Japanese readers."""
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
