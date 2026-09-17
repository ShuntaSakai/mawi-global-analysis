import json
from pathlib import Path


NOTEBOOK_PATH = (
    Path(__file__).parents[2] / "notebooks" / "02_main_prefix_comparison_3_2.ipynb"
)


def _notebook_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def _packet_count_distribution_source() -> str:
    notebook = json.loads(NOTEBOOK_PATH.read_text())
    return next(
        "".join(cell["source"])
        for cell in notebook["cells"]
        if cell.get("id") == "161e432a"
    )


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


def test_packet_count_cdf_compares_overall_and_prefix_within_each_removal_state() -> None:
    """Keep packet-count CDFs split into the before/after removal comparison."""
    source = _packet_count_distribution_source()

    assert "packet_cdf_scopes = [('全トラフィック', ipv4_flows, 'tab:orange', '-')" in source
    assert "('プレフィックストラフィック', selected_scope_flows, 'tab:green', '-')" in source
    assert "plot_packet_distribution(raw_packet_cdf_series, '除外前')" in source
    assert "plot_packet_distribution(broad_packet_cdf_series, '除外後', reference_series=raw_packet_cdf_series)" in source
    assert "series.append({'protocol': protocol, 'scope': scope, 'style': style, 'label': f'{protocol}: {scope}', 'packets': packets})" in source
    assert "title=f'{title_prefix}：パケット数ヒストグラム'" in source
    assert "title=f'{title_prefix}：パケット数のCDF'" in source
    assert "def packet_cdf_series(condition):" in source
    assert "def plot_packet_distribution(series, title_prefix, reference_series=None):" in source
    assert "linestyle=':', alpha=0.35" in source
    assert "Raw: パケット数のCDF" not in source
    assert "Broad除外: パケット数のCDF" not in source


def test_packet_count_cdf_displays_slide_statistics_from_its_exact_series() -> None:
    """Expose median and P95 without changing the CDF population."""
    source = _packet_count_distribution_source()

    assert "def slide_packet_stats(condition):" in source
    assert "series = packet_cdf_series(condition)" in source
    assert "'フロー数': len(item['packets'])" in source
    assert "'中央値': item['packets'].median()" in source
    assert "'95パーセンタイル': item['packets'].quantile(0.95)" in source
    assert "slide_packet_statistics = pd.concat([" in source
    assert "display(slide_packet_statistics)" in source
    assert source.index("display(slide_packet_statistics)") < source.index(
        "plot_packet_distribution(raw_packet_cdf_series, '除外前')"
    )
