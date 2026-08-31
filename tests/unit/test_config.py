from pathlib import Path

import pytest
from pydantic import ValidationError

from mawi_global_analysis.config import load_config


ROOT = Path(__file__).parents[2]


def test_baseline_config_preserves_corrected_defaults() -> None:
    config = load_config(ROOT / "configs" / "baseline.yaml")

    assert config.experiment.name == "baseline"
    assert config.experiment.description == "Corrected raw analysis"
    assert config.flow.inactive_timeout_seconds is None
    assert config.prefix.ip_version == 4
    assert config.prefix.candidate_sources == ["src_prefix", "dst_prefix"]
    assert config.prefix.membership_mode == "src_or_dst"
    assert config.prefix.top_k is None
    assert config.scan.window_size_seconds == 60
    assert config.scan.window_step_seconds == 10
    assert config.scan.strict.enabled is False
    assert config.scan.broad.enabled is False
    assert config.aguri.aguri3_executable is None
    assert config.aguri.agurim_executable is None
    assert config.analysis.overall_ip_scope == "ipv4"


@pytest.mark.parametrize(
    "replacement",
    [
        ("ip_version: 4", "ip_version: 6"),
        (
            "candidate_sources: [src_prefix, dst_prefix]",
            "candidate_sources: [dst_prefix]",
        ),
        ("membership_mode: src_or_dst", "membership_mode: dst_only"),
        ("top_k: null", "top_k: 10"),
        ("overall_ip_scope: ipv4", "overall_ip_scope: ipv4_ipv6"),
    ],
)
def test_baseline_identity_rejects_corrected_methodology_regressions(
    tmp_path: Path, replacement: tuple[str, str]
) -> None:
    """A baseline config must not silently adopt legacy prefix semantics."""
    config_path = tmp_path / "regressed_baseline.yaml"
    baseline_config = (ROOT / "configs" / "baseline.yaml").read_text(
        encoding="utf-8"
    )
    config_path.write_text(
        baseline_config.replace(*replacement), encoding="utf-8"
    )

    with pytest.raises(ValidationError, match="baseline requires"):
        load_config(config_path)


def test_legacy_scope_matches_the_verified_old_result_artifacts() -> None:
    """The legacy block explicitly preserves the old IPv4-and-IPv6 candidate scope."""
    config = load_config(ROOT / "configs" / "paper_legacy.yaml")

    assert config.legacy is not None
    assert config.legacy.candidate_ip_scope == "ipv4_ipv6"
    assert config.analysis.overall_ip_scope == "ipv4_ipv6"


def test_paper_legacy_config_encodes_the_verified_old_selection_contract() -> None:
    """The legacy-only block freezes the old result-generation parameters."""
    config = load_config(ROOT / "configs" / "paper_legacy.yaml")

    assert config.legacy is not None
    assert config.legacy.prefix_len == 24
    assert config.legacy.min_flows == 100
    assert config.legacy.min_packets == 1000
    assert config.legacy.min_bytes == 100000
    assert config.legacy.max_short_flow_ratio == 0.8
    assert config.legacy.max_tiny_flow_ratio == 0.8
    assert config.legacy.max_syn_only_like_ratio == 0.5
    assert config.legacy.max_rst_observed_ratio == 0.8
    assert config.legacy.short_duration_threshold == 1.0
    assert config.legacy.tiny_packet_threshold == 3
    assert config.legacy.top_k == 10
    assert config.legacy.plot_min_flow_count == 1000
    assert config.legacy.score_weights.model_dump() == {
        "flow_count": 0.20,
        "packet_count": 0.20,
        "byte_count": 0.20,
        "low_short_flow_ratio": 0.15,
        "low_tiny_flow_ratio": 0.15,
        "low_syn_only_like_ratio": 0.10,
    }


@pytest.mark.parametrize(
    ("filename", "expected_name"),
    [
        ("paper_legacy.yaml", "paper_legacy"),
        ("baseline.yaml", "baseline"),
        ("threshold_exploration.yaml", "threshold_exploration"),
    ],
)
def test_each_config_declares_its_experiment_identity(
    filename: str, expected_name: str
) -> None:
    """A manifest-facing experiment identity must come from its YAML."""
    config = load_config(ROOT / "configs" / filename)

    assert config.experiment.name == expected_name
    assert config.experiment.description.strip()


@pytest.mark.parametrize(
    "path",
    [
        ROOT / "tests" / "fixtures" / "configs" / "invalid_window.yaml",
        ROOT / "tests" / "fixtures" / "configs" / "unknown_key.yaml",
    ],
)
def test_invalid_config_raises_validation_error(path: Path) -> None:
    with pytest.raises(ValidationError):
        load_config(path)


@pytest.mark.parametrize(
    "replacement",
    [
        ("window_size_seconds: 60", 'window_size_seconds: "60"'),
        ("enabled: false", 'enabled: "false"'),
    ],
)
def test_quoted_scalar_config_values_are_rejected(
    tmp_path: Path, replacement: tuple[str, str]
) -> None:
    """Configuration scalar types must match their declared schema types."""
    config_path = tmp_path / "quoted_scalar.yaml"
    baseline_config = (ROOT / "configs" / "baseline.yaml").read_text(
        encoding="utf-8"
    )
    config_path.write_text(
        baseline_config.replace(*replacement), encoding="utf-8"
    )

    with pytest.raises(ValidationError):
        load_config(config_path)


def test_native_scalar_config_values_are_accepted(tmp_path: Path) -> None:
    config_path = tmp_path / "native_scalars.yaml"
    config_path.write_text(
        (ROOT / "configs" / "baseline.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.scan.window_size_seconds == 60
    assert config.scan.strict.enabled is False


@pytest.mark.parametrize(
    "config_text",
    [
        """
experiment: {name: strict_enabled, description: Strict threshold validation fixture}
flow: {inactive_timeout_seconds: null}
prefix: {ip_version: 4, candidate_sources: [src_prefix, dst_prefix], min_prefix_length: 24, containment_strategy: prefer_broader, membership_mode: src_or_dst, normalized_24_enabled: true, top_k: null}
scan:
  window_size_seconds: 60
  window_step_seconds: 10
  strict: {enabled: true}
  broad: {enabled: false}
aguri: {aguri3_executable: aguri3, agurim_executable: agurim, options: []}
analysis: {overall_ip_scope: ipv4}
        """,
        """
experiment: {name: broad_enabled, description: Broad threshold validation fixture}
flow: {inactive_timeout_seconds: null}
prefix: {ip_version: 4, candidate_sources: [src_prefix, dst_prefix], min_prefix_length: 24, containment_strategy: prefer_broader, membership_mode: src_or_dst, normalized_24_enabled: true, top_k: null}
scan:
  window_size_seconds: 60
  window_step_seconds: 10
  strict: {enabled: false}
  broad: {enabled: true}
aguri: {aguri3_executable: aguri3, agurim_executable: agurim, options: []}
analysis: {overall_ip_scope: ipv4}
""",
    ],
)
def test_enabled_scan_modes_require_explicit_thresholds(tmp_path: Path, config_text: str) -> None:
    config_path = tmp_path / "missing_thresholds.yaml"
    config_path.write_text(config_text, encoding="utf-8")

    with pytest.raises(ValidationError):
        load_config(config_path)


@pytest.mark.parametrize(
    ("ip_version", "min_prefix_length", "is_valid"),
    [
        (4, 32, True),
        (4, 33, False),
        (6, 64, True),
        (6, 129, False),
    ],
)
def test_prefix_length_bound_matches_selected_ip_version(
    tmp_path: Path, ip_version: int, min_prefix_length: int, is_valid: bool
) -> None:
    """Prefix limits must reflect the address family selected for analysis."""
    config_path = tmp_path / "prefix_length.yaml"
    config_path.write_text(
        f"""
experiment: {{name: prefix_length, description: Prefix length validation fixture}}
flow: {{inactive_timeout_seconds: null}}
prefix: {{ip_version: {ip_version}, candidate_sources: [src_prefix, dst_prefix], min_prefix_length: {min_prefix_length}, containment_strategy: prefer_broader, membership_mode: src_or_dst, normalized_24_enabled: true, top_k: null}}
scan:
  window_size_seconds: 60
  window_step_seconds: 10
  strict: {{enabled: false}}
  broad: {{enabled: false}}
aguri: {{aguri3_executable: aguri3, agurim_executable: agurim, options: []}}
analysis: {{overall_ip_scope: ipv4}}
""",
        encoding="utf-8",
    )

    if is_valid:
        assert load_config(config_path).prefix.min_prefix_length == min_prefix_length
    else:
        with pytest.raises(ValidationError):
            load_config(config_path)
