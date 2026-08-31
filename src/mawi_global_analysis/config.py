"""Strict experiment configuration loading."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ExperimentMetadataConfig(StrictModel):
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)


class FlowConfig(StrictModel):
    protocols: list[Literal["tcp", "udp"]] = Field(
        default_factory=lambda: ["tcp", "udp"], min_length=1
    )
    inactive_timeout_seconds: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def require_unique_protocols(self) -> "FlowConfig":
        if len(set(self.protocols)) != len(self.protocols):
            raise ValueError("flow protocols must not contain duplicates")
        return self


class PrefixConfig(StrictModel):
    ip_version: Literal[4, 6]
    candidate_sources: list[Literal["src_prefix", "dst_prefix"]]
    min_prefix_length: int = Field(ge=0, le=128)
    containment_strategy: Literal["prefer_broader"]
    membership_mode: Literal["src_or_dst", "dst_only"]
    normalized_24_enabled: bool
    top_k: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_prefix_length_for_ip_version(self) -> "PrefixConfig":
        max_prefix_length = 32 if self.ip_version == 4 else 128
        if self.min_prefix_length > max_prefix_length:
            raise ValueError(
                f"IPv{self.ip_version} min_prefix_length must not exceed "
                f"{max_prefix_length}"
            )
        return self


class StrictScanConfig(StrictModel):
    enabled: bool
    min_pattern_count: int | None = Field(default=None, gt=0)
    min_unique_targets: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def require_thresholds_when_enabled(self) -> "StrictScanConfig":
        if self.enabled and (
            self.min_pattern_count is None or self.min_unique_targets is None
        ):
            raise ValueError("enabled strict scan mode requires explicit thresholds")
        return self


class BroadScanConfig(StrictModel):
    enabled: bool
    min_syn_initiated_flows: int | None = Field(default=None, gt=0)
    min_unique_targets: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def require_thresholds_when_enabled(self) -> "BroadScanConfig":
        if self.enabled and (
            self.min_syn_initiated_flows is None or self.min_unique_targets is None
        ):
            raise ValueError("enabled broad scan mode requires explicit thresholds")
        return self


class ScanConfig(StrictModel):
    window_size_seconds: int = Field(gt=0)
    window_step_seconds: int = Field(gt=0)
    window_anchor: Literal["capture_start"] = "capture_start"
    window_membership: Literal["[start,end)"] = "[start,end)"
    strict: StrictScanConfig
    broad: BroadScanConfig


class AguriConfig(StrictModel):
    aguri3_executable: str | None = None
    agurim_executable: str | None = None
    options: list[str] = Field(default_factory=list)


class AnalysisConfig(StrictModel):
    overall_ip_scope: Literal["ipv4", "ipv6", "ipv4_ipv6"]


class LegacyScoreWeights(StrictModel):
    flow_count: float = Field(ge=0)
    packet_count: float = Field(ge=0)
    byte_count: float = Field(ge=0)
    low_short_flow_ratio: float = Field(ge=0)
    low_tiny_flow_ratio: float = Field(ge=0)
    low_syn_only_like_ratio: float = Field(ge=0)

    @model_validator(mode="after")
    def require_unit_weight_sum(self) -> "LegacyScoreWeights":
        if abs(sum(self.model_dump().values()) - 1.0) > 1e-9:
            raise ValueError("legacy score weights must sum to 1.0")
        return self


class LegacyConfig(StrictModel):
    candidate_ip_scope: Literal["ipv4_ipv6"]
    prefix_len: int = Field(ge=0, le=128)
    min_flows: int = Field(ge=0)
    min_packets: int = Field(ge=0)
    min_bytes: int = Field(ge=0)
    max_short_flow_ratio: float = Field(ge=0, le=1)
    max_tiny_flow_ratio: float = Field(ge=0, le=1)
    max_syn_only_like_ratio: float = Field(ge=0, le=1)
    max_rst_observed_ratio: float = Field(ge=0, le=1)
    short_duration_threshold: float = Field(ge=0)
    tiny_packet_threshold: int = Field(ge=0)
    top_k: int = Field(gt=0)
    score_weights: LegacyScoreWeights
    plot_min_flow_count: int = Field(ge=0)


class ExperimentConfig(StrictModel):
    experiment: ExperimentMetadataConfig
    flow: FlowConfig
    prefix: PrefixConfig
    scan: ScanConfig
    aguri: AguriConfig
    analysis: AnalysisConfig
    legacy: LegacyConfig | None = None

    @model_validator(mode="after")
    def restrict_legacy_block_to_legacy_experiment(self) -> "ExperimentConfig":
        if self.experiment.name == "paper_legacy" and self.legacy is None:
            raise ValueError("paper_legacy requires a legacy configuration block")
        if self.experiment.name != "paper_legacy" and self.legacy is not None:
            raise ValueError("legacy configuration is reserved for paper_legacy")
        if self.experiment.name == "baseline":
            if self.prefix.ip_version != 4:
                raise ValueError("baseline requires an IPv4 prefix analysis scope")
            if self.prefix.candidate_sources != ["src_prefix", "dst_prefix"]:
                raise ValueError(
                    "baseline requires src_prefix and dst_prefix candidate sources"
                )
            if self.prefix.membership_mode != "src_or_dst":
                raise ValueError("baseline requires src_or_dst prefix membership")
            if self.prefix.top_k is not None:
                raise ValueError("baseline requires no corrected top-k limit")
            if self.analysis.overall_ip_scope != "ipv4":
                raise ValueError("baseline requires an IPv4 overall analysis scope")
        return self


def load_config(path: Path) -> ExperimentConfig:
    """Load one self-contained YAML experiment configuration."""
    with path.open(encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file)
    return ExperimentConfig.model_validate(raw_config)
