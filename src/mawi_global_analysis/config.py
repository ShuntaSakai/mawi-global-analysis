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
    aguri3_executable: str
    agurim_executable: str
    options: list[str]


class AnalysisConfig(StrictModel):
    overall_ip_scope: Literal["ipv4", "ipv6", "ipv4_ipv6"]


class ExperimentConfig(StrictModel):
    experiment: ExperimentMetadataConfig
    flow: FlowConfig
    prefix: PrefixConfig
    scan: ScanConfig
    aguri: AguriConfig
    analysis: AnalysisConfig


def load_config(path: Path) -> ExperimentConfig:
    """Load one self-contained YAML experiment configuration."""
    with path.open(encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file)
    return ExperimentConfig.model_validate(raw_config)
