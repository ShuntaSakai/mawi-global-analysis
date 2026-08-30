"""Prefix-selection strategies, including the isolated paper legacy path."""

from __future__ import annotations

import ipaddress
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pandas as pd


LEGACY_OUTPUT_COLUMNS = (
    "aggregate_id",
    "src_prefix",
    "dst_prefix",
    "normalized_dst_prefix",
    "match_status",
    "ip_version",
    "prefix_length",
    "prefix_is_host",
    "prefix_is_broader_than_target",
    "flow_count",
    "packet_count",
    "byte_count",
    "short_flow_ratio",
    "tiny_flow_ratio",
    "syn_only_like_ratio",
    "rst_observed_ratio",
    "scan_candidate",
    "passes_filters",
    "score",
    "selected",
    "exclusion_reason",
)


def legacy_select_prefixes(
    aguri_df: pd.DataFrame, flows: pd.DataFrame, cfg: Mapping[str, Any] | Any
) -> pd.DataFrame:
    """Reproduce the old destination-prefix score and top-k selection behavior.

    This function deliberately keeps the historic directionality, feature
    filters, and ranking separate from corrected candidate selection.
    """
    settings = _legacy_settings(cfg)
    _require_columns(aguri_df, {"aggregate_id", "src_prefix", "dst_prefix"}, "Aguri")
    _require_columns(
        flows,
        {"dst_ip", "protocol", "duration", "packet_count", "byte_count"},
        "flows",
    )
    rows = [
        row
        for _, candidate in aguri_df.iterrows()
        if (row := _legacy_candidate_row(candidate, flows, settings)) is not None
    ]
    output = pd.DataFrame(rows, columns=LEGACY_OUTPUT_COLUMNS)
    if output.empty:
        return output

    # The old code assigned percentile ranks before applying any filters. This
    # deliberately includes no-match and broader-prefix rows with zero metrics.
    rankable = output[output["match_status"] != "invalid_prefix"].copy()
    if not rankable.empty:
        weights = settings["score_weights"]
        output.loc[rankable.index, "score"] = (
            rankable["flow_count"].rank(method="average", pct=True) * weights["flow_count"]
            + rankable["packet_count"].rank(method="average", pct=True) * weights["packet_count"]
            + rankable["byte_count"].rank(method="average", pct=True) * weights["byte_count"]
            + (1.0 - rankable["short_flow_ratio"]) * weights["low_short_flow_ratio"]
            + (1.0 - rankable["tiny_flow_ratio"]) * weights["low_tiny_flow_ratio"]
            + (1.0 - rankable["syn_only_like_ratio"]) * weights["low_syn_only_like_ratio"]
        )

    eligible = output[output["passes_filters"]].sort_values(
        ["score", "flow_count", "packet_count", "byte_count"],
        ascending=False,
        kind="mergesort",
    )
    output.loc[eligible.head(settings["top_k"]).index, "selected"] = True
    return output


def legacy_display_prefixes(selection: pd.DataFrame, cfg: Mapping[str, Any] | Any) -> pd.DataFrame:
    """Apply the old notebook's display-only count threshold and ordering."""
    settings = _legacy_settings(cfg)
    _require_columns(selection, {"selected", "flow_count"}, "legacy selection")
    return selection.loc[
        selection["selected"] & (selection["flow_count"] >= settings["plot_min_flow_count"])
    ].sort_values("flow_count", ascending=False, kind="mergesort").head(settings["top_k"]).copy()


def run_legacy_prefix_stage(
    flows_path: Path, aguri_path: Path, cfg: Any, output_path: Path
) -> Path:
    """Run the legacy selector from canonical flow and Aguri CSV artifacts."""
    if getattr(cfg.experiment, "name", None) != "paper_legacy" or cfg.legacy is None:
        raise ValueError("legacy prefix stage requires the paper_legacy configuration")
    flows = pd.read_csv(flows_path)
    aguri = pd.read_csv(aguri_path)
    selection = legacy_select_prefixes(aguri, flows, cfg.legacy)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_csv_atomically(output_path, selection)
    return output_path


def _legacy_candidate_row(
    candidate: pd.Series, flows: pd.DataFrame, settings: dict[str, Any]
) -> dict[str, object] | None:
    raw_prefix = str(candidate["dst_prefix"]).strip()
    base = _empty_legacy_row(candidate, raw_prefix)
    try:
        network = ipaddress.ip_network(raw_prefix, strict=False)
    except ValueError:
        return None
    base.update(
        normalized_dst_prefix=str(network),
        ip_version=network.version,
        prefix_length=network.prefixlen,
        prefix_is_host=network.prefixlen == network.max_prefixlen,
    )
    # This is intentionally the historic condition: IPv6 candidates were not
    # excluded by the old script, while only broader IPv4 prefixes were filtered.
    broader_than_target = (
        network.version == 4
        and network.prefixlen < settings["prefix_len"]
        and network.prefixlen != network.max_prefixlen
    )
    base["prefix_is_broader_than_target"] = broader_than_target
    destination_addresses = flows["dst_ip"].map(_parse_ip)
    membership = destination_addresses.map(
        lambda address: address is not None
        and address.version == network.version
        and address in network
    )
    matched = flows.loc[membership].copy()
    if matched.empty:
        base["match_status"] = "no_matching_flows"
        base["exclusion_reason"] = "no_matching_flows"
        return base

    _require_legacy_flag_columns(matched)
    protocol = matched["protocol"].astype(str)
    syn_count = pd.to_numeric(matched["syn_count"], errors="raise")
    ack_count = pd.to_numeric(matched["ack_count"], errors="raise")
    rst_count = pd.to_numeric(matched["rst_count"], errors="raise")
    packet_count = pd.to_numeric(matched["packet_count"], errors="raise")
    duration = pd.to_numeric(matched["duration"], errors="raise")
    byte_count = pd.to_numeric(matched["byte_count"], errors="raise")
    flow_count = int(len(matched))
    short = duration <= settings["short_duration_threshold"]
    tiny = packet_count <= settings["tiny_packet_threshold"]
    syn_only_like = (
        (protocol == "6")
        & (syn_count > 0)
        & (ack_count == 0)
        & tiny
    )
    rst = rst_count > 0
    base.update(
        match_status="matched",
        flow_count=flow_count,
        packet_count=int(packet_count.sum()),
        byte_count=int(byte_count.sum()),
        short_flow_ratio=float(short.mean()),
        tiny_flow_ratio=float(tiny.mean()),
        syn_only_like_ratio=float(syn_only_like.mean()),
        rst_observed_ratio=float(rst.mean()),
    )
    base["scan_candidate"] = bool(
        base["short_flow_ratio"] > settings["max_short_flow_ratio"]
        or base["tiny_flow_ratio"] > settings["max_tiny_flow_ratio"]
        or base["syn_only_like_ratio"] > settings["max_syn_only_like_ratio"]
    )
    base["passes_filters"] = bool(
        base["flow_count"] >= settings["min_flows"]
        and base["packet_count"] >= settings["min_packets"]
        and base["byte_count"] >= settings["min_bytes"]
        and base["short_flow_ratio"] <= settings["max_short_flow_ratio"]
        and base["tiny_flow_ratio"] <= settings["max_tiny_flow_ratio"]
        and base["syn_only_like_ratio"] <= settings["max_syn_only_like_ratio"]
        and base["rst_observed_ratio"] <= settings["max_rst_observed_ratio"]
        and not broader_than_target
    )
    if not base["passes_filters"]:
        base["exclusion_reason"] = "legacy_filters"
    return base


def _empty_legacy_row(candidate: pd.Series, raw_prefix: str) -> dict[str, object]:
    return {
        "aggregate_id": str(candidate["aggregate_id"]),
        "src_prefix": str(candidate["src_prefix"]),
        "dst_prefix": raw_prefix,
        "normalized_dst_prefix": raw_prefix,
        "match_status": "unprocessed",
        "ip_version": None,
        "prefix_length": None,
        "prefix_is_host": False,
        "prefix_is_broader_than_target": False,
        "flow_count": 0,
        "packet_count": 0,
        "byte_count": 0,
        "short_flow_ratio": 0.0,
        "tiny_flow_ratio": 0.0,
        "syn_only_like_ratio": 0.0,
        "rst_observed_ratio": 0.0,
        "scan_candidate": False,
        "passes_filters": False,
        "score": 0.0,
        "selected": False,
        "exclusion_reason": "",
    }


def _legacy_settings(cfg: Mapping[str, Any] | Any) -> dict[str, Any]:
    value = cfg.model_dump() if hasattr(cfg, "model_dump") else dict(cfg)
    if "legacy" in value:
        value = value["legacy"]
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    required = {
        "prefix_len", "min_flows", "min_packets", "min_bytes",
        "max_short_flow_ratio", "max_tiny_flow_ratio", "max_syn_only_like_ratio",
        "max_rst_observed_ratio", "short_duration_threshold", "tiny_packet_threshold",
        "top_k", "score_weights",
    }
    missing = sorted(required - set(value))
    if missing:
        raise ValueError("legacy configuration is missing: " + ", ".join(missing))
    if "plot_min_flow_count" not in value:
        value["plot_min_flow_count"] = 0
    return value


def _parse_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def _require_columns(frame: pd.DataFrame, required: set[str], label: str) -> None:
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"{label} is missing required columns: {', '.join(missing)}")


def _require_legacy_flag_columns(flows: pd.DataFrame) -> None:
    _require_columns(flows, {"syn_count", "ack_count", "rst_count"}, "flows")


def _write_csv_atomically(path: Path, frame: pd.DataFrame) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary_path = Path(output.name)
            frame.to_csv(output, index=False)
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
