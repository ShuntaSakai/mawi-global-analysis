"""Corrected native and true normalized-/24 flow-prefix membership."""

from __future__ import annotations

import ipaddress

import pandas as pd


MEMBERSHIP_COLUMNS = (
    "flow_id",
    "analysis_scope",
    "analysis_prefix",
    "src_match",
    "dst_match",
)


def build_membership(flows: pd.DataFrame, prefixes: pd.DataFrame) -> pd.DataFrame:
    """Map flows to selected native and recomputed normalized-/24 scopes.

    Native scopes use each selected corrected prefix exactly. Normalized scopes
    use the full containing /24, deduplicated across selected native prefixes.
    ``src_match`` and ``dst_match`` retain the flow observation direction.
    """
    _require_columns(flows, {"flow_id", "src_ip", "dst_ip"}, "flows")
    _require_columns(prefixes, {"prefix", "selected_for_analysis"}, "prefixes")
    _require_unique_flow_ids(flows)

    parsed_flows = [
        (flow.flow_id, _parse_address(flow.src_ip), _parse_address(flow.dst_ip))
        for flow in flows.loc[:, ["flow_id", "src_ip", "dst_ip"]].itertuples(index=False)
    ]
    selected_networks = _selected_networks(prefixes)
    scopes = [
        ("native", network) for network in selected_networks
    ] + [
        ("normalized_24", network)
        for network in _normalized_24_networks(selected_networks)
    ]

    rows: list[dict[str, object]] = []
    for analysis_scope, network in scopes:
        for flow_id, src_address, dst_address in parsed_flows:
            src_match = src_address.version == 4 and src_address in network
            dst_match = dst_address.version == 4 and dst_address in network
            if src_match or dst_match:
                rows.append(
                    {
                        "flow_id": flow_id,
                        "analysis_scope": analysis_scope,
                        "analysis_prefix": str(network),
                        "src_match": src_match,
                        "dst_match": dst_match,
                    }
                )

    return pd.DataFrame(rows, columns=MEMBERSHIP_COLUMNS)


def _selected_networks(prefixes: pd.DataFrame) -> list[ipaddress.IPv4Network]:
    selected = prefixes.loc[prefixes["selected_for_analysis"] == True, "prefix"]  # noqa: E712
    networks: list[ipaddress.IPv4Network] = []
    seen: set[ipaddress.IPv4Network] = set()
    for value in selected:
        network = _parse_selected_network(value)
        if network not in seen:
            networks.append(network)
            seen.add(network)
    return networks


def _normalized_24_networks(
    native_networks: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    normalized: list[ipaddress.IPv4Network] = []
    seen: set[ipaddress.IPv4Network] = set()
    for network in native_networks:
        normalized_network = ipaddress.ip_network(
            f"{network.network_address}/24", strict=False
        )
        assert isinstance(normalized_network, ipaddress.IPv4Network)
        if normalized_network not in seen:
            normalized.append(normalized_network)
            seen.add(normalized_network)
    return normalized


def _parse_selected_network(value: object) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(str(value), strict=False)
    except ValueError as error:
        raise ValueError(f"selected prefix is not a concrete network: {value!r}") from error
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen < 24:
        raise ValueError(
            "selected corrected prefixes must be IPv4 networks with prefix length >= 24"
        )
    return network


def _parse_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(str(value))
    except ValueError as error:
        raise ValueError(f"flow endpoint is not an IP address: {value!r}") from error


def _require_columns(frame: pd.DataFrame, required: set[str], name: str) -> None:
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"{name} missing required columns: {', '.join(missing)}")


def _require_unique_flow_ids(flows: pd.DataFrame) -> None:
    duplicate_ids = flows.loc[flows["flow_id"].duplicated(keep=False), "flow_id"]
    if not duplicate_ids.empty:
        raise ValueError(
            "flows contain duplicate canonical flow_id values: "
            f"{duplicate_ids.drop_duplicates().tolist()!r}"
        )
