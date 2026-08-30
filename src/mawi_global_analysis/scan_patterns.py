"""Classify ordered TCP observation facts without assigning scan labels."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal


ObservedTcpPattern = Literal["none", "syn_to_rst", "syn_synack_rst", "syn_only_observed"]


def _number(row: Mapping[str, object], field: str) -> float | None:
    value = row.get(field)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _count(row: Mapping[str, object], field: str) -> int:
    value = _number(row, field)
    return int(value) if value is not None else 0


def _boolean(row: Mapping[str, object], field: str) -> bool:
    value = row.get(field, False)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return bool(value)


def classify_observed_tcp_pattern(row: Mapping[str, object]) -> ObservedTcpPattern:
    """Describe a TCP packet pattern supported by recorded directional facts.

    The result is an observation descriptor, not a scan or maliciousness label.
    """
    if _boolean(row, "transport_payload_observed"):
        return "none"

    first_syn = _number(row, "first_syn_time")
    responder_rst = _number(row, "first_responder_rst_time")
    responder_synack = _number(row, "first_responder_synack_time")
    initiator_rst = _number(row, "first_initiator_rst_time")

    if (
        _count(row, "syn_from_initiator") > 0
        and _count(row, "rst_from_responder") > 0
        and first_syn is not None
        and responder_rst is not None
        and first_syn <= responder_rst
    ):
        return "syn_to_rst"

    if (
        _count(row, "syn_from_initiator") > 0
        and _count(row, "synack_from_responder") > 0
        and _count(row, "rst_from_initiator") > 0
        and first_syn is not None
        and responder_synack is not None
        and initiator_rst is not None
        and first_syn <= responder_synack <= initiator_rst
    ):
        return "syn_synack_rst"

    if (
        row.get("initial_syn_sender_ip") is not None
        and _count(row, "syn_from_initiator") > 0
        and _count(row, "synack_from_responder") == 0
        and _count(row, "rst_from_responder") == 0
        and not _boolean(row, "non_syn_response_observed")
    ):
        return "syn_only_observed"

    return "none"
