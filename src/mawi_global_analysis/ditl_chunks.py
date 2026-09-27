"""Operational DITL quarter-hour chunk planning (not packet-time semantics)."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from urllib.parse import urlparse


class DITLPlanError(ValueError):
    """Raised for invalid operational chunk identifiers or URLs."""


def normalized_day(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%Y%m%d").date() if len(value) == 8 else date.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise DITLPlanError("date must be YYYYMMDD or YYYY-MM-DD") from error
    return parsed.strftime("%Y%m%d")


def expected_chunk_ids(value: str) -> tuple[str, ...]:
    day = normalized_day(value)
    start = datetime.strptime(day, "%Y%m%d")
    return tuple((start + timedelta(minutes=15 * index)).strftime("%Y%m%d%H%M") for index in range(96))


def validate_chunk_id(chunk_id: str) -> str:
    if not isinstance(chunk_id, str) or len(chunk_id) != 12 or not chunk_id.isdigit():
        raise DITLPlanError("chunk_id must be a 12-digit YYYYMMDDHHMM identifier")
    try:
        datetime.strptime(chunk_id, "%Y%m%d%H%M")
    except ValueError as error:
        raise DITLPlanError("chunk_id is not a valid calendar minute") from error
    if int(chunk_id[-2:]) not in {0, 15, 30, 45}:
        raise DITLPlanError("chunk_id must identify a 15-minute slot")
    return chunk_id


def validate_target_chunk(day: str, chunk_id: str) -> str:
    chunk_id = validate_chunk_id(chunk_id)
    if chunk_id[:8] != normalized_day(day):
        raise DITLPlanError("target chunk does not belong to requested day")
    return chunk_id


def render_chunk_url(template: str, chunk_id: str) -> str:
    validate_chunk_id(chunk_id)
    if not isinstance(template, str) or template.count("{chunk_id}") != 1:
        raise DITLPlanError("URL template must contain exactly one {chunk_id} placeholder")
    url = template.replace("{chunk_id}", chunk_id)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise DITLPlanError("URL template must render an absolute http or https URL")
    return url
