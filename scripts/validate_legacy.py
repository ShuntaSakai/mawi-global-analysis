#!/usr/bin/env python3
"""Validate legacy prefix-selection output against an exported golden JSON."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any


EXACT_FIELDS = (
    "aggregate_id",
    "src_prefix",
    "dst_prefix",
    "normalized_dst_prefix",
    "match_status",
    "ip_version",
    "prefix_length",
    "prefix_is_broader_than_target",
    "flow_count",
    "packet_count",
    "byte_count",
    "passes_filters",
    "selected",
)
FLOAT_FIELDS = (
    "short_flow_ratio",
    "tiny_flow_ratio",
    "syn_only_like_ratio",
    "rst_observed_ratio",
    "score",
)
FLOAT_TOLERANCE = 1e-8


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual", type=Path, required=True, help="Legacy prefixes CSV")
    parser.add_argument("--golden", type=Path, required=True, help="Verified legacy JSON")
    return parser.parse_args()


def validate(actual_path: Path, golden_path: Path) -> list[str]:
    """Return exact/tight-tolerance differences without hiding mismatches."""
    actual_rows = _read_csv(actual_path)
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    expected_rows = golden.get("selected_prefixes")
    if not isinstance(expected_rows, list):
        return ["golden JSON is missing selected_prefixes"]
    actual = {
        _row_key(row): row
        for row in actual_rows
        if "selected" not in row or _as_bool(row.get("selected"))
    }
    expected = {_row_key(row): row for row in expected_rows}
    differences: list[str] = []
    if actual.keys() != expected.keys():
        differences.append(
            "selected prefix membership differs: "
            f"actual={sorted(actual)} expected={sorted(expected)}"
        )
    for key in sorted(actual.keys() & expected.keys()):
        differences.extend(_compare_row(key, actual[key], expected[key]))
    return differences


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _row_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("aggregate_id", "")), str(row.get("normalized_dst_prefix", "")))


def _compare_row(key: tuple[str, str], actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    differences: list[str] = []
    for field in EXACT_FIELDS:
        if field not in expected:
            continue
        actual_value = _canonical_exact(
            True if field == "selected" and field not in actual else actual.get(field)
        )
        expected_value = _canonical_exact(expected[field])
        if actual_value != expected_value:
            differences.append(
                f"{key} {field}: actual={actual_value!r} expected={expected_value!r}"
            )
    for field in FLOAT_FIELDS:
        if field not in expected:
            continue
        try:
            actual_value = float(actual[field])
            expected_value = float(expected[field])
        except (KeyError, TypeError, ValueError):
            differences.append(f"{key} {field}: missing or non-numeric actual value")
            continue
        if not math.isclose(
            actual_value, expected_value, rel_tol=FLOAT_TOLERANCE, abs_tol=FLOAT_TOLERANCE
        ):
            differences.append(
                f"{key} {field}: actual={actual_value:.17g} expected={expected_value:.17g} "
                f"(tolerance={FLOAT_TOLERANCE:g})"
            )
    return differences


def _canonical_exact(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    if text.lower() in {"true", "false"}:
        return text.lower()
    try:
        return str(int(text))
    except ValueError:
        return text


def _as_bool(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def main() -> int:
    args = parse_args()
    try:
        differences = validate(args.actual, args.golden)
    except (OSError, csv.Error, json.JSONDecodeError) as error:
        print(f"legacy validation failed: {error}", file=sys.stderr)
        return 2
    if differences:
        print("legacy validation failed:", file=sys.stderr)
        print("\n".join(f"- {difference}" for difference in differences), file=sys.stderr)
        return 1
    print("legacy validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
