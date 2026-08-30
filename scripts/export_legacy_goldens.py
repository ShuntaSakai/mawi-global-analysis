#!/usr/bin/env python3
"""Export unrounded legacy regression values from a checked-out old repository."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


PREFIX_FIELDS = (
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
    "short_flow_ratio",
    "tiny_flow_ratio",
    "syn_only_like_ratio",
    "rst_observed_ratio",
    "passes_filters",
    "score",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def export_golden(legacy_root: Path, dataset_id: str) -> dict[str, Any]:
    """Extract verified values directly from old result artifacts."""
    selected_path = legacy_root / "results" / "prefix" / dataset_id / "selected_prefixes.csv"
    comparison_path = legacy_root / "results" / "comparison" / dataset_id / "comparison_summary.csv"
    selected_rows = _read_csv(selected_path)
    comparison_rows = _read_csv(comparison_path)
    return {
        "dataset_id": dataset_id,
        "provenance": {
            "legacy_root": str(legacy_root.resolve()),
            "selected_prefixes_csv": str(selected_path.resolve()),
            "comparison_summary_csv": str(comparison_path.resolve()),
        },
        "selected_prefixes": [
            {**{field: _coerce(row[field]) for field in PREFIX_FIELDS}, "selected": True}
            for row in selected_rows
        ],
        "overall_sanity": _overall_sanity(comparison_rows),
    }


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _overall_sanity(rows: list[dict[str, str]]) -> dict[str, Any]:
    overall = next((row for row in rows if row.get("target") == "overall"), None)
    if overall is None:
        raise ValueError("comparison summary has no overall row")
    return {
        "flow_count": int(overall["flow_count"]),
        "packet_count_median": float(overall["packet_count_median"]),
        "byte_count_median": float(overall["byte_count_median"]),
        "duration_median": float(overall["duration_median"]),
    }


def _coerce(value: str) -> str | int | float:
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


def main() -> int:
    args = parse_args()
    try:
        golden = export_golden(args.legacy_root, args.dataset)
    except (OSError, ValueError, csv.Error) as error:
        raise SystemExit(f"legacy golden export failed: {error}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(golden, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"exported {len(golden['selected_prefixes'])} legacy selected prefixes to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
