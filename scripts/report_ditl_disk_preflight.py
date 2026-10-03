"""Read-only metadata report; never constructs SQLite aggregation state.

The cohort row count is an explicit planning input because durable chunk
metadata records observation counts, not the number of cohort targets.
This report checks metadata and file locations/sizes, not CSV checksums or
contents; it is not full durable-cache validation or an aggregation run.
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import asdict
from pathlib import Path

from mawi_global_analysis.ditl_chunks import expected_chunk_ids, validate_chunk_id
from mawi_global_analysis.ditl_context_sqlite import (
    SOURCE_WINDOW_CHUNK_SPANS,
    estimate_aggregation_disk_space,
    max_rolling_source_syn_rows,
)


def load_metadata(cache_root: Path, day: str) -> list[dict]:
    """Read one complete, unambiguous 96-chunk cache cohort for a fixed day."""
    root = cache_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("cache root must be a directory")
    items = []
    for path in sorted(root.rglob("chunk_metadata.json")):
        with path.open(encoding="utf-8") as stream:
            item = json.load(stream)
        if not isinstance(item, dict) or item.get("status") != "success":
            raise ValueError(f"metadata must describe a successful chunk: {path}")
        chunk_id = validate_chunk_id(item.get("chunk_id"))
        if path.parent.name != chunk_id:
            raise ValueError(f"chunk ID disagrees with metadata directory: {path}")
        for name in ("target_observations", "source_syn_observations"):
            artifacts = item.get("artifacts")
            record = artifacts.get(name) if isinstance(artifacts, dict) else None
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise ValueError(f"missing observation artifact metadata: {path}")
            artifact = Path(record["path"])
            if (not artifact.is_absolute() or not artifact.is_file()
                    or artifact.resolve().parent != path.parent.resolve()):
                raise ValueError(f"observation artifact missing or outside chunk directory: {path}")
        items.append(item)
    items.sort(key=lambda item: item["chunk_id"])
    if tuple(item["chunk_id"] for item in items) != expected_chunk_ids(day):
        raise ValueError("exactly the 96 unique expected quarter-hour chunks are required")
    for field in ("cohort_identity", "observation_code_identity"):
        identities = [item.get(field) for item in items]
        if (any(not isinstance(value, str) or not value for value in identities)
                or len(set(identities)) != 1):
            raise ValueError(f"all chunks must have one consistent {field}")
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--spool", type=Path, required=True)
    parser.add_argument("--day", required=True)
    parser.add_argument("--cohort-row-count", type=int, required=True,
                        help="actual cohort target count used by the stopped preflight")
    args = parser.parse_args(argv)
    metadata = load_metadata(args.cache_root, args.day)
    spool = args.spool.resolve(strict=True)
    if not spool.is_dir():
        raise ValueError("spool must be an existing directory")
    estimate = estimate_aggregation_disk_space(
        metadata, cohort_row_count=args.cohort_row_count,
        available_bytes=shutil.disk_usage(spool).free,
    )
    print(json.dumps({
        "successful_chunks": len(metadata),
        "cohort_row_count": args.cohort_row_count,
        "max_rolling_source_syn_rows": {
            str(window): max_rolling_source_syn_rows(metadata, span)
            for window, span in SOURCE_WINDOW_CHUNK_SPANS
        },
        "disk_estimate": asdict(estimate),
        "preflight_passes": estimate.available_bytes >= estimate.required_bytes,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
