"""Check three existing RLS runs. Never execute stages or save artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validation import ComparisonValidationError, validate_comparison


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate-only', action='store_true', required=True,
                        help='Required: read saved inputs and print validation only')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--packet-run', required=True)
    parser.add_argument('--byte-run', required=True)
    parser.add_argument('--flow-run', required=True)
    parser.add_argument('--chunksize', type=int, default=100_000)
    parser.add_argument('--json', action='store_true', help='Print validation metadata as JSON to stdout')
    args = parser.parse_args(argv)
    try:
        result = validate_comparison(args.root, args.dataset, packet_run=args.packet_run,
            byte_run=args.byte_run, flow_run=args.flow_run, chunksize=args.chunksize)
    except ComparisonValidationError as exc:
        parser.exit(2, f'比較条件を検証できません: {exc}\n')
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    else:
        print('Validation succeeded: packet / byte / flow; threshold=1%; disable-heuristics=2')
        for mode, entry in result['runs'].items():
            print(f"  {mode}: {entry['run_name']}")
        print('Read-only contract/integrity validation; no distribution or coverage computed.')
    return 0
