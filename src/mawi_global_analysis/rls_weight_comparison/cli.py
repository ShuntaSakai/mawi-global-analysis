"""Validate saved RLS runs or export their comparison; never execute input stages."""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from .validation import ComparisonValidationError, validate_comparison
from .generation import generate_comparison
from .refresh import refresh_dashboard
from .native_generation import generate_native_comparison


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--validate-only', action='store_true', help='Read saved inputs and print validation only')
    action.add_argument('--output-dir',type=Path,help='Generate a new comparison bundle including dashboard.html')
    parser.add_argument('--include-native',action='store_true',help='Add native evaluation and same-selection scope comparison from saved runs')
    parser.add_argument('--from-comparison',type=Path,help='Refresh verified comparison bundle without reading canonical flows or runs')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--dataset')
    parser.add_argument('--packet-run')
    parser.add_argument('--byte-run')
    parser.add_argument('--flow-run')
    parser.add_argument('--chunksize', type=int, default=100_000)
    parser.add_argument('--scratch-dir',type=Path)
    parser.add_argument('--max-ecdf-points',type=int,default=2000)
    parser.add_argument('--json', action='store_true', help='Print validation metadata as JSON to stdout')
    args = parser.parse_args(argv)
    if args.include_native:
        if args.validate_only or not all((args.root,args.dataset,args.packet_run,args.byte_run,args.flow_run)):
            parser.error('--include-native requires --output-dir and all root/dataset/run arguments')
    elif args.from_comparison:
        if args.validate_only or any((args.root,args.dataset,args.packet_run,args.byte_run,args.flow_run)):
            parser.error('--from-comparison requires --output-dir and cannot be mixed with run validation arguments')
    elif not all((args.root,args.dataset,args.packet_run,args.byte_run,args.flow_run)):
        parser.error('--root, --dataset, --packet-run, --byte-run and --flow-run are required for run-based operations')
    try:
        if args.include_native:
            path=generate_native_comparison(args.root,args.dataset,packet_run=args.packet_run,byte_run=args.byte_run,
                flow_run=args.flow_run,output_dir=args.output_dir,comparison_manifest=args.from_comparison,
                chunksize=args.chunksize,scratch_dir=args.scratch_dir,max_ecdf_points=args.max_ecdf_points)
            result={'status':'success','manifest':str(path),'dashboard':str(path.with_name('dashboard_native.html'))}
        elif args.from_comparison:
            path=refresh_dashboard(args.from_comparison,args.output_dir,scratch_dir=args.scratch_dir)
            result={'status':'success','manifest':str(path),'dashboard':str(path.with_name('dashboard.html'))}
        elif args.validate_only:
            result = validate_comparison(args.root, args.dataset, packet_run=args.packet_run,
                byte_run=args.byte_run, flow_run=args.flow_run, chunksize=args.chunksize)
        else:
            path=generate_comparison(args.root,args.dataset,packet_run=args.packet_run,
                byte_run=args.byte_run,flow_run=args.flow_run,output_dir=args.output_dir,
                scratch_dir=args.scratch_dir,chunksize=args.chunksize,max_ecdf_points=args.max_ecdf_points)
            result={'status':'success','manifest':str(path),'dashboard':str(path.with_name('dashboard.html'))}
    except (ComparisonValidationError,ValueError,OSError,sqlite3.Error) as exc:
        parser.exit(2, f'比較条件を検証できません: {exc}\n')
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    elif args.validate_only:
        print('Validation succeeded: packet / byte / flow; threshold=1%; disable-heuristics=2')
        for mode, entry in result['runs'].items():
            print(f"  {mode}: {entry['run_name']}")
        print('Read-only contract/integrity validation; no distribution or coverage computed.')
    else:
        print(f"Dashboard: {result['dashboard']}")
        print(f"Manifest: {result['manifest']}")
    return 0
