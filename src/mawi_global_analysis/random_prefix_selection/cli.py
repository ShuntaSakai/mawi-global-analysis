"""Select observed /24 controls without executing Aguri or parsing PCAPs."""
import argparse
import csv
import json
from pathlib import Path
import sqlite3

from .run import run_random_selection, verify_run
from .validation import validate_inputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('run', 'audit-inputs'):
        p = commands.add_parser(command)
        p.add_argument('--root', type=Path, required=True)
        p.add_argument('--dataset', required=True)
        p.add_argument('--flows', type=Path, required=command == 'run')
        p.add_argument('--flow-run', required=True)
        p.add_argument('--packet-run', required=True)
        p.add_argument('--json', action='store_true')
        if command == 'run':
            p.add_argument('--run', required=True)
            p.add_argument('--count', type=int, default=18)
            p.add_argument('--seed', type=int, default=20260408)
            p.add_argument('--chunksize', type=int, default=100000)
    p = commands.add_parser('verify')
    p.add_argument('manifest', type=Path)
    p.add_argument('--chunksize', type=int, default=100000)
    p.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'run':
            path = run_random_selection(args.root, args.dataset, args.run, args.flows,
                                        args.flow_run, args.packet_run, count=args.count,
                                        seed=args.seed, chunksize=args.chunksize)
            result = dict(status='success', run_manifest=str(path))
        elif args.command == 'audit-inputs':
            result = validate_inputs(args.root, args.dataset, args.flows, args.flow_run, args.packet_run)
        else:
            result = verify_run(args.manifest, chunksize=args.chunksize)
    except (ValueError, OSError, KeyError, TypeError, csv.Error, sqlite3.Error) as exc:
        parser.exit(2, f'Random /24 selection failed: {exc}\n')
    print(json.dumps(result, indent=2 if args.json else None, ensure_ascii=False, allow_nan=False))
    return 0
