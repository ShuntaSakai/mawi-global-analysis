"""Canonical-input RLS selection and shared Raw /24 dashboard."""
from __future__ import annotations

import argparse
from pathlib import Path

from .stage import METHODS, run_prime


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--dataset',required=True)
    parser.add_argument('--run',required=True,help='New run name; never overwritten')
    parser.add_argument('--flows',type=Path,required=True,help='Canonical flows.csv, adjacent flow_manifest.json required')
    parser.add_argument('--agurim',type=Path,required=True,help='Local fork executable with adjacent build_manifest.json')
    parser.add_argument('--mode',choices=list(METHODS),default='flow')
    parser.add_argument('--threshold',type=int,default=1,help='Integer percent, 1..100 (upstream semantics)')
    parser.add_argument('--disable-heuristics',type=int,choices=(0,1,2),default=0)
    parser.add_argument('--chunksize',type=int,default=100_000)
    parser.add_argument('--output',type=Path,help='Optional new offline Raw /24 HTML, outside data/results/cache')
    parser.add_argument('--histogram-spec',type=Path)
    parser.add_argument('--scratch-dir',type=Path)
    args=parser.parse_args(argv)
    try:
        # Resolve output constraints before any costly work; export repeats checks.
        if args.output and args.output.expanduser().exists():
            raise FileExistsError(f'existing HTML will not be overwritten: {args.output}')
        path=run_prime(args.root,args.dataset,args.run,args.flows,args.agurim,mode=args.mode,
            threshold=args.threshold,heuristics=args.disable_heuristics,chunksize=args.chunksize)
        print(f'Manifest: {path}')
        if args.output:
            import json
            from mawi_global_analysis.normalized24 import HistogramSpec
            from mawi_global_analysis.normalized24.dashboard import export_dashboard
            spec=HistogramSpec.from_dict(json.loads(args.histogram_spec.read_text())) if args.histogram_spec else None
            result=export_dashboard(args.root,args.dataset,args.run,args.output,chunksize=args.chunksize,
                                    scratch_dir=args.scratch_dir,spec=spec)
            print(f'HTML: {result}')
    except (OSError,ValueError,RuntimeError) as exc:
        parser.exit(2,f'Agurim prime を生成できません: {exc}\n既存成果物は上書きしていません。\n')
    return 0
