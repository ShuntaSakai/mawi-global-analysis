"""Export Experiment 1's Raw agurim /24 dashboard from saved run CSVs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mawi_global_analysis.normalized24 import HistogramSpec
from mawi_global_analysis.normalized24_dashboard import export_dashboard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--dataset',required=True)
    parser.add_argument('--run',required=True)
    parser.add_argument('--output',type=Path,required=True,help='New standalone HTML outside data/results/cache')
    parser.add_argument('--chunksize',type=int,default=100_000)
    parser.add_argument('--scratch-dir',type=Path,help='Existing local disk directory with sufficient free space')
    parser.add_argument('--histogram-spec',type=Path,help='Shared histogram_spec JSON object from a prior export')
    args = parser.parse_args(argv)
    try:
        spec = HistogramSpec.from_dict(json.loads(args.histogram_spec.read_text())) if args.histogram_spec else None
        result = export_dashboard(args.root,args.dataset,args.run,args.output,chunksize=args.chunksize,
            scratch_dir=args.scratch_dir,spec=spec,progress=lambda name,n: print(f'{name}: {n:,} rows',flush=True))
    except (OSError,ValueError) as exc:
        parser.exit(2,f'HTMLを生成できません: {exc}\n入力・既存cacheは変更していません。\n')
    print(f'HTML: {result}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
