"""Aggregate saved run artifacts into an immutable fixed-Raw-sender bundle."""
import argparse
from pathlib import Path
from mawi_global_analysis.prefix_ip_behavior import aggregate_run


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','output-dir'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('dataset','run'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--scratch-dir',type=Path)
    parser.add_argument('--expected-prefix-count',type=int,default=18)
    args=parser.parse_args(argv)
    try:
        out=aggregate_run(args.root,args.dataset,args.run,output_dir=args.output_dir,
            scratch_dir=args.scratch_dir,expected_prefix_count=args.expected_prefix_count,
            progress=lambda stage,n: print(f'{stage}: {n:,}',flush=True))
    except (OSError,ValueError) as exc:
        parser.exit(2,f'集計を中止しました: {exc}\n')
    print(f'Validated bundle: {out}')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
