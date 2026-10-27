"""Attach verified IP observations to a trusted offline dashboard at a new path."""
import argparse
from pathlib import Path
from mawi_global_analysis.prefix_dashboard import enrich_ip_behavior


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('input','behavior-csv','ports-csv','manifest','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--top-k',type=int,default=10)
    args=parser.parse_args(argv)
    try:
        output=enrich_ip_behavior(args.input,args.behavior_csv,args.ports_csv,args.manifest,args.output,top_k=args.top_k)
    except (OSError,ValueError) as exc:
        parser.exit(2,f'HTMLを生成できません: {exc}\n')
    print(f'HTML: {output}')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
