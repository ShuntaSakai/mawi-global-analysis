"""Compare saved legacy Aguri BPF and canonical Aguri selections."""
import argparse
import json
from pathlib import Path
import sqlite3

from .generation import generate
from .validation import validate_inputs,DEFAULT_RUNS


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True);p.add_argument('--dataset',default='202604081400')
    for key in ('A','B'):
        p.add_argument('--run-'+key.lower(),default=DEFAULT_RUNS[key])
    p.add_argument('--run-c',help=f"v1 canonical packet run (default: {DEFAULT_RUNS['C']})",default=None)
    p.add_argument('--run-c-packet',help='v2 two-stage packet run; requires --run-c-flow')
    p.add_argument('--run-c-flow',help='v2 two-stage flow run; requires --run-c-packet')
    action=p.add_mutually_exclusive_group(required=True)
    action.add_argument('--validate-only',action='store_true');action.add_argument('--output-dir',type=Path)
    p.add_argument('--chunksize',type=int,default=100000);p.add_argument('--scratch-dir',type=Path)
    p.add_argument('--max-ecdf-points',type=int,default=2000);p.add_argument('--target',default='93.139.29.123/32')
    p.add_argument('--legacy-reference',type=Path);p.add_argument('--json',action='store_true')
    a=p.parse_args(argv)
    v2=a.run_c_packet is not None or a.run_c_flow is not None
    kwargs=dict(run_a=a.run_a,run_b=a.run_b,run_c=a.run_c,run_c_packet=a.run_c_packet,
                run_c_flow=a.run_c_flow,chunksize=a.chunksize)
    try:
        if a.validate_only:result=validate_inputs(a.root,a.dataset,**kwargs,scratch_dir=a.scratch_dir)
        else:
            path=generate(a.root,a.dataset,a.output_dir,**kwargs,scratch_dir=a.scratch_dir,max_ecdf_points=a.max_ecdf_points,
                          target=a.target,legacy_reference=a.legacy_reference)
            result={'status':'success','manifest':str(path)}
            if not v2:
                result['dashboard']=str(path.with_name('dashboard.html'))
    except (ValueError,OSError,sqlite3.Error) as e:p.exit(2,f'A/B/C比較を実行できません: {e}\n')
    if a.json:
        print(json.dumps(result,indent=2,ensure_ascii=False))
    elif a.validate_only:
        print('Read-only four-condition validation succeeded' if v2 else 'Read-only A/B/C validation succeeded')
    else:
        print(result['manifest' if v2 else 'dashboard'])
    return 0
