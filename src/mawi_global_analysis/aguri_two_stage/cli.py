"""New canonical Aguri3→Agurim runs and read-only exact comparison exports."""
import argparse
import json
from pathlib import Path
import sqlite3
from .stage import run_two_stage,ALL_MODES
from .validation import validate_runs
from .comparison import generate_comparison,verify_manifest

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);commands=p.add_subparsers(dest='command',required=True)
    run=commands.add_parser('run',help='Execute both existing C stages from a saved canonical CSV')
    run.add_argument('--root',type=Path,required=True);run.add_argument('--dataset',required=True)
    run.add_argument('--run');run.add_argument('--flows',type=Path,required=True);run.add_argument('--build-dir',type=Path,required=True)
    run.add_argument('--mode',choices=ALL_MODES,required=True);run.add_argument('--threshold',type=int,default=1)
    run.add_argument('--disable-heuristics',type=int,default=0);run.add_argument('--max-hashentries',type=int,default=1000000)
    run.add_argument('--chunksize',type=int,default=100000);run.add_argument('--json',action='store_true')
    compare=commands.add_parser('compare',help='Validate three two-stage runs and export exact CSV/JSON data',
                                epilog='For HTML dashboards, use mawi_global_analysis.aguri_selection_comparison v2 with --run-c-packet and --run-c-flow.')
    compare.add_argument('--root',type=Path,required=True);compare.add_argument('--dataset',required=True)
    for mode in ('packet','byte','flow'):compare.add_argument('--'+mode+'-run',required=True)
    action=compare.add_mutually_exclusive_group(required=True);action.add_argument('--validate-only',action='store_true');action.add_argument('--output-dir',type=Path)
    compare.add_argument('--chunksize',type=int,default=100000);compare.add_argument('--scratch-dir',type=Path)
    compare.add_argument('--max-ecdf-points',type=int,default=2000,help='Compatibility option; exact CSV/JSON results are independent of this limit');compare.add_argument('--json',action='store_true')
    verify=commands.add_parser('verify',help='Verify a completed comparison bundle without executing analysis')
    verify.add_argument('manifest',type=Path);verify.add_argument('--json',action='store_true')
    a=p.parse_args(argv)
    try:
        if a.command=='run':
            name=a.run or f'canonical-2stage-{a.mode}-t{a.threshold}-h{a.disable_heuristics}'+(f'-H{a.max_hashentries}' if a.max_hashentries!=1000000 else '')
            path=run_two_stage(a.root,a.dataset,name,a.flows,a.build_dir,mode=a.mode,threshold=a.threshold,heuristics=a.disable_heuristics,max_hashentries=a.max_hashentries,chunksize=a.chunksize)
            value={'status':'success','run_manifest':str(path)}
        elif a.command=='compare':
            kwargs=dict(packet_run=a.packet_run,byte_run=a.byte_run,flow_run=a.flow_run,chunksize=a.chunksize)
            if a.validate_only:value=validate_runs(a.root,a.dataset,**kwargs)
            else:
                path=generate_comparison(a.root,a.dataset,**kwargs,output_dir=a.output_dir,scratch_dir=a.scratch_dir,max_ecdf_points=a.max_ecdf_points)
                names=('summary.json','native_selection_summary.csv','native_prefix_stats.csv','native_pairwise_jaccard.csv',
                       'ecdf_counts.csv','native_ecdf_counts.csv','scope_comparison.csv','scope_ecdf_counts.csv')
                value={'status':'success','manifest':str(path),'comparison_manifest':str(path),
                       'artifacts':{name:str(path.with_name(name)) for name in names}}
        else:value=verify_manifest(a.manifest)
    except (ValueError,OSError,KeyError,sqlite3.Error) as e:
        p.exit(2,f'Two-stage comparison failed: {e}\n')
    print(json.dumps(value,indent=2,allow_nan=False) if a.json else json.dumps(value,ensure_ascii=False))
    return 0
