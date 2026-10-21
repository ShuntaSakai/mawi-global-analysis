"""Independent linear integer-bin plots and one-cell-per-target notebooks."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3

import numpy as np
import pandas as pd

from mawi_global_analysis.flow_length import GROUPS
from mawi_global_analysis.hashing import sha256_file


@dataclass
class IntegerDistribution:
    counts: pd.DataFrame
    statistics: pd.DataFrame
    x_max: int


@dataclass
class IndividualPlots:
    distribution: IntegerDistribution
    figures: dict
    saved_paths: list[Path]


def _exact_path(result) -> Path:
    path = result.exact_counts_path
    if path is None or Path(path).suffix != '.sqlite':
        raise ValueError('整数packet_count別のexact度数がありません。粗いflow_length_histogram.csvから'
                         '補間しません。exact_cache_dirを指定して既存CSVの追加集計が必要です。PCAP再処理は不要です')
    path = Path(path)
    try:
        record = json.loads((path.parent/'cache_manifest.json').read_text(encoding='utf-8'))
        if sha256_file(path) != record['sha256']['exact_counts.sqlite']:
            raise ValueError('exact counts checksum mismatch')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f'exact整数度数が破損または不整合です: {path}: {exc}') from exc
    return path


def integer_distribution(result, target: str, *, x_max: int | None = None) -> IntegerDistribution:
    """Sparse non-zero integer bins; implicit missing integers are exact zeroes.

    Percentages use all flows in each group, including flows above x_max.
    Full range allocates no array proportional to the maximum packet_count.
    """
    if x_max is not None and (type(x_max) is not int or x_max < 1):
        raise ValueError('X_MAX must be None or a positive integer')
    if target not in [*result.inspection.selected_prefixes, 'selected_union', 'overall_ipv4']:
        raise ValueError(f'未知の対象です: {target}')
    path = _exact_path(result)
    statistics = result.summary.loc[result.summary.prefix.eq(target)].copy()
    if len(statistics) != 3 or set(statistics.group) != set(GROUPS):
        raise ValueError(f'対象の3群のsummaryが不正です: {target}')
    rows, outside = [], {}
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)
    try:
        maximum = db.execute('SELECT MAX(packets) FROM counts WHERE prefix=?', (target,)).fetchone()[0]
        limit = x_max if x_max is not None else max(3, maximum or 0)
        for group, condition in [('Raw','1'),('removed','removed=1'),('retained','removed=0')]:
            n = int(statistics.loc[statistics.group.eq(group), 'flow_count'].iloc[0])
            actual = db.execute(f'SELECT COALESCE(SUM(n),0) FROM counts WHERE prefix=? AND {condition}', (target,)).fetchone()[0]
            if actual != n:
                raise ValueError(f'exact counts / summary count mismatch: {target}/{group}')
            outside[group] = db.execute(f'SELECT COALESCE(SUM(n),0) FROM counts WHERE prefix=? AND {condition} AND packets>?', (target,limit)).fetchone()[0]
            for packets, count in db.execute(f'''SELECT packets,SUM(n) FROM counts
                    WHERE prefix=? AND {condition} AND packets<=? GROUP BY packets ORDER BY packets''', (target,limit)):
                rows.append({'group': group, 'packet_count': packets, 'flow_count': count,
                             'percent': count/n*100 if n else float('nan')})
    finally:
        db.close()
    statistics['outside_flow_count'] = statistics.group.map(outside)
    statistics['outside_rate'] = statistics.outside_flow_count / statistics.flow_count.replace(0, np.nan)
    return IntegerDistribution(pd.DataFrame(rows, columns=['group','packet_count','flow_count','percent']),
                               statistics, limit)


def _number(value):
    return 'NA' if pd.isna(value) else f'{value:,.4g}'


def plot_individual_target(result, target: str, *, x_max: int | None = None,
                           y_axis: str = 'count', output_dir: Path | None = None) -> IndividualPlots:
    """Three separate figures, width-one bins, and linear x/y axes throughout."""
    import matplotlib.pyplot as plt
    from matplotlib.collections import PolyCollection
    from matplotlib.ticker import MaxNLocator

    if y_axis not in ('count','percent'):
        raise ValueError('y_axis must be count or percent')
    data = integer_distribution(result, target, x_max=x_max)
    colors = {'Raw':'#4477AA','removed':'#CC6677','retained':'#228833'}
    names = {'Raw':'Raw','removed':'Broad removed','retained':'Broad retained'}
    figures, saved = {}, []
    output = Path(output_dir).expanduser().resolve() if output_dir is not None else None
    paths = {}
    if output is not None:
        # New filenames are disjoint from the existing comparison PNGs.
        slug = target.replace('/','_')
        zoom = 'full' if x_max is None else f'xmax_{x_max}'
        paths = {g: output/f'individual_{slug}_{g}_{zoom}_{y_axis}.png' for g in GROUPS}
        if any(path.exists() for path in paths.values()):
            raise FileExistsError('個別PNGは上書きしません。別の保存先または表示範囲を指定してください')
        output.mkdir(parents=True, exist_ok=True)
    stats = data.statistics.set_index('group')
    raw_n = int(stats.loc['Raw','flow_count'])
    rate = stats.loc['Raw','removal_rate']
    rate_label = 'NA' if pd.isna(rate) else f'{rate:.2%}'
    evidence = ' | SYNTHETIC DEMO' if result.inspection.manifest.get('evidence_level') == 'synthetic_demo' else ''
    try:
        for group in GROUPS:
            fig, axis = plt.subplots(figsize=(11,4.6))
            figures[group] = fig
            points = data.counts.loc[data.counts.group.eq(group)]
            values = points['flow_count' if y_axis == 'count' else 'percent'].to_numpy()
            x = points.packet_count.to_numpy(dtype=float)
            if len(x):
                # Width-one rectangles for occupied bins only. This preserves zero
                # bins while avoiding millions of empty bars on long linear tails.
                vertices = np.stack([np.column_stack([x-.5,np.zeros(len(x))]),
                    np.column_stack([x-.5,values]), np.column_stack([x+.5,values]),
                    np.column_stack([x+.5,np.zeros(len(x))])], axis=1)
                axis.add_collection(PolyCollection(vertices, facecolor=colors[group],
                                                    edgecolor='white', linewidth=.3))
                ymax = float(values.max())
            else:
                ymax = 0
            axis.set_xscale('linear')
            axis.set_yscale('linear')
            axis.set_xlim(.5, data.x_max+.5)
            axis.set_ylim(0, max(1,ymax*1.35))
            if data.x_max <= 20:
                axis.set_xticks(range(1,data.x_max+1))
            elif data.x_max <= 200:
                regular = MaxNLocator(nbins=10, integer=True).tick_values(.5,data.x_max+.5)
                axis.set_xticks([1,2,3]+[v for v in regular if 10 <= v <= data.x_max])
                axis.tick_params(axis='x', labelsize=8)
            else:
                axis.xaxis.set_major_locator(MaxNLocator(nbins=10, integer=True))
            if y_axis == 'count':
                axis.yaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
            axis.set_xlabel('Packets per flow (packet_count) — integer bins of width 1')
            axis.set_ylabel('Flow count' if y_axis == 'count' else 'Flows within full group (%)')
            axis.grid(axis='y', alpha=.2)
            s = stats.loc[group]
            one = 'NA' if pd.isna(s.one_packet_rate) else f'{s.one_packet_rate:.2%}'
            outside = 'NA' if pd.isna(s.outside_rate) else f'{s.outside_rate:.2%}'
            axis.set_title(f'{target} | {names[group]}{evidence}\nRaw n={raw_n:,}; removed / Raw={rate_label}', fontsize=11)
            axis.text(.99,.98, f'n={int(s.flow_count):,}; median={_number(s["median"])}; '
                      f'p95={_number(s.p95)}; 1 packet={one}\n'
                      f'outside (> {data.x_max:,} packets): {int(s.outside_flow_count):,} ({outside})',
                      transform=axis.transAxes, ha='right', va='top', fontsize=9,
                      bbox={'facecolor':'white','alpha':.9,'edgecolor':'none'})
            if not int(s.flow_count):
                axis.text(.5,.45,'No flows',transform=axis.transAxes,ha='center')
            fig.tight_layout()
            if output is not None:
                with paths[group].open('xb') as stream:
                    fig.savefig(stream,format='png',dpi=140,bbox_inches='tight')
                saved.append(paths[group])
    except BaseException:
        for fig in figures.values():
            plt.close(fig)
        raise
    return IndividualPlots(data,figures,saved)


def write_individual_notebook(result, destination: Path, *, x_max: int | None = None) -> Path:
    """Generate a native Markdown/code pair per selected target, without a fixed N.

    Does not edit the source notebook or execute heavy analysis. Real-data views
    require a matching exact cache and stop rather than scan flows on a miss.
    """
    path = _exact_path(result)
    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise FileExistsError(destination)
    targets = [*result.inspection.selected_prefixes,'selected_union','overall_ipv4']
    root = result.inspection.manifest_path.parents[3]
    run = result.inspection.manifest_path.parent.name
    dataset = result.inspection.manifest['dataset_id']
    code_root = Path(__file__).resolve().parents[2]
    synthetic = result.inspection.manifest.get('evidence_level') == 'synthetic_demo'
    cells = []
    def add(kind, text, target=None):
        metadata = {'flow_length_target':target} if target else {}
        cell = {'cell_type':kind,'id':f'individual-{len(cells):03d}',
                'metadata':metadata,'source':text.splitlines(True)}
        if kind == 'code':
            cell.update(execution_count=None,outputs=[])
        cells.append(cell)
    add('markdown', '# 個別フロー長ヒストグラム\n\n'
        '06 Notebookの選定台帳から生成した対象別ビューです。各対象の3群を別々の図に描きます。\n'
        '`X_MAX=None` は全範囲、`100` / `200` は拡大表示。縦軸は `Y_AXIS="count"` または `"percent"`。\n'
        '再集計せず、設定セルと目的の対象セルだけを再実行できます。線形・幅1の整数ビン、範囲外件数は必ず表示します。\n'
        'PNG保存時は `INDIVIDUAL_OUTPUT_DIR` を指定してください。既存PNGは上書きしません。\n'
        + ('\n**SYNTHETIC DEMO — 実データ再現ではありません。**\n' if synthetic else
           '\n一致する整数度数cacheがない場合は停止します。06 Notebookで既存CSVの追加集計が必要です。\n'))
    setup = f'''from pathlib import Path
import sys
sys.path.insert(0, {str(code_root/'src')!r})
import matplotlib.pyplot as plt
from IPython.display import display, Markdown
from mawi_global_analysis.flow_length_individual import plot_individual_target
X_MAX = {x_max!r}
Y_AXIS = 'count'
INDIVIDUAL_OUTPUT_DIR = None  # 保存する場合は新しいフォルダ
rendered_targets = []
result = None
_view_valid = False
'''
    if synthetic:
        setup += '''import tempfile
from mawi_global_analysis.flow_length import make_demo_run, analyze_run
_demo = tempfile.TemporaryDirectory(prefix='mawi-individual-demo-')
_root = Path(_demo.name)
_dataset, _run = make_demo_run(_root)
result = analyze_run(_root, _dataset, _run, exact_cache_dir=_root/'integer_cache')
'''
    else:
        setup += f'''from mawi_global_analysis.flow_length_cache import load_cached_run
result = load_cached_run(Path({str(root)!r}), {dataset!r}, {run!r}, Path({str(path.parent.parent)!r}))
'''
    setup += '''_view_valid = True
def render_target(target):
    if not _view_valid or result is None:
        raise RuntimeError('入力検査に失敗しています。結果を使う前に設定セルを再実行してください。')
    view = plot_individual_target(result, target, x_max=X_MAX, y_axis=Y_AXIS,
                                  output_dir=Path(INDIVIDUAL_OUTPUT_DIR) if INDIVIDUAL_OUTPUT_DIR else None)
    display(view.distribution.statistics)
    for fig in view.figures.values():
        display(fig)
        plt.close(fig)
    rendered_targets.append(target)
'''
    add('code', setup)
    for i,target in enumerate(targets,1):
        add('markdown',f'## {i}. {target}\n\nRaw／Broad removed／Broad retainedを独立表示します。\n',target)
        add('code',f'render_target({target!r})\n',target)
    notebook = {'cells':cells,'nbformat':4,'nbformat_minor':5,'metadata':{
        'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},
        'language_info':{'name':'python'},
        'flow_length_source':{'dataset_id':dataset,'run_name':run,
                             'selected_prefix_count':len(result.inspection.selected_prefixes)}}}
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open('x',encoding='utf-8') as stream:
        json.dump(notebook,stream,ensure_ascii=False,indent=1)
        stream.write('\n')
    return destination
