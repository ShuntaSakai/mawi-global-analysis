"""Disk-backed exact descriptive metrics, with bounded browser display samples."""
from __future__ import annotations

import csv
from fractions import Fraction
from itertools import combinations

MODES = ('packet','byte','flow')
BITS = {'packet':1,'byte':2,'flow':4}
ECDF_COLUMNS = ('distribution','packet_count','frequency','cumulative_count','total_flow_count','cumulative_fraction')


def ratio(numerator: int, denominator: int) -> float | None:
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError(f'invalid subset ratio: {numerator}/{denominator}')
    return numerator/denominator if denominator else None


def flow_jaccards(db) -> list[dict]:
    """flow_sets has one disk row per flow ID and a three-mode membership mask."""
    rows=[]
    for a,b in combinations(MODES,2):
        intersection=db.execute('SELECT COUNT(*) FROM flow_sets WHERE mask & ? != 0 AND mask & ? != 0',
                                 (BITS[a],BITS[b])).fetchone()[0]
        union=db.execute('SELECT COUNT(*) FROM flow_sets WHERE mask & ? != 0',(BITS[a]|BITS[b],)).fetchone()[0]
        rows.append(dict(mode_a=a,mode_b=b,set_kind='flow_id',intersection_count=intersection,
                         union_count=union,jaccard=ratio(intersection,union)))
    return rows


def ks_distance(db, left: str, right: str) -> dict:
    """Merge exact ordered integer frequencies. No p-value or histogram approximation."""
    count=lambda name:db.execute('SELECT COALESCE(SUM(n),0) FROM frequencies WHERE distribution=?',(name,)).fetchone()[0]
    na,nb=count(left),count(right)
    if not na or not nb:
        return dict(ks_distance=None,ks_numerator=None,ks_denominator=None)
    a=iter(db.execute('SELECT packets,n FROM frequencies WHERE distribution=? ORDER BY packets',(left,)))
    b=iter(db.execute('SELECT packets,n FROM frequencies WHERE distribution=? ORDER BY packets',(right,)))
    ar,br=next(a,None),next(b,None)
    ca=cb=maximum=0
    while ar is not None or br is not None:
        x=min(r[0] for r in (ar,br) if r is not None)
        if ar is not None and ar[0]==x:
            ca+=ar[1];ar=next(a,None)
        if br is not None and br[0]==x:
            cb+=br[1];br=next(b,None)
        maximum=max(maximum,abs(ca*nb-cb*na))
    exact=Fraction(maximum,na*nb)
    return dict(ks_distance=float(exact),ks_numerator=str(exact.numerator),ks_denominator=str(exact.denominator))


def write_ecdf(db, totals: dict[str,int], stream, *, max_points: int = 2000) -> dict:
    """Stream every exact point to CSV; keep only bounded genuine points for HTML.

    When sampled, HV steps through retained points are a lower bound; the next
    retained cumulative value bounds each interval from above. Width is recorded.
    """
    if type(max_points) is not int or not 2 <= max_points <= 50_000:
        raise ValueError('max_ecdf_points must be an integer in [2,50000]')
    writer=csv.writer(stream,lineterminator='\n');writer.writerow(ECDF_COLUMNS)
    curves={}
    for name,total in totals.items():
        count=db.execute('SELECT COUNT(*) FROM frequencies WHERE distribution=?',(name,)).fetchone()[0]
        selected={i*(count-1)//(max_points-1) for i in range(max_points)} if count>max_points else None
        points=[];cumulative=0
        for index,(packets,n) in enumerate(db.execute('SELECT packets,n FROM frequencies WHERE distribution=? ORDER BY packets',(name,))):
            cumulative+=n
            if not total:
                raise ValueError(f'{name}: frequency rows with zero flow_count')
            fraction=ratio(cumulative,total)
            writer.writerow((name,packets,n,cumulative,total,fraction))
            if selected is None or index in selected:
                points.append(dict(packet_count=str(packets),frequency=str(n),
                    cumulative_count=str(cumulative),cumulative_fraction=fraction))
        if cumulative!=total:
            raise ValueError(f'{name}: frequencies sum {cumulative} differs from flow_count {total}')
        width=max((int(b['cumulative_count'])-int(a['cumulative_count'])
                   for a,b in zip(points,points[1:])),default=0) if selected else 0
        curves[name]=dict(total_flow_count=str(total),exact_point_count=count,
            displayed_point_count=len(points),simplified=selected is not None,
            error_bound=width/total if total else None,
            error_bound_numerator=str(width),error_bound_denominator=str(total),points=points)
    return curves
