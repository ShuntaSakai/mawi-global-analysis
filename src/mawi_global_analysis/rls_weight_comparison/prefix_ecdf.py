"""Bounded display curves from saved exact /24 frequencies, never raw flows."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
import tempfile

from mawi_global_analysis.normalized24.statistics import FREQUENCY_COLUMNS
from .metrics import MODES, write_ecdf

SCHEMA = 'rls-per-prefix-ecdf-v1'
POINT_BUDGET = 200_000
PER_PREFIX_LIMIT = 200


def display_limit(prefix_count: int) -> int:
    """Two endpoints minimum; otherwise adapt to a shared HTML point budget."""
    return min(PER_PREFIX_LIMIT, max(2, POINT_BUDGET // max(1, prefix_count)))


def build_prefix_ecdfs(base: Path, prefixes: list[dict], *, scratch_dir: Path | None = None,
                       prefix_field: str = 'prefix_24', membership_scope: str = 'normalized_24') -> dict:
    """Validate exact saved populations and store only bounded, lazily decoded points.

    Each /24 is stored once. Mode copies must agree at EVERY distinct packet size,
    including when totals/quantiles happen to match. Temporary SQLite holds all
    frequency rows; Python retains only selected points and small prefix records.
    """
    if (prefix_field,membership_scope) not in (('prefix_24','normalized_24'),('prefix','native')):
        raise ValueError('unsupported prefix field / membership scope')
    cards={row[prefix_field]:row for row in prefixes}
    if len(cards)!=len(prefixes):
        raise ValueError('per_prefix_ecdf: duplicate prefix records')
    display=_build_frequency_curves(base,cards,MODES,scratch_dir=scratch_dir)
    return dict(schema_version=SCHEMA if membership_scope=='normalized_24' else 'rls-native-prefix-ecdf-v1',
                **display,
                exact_source=('native/' if membership_scope=='native' else '')+'modes/<mode>/frequencies.csv; unchanged full integer frequencies',
                membership=('Each /24: canonical src OR dst, flow_id unique within /24; flows can occur in multiple /24s.' if membership_scope=='normalized_24' else 'Each native prefix: canonical src OR dst, flow_id unique within prefix; flows can occur in multiple prefixes.'),
                encoding=('One curve per unique /24' if membership_scope=='normalized_24' else 'One curve per unique native prefix')+'; encoded_points is JSON decoded on selection only.',
                sampling='Uniform observed-size rank, both endpoints retained; lower HV bound and next-point upper envelope.')


def _build_frequency_curves(base: Path, cards: dict, modes: tuple[str, ...], *, scratch_dir: Path | None = None) -> dict:
    """Check exact frequency CSVs and return one lazy display curve per selected key."""
    curves={};limit=display_limit(len(cards));point_total=0
    with tempfile.TemporaryDirectory(prefix='prefix-ecdf-',dir=scratch_dir) as temporary:
        db=sqlite3.connect(Path(temporary)/'frequencies.sqlite')
        try:
            db.execute('PRAGMA cache_size=-32768');db.execute('PRAGMA temp_store=FILE')
            db.execute('CREATE TABLE frequencies(distribution TEXT,packets INTEGER,n INTEGER, PRIMARY KEY(distribution,packets)) WITHOUT ROWID')
            for mode in modes:
                with (Path(base)/'modes'/mode/'frequencies.csv').open(encoding='utf-8',newline='') as stream:
                    reader=csv.DictReader(stream,strict=True)
                    if reader.fieldnames!=list(FREQUENCY_COLUMNS):
                        raise ValueError(f'{mode}.frequencies: unsupported columns')
                    for row in reader:
                        prefix=row['distribution']
                        if prefix in ('overall_ipv4','selected_union'):
                            continue
                        if prefix not in cards or mode not in cards[prefix]['modes']:
                            raise ValueError(f'{mode}.{prefix}: unselected prefix frequency rows')
                        packets,n=int(row['packet_count']),int(row['frequency'])
                        if packets<=0 or n<=0:
                            raise ValueError(f'{mode}.{prefix}: positive integer frequencies required')
                        try:
                            db.execute('INSERT INTO frequencies VALUES (?,?,?)',(mode+':'+prefix,packets,n))
                        except sqlite3.IntegrityError as exc:
                            raise ValueError(f'{mode}.{prefix}: duplicate packet_count') from exc
            for prefix,card in cards.items():
                selected=card['modes'];stats=card['stats']
                if not selected or any(m not in modes for m in selected):
                    raise ValueError(f'{prefix}: invalid selected modes')
                first=selected[0]+':'+prefix
                for mode in selected:
                    key=mode+':'+prefix
                    count=packet_total=0
                    for packets,n in db.execute('SELECT packets,n FROM frequencies WHERE distribution=? ORDER BY packets',(key,)):
                        count+=n;packet_total+=packets*n
                    if count!=int(stats['flow_count']):
                        raise ValueError(f'{mode}.{prefix}: frequencies sum {count} differs from flow_count {stats["flow_count"]}')
                    if packet_total!=int(stats['packet_total']):
                        raise ValueError(f'{mode}.{prefix}: frequency weighted total differs from packet_total')
                    if key!=first:
                        for a,b in ((first,key),(key,first)):
                            diff=db.execute('SELECT packets,n FROM frequencies WHERE distribution=? EXCEPT SELECT packets,n FROM frequencies WHERE distribution=?',(a,b)).fetchone()
                            if diff:
                                raise ValueError(f'{mode}.{prefix}: exact frequencies differ between modes')
                curve=write_ecdf(db,{first:int(stats['flow_count'])},None,max_points=limit)[first]
                points=curve.pop('points')
                # Nested JSON stays a string during initial page parse; decode only
                # the curves needed for the current view.
                curve['encoded_points']=json.dumps(points,separators=(',',':'),allow_nan=False)
                curves[prefix]=curve;point_total+=len(points)
        finally:
            db.close()
    return dict(prefix_count=len(cards),curves=curves,max_points_per_prefix=limit,
                point_budget=POINT_BUDGET,displayed_point_count=point_total,
                point_upper_bound=max(POINT_BUDGET,2*len(cards)))
