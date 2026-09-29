"""Bounded-memory SQLite aggregation for durable DITL observations."""
from __future__ import annotations

import sqlite3
from collections import Counter, deque
from pathlib import Path
from typing import Iterator

import pandas as pd

from mawi_global_analysis.flow import FlowKey
from mawi_global_analysis.one_packet_context import (
    ONE_PACKET_CONTEXT_COLUMNS, ONE_PACKET_SOURCE_CONTEXT_COLUMNS, _tcp_flags_text,
)


class SQLiteContextAggregator:
    """Ingest one chunk at a time and emit context rows without all-chunk frames."""
    def __init__(self, path: Path, cohort: pd.DataFrame) -> None:
        self.path = Path(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA cache_size=-65536")
        self.connection.execute("PRAGMA temp_store=FILE")
        self.connection.execute("CREATE TABLE cohort (id INTEGER PRIMARY KEY, source_flow_id, ts REAL, a_ip TEXT, a_port INTEGER, b_ip TEXT, b_port INTEGER, protocol INTEGER)")
        self.connection.execute("CREATE TABLE observations (ts REAL, a_ip TEXT, a_port INTEGER, b_ip TEXT, b_port INTEGER, protocol INTEGER, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, captured INTEGER, original INTEGER, ip_len INTEGER, payload INTEGER, flags INTEGER)")
        self.connection.execute("CREATE TABLE syns (ts REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER)")
        rows=[]
        for i,row in enumerate(cohort.itertuples(index=False)):
            key=FlowKey.from_packet(str(row.src_ip),int(row.src_port),str(row.dst_ip),int(row.dst_port),int(row.protocol))
            rows.append((i,row.source_flow_id,float(row.target_timestamp),key.endpoint_a.ip,key.endpoint_a.port,key.endpoint_b.ip,key.endpoint_b.port,key.protocol))
        self.connection.executemany("INSERT INTO cohort VALUES (?,?,?,?,?,?,?,?)",rows)
        self.connection.commit()

    def ingest_frames(self, targets: pd.DataFrame, syns: pd.DataFrame) -> None:
        rows=[]
        for row in targets.itertuples(index=False):
            key=FlowKey.from_packet(str(row.src_ip),int(row.src_port),str(row.dst_ip),int(row.dst_port),int(row.protocol))
            flags=None if pd.isna(row.tcp_flags_raw) else int(row.tcp_flags_raw)
            rows.append((float(row.timestamp),key.endpoint_a.ip,key.endpoint_a.port,key.endpoint_b.ip,key.endpoint_b.port,key.protocol,str(row.src_ip),int(row.src_port),str(row.dst_ip),int(row.dst_port),int(row.captured_frame_length),int(row.original_frame_length),int(row.ip_total_length),int(row.transport_payload_length),flags))
        self.connection.executemany("INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",rows)
        self.connection.executemany("INSERT INTO syns VALUES (?,?,?,?)",[(float(r.timestamp),str(r.src_ip),str(r.dst_ip),int(r.dst_port)) for r in syns.itertuples(index=False)])
        self.connection.commit()

    def compute(self) -> None:
        c=self.connection
        c.execute("CREATE INDEX obs_key ON observations(a_ip,a_port,b_ip,b_port,protocol,ts)")
        c.execute("CREATE INDEX syn_source ON syns(src_ip,ts)")
        c.execute("CREATE TABLE matches AS SELECT c.id,o.* FROM cohort c JOIN observations o ON (c.a_ip=o.a_ip AND c.a_port=o.a_port AND c.b_ip=o.b_ip AND c.b_port=o.b_port AND c.protocol=o.protocol AND c.ts=o.ts)")
        bad=c.execute("SELECT c.source_flow_id, count(m.id) FROM cohort c LEFT JOIN matches m ON c.id=m.id GROUP BY c.id HAVING count(m.id)!=1 LIMIT 1").fetchone()
        if bad:
            kind="missing" if bad[1]==0 else "ambiguous"
            raise ValueError(f"{kind} target matches for source_flow_id={bad[0]}")
        c.execute("CREATE INDEX match_key ON matches(a_ip,a_port,b_ip,b_port,protocol)")
        c.execute("CREATE TABLE tuple_stats AS SELECT m.id, count(o.ts) total, sum(o.ts<m.ts) before_count, sum(o.ts>m.ts) after_count, sum(o.src_ip=m.src_ip AND o.src_port=m.src_port) forward_count, max(CASE WHEN o.ts<m.ts THEN o.ts END) previous_ts, min(CASE WHEN o.ts>m.ts THEN o.ts END) next_ts, min(CASE WHEN o.ts<m.ts AND NOT(o.src_ip=m.src_ip AND o.src_port=m.src_port) THEN m.ts-o.ts END) reverse_before, min(CASE WHEN o.ts>m.ts AND NOT(o.src_ip=m.src_ip AND o.src_port=m.src_port) THEN o.ts-m.ts END) reverse_after, sum(o.ts<m.ts AND m.ts-o.ts<=1) b1, sum(o.ts<m.ts AND m.ts-o.ts<=10) b10, sum(o.ts<m.ts AND m.ts-o.ts<=60) b60, sum(o.ts<m.ts AND m.ts-o.ts<=300) b300, sum(o.ts>m.ts AND o.ts-m.ts<=1) a1, sum(o.ts>m.ts AND o.ts-m.ts<=10) a10, sum(o.ts>m.ts AND o.ts-m.ts<=60) a60, sum(o.ts>m.ts AND o.ts-m.ts<=300) a300 FROM matches m JOIN observations o USING(a_ip,a_port,b_ip,b_port,protocol) GROUP BY m.id")
        c.execute("CREATE TABLE source_context (id INTEGER PRIMARY KEY, applicable INTEGER, src_ip TEXT, p5 INTEGER,u5 INTEGER,i5 INTEGER,o5 INTEGER,p15 INTEGER,u15 INTEGER,i15 INTEGER,o15 INTEGER,p1 INTEGER,u1 INTEGER,i1 INTEGER,o1 INTEGER,p24 INTEGER,u24 INTEGER,i24 INTEGER,o24 INTEGER)")
        self._compute_source_context()
        c.commit()

    def _compute_source_context(self) -> None:
        """Sweep each source once; no target-by-SYN relation is materialized."""
        c = self.connection
        applicable = c.execute("SELECT id,ts,src_ip FROM matches WHERE flags & 2 != 0 AND flags & 16 = 0 ORDER BY src_ip,ts,id")
        grouped: dict[str, list[tuple[int,float]]] = {}
        for ident, ts, source in applicable:
            grouped.setdefault(source, []).append((ident, ts))
        # The result table makes publication one ordered scan.  This small
        # implementation is replaced by partitioned cursor sweeping in the
        # orchestration path before real-data use.
        for source, targets in grouped.items():
            events = c.execute("SELECT ts,dst_ip,dst_port FROM syns WHERE src_ip=? ORDER BY ts", (source,)).fetchall()
            day_pairs={(x[1],x[2]) for x in events}
            for ident, ts in targets:
                stats=[]
                for window in (300,900,3600):
                    selected=[x for x in events if abs(x[0]-ts)<=window]
                    pairs={(x[1],x[2]) for x in selected}
                    stats.extend((len(selected),len(pairs),len({x[1] for x in selected}),len({x[2] for x in selected})))
                stats.extend((len(events),len(day_pairs),len({x[1] for x in events}),len({x[2] for x in events})))
                c.execute("INSERT INTO source_context VALUES (?,?,?, ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(ident,1,source,*stats))
        c.execute("INSERT INTO source_context SELECT id,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM matches WHERE NOT(flags & 2 != 0 AND flags & 16 = 0)")

    def iter_context_rows(self) -> Iterator[dict[str,object]]:
        q="SELECT m.*,s.total,s.before_count,s.after_count,s.forward_count,s.previous_ts,s.next_ts,s.reverse_before,s.reverse_after,s.b1,s.b10,s.b60,s.b300,s.a1,s.a10,s.a60,s.a300 FROM matches m JOIN tuple_stats s ON m.id=s.id ORDER BY m.id"
        for r in self.connection.execute(q):
            (i,ts,aip,ap,bip,bp,proto,src,sp,dst,dp,captured,original,iplen,payload,flags,total,before,after,forward,prev,nxt,rb,ra,b1,b10,b60,b300,a1,a10,a60,a300)=r
            row=dict(zip(ONE_PACKET_CONTEXT_COLUMNS,[self.connection.execute("SELECT source_flow_id FROM cohort WHERE id=?",(i,)).fetchone()[0],ts,src,sp,dst,dp,captured,original,iplen,payload,flags,_tcp_flags_text(flags),total,before,after,forward,total-forward,prev,None if prev is None else ts-prev,nxt,None if nxt is None else nxt-ts,rb,ra,b1,b10,b60,b300,a1,a10,a60,a300]))
            yield row

    def iter_source_context_rows(self) -> Iterator[dict[str,object]]:
        query="SELECT c.source_flow_id,m.ts,s.* FROM matches m JOIN cohort c ON c.id=m.id JOIN source_context s ON s.id=m.id ORDER BY m.id"
        for source_id, ts, ident, applicable, src, *stats in self.connection.execute(query):
            yield dict(zip(ONE_PACKET_SOURCE_CONTEXT_COLUMNS,[source_id,ts,bool(applicable),src,*stats]))

    def close(self, *, delete: bool) -> None:
        self.connection.close()
        if delete and self.path.exists(): self.path.unlink()
