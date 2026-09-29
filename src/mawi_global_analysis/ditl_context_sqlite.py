"""Disk-backed, bounded-batch DITL context aggregation."""
from __future__ import annotations
import json
import os
import shutil
import sqlite3
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from pathlib import Path
import pandas as pd
from mawi_global_analysis.flow import FlowKey
from mawi_global_analysis.one_packet_context import ONE_PACKET_CONTEXT_COLUMNS, ONE_PACKET_SOURCE_CONTEXT_COLUMNS, _tcp_flags_text
from mawi_global_analysis.hashing import stable_json_hash


SQLITE_SCHEMA_VERSION = "ditl-context-sqlite-v1"
MINIMUM_FREE_BYTES = 2 * 1024**3


class InsufficientAggregationDiskSpace(ValueError):
    """Raised before ingestion when controlled spool space is insufficient."""


def require_aggregation_disk_space(directory: Path, metadata: list[dict]) -> int:
    """Reserve a conservative, metadata-derived SQLite and staging budget."""
    observed = sum(
        Path(record["path"]).stat().st_size
        for item in metadata for record in item["artifacts"].values()
    )
    required = max(MINIMUM_FREE_BYTES, observed * 4)
    available = shutil.disk_usage(directory).free
    if available < required:
        raise InsufficientAggregationDiskSpace(
            f"aggregation requires at least {required} free bytes; only {available} available"
        )
    return required

class SQLiteContextAggregator:
 def __init__(self,path:Path,cohort:pd.DataFrame,*,batch_size:int=10_000,identity:dict|None=None)->None:
  self.path,self.batch_size=Path(path),batch_size; self.checkpoint_path=self.path.with_suffix(".checkpoint.json")
  self.identity={"schema_version":SQLITE_SCHEMA_VERSION,**(identity or {})}
  self.ingested_chunks: list[str] = []
  if self.path.exists() or self.checkpoint_path.exists():
   if self._resume_if_compatible(): return
   self._quarantine_stale_state()
  self.connection=sqlite3.connect(self.path)
  c=self.connection; c.execute("PRAGMA cache_size=-65536"); c.execute("PRAGMA temp_store=FILE")
  c.execute("CREATE TABLE cohort(id INTEGER PRIMARY KEY,source_flow_id,ts REAL,a TEXT,ap INTEGER,b TEXT,bp INTEGER,p INTEGER)")
  c.execute("CREATE TABLE o(ts REAL,a TEXT,ap INTEGER,b TEXT,bp INTEGER,p INTEGER,src TEXT,sp INTEGER,dst TEXT,dp INTEGER,cap INTEGER,orig INTEGER,iplen INTEGER,payload INTEGER,flags INTEGER)")
  c.execute("CREATE TABLE syn(ts REAL,src TEXT,dst TEXT,dp INTEGER)")
  def rows():
   for i,r in enumerate(cohort.itertuples(index=False)):
    k=FlowKey.from_packet(str(r.src_ip),int(r.src_port),str(r.dst_ip),int(r.dst_port),int(r.protocol)); yield i,r.source_flow_id,float(r.target_timestamp),k.endpoint_a.ip,k.endpoint_a.port,k.endpoint_b.ip,k.endpoint_b.port,k.protocol
  self._insert("INSERT INTO cohort VALUES(?,?,?,?,?,?,?,?)",rows()); c.commit()
  self._write_checkpoint([])
 def _resume_if_compatible(self)->bool:
  try:
   record=json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
   if record.get("identity") != self.identity: return False
   connection=sqlite3.connect(self.path)
   if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",): connection.close(); return False
   self.connection=connection; self.ingested_chunks=list(record.get("ingested",[])); return True
  except (OSError,json.JSONDecodeError,sqlite3.Error): return False
 def _quarantine_stale_state(self)->None:
  for value in (self.path,self.checkpoint_path):
   if value.exists(): value.replace(value.with_name(value.name+".stale"))
 def _write_checkpoint(self, ingested:list[str])->None:
  temporary=self.checkpoint_path.with_suffix(".tmp")
  temporary.write_text(json.dumps({"identity":self.identity,"ingested":ingested},sort_keys=True),encoding="utf-8")
  os.replace(temporary,self.checkpoint_path)
 def _insert(self,sql:str,rows:Iterable[tuple])->None:
  batch=[]
  for r in rows:
   batch.append(r)
   if len(batch)>=self.batch_size: self.connection.executemany(sql,batch); batch.clear()
  if batch:self.connection.executemany(sql,batch)
 def ingest_frames(self,targets:pd.DataFrame,syns:pd.DataFrame,*,chunk_id:str|None=None)->None:
  def obs():
   for r in targets.itertuples(index=False):
    k=FlowKey.from_packet(str(r.src_ip),int(r.src_port),str(r.dst_ip),int(r.dst_port),int(r.protocol)); f=None if pd.isna(r.tcp_flags_raw) else int(r.tcp_flags_raw)
    yield float(r.timestamp),k.endpoint_a.ip,k.endpoint_a.port,k.endpoint_b.ip,k.endpoint_b.port,k.protocol,str(r.src_ip),int(r.src_port),str(r.dst_ip),int(r.dst_port),int(r.captured_frame_length),int(r.original_frame_length),int(r.ip_total_length),int(r.transport_payload_length),f
  self._insert("INSERT INTO o VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",obs()); self._insert("INSERT INTO syn VALUES(?,?,?,?)",((float(r.timestamp),str(r.src_ip),str(r.dst_ip),int(r.dst_port)) for r in syns.itertuples(index=False))); self.connection.commit()
  if chunk_id is not None:
   self.ingested_chunks.append(chunk_id); self._write_checkpoint(self.ingested_chunks)
 def compute(self)->None:
  c=self.connection;c.execute("CREATE INDEX ok ON o(a,ap,b,bp,p,ts)");c.execute("CREATE INDEX sk ON syn(src,ts)")
  c.execute("CREATE TABLE m AS SELECT c.id,o.* FROM cohort c JOIN o ON c.a=o.a AND c.ap=o.ap AND c.b=o.b AND c.bp=o.bp AND c.p=o.p AND c.ts=o.ts")
  bad=c.execute("SELECT c.source_flow_id,count(m.id) FROM cohort c LEFT JOIN m ON c.id=m.id GROUP BY c.id HAVING count(m.id)!=1 LIMIT 1").fetchone()
  if bad:raise ValueError(f"{'missing' if bad[1]==0 else 'ambiguous'} target matches for source_flow_id={bad[0]}")
  c.execute("CREATE INDEX mk ON m(a,ap,b,bp,p)")
  c.execute("CREATE TABLE t AS SELECT m.id,count(o.ts) total,sum(o.ts<m.ts) bef,sum(o.ts>m.ts) aft,sum(o.src=m.src AND o.sp=m.sp) fwd,max(CASE WHEN o.ts<m.ts THEN o.ts END) prev,min(CASE WHEN o.ts>m.ts THEN o.ts END) nxt,min(CASE WHEN o.ts<m.ts AND NOT(o.src=m.src AND o.sp=m.sp) THEN m.ts-o.ts END) rb,min(CASE WHEN o.ts>m.ts AND NOT(o.src=m.src AND o.sp=m.sp) THEN o.ts-m.ts END) ra,sum(o.ts<m.ts AND m.ts-o.ts<=1)b1,sum(o.ts<m.ts AND m.ts-o.ts<=10)b10,sum(o.ts<m.ts AND m.ts-o.ts<=60)b60,sum(o.ts<m.ts AND m.ts-o.ts<=300)b300,sum(o.ts>m.ts AND o.ts-m.ts<=1)a1,sum(o.ts>m.ts AND o.ts-m.ts<=10)a10,sum(o.ts>m.ts AND o.ts-m.ts<=60)a60,sum(o.ts>m.ts AND o.ts-m.ts<=300)a300 FROM m JOIN o USING(a,ap,b,bp,p) GROUP BY m.id")
  self._source();c.commit()
 def _source(self)->None:
  c=self.connection
  c.execute("CREATE TEMP TABLE day AS SELECT n.src,n.n,p.u,n.i,n.p FROM (SELECT src,count(*) n,count(DISTINCT dst)i,count(DISTINCT dp)p FROM syn GROUP BY src)n LEFT JOIN (SELECT src,count(*)u FROM (SELECT DISTINCT src,dst,dp FROM syn)GROUP BY src)p ON n.src=p.src")
  for w,name in ((300,'w5'),(900,'w15'),(3600,'w1')):
   c.execute(f"CREATE TABLE {name}(id PRIMARY KEY,n,u,i,p)"); q=c.execute("SELECT id,ts,src FROM m WHERE flags IS NOT NULL AND(flags&2)!=0 AND(flags&16)=0 ORDER BY src,ts,id")
   current=None;ev=iter(());next_ev=None;active=deque();pair=Counter();ip=Counter();port=Counter();out=[]
   for ident,ts,src in q:
    if src!=current: current=src;ev=iter(c.execute("SELECT ts,dst,dp FROM syn WHERE src=? ORDER BY ts",(src,)));next_ev=next(ev,None);active.clear();pair.clear();ip.clear();port.clear()
    while next_ev and next_ev[0]<=ts+w:
     x=next_ev;active.append(x);pair[(x[1],x[2])]+=1;ip[x[1]]+=1;port[x[2]]+=1;next_ev=next(ev,None)
    while active and active[0][0]<ts-w:
     x=active.popleft();pair[(x[1],x[2])]-=1;ip[x[1]]-=1;port[x[2]]-=1
     if not pair[(x[1],x[2])]:del pair[(x[1],x[2])]
     if not ip[x[1]]:del ip[x[1]]
     if not port[x[2]]:del port[x[2]]
    out.append((ident,len(active),len(pair),len(ip),len(port)))
    if len(out)>=self.batch_size:c.executemany(f"INSERT INTO {name} VALUES(?,?,?,?,?)",out);out.clear()
   if out:c.executemany(f"INSERT INTO {name} VALUES(?,?,?,?,?)",out)
  c.execute("CREATE TABLE s AS SELECT m.id,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN 1 ELSE 0 END app,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN m.src END src,w5.n,w5.u,w5.i,w5.p,w15.n,w15.u,w15.i,w15.p,w1.n,w1.u,w1.i,w1.p,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN day.n END,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN day.u END,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN day.i END,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN day.p END FROM m LEFT JOIN w5 ON m.id=w5.id LEFT JOIN w15 ON m.id=w15.id LEFT JOIN w1 ON m.id=w1.id LEFT JOIN day ON m.src=day.src")
 def iter_context_rows(self)->Iterator[dict]:
  q="SELECT c.source_flow_id,m.*,t.* FROM m JOIN cohort c ON c.id=m.id JOIN t ON m.id=t.id ORDER BY m.id"
  for r in self.connection.execute(q):
   sid,i,ts,a,ap,b,bp,p,src,sp,dst,dp,cap,orig,iplen,pay,flags,_,total,bef,aft,fwd,prev,nxt,rb,ra,b1,b10,b60,b300,a1,a10,a60,a300=r;yield dict(zip(ONE_PACKET_CONTEXT_COLUMNS,[sid,ts,src,sp,dst,dp,cap,orig,iplen,pay,flags,_tcp_flags_text(flags),total,bef,aft,fwd,total-fwd,prev,None if prev is None else ts-prev,nxt,None if nxt is None else nxt-ts,rb,ra,b1,b10,b60,b300,a1,a10,a60,a300]))
 def iter_source_context_rows(self)->Iterator[dict]:
  for sid,ts,*r in self.connection.execute("SELECT c.source_flow_id,m.ts,s.* FROM m JOIN cohort c ON c.id=m.id JOIN s ON s.id=m.id ORDER BY m.id"):yield dict(zip(ONE_PACKET_SOURCE_CONTEXT_COLUMNS,[sid,ts,bool(r[1]),r[2],*r[3:]]))
 def close(self,*,delete:bool)->None:
  self.connection.close()
  if delete and self.path.exists():self.path.unlink()
