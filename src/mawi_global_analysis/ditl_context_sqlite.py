"""Disk-backed, bounded-batch DITL context aggregation."""

from __future__ import annotations
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import islice
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from pathlib import Path
import pandas as pd
from mawi_global_analysis.ditl_chunks import validate_chunk_id
from mawi_global_analysis.flow import FlowKey
from mawi_global_analysis.one_packet_context import (
    ONE_PACKET_CONTEXT_COLUMNS,
    ONE_PACKET_SOURCE_CONTEXT_COLUMNS,
    _tcp_flags_text,
)
from mawi_global_analysis.hashing import stable_json_hash
from mawi_global_analysis.hashing import sha256_file


SQLITE_SCHEMA_VERSION = "ditl-context-sqlite-v1"
MINIMUM_FREE_BYTES = 2 * 1024**3

# These deliberately rounded planning coefficients reserve space rather than
# predicting SQLite's exact on-disk layout.  They cover the tables below plus
# row headers and normal variable-width values.  The preflight is based only
# on durable cache metadata and file sizes; it never loads observations.
COHORT_ROW_BYTES = 160
TARGET_OBSERVATION_ROW_BYTES = 192
SOURCE_SYN_ROW_BYTES = 128
LEDGER_ROW_BYTES = 2_048
DERIVED_TARGET_ROW_BYTES = 384
SPILL_SOURCE_ROW_BYTES = 512
# Inclusive centered windows can intersect one extra quarter-hour at endpoints.
SOURCE_WINDOW_CHUNK_SPANS = ((300, 2), (900, 3), (3600, 9))
COHORT_CSV_ROW_BYTES = 512
CONTEXT_CSV_ROW_BYTES = 1_024
SOURCE_CONTEXT_CSV_ROW_BYTES = 768
MANIFEST_STAGING_BYTES = 4 * 1024**2
SQLITE_INDEX_MULTIPLIER = 1.0
SQLITE_TEMP_JOURNAL_MULTIPLIER = 0.75
SAFETY_MARGIN_FRACTION = 0.25


@dataclass(frozen=True)
class AggregationDiskEstimate:
    """Explainable conservative space reservation for one DITL aggregation."""

    cache_observation_bytes: int
    sqlite_raw_bytes: int
    sqlite_index_bytes: int
    derived_bytes: int
    spill_headroom_bytes: int
    sqlite_temp_journal_bytes: int
    publication_bytes: int
    safety_margin_bytes: int
    required_bytes: int
    available_bytes: int


class InsufficientAggregationDiskSpace(ValueError):
    """Raised before ingestion when controlled spool space is insufficient."""


def aggregation_code_identity() -> str:
    """Identity temporary state by every source that changes final values."""
    module = Path(__file__)
    return stable_json_hash(
        {
            "sqlite_aggregation": sha256_file(module),
            "streaming_publication": sha256_file(
                module.with_name("one_packet_context_run.py")
            ),
        }
    )


def _non_negative_row_count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _metadata_artifact_bytes(metadata: dict) -> int:
    artifacts = metadata.get("artifacts", {})
    if not isinstance(artifacts, dict):
        raise ValueError("chunk metadata artifacts must be a mapping")
    total = 0
    for artifact in artifacts.values():
        if not isinstance(artifact, dict):
            raise ValueError("chunk metadata artifact must be a mapping")
        path = artifact.get("path")
        if path is not None:
            total += Path(path).stat().st_size
    return total


def _ordered_source_syn_counts(metadata: Iterable[dict]) -> list[int]:
    """Validate consecutive quarter-hour metadata; never silently reorder it.

    Small contiguous subsets are supported for fixtures. The production caller
    supplies the complete fixed 96-slot day plan before any SQLite ingestion.
    """
    counts: list[int] = []
    previous = None
    day = None
    for item in metadata:
        if not isinstance(item, dict):
            raise ValueError("chunk metadata must be a mapping")
        chunk_id = validate_chunk_id(item.get("chunk_id"))
        timestamp = datetime.strptime(chunk_id, "%Y%m%d%H%M")
        if day is None:
            day = timestamp.date()
        if timestamp.date() != day or (
            previous is not None and timestamp != previous + timedelta(minutes=15)
        ):
            raise ValueError(
                "chunk metadata must have unique chronological consecutive "
                "15-minute chunk IDs within one day"
            )
        counts.append(_non_negative_row_count(
            item.get("source_syn_observation_row_count"),
            "source_syn_observation_row_count",
        ))
        previous = timestamp
    return counts


def max_rolling_source_syn_rows(metadata: Iterable[dict], chunk_span: int) -> int:
    """Maximum total SYN rows in any ``chunk_span`` consecutive chunk slots.

    Non-negative counts make shorter boundary ranges no larger than a full
    span. If fewer chunks exist, their total is the conservative bound.
    This uses metadata only and assumes nothing about source distribution.
    """
    if isinstance(chunk_span, bool) or not isinstance(chunk_span, int) or chunk_span <= 0:
        raise ValueError("chunk_span must be a positive integer")
    counts = _ordered_source_syn_counts(metadata)
    rolling = maximum = 0
    for index, count in enumerate(counts):
        rolling += count
        if index >= chunk_span:
            rolling -= counts[index - chunk_span]
        maximum = max(maximum, rolling)
    return maximum


def estimate_spill_headroom_bytes(metadata: Iterable[dict]) -> int:
    """Reserve the largest live source window, including its distinct counters.

    Requires observations partitioned into the fixed 15-minute DITL chunks;
    operational IDs alone do not validate packet timestamps.
    Source completion deletes spill state and expiration precedes insertion,
    allowing SQLite pages to be reused across sources and window passes. One
    source's live rows cannot exceed all sources' rows in intersecting chunks.
    The 512 B/row coefficient includes event and pair/IP/port state plus indexes.
    No VACUUM or source-distribution assumption is required.
    """
    items = list(metadata)
    return max(
        max_rolling_source_syn_rows(items, span)
        for _, span in SOURCE_WINDOW_CHUNK_SPANS
    ) * SPILL_SOURCE_ROW_BYTES


def estimate_aggregation_disk_space(
    metadata: Iterable[dict],
    *,
    cohort_row_count: int,
    available_bytes: int,
) -> AggregationDiskEstimate:
    """Estimate space needed without reading cohort or observation frames.

    Cache bytes are intentionally included in the reserve even though the
    durable files already occupy disk.  That is conservative: the run must
    coexist with those immutable caches and never treats them as reclaimable.
    """
    cohort_rows = _non_negative_row_count(cohort_row_count, "cohort_row_count")
    available = _non_negative_row_count(available_bytes, "available_bytes")
    items = list(metadata)
    spill = estimate_spill_headroom_bytes(items)
    target_rows = source_rows = cache_bytes = chunk_count = 0
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("chunk metadata must be a mapping")
        target_rows += _non_negative_row_count(
            item.get("target_observation_row_count"),
            "target_observation_row_count",
        )
        source_rows += _non_negative_row_count(
            item.get("source_syn_observation_row_count"),
            "source_syn_observation_row_count",
        )
        cache_bytes += _metadata_artifact_bytes(item)
        chunk_count += 1

    sqlite_raw = (
        cohort_rows * COHORT_ROW_BYTES
        + target_rows * TARGET_OBSERVATION_ROW_BYTES
        + source_rows * SOURCE_SYN_ROW_BYTES
        + chunk_count * LEDGER_ROW_BYTES
    )
    sqlite_indexes = int(sqlite_raw * SQLITE_INDEX_MULTIPLIER)
    derived = target_rows * DERIVED_TARGET_ROW_BYTES
    sqlite_temp = int(
        (sqlite_raw + sqlite_indexes + derived + spill) * SQLITE_TEMP_JOURNAL_MULTIPLIER
    )
    publication = (
        cohort_rows
        * (COHORT_CSV_ROW_BYTES + CONTEXT_CSV_ROW_BYTES + SOURCE_CONTEXT_CSV_ROW_BYTES)
        + MANIFEST_STAGING_BYTES
    )
    subtotal = (
        cache_bytes
        + sqlite_raw
        + sqlite_indexes
        + derived
        + spill
        + sqlite_temp
        + publication
    )
    safety_margin = max(MINIMUM_FREE_BYTES, int(subtotal * SAFETY_MARGIN_FRACTION))
    required = subtotal + safety_margin
    return AggregationDiskEstimate(
        cache_observation_bytes=cache_bytes,
        sqlite_raw_bytes=sqlite_raw,
        sqlite_index_bytes=sqlite_indexes,
        derived_bytes=derived,
        spill_headroom_bytes=spill,
        sqlite_temp_journal_bytes=sqlite_temp,
        publication_bytes=publication,
        safety_margin_bytes=safety_margin,
        required_bytes=required,
        available_bytes=available,
    )


def require_aggregation_disk_space(
    directory: Path,
    metadata: Iterable[dict],
    *,
    cohort_row_count: int,
) -> AggregationDiskEstimate:
    """Fail before SQLite ingestion if explainable conservative space is absent."""
    estimate = estimate_aggregation_disk_space(
        metadata,
        cohort_row_count=cohort_row_count,
        available_bytes=shutil.disk_usage(directory).free,
    )
    if estimate.available_bytes < estimate.required_bytes:
        raise InsufficientAggregationDiskSpace(
            "aggregation estimated required bytes: "
            f"{estimate.required_bytes} free bytes; only "
            f"{estimate.available_bytes} available"
        )
    return estimate


class SQLiteContextAggregator:
    def __init__(
        self,
        path: Path,
        cohort: pd.DataFrame,
        *,
        batch_size: int = 10_000,
        active_state_limit: int = 100_000,
        spill_batch_size: int = 1_000,
        identity: dict | None = None,
    ) -> None:
        """Build context rows without retaining a cohort-sized Python tuple list."""
        if batch_size <= 0 or active_state_limit <= 0 or spill_batch_size <= 0:
            raise ValueError("batch and spill limits must be positive")
        self.path = Path(path)
        self.batch_size = batch_size
        self.active_state_limit = active_state_limit
        self.spill_batch_size = spill_batch_size
        self.checkpoint_path = self.path.with_suffix(".checkpoint.json")
        self.identity = {
            "schema_version": SQLITE_SCHEMA_VERSION,
            "aggregation_code_identity": aggregation_code_identity(),
            **(identity or {}),
        }
        self.spill_used = False
        self.spill_count = 0
        self.max_python_active_events = 0
        self.max_python_pair_entries = 0
        self.max_python_ip_entries = 0
        self.max_python_port_entries = 0
        self.max_spill_batch_rows = 0
        self.spill_count_by_window = {300: 0, 900: 0, 3600: 0}
        self.post_spill_python_state_sizes = []
        self.max_post_spill_python_state = (0, 0, 0, 0)
        self.spill_migration_batches_by_table = {
            "event": 0,
            "pair": 0,
            "ip": 0,
            "port": 0,
        }
        self.ingested_chunks: list[str] = []
        state_paths = self._state_paths()
        # Do not let sqlite open a new primary database beside an orphan journal,
        # WAL/SHM, or checkpoint temporary file.  SQLite may otherwise consume or
        # alter that evidence before compatibility checks can quarantine it.
        if not self.path.exists() and any(
            path.exists() for path in state_paths if path != self.path
        ):
            self._quarantine_stale_state()
        elif any(path.exists() for path in state_paths):
            if self._resume_if_compatible():
                return
            self._quarantine_stale_state()
        self.connection = sqlite3.connect(self.path)
        c = self.connection
        c.execute("PRAGMA cache_size=-65536")
        c.execute("PRAGMA temp_store=FILE")
        c.execute("CREATE TABLE state(identity TEXT NOT NULL)")
        c.execute(
            "INSERT INTO state VALUES(?)", (json.dumps(self.identity, sort_keys=True),)
        )
        c.execute(
            "CREATE TABLE ingestion_ledger(chunk_id TEXT PRIMARY KEY,metadata_identity TEXT NOT NULL,target_rows INTEGER NOT NULL,source_rows INTEGER NOT NULL)"
        )
        c.execute(
            "CREATE TABLE cohort(id INTEGER PRIMARY KEY,source_flow_id,ts REAL,a TEXT,ap INTEGER,b TEXT,bp INTEGER,p INTEGER)"
        )
        c.execute(
            "CREATE TABLE o(ts REAL,a TEXT,ap INTEGER,b TEXT,bp INTEGER,p INTEGER,src TEXT,sp INTEGER,dst TEXT,dp INTEGER,cap INTEGER,orig INTEGER,iplen INTEGER,payload INTEGER,flags INTEGER)"
        )
        c.execute("CREATE TABLE syn(ts REAL,src TEXT,dst TEXT,dp INTEGER)")

        def rows():
            for i, r in enumerate(cohort.itertuples(index=False)):
                k = FlowKey.from_packet(
                    str(r.src_ip),
                    int(r.src_port),
                    str(r.dst_ip),
                    int(r.dst_port),
                    int(r.protocol),
                )
                yield (
                    i,
                    r.source_flow_id,
                    float(r.target_timestamp),
                    k.endpoint_a.ip,
                    k.endpoint_a.port,
                    k.endpoint_b.ip,
                    k.endpoint_b.port,
                    k.protocol,
                )

        self._insert("INSERT INTO cohort VALUES(?,?,?,?,?,?,?,?)", rows())
        c.commit()
        self._write_checkpoint([])

    def _resume_if_compatible(self) -> bool:
        try:
            connection = sqlite3.connect(self.path)
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                connection.close()
                return False
            state = connection.execute("SELECT identity FROM state").fetchone()
            if state != (json.dumps(self.identity, sort_keys=True),):
                connection.close()
                return False
            self.connection = connection
            self.ingested_chunks = [
                row[0]
                for row in connection.execute(
                    "SELECT chunk_id FROM ingestion_ledger ORDER BY rowid"
                )
            ]
            return True
        except (OSError, json.JSONDecodeError, sqlite3.Error):
            return False

    def _quarantine_stale_state(self) -> None:
        for value in self._state_paths():
            if value.exists():
                suffix = 1
                destination = value.with_name(f"{value.name}.stale.{suffix}")
                while destination.exists():
                    suffix += 1
                    destination = value.with_name(f"{value.name}.stale.{suffix}")
                value.replace(destination)

    def _state_paths(self) -> tuple[Path, ...]:
        return (
            self.path,
            Path(str(self.path) + "-journal"),
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
            self.checkpoint_path,
            self.checkpoint_path.with_suffix(".tmp"),
        )

    def quarantine(self) -> None:
        """Close and preserve incompatible temporary state for diagnosis."""
        self.connection.close()
        self._quarantine_stale_state()

    def validate_ingestion_ledger(
        self, expected: dict[str, tuple[str, int, int]]
    ) -> None:
        """Reject any committed record not matching current durable cache metadata."""
        rows = list(
            self.connection.execute(
                "SELECT chunk_id,metadata_identity,target_rows,source_rows FROM ingestion_ledger"
            )
        )
        if len({row[0] for row in rows}) != len(rows):
            raise ValueError("duplicate SQLite ingestion ledger entries")
        for chunk_id, identity, target_rows, source_rows in rows:
            if expected.get(chunk_id) != (identity, target_rows, source_rows):
                raise ValueError(
                    "SQLite ingestion ledger does not match durable chunk metadata"
                )

    def require_complete_ledger(
        self, expected: dict[str, tuple[str, int, int]]
    ) -> None:
        self.validate_ingestion_ledger(expected)
        if set(self.ingested_chunks) != set(expected):
            raise ValueError(
                "all expected DITL chunk caches must be committed before aggregation"
            )

    def _write_checkpoint(self, ingested: list[str]) -> None:
        temporary = self.checkpoint_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {"identity": self.identity, "ingested": ingested}, sort_keys=True
            ),
            encoding="utf-8",
        )
        os.replace(temporary, self.checkpoint_path)

    def _insert(self, sql: str, rows: Iterable[tuple]) -> None:
        batch = []
        for r in rows:
            batch.append(r)
            if len(batch) >= self.batch_size:
                self.connection.executemany(sql, batch)
                batch.clear()
        if batch:
            self.connection.executemany(sql, batch)

    def ingest_frames(
        self,
        targets: pd.DataFrame,
        syns: pd.DataFrame,
        *,
        chunk_id: str | None = None,
        chunk_identity: str | None = None,
    ) -> None:
        def obs():
            for r in targets.itertuples(index=False):
                k = FlowKey.from_packet(
                    str(r.src_ip),
                    int(r.src_port),
                    str(r.dst_ip),
                    int(r.dst_port),
                    int(r.protocol),
                )
                f = None if pd.isna(r.tcp_flags_raw) else int(r.tcp_flags_raw)
                yield (
                    float(r.timestamp),
                    k.endpoint_a.ip,
                    k.endpoint_a.port,
                    k.endpoint_b.ip,
                    k.endpoint_b.port,
                    k.protocol,
                    str(r.src_ip),
                    int(r.src_port),
                    str(r.dst_ip),
                    int(r.dst_port),
                    int(r.captured_frame_length),
                    int(r.original_frame_length),
                    int(r.ip_total_length),
                    int(r.transport_payload_length),
                    f,
                )

        try:
            self._insert("INSERT INTO o VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", obs())
            self._insert(
                "INSERT INTO syn VALUES(?,?,?,?)",
                (
                    (float(r.timestamp), str(r.src_ip), str(r.dst_ip), int(r.dst_port))
                    for r in syns.itertuples(index=False)
                ),
            )
            if chunk_id is not None:
                self.connection.execute(
                    "INSERT INTO ingestion_ledger VALUES(?,?,?,?)",
                    (chunk_id, chunk_identity or "", len(targets), len(syns)),
                )
            self.connection.commit()
        except BaseException:
            # The ledger and its observations are one SQLite transaction.  A caught
            # failure is rolled back immediately; a SIGKILL before commit likewise
            # leaves neither durable once SQLite recovers the journal.
            self.connection.rollback()
            raise
        if chunk_id is not None:
            self.ingested_chunks.append(chunk_id)
            self._write_checkpoint(self.ingested_chunks)

    def compute(self) -> None:
        c = self.connection
        c.execute("BEGIN IMMEDIATE")
        # Only raw observations and ingestion_ledger are restart-durable.  Derived
        # tables are discarded before every attempt, so a SIGKILL in compute cannot
        # make an otherwise complete ingestion database unusable.
        for table in (
            "s",
            "w5",
            "w15",
            "w1",
            "t",
            "m",
            "spill_event",
            "spill_pair",
            "spill_ip",
            "spill_port",
        ):
            c.execute(f"DROP TABLE IF EXISTS {table}")
        for index in ("ok", "sk", "mk"):
            c.execute(f"DROP INDEX IF EXISTS {index}")
        c.execute("DROP TABLE IF EXISTS day")
        c.execute("CREATE INDEX ok ON o(a,ap,b,bp,p,ts)")
        c.execute("CREATE INDEX sk ON syn(src,ts)")
        c.execute(
            "CREATE TABLE m AS SELECT c.id,o.* FROM cohort c JOIN o ON c.a=o.a AND c.ap=o.ap AND c.b=o.b AND c.bp=o.bp AND c.p=o.p AND c.ts=o.ts"
        )
        bad = c.execute(
            "SELECT c.source_flow_id,count(m.id) FROM cohort c LEFT JOIN m ON c.id=m.id GROUP BY c.id HAVING count(m.id)!=1 LIMIT 1"
        ).fetchone()
        if bad:
            raise ValueError(
                f"{'missing' if bad[1] == 0 else 'ambiguous'} target matches for source_flow_id={bad[0]}"
            )
        c.execute("CREATE INDEX mk ON m(a,ap,b,bp,p)")
        c.execute(
            "CREATE TABLE t AS SELECT m.id,count(o.ts) total,sum(o.ts<m.ts) bef,sum(o.ts>m.ts) aft,sum(o.src=m.src AND o.sp=m.sp) fwd,max(CASE WHEN o.ts<m.ts THEN o.ts END) prev,min(CASE WHEN o.ts>m.ts THEN o.ts END) nxt,min(CASE WHEN o.ts<m.ts AND NOT(o.src=m.src AND o.sp=m.sp) THEN m.ts-o.ts END) rb,min(CASE WHEN o.ts>m.ts AND NOT(o.src=m.src AND o.sp=m.sp) THEN o.ts-m.ts END) ra,sum(o.ts<m.ts AND m.ts-o.ts<=1)b1,sum(o.ts<m.ts AND m.ts-o.ts<=10)b10,sum(o.ts<m.ts AND m.ts-o.ts<=60)b60,sum(o.ts<m.ts AND m.ts-o.ts<=300)b300,sum(o.ts>m.ts AND o.ts-m.ts<=1)a1,sum(o.ts>m.ts AND o.ts-m.ts<=10)a10,sum(o.ts>m.ts AND o.ts-m.ts<=60)a60,sum(o.ts>m.ts AND o.ts-m.ts<=300)a300 FROM m JOIN o USING(a,ap,b,bp,p) GROUP BY m.id"
        )
        self._source()
        c.commit()

    def _source(self) -> None:
        c = self.connection
        # Spill tables are derived compute state.  They are dropped at the start of
        # compute with every other derived table, never persisted as cache input.
        c.execute(
            "CREATE TABLE spill_event(window INTEGER,src TEXT,seq INTEGER,ts REAL,dst TEXT,dp INTEGER,PRIMARY KEY(window,src,seq))"
        )
        # Expiration filters by timestamp; this avoids scanning another source's
        # active events before ordering the bounded expired batch by sequence.
        c.execute("CREATE INDEX spill_expiry ON spill_event(window,src,ts,seq)")
        c.execute(
            "CREATE TABLE spill_pair(window INTEGER,src TEXT,dst TEXT,dp INTEGER,n INTEGER,PRIMARY KEY(window,src,dst,dp))"
        )
        c.execute(
            "CREATE TABLE spill_ip(window INTEGER,src TEXT,dst TEXT,n INTEGER,PRIMARY KEY(window,src,dst))"
        )
        c.execute(
            "CREATE TABLE spill_port(window INTEGER,src TEXT,dp INTEGER,n INTEGER,PRIMARY KEY(window,src,dp))"
        )
        c.execute(
            "CREATE TEMP TABLE day AS SELECT n.src,n.n,p.u,n.i,n.p FROM (SELECT src,count(*) n,count(DISTINCT dst)i,count(DISTINCT dp)p FROM syn GROUP BY src)n LEFT JOIN (SELECT src,count(*)u FROM (SELECT DISTINCT src,dst,dp FROM syn)GROUP BY src)p ON n.src=p.src"
        )
        for w, name in ((300, "w5"), (900, "w15"), (3600, "w1")):
            c.execute(f"CREATE TABLE {name}(id PRIMARY KEY,n,u,i,p)")
            q = c.execute(
                "SELECT id,ts,src FROM m WHERE flags IS NOT NULL AND(flags&2)!=0 AND(flags&16)=0 ORDER BY src,ts,id"
            )
            current = None
            ev = iter(())
            next_ev = None
            active = deque()
            pair = Counter()
            ip = Counter()
            port = Counter()
            out = []
            spilled = False
            spill_state = {
                "packets": 0,
                "pairs": 0,
                "ips": 0,
                "ports": 0,
                "seq": 0,
                "oldest": None,
            }
            for ident, ts, src in q:
                if src != current:
                    if current is not None:
                        self._clear_spill_source(w, current)
                    current = src
                    ev = iter(
                        c.execute(
                            "SELECT ts,dst,dp FROM syn WHERE src=? ORDER BY ts", (src,)
                        )
                    )
                    next_ev = next(ev, None)
                    active.clear()
                    pair.clear()
                    ip.clear()
                    port.clear()
                    spilled = False
                    spill_state = {
                        "packets": 0,
                        "pairs": 0,
                        "ips": 0,
                        "ports": 0,
                        "seq": 0,
                        "oldest": None,
                    }
                # Reclaim the old window before adding new events: transient
                # spill state must also fit the metadata rolling-window bound.
                if spilled:
                    self._spill_expire(w, src, ts - w, spill_state)
                while not spilled and active and active[0][0] < ts - w:
                    x = active.popleft()
                    pair[(x[1], x[2])] -= 1
                    ip[x[1]] -= 1
                    port[x[2]] -= 1
                    if not pair[(x[1], x[2])]:
                        del pair[(x[1], x[2])]
                    if not ip[x[1]]:
                        del ip[x[1]]
                    if not port[x[2]]:
                        del port[x[2]]
                # Skip pre-window observations (including gaps between targets)
                # without ever inserting them into Python or SQLite spill state.
                while next_ev and next_ev[0] < ts - w:
                    next_ev = next(ev, None)
                while next_ev and next_ev[0] <= ts + w:
                    x = next_ev
                    if not spilled and len(active) >= self.active_state_limit:
                        self._migrate_window_to_spill(
                            w, src, active, pair, ip, port, spill_state
                        )
                        active.clear()
                        pair.clear()
                        ip.clear()
                        port.clear()
                        self.post_spill_python_state_sizes.append(
                            (len(active), len(pair), len(ip), len(port))
                        )
                        spilled = True
                    if spilled:
                        self._spill_add(w, src, x, spill_state)
                    else:
                        active.append(x)
                        pair[(x[1], x[2])] += 1
                        ip[x[1]] += 1
                        port[x[2]] += 1
                        self._observe_python_state(active, pair, ip, port)
                    next_ev = next(ev, None)
                if spilled:
                    self.max_post_spill_python_state = tuple(
                        max(a, b)
                        for a, b in zip(
                            self.max_post_spill_python_state,
                            (len(active), len(pair), len(ip), len(port)),
                        )
                    )
                out.append(
                    (
                        ident,
                        spill_state["packets"],
                        spill_state["pairs"],
                        spill_state["ips"],
                        spill_state["ports"],
                    )
                    if spilled
                    else (ident, len(active), len(pair), len(ip), len(port))
                )
                if len(out) >= self.batch_size:
                    c.executemany(f"INSERT INTO {name} VALUES(?,?,?,?,?)", out)
                    out.clear()
            if out:
                c.executemany(f"INSERT INTO {name} VALUES(?,?,?,?,?)", out)
            if current is not None:
                self._clear_spill_source(w, current)
        c.execute(
            "CREATE TABLE s AS SELECT m.id,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN 1 ELSE 0 END app,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN m.src END src,w5.n,w5.u,w5.i,w5.p,w15.n,w15.u,w15.i,w15.p,w1.n,w1.u,w1.i,w1.p,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN COALESCE(day.n,0) END,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN COALESCE(day.u,0) END,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN COALESCE(day.i,0) END,CASE WHEN m.flags IS NOT NULL AND(m.flags&2)!=0 AND(m.flags&16)=0 THEN COALESCE(day.p,0) END FROM m LEFT JOIN w5 ON m.id=w5.id LEFT JOIN w15 ON m.id=w15.id LEFT JOIN w1 ON m.id=w1.id LEFT JOIN day ON m.src=day.src"
        )

    def _clear_spill_source(self, window: int, src: str) -> None:
        """Release completed derived state inside compute's outer transaction.

        Output values have already been copied into scalar rows. Deleted pages
        remain allocated and reusable; raw observations and ledger are untouched.
        """
        for table in ("spill_event", "spill_pair", "spill_ip", "spill_port"):
            self.connection.execute(
                f"DELETE FROM {table} WHERE window=? AND src=?", (window, src)
            )

    def _observe_python_state(self, active, pair, ip, port) -> None:
        self.max_python_active_events = max(self.max_python_active_events, len(active))
        self.max_python_pair_entries = max(self.max_python_pair_entries, len(pair))
        self.max_python_ip_entries = max(self.max_python_ip_entries, len(ip))
        self.max_python_port_entries = max(self.max_python_port_entries, len(port))

    def _spill_add(self, w, src, event, state) -> None:
        ts, dst, dp = event
        state["seq"] += 1
        self.connection.execute(
            "INSERT INTO spill_event VALUES(?,?,?,?,?,?)",
            (w, src, state["seq"], ts, dst, dp),
        )
        state["packets"] += 1
        for table, fields, key, count in (
            ("spill_pair", "dst,dp", (dst, dp), "pairs"),
            ("spill_ip", "dst", (dst,), "ips"),
            ("spill_port", "dp", (dp,), "ports"),
        ):
            where = " AND ".join(f"{field}=?" for field in fields.split(","))
            row = self.connection.execute(
                f"SELECT n FROM {table} WHERE window=? AND src=? AND {where}",
                (w, src, *key),
            ).fetchone()
            if row is None:
                self.connection.execute(
                    f"INSERT INTO {table}(window,src,{fields},n) VALUES(?,?,{','.join('?' for _ in key)},1)",
                    (w, src, *key),
                )
                state[count] += 1
            else:
                self.connection.execute(
                    f"UPDATE {table} SET n=n+1 WHERE window=? AND src=? AND {where}",
                    (w, src, *key),
                )
        if state["oldest"] is None:
            state["oldest"] = ts

    def _migrate_window_to_spill(self, w, src, active, pair, ip, port, state) -> None:
        """Move one bounded Python window into derived SQLite state.

        The savepoint makes the pre-spill Python deque/Counters authoritative until
        its release succeeds.  Release is *not* a durable commit: it is nested in
        ``compute()``'s outer transaction.  If that outer transaction later rolls
        back or a process dies, the next compute attempt discards every derived
        spill table and reconstructs it from committed raw observations.
        """
        self.connection.execute("SAVEPOINT spill_migration")
        try:
            event_count = len(active)
            iterator = iter(active)
            while batch := [
                (w, src, state["seq"] + index, *event)
                for index, event in enumerate(
                    islice(iterator, self.spill_batch_size), start=1
                )
            ]:
                self.max_spill_batch_rows = max(self.max_spill_batch_rows, len(batch))
                self.spill_migration_batches_by_table["event"] += 1
                state["seq"] += len(batch)
                self.connection.executemany(
                    "INSERT INTO spill_event VALUES(?,?,?,?,?,?)", batch
                )
            for table, fields, values, count in (
                ("spill_pair", "dst,dp", pair.items(), "pairs"),
                ("spill_ip", "dst", ip.items(), "ips"),
                ("spill_port", "dp", port.items(), "ports"),
            ):
                entry_count = len(values)
                iterator = iter(values)
                while batch := [
                    (w, src, *((key,) if not isinstance(key, tuple) else key), n)
                    for key, n in islice(iterator, self.spill_batch_size)
                ]:
                    self.max_spill_batch_rows = max(
                        self.max_spill_batch_rows, len(batch)
                    )
                    self.spill_migration_batches_by_table[
                        {"spill_pair": "pair", "spill_ip": "ip", "spill_port": "port"}[
                            table
                        ]
                    ] += 1
                    self.connection.executemany(
                        f"INSERT INTO {table}(window,src,{fields},n) VALUES(?,?,{','.join('?' for _ in range(len(batch[0]) - 2))})",
                        batch,
                    )
                state[count] = entry_count
            state["packets"] = event_count
            state["oldest"] = active[0][0] if active else None
            if (state["packets"], state["pairs"], state["ips"], state["ports"]) != (
                len(active),
                len(pair),
                len(ip),
                len(port),
            ):
                raise ValueError("spill migration verification failed")
            self.connection.execute("RELEASE spill_migration")
            self.spill_used = True
            self.spill_count += 1
            self.spill_count_by_window[w] += 1
        except BaseException:
            self.connection.execute("ROLLBACK TO spill_migration")
            self.connection.execute("RELEASE spill_migration")
            raise

    def _spill_expire(self, w, src, cutoff, state) -> None:
        while state["oldest"] is not None and state["oldest"] < cutoff:
            rows = list(
                self.connection.execute(
                    "SELECT seq,ts,dst,dp FROM spill_event WHERE window=? AND src=? AND ts<? ORDER BY ts,seq LIMIT ?",
                    (w, src, cutoff, self.spill_batch_size),
                )
            )
            self.max_spill_batch_rows = max(self.max_spill_batch_rows, len(rows))
            if not rows:
                state["oldest"] = None
                break
            for seq, ts, dst, dp in rows:
                self.connection.execute(
                    "DELETE FROM spill_event WHERE window=? AND src=? AND seq=?",
                    (w, src, seq),
                )
                state["packets"] -= 1
                for table, fields, key, count in (
                    ("spill_pair", "dst,dp", (dst, dp), "pairs"),
                    ("spill_ip", "dst", (dst,), "ips"),
                    ("spill_port", "dp", (dp,), "ports"),
                ):
                    where = " AND ".join(f"{field}=?" for field in fields.split(","))
                    row = self.connection.execute(
                        f"SELECT n FROM {table} WHERE window=? AND src=? AND {where}",
                        (w, src, *key),
                    ).fetchone()
                    if row[0] == 1:
                        self.connection.execute(
                            f"DELETE FROM {table} WHERE window=? AND src=? AND {where}",
                            (w, src, *key),
                        )
                        state[count] -= 1
                    else:
                        self.connection.execute(
                            f"UPDATE {table} SET n=n-1 WHERE window=? AND src=? AND {where}",
                            (w, src, *key),
                        )
            state["oldest"] = self.connection.execute(
                "SELECT min(ts) FROM spill_event WHERE window=? AND src=?", (w, src)
            ).fetchone()[0]

    def iter_context_rows(self) -> Iterator[dict]:
        q = "SELECT c.source_flow_id,m.*,t.* FROM m JOIN cohort c ON c.id=m.id JOIN t ON m.id=t.id ORDER BY m.id"
        for r in self.connection.execute(q):
            (
                sid,
                i,
                ts,
                a,
                ap,
                b,
                bp,
                p,
                src,
                sp,
                dst,
                dp,
                cap,
                orig,
                iplen,
                pay,
                flags,
                _,
                total,
                bef,
                aft,
                fwd,
                prev,
                nxt,
                rb,
                ra,
                b1,
                b10,
                b60,
                b300,
                a1,
                a10,
                a60,
                a300,
            ) = r
            yield dict(
                zip(
                    ONE_PACKET_CONTEXT_COLUMNS,
                    [
                        sid,
                        ts,
                        src,
                        sp,
                        dst,
                        dp,
                        cap,
                        orig,
                        iplen,
                        pay,
                        flags,
                        _tcp_flags_text(flags),
                        total,
                        bef,
                        aft,
                        fwd,
                        total - fwd,
                        prev,
                        None if prev is None else ts - prev,
                        nxt,
                        None if nxt is None else nxt - ts,
                        rb,
                        ra,
                        b1,
                        b10,
                        b60,
                        b300,
                        a1,
                        a10,
                        a60,
                        a300,
                    ],
                )
            )

    def iter_source_context_rows(self) -> Iterator[dict]:
        query = """
      SELECT c.source_flow_id, m.ts, s.*
      FROM m
      JOIN cohort c ON c.id = m.id
      JOIN s ON s.id = m.id
      ORDER BY m.id
  """
        for sid, ts, *values in self.connection.execute(query):
            # ``s`` is stored window-major for streaming inserts (w5, w15, w1),
            # whereas the public CSV is statistic-major (all packet counts, then all
            # unique pair counts, and so on).  Keep this reshuffle explicit so an
            # internal layout change cannot silently change the artifact schema.
            (
                _,
                applicable,
                source_ip,
                *window_values,
                day_packets,
                day_pairs,
                day_ips,
                day_ports,
            ) = values
            w5, w15, w1 = (
                window_values[offset : offset + 4] for offset in range(0, 12, 4)
            )
            public_values = [
                sid,
                ts,
                bool(applicable),
                source_ip,
                w5[0],
                w15[0],
                w1[0],
                w5[1],
                w15[1],
                w1[1],
                w5[2],
                w15[2],
                w1[2],
                w5[3],
                w15[3],
                w1[3],
                day_packets,
                day_pairs,
                day_ips,
                day_ports,
            ]
            yield dict(zip(ONE_PACKET_SOURCE_CONTEXT_COLUMNS, public_values))

    def close(self, *, delete: bool) -> None:
        self.connection.close()
        if delete:
            # This path is called only after successful final publication.
            # Keep the complete state set after failure, but do not leave a
            # cohort-scale database/checkpoint beside an already-final run.
            for state_path in self._state_paths():
                if state_path.exists():
                    state_path.unlink()
