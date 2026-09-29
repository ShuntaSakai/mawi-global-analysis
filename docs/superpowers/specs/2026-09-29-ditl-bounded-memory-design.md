# DITL Bounded-Memory Aggregation Design

## Goal

Finish a 96-chunk DITL one-packet-context run on the 61 GiB host without
retaining completed chunk observations or final output tables in RAM, while
preserving the observation semantics and the 18 already-valid chunk caches.

## Compatibility boundary

Chunk validity remains defined by the existing metadata, checksums, schemas,
cohort identity, and `observation_code_identity`.  The latter hashes
`one_packet_context_chunks.py`, `one_packet_context.py`, and `flow.py`.
Those three files are not changed.  Existing successful caches are therefore
reused after their normal validation; no cache is repaired, overwritten, or
regenerated merely because this aggregation implementation is new.

## Storage and lifecycle

A temporary SQLite database will live beneath the context run's controlled
DITL spool directory, for example
`data/<dataset>/raw/ditl_stream/<context-run>/.aggregation.sqlite3`.  It is
not a cache and is not part of the published result.  It is retained on an
aggregation or publication failure for diagnosis, and is deleted only after
the final CSV artifacts, checksums, manifest, and bounded-memory validation
have succeeded.  Durable chunk caches are never removed to make disk space.

Before ingestion, the process estimates required free space from the 96
validated metadata row counts and artifact byte sizes, applies a documented
conservative multiplier for SQLite tables/indexes and final CSV staging, and
uses `shutil.disk_usage`.  A shortfall fails before loading observation CSVs.

## SQLite representation

The database stores these normalized, disk-backed relations:

- `cohort`: one row per `source_flow_id`, exact IEEE-754 `REAL`
  `target_timestamp`, direction-independent FlowKey endpoint columns, and
  original cohort columns needed for output.
- `target_observation`: each retained observation, with exact `REAL`
  timestamp, canonical FlowKey columns, original packet direction, lengths,
  and TCP flags.
- `source_syn_observation`: retained plain-SYN rows by source IP, exact
  timestamp, destination IP, and destination port.
- `target_match`: the unique exact `(FlowKey, timestamp)` target packet for
  each cohort row after validation.
- disk-backed aggregate tables for tuple context, 24-hour source statistics,
  and per-target source-window statistics.

`REAL` values are inserted from Python `float` and compared with SQLite `=`;
there is no cast to integer, formatted timestamp key, tolerance, rounding, or
range expansion for target matching.  Fixture tests pin exact and nearby
timestamps.

Justified indexes are:

- `target_observation` on `(FlowKey columns, timestamp)` for the exact target
  join and grouped tuple join;
- `source_syn_observation` on `(src_ip, timestamp)` for the bounded source
  range join;
- `target_match` on its canonical FlowKey for tuple aggregation, and on
  `(packet_src_ip, target_timestamp)` for source processing;
- primary keys on cohort and aggregate tables for deterministic streamed
  output joins.

No index is created merely for convenience; each exists for one stated join or
ordered output operation.

## Set-based aggregation

After all chunks are ingested one at a time, a set-based exact join creates
`target_match` and a grouped validation query rejects any cohort row with a
match count other than one.  A single grouped join from `target_match` to
`target_observation` by canonical FlowKey produces total/before/after,
forward/reverse, nearest timestamps and reverse gaps, and all 1/10/60/300s
counts.  This preserves the original direction-independent key behavior and
target-relative direction definitions.

Source context first groups every source's full-day count and distinct
destination-pair/IP/port statistics once.  It then processes applicable
targets and source-SYN observations one source at a time, both ordered by
timestamp.  Three inclusive sliding windows (5 minutes, 15 minutes, and one
hour) advance left/right cursors over that source's SYN observations.  Each
window maintains packet count plus reference-counted destination-pair,
destination-IP, and destination-port maps.  A source's target rows are
written to disk-backed result tables in bounded batches before moving to the
next source.  This avoids a global target-by-observation pair relation.

The scan uses a bounded source partition: if a source has more observations
or applicable targets than the configured in-memory partition limit, its
ordered rows are read in overlapping timestamp blocks, with the left/right
window state carried across blocks.  The maximum live state is the largest
one-hour active window (or the configured spill representation), not every
target/SYN pair for that source.  A temporary SQLite spill table backs the
reference counts when that active window crosses the memory threshold, so one
prolific source cannot force unbounded RAM.  Non-applicable targets retain
null source statistics exactly as now.

For `C` cohort rows, `O` target observations, and `S` source observations,
ingest is `O + S` rows in bounded batches; indexed tuple joins are
approximately `O log O + C log O` plus the unavoidable tuple-match output
cardinality.  The source pass is an ordered `O + S` scan with a constant
three-window factor and logarithmic/reference-count updates; it never has a
target/SYN-pair-table cardinality term.  Memory is bounded by SQLite
page/cache settings, write batches, and the configured active-window spill
threshold, rather than `C`, `O`, `S`, or 96 DataFrames. Disk usage scales with
input relations, indexes, aggregate results, and any spill state—not a
Cartesian window-pair relation.

## Restart behavior

The SQLite database has its own small JSON checkpoint beside it containing a
schema version, aggregation-code identity, cohort identity, ordered 96 chunk
metadata identities, and an ingestion checkpoint.  A database is resumable
only when all of those identities match and SQLite integrity checks pass; a
resume continues at the first uncommitted chunk after independently
revalidating its durable cache.  Any missing, malformed, identity-mismatched,
or failed-integrity database is never reused.  It is renamed to a
timestamped diagnostic path (not deleted) and a fresh database is built from
the durable caches.  This policy preserves caches and makes stale state
explicit rather than silently trusting it.

## Publication and safety

Final cohort, context, and source-context CSVs are written in deterministic
cohort order using cursor batches; checksums and row counts are streaming.
A new bounded-memory final-artifact validator verifies headers, checksums,
row counts, and source-flow/target-timestamp linkage without calling the
DataFrame-returning public loader.  The public loader is unchanged.  The
target raw chunk is eligible for deletion only after this validation and a
successful durable manifest.

Progress logging names reuse/extraction and `[completed/96]` during
acquisition, then each ingest chunk, index construction, tuple computation,
source computation, artifact writing, and final validation.
