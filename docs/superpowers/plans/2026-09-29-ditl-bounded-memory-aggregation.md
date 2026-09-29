# DITL Bounded-Memory Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resume and complete 96 DITL context chunks with bounded RAM and disk-backed final aggregation while preserving existing cache and analytical semantics.

**Architecture:** A new SQLite-focused module validates/ingests one existing chunk at a time and performs set-based aggregate queries into disk-backed tables. `ditl_context.py` retains only cache metadata during acquisition, while a streaming publication path writes and validates final CSVs without full DataFrames.

**Tech Stack:** Python 3 standard-library `sqlite3`, `csv`, `hashlib`, `shutil`; existing pandas only for the already-loaded cohort and one transient chunk at a time.

**Spec:** `docs/superpowers/specs/2026-09-29-ditl-bounded-memory-design.md`

## Global Constraints

- Do not modify `one_packet_context_chunks.py`, `one_packet_context.py`, or `flow.py`; their hashes preserve the 18 completed cache identities.
- Reuse only normally validated successful caches; never silently overwrite, repair, or regenerate one.
- Require all expected 96 chunk IDs before final aggregation.
- Keep exact IEEE-754 timestamp equality for target matching; do not introduce tolerance or timestamp normalization.
- Use explicit SQLite transactions, bounded insert/cursor batches, and only documented indexes.
- Retain the SQLite database on failure and delete it only after successful, durable artifact and manifest validation.
- Preserve existing public output schemas and all current analytical values.
- Do not delete owned raw data before durable chunk validation; retain target raw data until final validation succeeds.
- Do not add dependencies; explain and test the stdlib SQLite choice.

## Review Focus

- Existing v1 cache identity remains valid after every code change; test reuse without extraction and cache conflict behavior.
- A timestamp one representable step away is not an exact target match; test both directions and duplicate exact matches.
- Tuple direction counts and reverse gaps remain target-relative for TCP and UDP; test reverse-direction packets.
- Inclusive source windows at exactly ±300, ±900, and ±3600 seconds preserve count and distinct semantics.
- Final CSV/manifest validation streams rather than loading the 12-million-row artifacts; test a guard that rejects full-frame loader use.

---

### Task 1: Disk-backed aggregation primitives

**Files:**
- Create: `src/mawi_global_analysis/ditl_context_sqlite.py`
- Test: `tests/unit/test_ditl_context_sqlite.py`

**Interfaces:**
- Produces `estimate_required_bytes(metadata: Sequence[Mapping[str, Any]], cohort: pd.DataFrame) -> int`, `require_disk_space(directory: Path, required_bytes: int) -> None`, and `SQLiteContextAggregator`.
- Consumes lightweight successful chunk metadata with existing artifact records and the current cohort DataFrame.

- [ ] **Step 1: Write failing disk-space and temporary-database lifecycle tests**

```python
def test_preflight_fails_before_ingestion_when_free_space_is_insufficient(...):
    with pytest.raises(InsufficientAggregationDiskSpace):
        require_disk_space(tmp_path, required_bytes=100)

def test_failed_aggregation_retains_database_for_diagnosis(...):
    assert database_path.exists()
```

- [ ] **Step 2: Run the focused tests to verify failure**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py -v`
Expected: FAIL because the module and interfaces do not exist.

- [ ] **Step 3: Implement SQLite setup, conservative preflight, and lifecycle policy**

Create tables `cohort`, `target_observation`, `source_syn_observation`,
`target_match`, `tuple_context`, `source_day_statistics`, and
`source_window_statistics`. Use WAL or rollback-journal settings chosen for
safe local temporary operation, explicit transactions, configured bounded
cache size, and the documented spool-local database path. Estimate from cache
artifact byte sizes and row counts plus cohort/output staging; report required
and available bytes in the error.

- [ ] **Step 4: Run the focused tests to verify pass**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py -v`
Expected: PASS.

### Task 2: One-at-a-time validated cache ingestion

**Files:**
- Modify: `src/mawi_global_analysis/ditl_context.py`
- Modify: `src/mawi_global_analysis/one_packet_context_run.py`
- Modify: `tests/unit/test_ditl_chunks.py`
- Test: `tests/unit/test_ditl_context_sqlite.py`

**Interfaces:**
- Consumes `SQLiteContextAggregator.ingest_chunk(metadata: Mapping[str, Any]) -> None`.
- Produces a deterministic lightweight metadata sequence for provenance and final publication.

- [ ] **Step 1: Write failing reuse and no-accumulation tests**

```python
def test_orchestrator_reuses_valid_cache_and_keeps_only_metadata(...):
    assert extracted == []
    assert retained_values == ["metadata"] * 96

def test_ingestion_loads_at_most_one_chunk_observation_pair_at_once(...):
    assert maximum_live_chunk_frames == 1
```

- [ ] **Step 2: Run focused tests to verify failure**

Run: `uv run pytest tests/unit/test_ditl_chunks.py tests/unit/test_ditl_context_sqlite.py -v`
Expected: FAIL under the current list-of-`ChunkObservations` behavior.

- [ ] **Step 3: Implement transient validation and batched ingestion**

Keep the existing cache loader as the authoritative validation mechanism, but
immediately copy only its metadata and delete the returned `ChunkObservations`.
For aggregation, reload exactly one validated cache, insert bounded record
batches into SQLite within explicit transactions, and release both DataFrames
before the next cache. Change final provenance revalidation to accept metadata
and perform the same transient one-cache validation rather than returning a
list of full chunks. Add acquisition logs in the required `[n/96] reused|extracted <id>` form.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `uv run pytest tests/unit/test_ditl_chunks.py tests/unit/test_ditl_context_sqlite.py -v`
Expected: PASS.

### Task 3: Set-based tuple aggregation and exact-match validation

**Files:**
- Modify: `src/mawi_global_analysis/ditl_context_sqlite.py`
- Test: `tests/unit/test_ditl_context_sqlite.py`

**Interfaces:**
- Produces `SQLiteContextAggregator.compute_tuple_context() -> None` and a cursor/batch iterator for context rows in cohort order.
- Consumes populated SQLite cohort and target-observation tables.

- [ ] **Step 1: Write failing equivalence tests**

```python
def test_sqlite_tuple_context_equals_in_memory_for_tcp_udp_and_reverse_packets(...):
    pd.testing.assert_frame_equal(actual, expected)

def test_sqlite_requires_exact_float_timestamp_match(...):
    with pytest.raises(ValueError, match="missing target"):
        aggregator.compute_tuple_context()

def test_sqlite_rejects_duplicate_exact_target_matches(...):
    with pytest.raises(ValueError, match="ambiguous target"):
        aggregator.compute_tuple_context()
```

- [ ] **Step 2: Run focused tests to verify failure**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py -k 'tuple or timestamp' -v`
Expected: FAIL because tuple aggregation is not implemented.

- [ ] **Step 3: Implement indexed set-based tuple operations**

Create the documented indexes after ingestion. Build `target_match` by an
exact `REAL = REAL` and canonical-FlowKey join, reject grouped counts other
than one, then use one grouped join from target matches to all same-key
observations. Compute counts, min/max timestamps, direction-relative counts,
reverse gaps, and threshold conditions in that query. Do not issue queries
per cohort row. Order emitted cursor results by the existing deterministic
cohort ordering.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py -k 'tuple or timestamp' -v`
Expected: PASS.

### Task 4: Ordered sliding-window source context

**Files:**
- Modify: `src/mawi_global_analysis/ditl_context_sqlite.py`
- Test: `tests/unit/test_ditl_context_sqlite.py`

**Interfaces:**
- Produces `SQLiteContextAggregator.compute_source_context() -> None` and a cursor/batch iterator for source-context rows.
- Consumes `target_match` and source-SYN observation tables.

- [ ] **Step 1: Write failing source-window boundary and order tests**

```python
def test_sqlite_source_context_matches_in_memory_at_inclusive_boundaries(...):
    pd.testing.assert_frame_equal(actual, expected)

def test_sqlite_results_are_chunk_order_independent_and_deterministic(...):
    pd.testing.assert_frame_equal(forward, reverse)
```

- [ ] **Step 2: Run focused tests to verify failure**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py -k 'source or order' -v`
Expected: FAIL because source context is not implemented.

- [ ] **Step 3: Implement source-wide and sliding-window aggregate passes**

Compute full-day statistics once grouped by source. Build applicable target
rows only when the target packet is plain SYN. For each source, stream
timestamp-ordered target and SYN rows through three inclusive sliding windows
with ref-counted packet/pair/IP/port statistics, flushing source results in
bounded batches. Carry state between bounded partitions; spill active-window
refcounts to SQLite at the configured threshold. Join full-day statistics back
to all target rows, using null statistics for non-applicable targets. Do not
execute SQL statements per target or materialize a global target/SYN-pair
relation.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py -k 'source or order' -v`
Expected: PASS.

### Task 5: Streaming publication, final validation, and integration

**Files:**
- Modify: `src/mawi_global_analysis/one_packet_context_run.py`
- Modify: `src/mawi_global_analysis/ditl_context.py`
- Test: `tests/unit/test_one_packet_context_run.py`
- Test: `tests/unit/test_ditl_chunks.py`
- Test: `tests/unit/test_ditl_context_sqlite.py`

**Interfaces:**
- Produces `write_one_packet_context_chunk_run_streaming(..., aggregator: SQLiteContextAggregator, metadata: Sequence[Mapping[str, Any]], ...) -> Path`.
- Consumes streaming row iterators and validated lightweight metadata.

- [ ] **Step 1: Write failing bounded-publication tests**

```python
def test_streaming_writer_preserves_csv_schema_checksums_and_linkage(...):
    assert manifest["status"] == "success"

def test_final_validation_does_not_call_dataframe_loader(...):
    monkeypatch.setattr(context_run, "load_one_packet_context", fail)
    assert write_streaming_run(...) == run_dir
```

- [ ] **Step 2: Run focused tests to verify failure**

Run: `uv run pytest tests/unit/test_one_packet_context_run.py tests/unit/test_ditl_chunks.py tests/unit/test_ditl_context_sqlite.py -v`
Expected: FAIL because no streaming writer exists.

- [ ] **Step 3: Implement atomic streamed CSV publication and validation**

Write headers and cursor batches to temporary files, `fsync`, atomically
publish, and calculate SHA-256 and row counts by streaming. Add a streaming
artifact/linkage validator and use it before writing the success manifest and
before target raw deletion. Keep existing DataFrame writer/public loader for
the legacy path. Log `building indexes`, `computing tuple context`,
`computing source context`, `writing final artifacts`, and `validating final
artifacts`.

- [ ] **Step 4: Run focused integration tests to verify pass**

Run: `uv run pytest tests/unit/test_one_packet_context_run.py tests/unit/test_ditl_chunks.py tests/unit/test_ditl_context_sqlite.py -v`
Expected: PASS.

### Task 6: Documentation, complete verification, and independent review

**Files:**
- Modify: `docs/agent/current-state.md` only if its implementation statement requires an accuracy update
- Modify: `docs/guide/real-data-execution-runbook.md` with temporary-space/preflight and resume behavior
- Test: relevant existing unit suite

**Interfaces:**
- Consumes the completed implementation and focused test evidence.
- Produces operational documentation and verification/review evidence.

- [ ] **Step 1: Update runbook with database location, disk preflight, progress messages, cache reuse, and failure-retention policy**

- [ ] **Step 2: Run focused verification and full suite**

Run: `uv run pytest tests/unit/test_ditl_context_sqlite.py tests/unit/test_ditl_chunks.py tests/unit/test_one_packet_context_chunks.py tests/unit/test_one_packet_context_run.py -v && uv run pytest -q`
Expected: all tests PASS.

- [ ] **Step 3: Obtain a fresh independent review**

Ask a fresh reviewer to inspect memory boundedness, set-based complexity,
semantic equivalence, existing-cache compatibility, resume/crash behavior,
and raw-data deletion ordering. Fix any material findings and rerun affected
tests.

- [ ] **Step 4: Inspect the final diff and report without committing**

Confirm no change to the three cache-identity files, no dependency addition,
and no `git add`, commit, or push.

## Self-Review

All user requirements map to Tasks 1–6: cache compatibility and acquisition
to Task 2; no per-target query strategy to Tasks 3–4; preflight/lifecycle to
Task 1; exact timestamp and semantic fixtures to Tasks 3–4; bounded
publication to Task 5; progress, full verification, and independent review to
Task 6.  Interfaces use the same `SQLiteContextAggregator` names throughout.
The plan deliberately keeps the cache-identity modules unchanged and contains
no new third-party dependency or automatic cache deletion.
