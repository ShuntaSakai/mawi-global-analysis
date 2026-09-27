# One-Packet Context DITL Chunk Processing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one-packet context analysis resumable over local DITL capture chunks while preserving the existing scientific outputs and single-capture API.

**Architecture:** A new processed-data cache stores only target-tuple packet facts and candidate-source plain-SYN facts per raw chunk.  One shared timestamp-based aggregator consumes either a capture-derived observation stream or validated durable chunk observations.  Final context-run provenance represents either a legacy full capture or validated DITL chunk identities.

**Tech Stack:** Python 3.12, pandas, dpkt, CSV, JSON manifests, pytest.

**Spec:** User-approved Phase 5A request and design review in this task; repository contract at `docs/agent/research-contract.md`.

## Global Constraints

- Work directly on the checked-out `main`; do not create a branch/worktree, stage, commit, push, reset, rebase, stash, or discard changes.
- Use only the public strict capture iterator; stream captures and never concatenate or canonical-flow aggregate chunks.
- Store reusable observational cache artifacts below `data/<dataset>/processed/`, never under `results/`.
- A completion record is safe only after artifacts plus metadata reload and validate from disk.
- Chunk identity includes chunk ID, source hash/size, cohort identity, schema/code identity, artifact schemas/checksums; `chunk_id` is not temporal evidence.
- Aggregation is explicit timestamp-based and independent of supplied chunk order, filenames, and directory iteration order.
- Preserve existing context schemas and single-capture public APIs; do not add HTTP retrieval or source-file deletion.
- Intermediate artifacts contain observations only: no connection/session reconstruction, scan labels, or behavioral interpretation.

## Review Focus

- Reuse after raw capture removal must depend only on artifact and manifest validation, not source-path existence.
- Equal timestamps in distinct chunks must still make duplicate target matches fail deterministically.
- Candidate plain-SYN retention must retain endpoints of cohort tuples before target applicability is resolved.
- Global source uniqueness counts must be set-unioned across chunks, including repeated destinations.
- Legacy source-window provenance and direct DITL-target-chunk provenance must reject checksum disagreement.

### Task 1: Durable chunk observation cache

**Files:**
- Create: `src/mawi_global_analysis/one_packet_context_chunks.py`
- Create: `tests/unit/test_one_packet_context_chunks.py`

**Interfaces:**
- Consumes: cohort frame satisfying `ONE_PACKET_COHORT_COLUMNS`; `iter_capture_packet_records`; `FlowKey`.
- Produces: `extract_one_packet_chunk_observations(capture_path, cohort, output_directory, chunk_id, source_url=None) -> ChunkMetadata`, `load_completed_chunk_observations(output_directory, chunk_id, cohort) -> ChunkObservations`, and completed-metadata enumeration.

- [ ] Write focused failing tests for target tuple filtering, candidate-source plain-SYN filtering, TCP/UDP facts, source identity, deterministic schemas/order, atomic completion validation, corrupted artifacts, changed capture, and changed cohort.
- [ ] Run the new tests and confirm they fail because the cache interfaces do not exist.
- [ ] Implement observational CSV schemas, canonical cohort identity, atomic dataframe publishing, metadata identity/checksum/schema validation, and reload-before-completion semantics.
- [ ] Run the focused cache tests and confirm they pass.

### Task 2: Shared timestamp-based aggregation

**Files:**
- Modify: `src/mawi_global_analysis/one_packet_context.py`
- Modify: `tests/unit/test_one_packet_context.py`
- Modify: `tests/unit/test_one_packet_context_chunks.py`

**Interfaces:**
- Consumes: `ChunkObservations` from Task 1 and legacy raw capture records.
- Produces: `aggregate_one_packet_context_observations(cohort, observations) -> tuple[pd.DataFrame, pd.DataFrame]`; existing `scan_one_packet_contexts` delegates to shared logic.

- [ ] Write failing tests proving combined-capture equivalence, arbitrary chunk order invariance, target uniqueness across chunks, previous/reverse observations across boundaries, inclusive source windows, and full-day set-union uniqueness.
- [ ] Run the selected tests and confirm failure before the aggregation interface exists.
- [ ] Refactor packet/source observation decoding and context accumulation into a single timestamp-aware aggregation path; make legacy scan extraction feed it.
- [ ] Run context and chunk aggregation tests and confirm they pass.

### Task 3: Multi-chunk context-run provenance

**Files:**
- Modify: `src/mawi_global_analysis/one_packet_context_run.py`
- Modify: `src/mawi_global_analysis/io.py`
- Modify: `tests/unit/test_one_packet_context_run.py`
- Modify: `tests/unit/test_one_packet_context_io.py`

**Interfaces:**
- Consumes: completed chunk metadata and observations, source run manifest, target chunk ID.
- Produces: a multi-chunk run entry point/writer with `input_mode: "ditl_chunks"`, final identity derived from chunk identities and code identity, and loader-compatible final artifacts.

- [ ] Write failing tests for aggregate-after-raw-deletion, direct DITL target-chunk source-run provenance, checksum mismatch failure, and loader compatibility.
- [ ] Run selected provenance tests and confirm they fail before the DITL path exists.
- [ ] Implement validated completed-chunk collection, direct target-chunk source-run ancestry checks, and non-breaking final manifest identity/provenance extensions.
- [ ] Run context-run and loader tests and confirm they pass.

### Task 4: Documentation and regression verification

**Files:**
- Modify: `docs/research/2026-09-27-one-packet-context-analysis.md`
- Modify: `docs/agent/current-state.md`

- [ ] Record the per-chunk acquisition → durable observation → verified checkpoint → eligible raw-deletion execution model, explicitly marking acquisition/deletion as Phase 5B deferred.
- [ ] Record only verified Phase 5A capabilities in current state.
- [ ] Run focused new tests, then all one-packet/capture/flow regressions, `uv run pytest -q`, and `git diff --check`; inspect outputs.
- [ ] Request one fresh reviewer focused on scientific equivalence, chunk-boundary/order behavior, checkpoint integrity, post-raw-deletion use, provenance, compatibility, and memory behavior; fix material findings and rerun affected checks.
