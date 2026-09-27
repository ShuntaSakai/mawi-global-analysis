# One-Packet Context Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make approved one-packet context analysis runnable, provenance-aware, and manifest-loadable without changing the source-run scan semantics.

**Architecture:** Extend the existing single-pass packet scanner to retain only plain-SYN observations from applicable target sources while it finds tuple context. Add a focused context-run module for deterministic CSV/manifest output and orchestration; keep the CLI a thin adapter. The loader reads only the manifest-declared artifacts.

**Tech Stack:** Python, pandas, dpkt, pytest.

**Spec:** `docs/research/2026-09-27-one-packet-context-analysis.md` plus the approved Phase 3 request supplied in this task.

## Global Constraints

- Work in the existing `main` tree; preserve Phase 1/2 and human changes; do not commit.
- Do not implement notebooks, real-data execution, 24-hour canonical flows, detector reruns, or behavioral labels.
- Plain-SYN source identity is the target packet's observed source only; non-plain-SYN targets retain null source statistics.
- Target-relative source windows are inclusive symmetric intervals; 24h values use all supplied-capture observations.
- Results are under `results/<dataset>/<context-run-name>/`, atomically published, schema-checked, and protected from incompatible identity overwrite.

## Review Focus

- A target ACK/RST/UDP must never use canonical flow `src_ip` as an inferred initiator; tests cover TCP and UDP non-applicability.
- An observation exactly at every ± window boundary must be included; tests cover ±5m, ±15m, and ±1h.
- A packet from an unrelated source must not be retained or counted; scanner test exercises mixed traffic.
- Existing successful output with a different capture/source-run identity must fail before replacement; writer test covers conflict.
- Loader paths must come from the manifest and CSV schemas/row linkage must be validated; IO tests cover missing and wrong artifacts.

### Task 1: Source-context streaming observations

**Files:**
- Modify: `src/mawi_global_analysis/one_packet_context.py`
- Test: `tests/unit/test_one_packet_context.py`

**Interfaces:**
- Produces `ONE_PACKET_SOURCE_CONTEXT_COLUMNS` and `scan_one_packet_contexts(full_capture_path, cohort) -> tuple[pd.DataFrame, pd.DataFrame]`; retain `scan_one_packet_context` compatibility.

- [ ] Write focused failing scanner tests for applicability, inclusive windows, target diversity, all-capture counts, and unrelated-source filtering.
- [ ] Run those tests and confirm they fail because source-context output/scanning is absent.
- [ ] Implement the minimal source observation index and single streaming scan.
- [ ] Run `uv run pytest tests/unit/test_one_packet_context.py -q` and confirm pass.

### Task 2: Deterministic context artifacts and manifest

**Files:**
- Create: `src/mawi_global_analysis/one_packet_context_run.py`
- Modify: `src/mawi_global_analysis/one_packet_context.py`
- Test: `tests/unit/test_one_packet_context_run.py`

**Interfaces:**
- Consumes cohort/context/source-context frames plus validated source/window provenance.
- Produces `run_one_packet_context_analysis(...) -> Path` and `context_manifest.json` with artifact checksums/row counts.

- [ ] Write failing tests for deterministic schemas/order, row linkage, manifest identity/provenance, failure-safe final status, and incompatible existing output.
- [ ] Run the new test module and confirm it fails because the module/interface is missing.
- [ ] Implement atomic CSV/manifest writers and source/window consistency validation.
- [ ] Run the module tests and confirm pass.

### Task 3: Manifest-driven context loader

**Files:**
- Modify: `src/mawi_global_analysis/io.py`
- Test: `tests/unit/test_one_packet_context_io.py`

**Interfaces:**
- Produces immutable `OnePacketContextData` and `load_one_packet_context(dataset_id, context_run_name, root=Path('.'))`.

- [ ] Write failing tests for successful manifest load, missing artifacts, wrong schemas, failed status, and manifest-declared paths.
- [ ] Run the new tests and confirm they fail because the public loader is missing.
- [ ] Implement focused manifest/schema/checksum/linkage validation without changing `RunData` behavior.
- [ ] Run loader tests and confirm pass.

### Task 4: Thin CLI and integration verification

**Files:**
- Create: `run_one_packet_context.py`
- Test: `tests/unit/test_one_packet_context_cli.py`

**Interfaces:**
- Parses `--dataset`, `--source-run`, `--full-capture`, and `--context-run-name`; delegates to Task 2.

- [ ] Write a failing tiny-fixture integration test showing the CLI creates three CSVs, a success manifest, and a loader-readable run.
- [ ] Run it and confirm it fails because the CLI is absent.
- [ ] Implement the thin argument parser/delegation.
- [ ] Run focused Phase 3 tests, shared-module regressions, full suite, and `git diff --check`.

## Final Verification

- [ ] Inspect the diff against the research contract and Phase 3 scope.
- [ ] Use one fresh reviewer for source-role semantics, boundaries, streaming-memory behavior, provenance, loader trust, and overwrite safety.
- [ ] Fix material findings and rerun affected tests; do not commit.
