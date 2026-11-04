# Normalized24 Exact Statistics Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for this approved phase. Keep changes uncommitted on main per AGENTS.md.

**Goal:** Extend the shared Raw /24 analysis with exact totals and bounded-memory, provenance-bearing frequency exports.

**Architecture:** Preserve the existing SQLite facts/membership/dist pipeline. Add canonical byte_count to facts, exact byte totals in a small per-target table and packet totals in the existing ordered frequency scan. Stream integer frequencies to CSV in an optional new single-run export bundle with summary.json, using the same analysis execution and validated inputs.

**Tech Stack:** Python 3.12, existing SQLite/pandas/stdlib CSV and JSON, pytest.

**Spec:** User's stage-2 request and the approved approach A; phase-3 Jaccard/coverage/ECDF/comparison manifest are excluded.

## Global Constraints

- Start from main f028910 with a clean tree; all ten phase-1 files match recorded hashes.
- No Git history/branch/worktree operations. Preserve existing data, runs, caches, source material and unrelated changes.
- Same full-/24 src OR dst membership and flow_id-deduplicated selected_union.
- Preserve median/p95 linear interpolation, one-packet rate and histogram bins/axes.
- Stats add packet_total, byte_total, mean_packet_count; totals are zero for empty sets, mean and existing undefined statistics are null.
- No unbounded list/fetchall/expanded packet arrays. Integer totals must not overflow SQLite signed SUM or become floats.
- Bump analysis payload schema to 2 and aggregation to normalized24-raw-v2. Existing field names/layout stay available; no new frequency array in HTML or default payload.
- Exact CSV schema: distribution,packet_count,frequency; unique sorted pairs. Empty distributions are represented in summary, with no fake CSV row.
- Optional export_raw_statistics returns a new bundle containing summary.json + frequencies.csv; this is a single-run artifact, not a comparison manifest.
- New output directories only, outside protected source/cache/run locations; publish summary last, reject overwrites, clean failed output owned by this call.

## Review Focus

- Prefix overlap across endpoints must not double-count union bytes or packets.
- Different packet sizes in one histogram bin must remain separate CSV records.
- Large integer totals remain exact in Python/JSON/CSV; HTML must not silently round new totals above JavaScript's exact integer range.
- Corrupt membership, concurrent input changes, output collisions and publication failures must not leave a successful export.
- Default analysis/HTML and phase-1 validation continue to work without exporting frequencies.

## Task 1: Shared totals and export

**Files:** Modify normalized24/analysis.py, __init__.py and dashboard.py; add normalized24/statistics.py. Add tests alongside existing tests/test_normalized24.py; update guide and research/current-state documentation.

**Interfaces:**
- Existing analyze_agurim_run signature remains compatible and returns schema 2.
- summarize_frequencies(db, target, spec, *, byte_total: int | None = None) keeps the original dist table contract; unavailable bytes in external adapters are null for nonempty groups, zero for empty groups.
- export_raw_statistics(root, dataset_id, run_name, output_dir, *, chunksize=100000, scratch_dir=None, spec=None, progress=None) -> Path returns a new summary.json path. Internal analysis accepts a streaming frequency sink only for the exporter.

- [x] Write tests with hand-computed /24, union and Overall totals, nulls, byte sums, chunk invariance, exact CSV within one bin, export provenance, protected paths, failure cleanup and large integers.
- [x] Run them RED before implementation.
- [x] Extend the existing SQLite aggregate and ordered summary scan, implement streaming single-run exporter and safe HTML encoding for new large totals.
- [x] Run new and existing normalized24/prime/phase-1 tests, document schema/compatibility and API.
- [x] Independent review; reproduce and fix material findings with regression tests.
- [x] Full suite and diff checks; report pre-existing failures separately, leave code uncommitted.

## Execution ledger

- Baseline: main f028910, clean; stage-1 ten-file checksums match. Stage-1 + existing normalized24 tests: 98 passed (25.07s).
- Ruling: The user approved implementation of stage 2 with detailed constraints. Implement directly without another approval; repo rules override worktree/commit defaults.
- Ruling: Use a single-run CSV + summary JSON bundle rather than embedding frequencies in the analysis payload; this preserves bounded memory and persists provenance without implementing a stage-3 comparison manifest.
- RED: initial selected tests failed for missing schema-2 totals/export API (7 failures); the existing no-array condition already passed.
- GREEN: all normalized24 tests 51 passed (35 existing + 16 new); related prime/C/phase-1 regression 163 passed in 30.99s.
- Independent review: no actionable findings; separate normalized24 run 51 passed in 11.88s.
- Full suite: pre-change 749 passed / 3 failed (54.72s); final 765 passed / same 3 failed (61.80s). Existing failures are Notebook06 tests `test_failed_notebook_rerun_cannot_display_or_export_previous_results`, `test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports`, and `test_eighteen_ledger_prefixes_display_twenty_inline_targets_without_files`.
- Synthetic smoke: exported saved packet-t1-h2 fixture via the new API; schema 2, 16 frequency rows, union 6 flows / 13 packets / 711 canonical bytes. These are synthetic values, not MAWI findings.
- Completion: source/input provenance, CSV frequency conservation and publication protections verified; no C/converter/prefix/membership/baseline or phase-1 code changes; no commit or history operations.
