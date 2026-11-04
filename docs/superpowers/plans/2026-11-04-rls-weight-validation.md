# RLS Weight Comparison Validation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for this single approved phase. Keep changes uncommitted on main per AGENTS.md.

**Goal:** Validate three saved canonical-input packet/byte/flow runs without writing analysis artifacts or rerunning stages.

**Architecture:** Add a small comparison package around existing `inspect_run` and `inspect_prime_lineage`. Check explicit per-mode requirements, compare common semantic identities, validate recorded binary/build files, and rehash inputs before returning. No ECDF, coverage, new caches, or membership algorithms.

**Tech Stack:** Python 3.12, existing pandas/Pydantic/YAML, argparse, pytest and real compiled synthetic runs.

**Spec:** User-approved approach A and phase 1 in the 2026-11-04 investigation report; the current user request authorizes implementation directly in `/Users/shunta/mawi-global-analysis`.

## Global Constraints

- Preserve existing changes; no branches, worktrees, staging, commits, pushes or PRs.
- Require the same canonical CSV/manifest/capture/fingerprint, TCP+UDP, no inactivity timeout.
- Require threshold 1 percent, disable-heuristics 2 (`-D -D`), `-F`, `-n 0` and precisely packet/byte/flow.
- Preserve corrected both-side /24+ selection, broader-first containment, full-/24 src-OR-dst evaluation, Raw and flow_id union deduplication.
- Compare semantic config sections, not config hashes or prime fingerprints across modes.
- Validate only: no files/directories created, no subprocess stage execution; JSON goes to stdout only.
- Do not change C, converter, prefix, membership or baseline. No distribution or coverage work.

## Review Focus

- A coherent but different CSV/build must fail common-identity checks, not just malformed metadata.
- Missing, contradictory or modified provenance must fail with the run/mode and field named.
- Actual command options must agree with identity options; repeated `-D` matters.
- Read-only validation must leave all input directories and file bytes/mtimes unchanged on success and failure.
- Validation checks saved selection/evaluation contracts and artifact integrity, not full membership recomputation or scientific validity.

## Task 1: Validation API, validation-only CLI and documentation

**Files:**
- Create `src/mawi_global_analysis/rls_weight_comparison/{__init__,__main__,validation,cli}.py`.
- Create `tests/test_rls_weight_comparison.py`.
- Create `docs/guide/rls-weight-comparison.md`; link it from `docs/agent/README.md`.
- Update `docs/agent/research-contract.md` and `docs/agent/current-state.md` with the validation scope.

**Interfaces:**
- Consumes successful prime run manifests/caches and existing canonical artifacts; `inspect_run(root, dataset_id, run_name, raw_only=True)` and `inspect_prime_lineage(info, root, input_hashes)`.
- Produces `validate_comparison(root: Path, dataset_id: str, *, packet_run: str, byte_run: str, flow_run: str, chunksize: int = 100_000) -> dict`.
- Raises `ComparisonValidationError(ValueError)` identifying mode/run and failing field.
- CLI: `python -m mawi_global_analysis.rls_weight_comparison --validate-only --root ... --dataset ... --packet-run ... --byte-run ... --flow-run ... [--chunksize ...] [--json]`. Exit 0 on success, 2 on invalid input. No output path option.

- [x] Write real-run tests: accept valid t1/h2 runs despite distinct config hashes/fingerprints, reject parameter/identity/contract/artifact mismatches, verify readonly success/failure and CLI errors.
- [x] Run new tests; confirm RED because validation API/CLI is absent.
- [x] Implement validation API and CLI only, preserving existing execution and analysis modules.
- [x] Run focused tests; resolve failures with RED/GREEN evidence.
- [x] Document API, restrictions, exact CLI and verification evidence.
- [x] Run prime/C/normalized24 and corrected-prefix/membership regressions plus full suite. Report unrelated baseline failures by name rather than fixing them in this phase.
- [x] Fresh independent review of the uncommitted files; address material findings with tests.
- [x] Review diff and status; leave changes uncommitted and report files/tests/limitations.

## Execution ledger

- Start: main `b95aeb7`, working tree clean. Existing project mirror remains untouched.
- Ruling: User explicitly approved phase 1 implementation, so execute without another plan approval. Repository rules override skill defaults about worktrees and commits.
- Pre-flight: Single task; API signature above is shared by CLI and tests.
- Task 1: complete, uncommitted. Initial acceptance test RED (API absent), then 35 GREEN; row-count and diagnostic gaps reproduced RED and fixed, reaching 51 GREEN.
- Independent review: three Important findings, no Critical or deferred Minor findings. Reproduced audit contract/type and build provenance gaps with 12 RED tests; fixed in the validator, resulting in 63 GREEN (10.64s).
- Verification: related regressions before review fixes 146 passed (27.17s); final full suite after review fixes 749 passed / 3 unchanged Notebook06 failures (54.90s). Baseline was 686 passed / those same 3 failures (48.10s).
- Existing failures: `test_flow_length.py::test_failed_notebook_rerun_cannot_display_or_export_previous_results`; `test_flow_length_individual.py::test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports`; `test_flow_length_individual.py::test_eighteen_ledger_prefixes_display_twenty_inline_targets_without_files` (all under tests/unit).
- Final: no distribution/coverage changes, no C/converter/prefix/membership/baseline changes, no branches/commits. Full membership reconstruction and real MAWI validation remain later work as specified.
