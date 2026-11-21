# Random /24 Prefix Selection Implementation Plan

Approved in the Codex conversation on 2026-11-21. Execute inline with
`superpowers:executing-plans`; keep changes uncommitted on the explicitly
requested `codex/random24-prefix-selection` branch. No worktree or publication.

## Goal and research contract

Draw 18 control /24s from canonical IPv4 TCP/UDP source OR destination observed
/24s, after excluding the union of containing /24s of **selected** native
prefixes from the fixed Flow18 and Packet15 two-stage runs. No traffic minimum,
scan removal, replacement, seed search, or changes to existing selectors/caches.
Native length and 18/15/18 count differences remain explicit confounders.
Canonical bytes count captured Ethernet frames; downstream original-frame bytes
may differ on truncated captures. Compare all three protocol groups using the
same downstream counters, PCAP, window, and src OR dst rule.

## Fixed algorithm and artifacts

`mawi-random24-sha256-v1`: SHA-256 of ASCII algorithm ID + NUL + unsigned
64-bit big-endian seed + 4-byte network address. Sort by digest bytes, then
numeric network address, and take count (default 18); seed defaults to 20260408.
Seed is an integer in [0, 2**64-1]. Set hashes use the explicit domain
`mawi-random24-set-v1` + NUL + ascending packed IPv4 network addresses;
selection hash uses `mawi-random24-selection-v1` + NUL + ranked addresses.
No claims of mathematically exact uniformity over the finite seed space.

New package: `src/mawi_global_analysis/random_prefix_selection/`:
`__init__.py`, `__main__.py`, `population.py`, `sampling.py`, `validation.py`,
`run.py`, `cli.py`. Existing code is reused without editing it.

Outputs: prefixes.csv (9 columns: prefix, prefix_length, normalized_prefix_24,
selected_for_analysis, analysis_scope, selection_rank, observed_flow_count,
observed_packet_count, observed_byte_count), the existing five-column membership
in native and normalized_24 scopes, selection_population.csv,
excluded_prefixes.csv, selection_config.yaml, run_manifest.json.
No fictional Aguri counters. Manifest schema `random-prefix-selection-run-v1`
binds input.sha256, both source runs/ledgers, canonical/flow manifest, sets,
algorithm/settings, all outputs and implementation; success is published last.

## Task ledger and dependencies

Every behavior task follows RED test -> observed failure -> implementation ->
GREEN -> diff/contract check. No commit commands; user owns history.

| ID / phase | Purpose and files | Interfaces / input -> output | Depends | Tests / completion / risks |
|---|---|---|---|---|
| P0-1 / 0 | Read real source runs, record evidence here | saved manifests -> CIDRs, real paths and hashes | lab access | Verify 18/15 and common input; unavailable here, never invent results |
| P0-2 / 0 | Save this plan; research-contract.md | approved design -> fixed research definition | approval | Check spec coverage; preserve previous semantics |
| P1-1 / 1 | population.py, tests/test_random_prefix_population.py | parent24; load_selected_prefixes; build_population -> disk-backed U/E/eligible | P0-2 | both endpoints, /24-/32, bools, duplicates, invalid rows; risk silent coercion |
| P2-1 / 2 | sampling.py, tests/test_random_prefix_sampling.py | score_prefix; select_prefixes -> ranked unique /24s | P0-2 | golden bytes, seed/range, order, collision, shortage; risk encoding drift |
| P3-1 / 3 | validation.py, tests/test_random_prefix_validation.py | validate_inputs -> verified manifests/paths/tracked hashes | P1-1 | exact 18/15, lineage, common inputs/settings, mutation; missing historical build fails explicitly |
| P3-2 / 3 | run.py, tests/test_random_prefix_membership.py | write_membership_and_counts -> scopes and exact counters | P1-1,P2-1,P3-1 | OR, both-end dedup, cross-prefix flows, global ID uniqueness; no full CSV in RAM |
| P3-3 / 3 | run.py, cli.py, entrypoints, tests/test_random_prefix_cli.py | run_random_selection / verify_run; run,audit-inputs,verify | P3-1,P3-2 | immutable destinations, atomic manifest-last publication, failure cleanup and races |
| P4-1 / 4 | tests/test_random_prefix_integration.py | synthetic canonical + Flow18/Packet15 -> Random18 | P3-3 | real compiled synthetic lineage, hashes, exclusion, counts, failures, unchanged inputs; full regression vs baseline |
| P5-1 / 5 | tests/test_random_prefix_compatibility.py | actual downstream loader + synthetic PCAP CLI | P4-1 | Random18/Flow18/Packet15, manifest/hash mismatch; do not modify other repository |
| P6-1 / 6 | guide/random-prefix-selection.md, agent index/current-state | audit -> run -> verify -> downstream commands | P5-1; real evidence P0-1 | copyable commands resolve paths from manifests; real MAWI/performance remain unverified |

## Review focus

- Incorrect flags/counts and resigned artifacts must not bypass source lineage.
- Same-capture but different canonical CSV/flow manifest is rejected.
- Duplicate flow IDs across chunks and reversed tuple duplicates are rejected.
- Existing paths/symlinks/concurrent destinations are never replaced.
- Mid-run input changes and failed output validation cannot publish success.

## Initial evidence / execution notes

- Main and clean global working tree verified before creating approved branch.
- Lab hostname is unavailable; target real runs/canonical not present locally.
  P0-1 real CIDRs, paths, 18/15 counts and real Random18 execution are deferred.
- Existing related tests: 42 passed in planning turn. Downstream prefix tests:
  11 passed, 3 Notebook output-state failures. Other repo's modified Notebook
  remains untouched. Whole-suite baseline is being collected before code work.
- Ruling: use one persistent plan ledger here instead of commit-based skill
  scripts: commits are forbidden by repository/user workflow. Keep RED/GREEN
  evidence here; no automatic staging, commits, or branch finishing actions.

## Progress

- P0-2 complete: approved branch and this plan created before code edits.
- P0-1 deferred: lab host unavailable; real CIDRs/paths/counts/Random18 unverified.
- P1-1/P2-1 complete: tests RED (34 failures missing implementation) -> GREEN
  (34 passed); golden SHA input independently checked with xxd/OpenSSL.
- P3-1 complete: authentic compiled synthetic Flow18/Packet15 fixture;
  strict lineage/count/flag/hash failures verified. Combined 41 passed.
- P3-2/P3-3/P4-1 basic complete: RED missing run writer -> GREEN 56 passed;
  expanded population/membership/shortage/publication-race checks 61 passed.
- Ruling: make membership serialization independent of chunks by sorting each
  chunk's edges by source row, scope, selection rank. Initial reconstructive
  verify exposed the inherited scope/prefix-major chunk ordering; corrected.
  Cost: per-chunk sorting/RAM, bounded by chunksize and selected count.
- Baseline whole suite: 1006 passed, 4 failed (222.16s). Existing failures:
  test_legacy_quickmerge_and_multiblock_controls_match (old scheduling path),
  test_failed_notebook_rerun_cannot_display_or_export_previous_results,
  test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports,
  test_eighteen_ledger_prefixes_display_twenty_inline_targets_without_files.
  Logs: /private/tmp/random24-baseline-tests.log (execution-local).
- P5-1 RED: actual downstream fixture required byte-bound synthetic PCAP; fixture
  now writes its packets and source manifest binds its real hash.
- P5-1 complete: actual sibling loader/CLI accepted Random18/Flow18/Packet15 and
  rejected a different PCAP. Fixture canonical is now extracted from the actual
  synthetic PCAP via existing run_flow_stage. Combined 64 passed.
- P6-1 complete: research contract, AI index/current-state and detailed guide
  written. Both copyable Bash runbook blocks passed bash -n. Real paths are
  resolved from source manifests; actual PCAP path is explicitly entered by user.
- Final independent review: one Important finding, no other actionable findings.
  Reproduced post-inspector cache corruption publishing success (RED 1 failed).
  Fixed by binding cache/build bytes to expected recorded hashes BEFORE inspection,
  refusing conflicting bindings, and checking before/after inspection/publication.
  Regression and combined new suite GREEN: 65 passed in 28.24s.
- Ruling: reviewer-declined actual MAWI CIDRs/counts/window, scientific
  representativeness, exact uniformity, real-scale performance and inherited C
  correctness remain explicit evidence limits, not inferred successes. Machine
  crash durability and hostile transient ABA/filesystem replacement are not
  claimed; manifest-last exception-safe publication and input hash checks are
  the implemented contract. Cost: real-data/performance and stronger adversarial
  guarantees require separate validation/design work. No deferred Minor findings.

## Final verification and deliverables

- Final full suite after review fix: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python
  -m pytest -q -p no:cacheprovider` -> **1072 passed, 3 failed in 243.84s**.
  The three failures are the same Notebook06 tests listed in the baseline above.
  The baseline legacy C scheduling failure did not reproduce; existing C code
  is unchanged. Log: /private/tmp/random24-after-review-suite.log.
- New tests: `... pytest -q -p no:cacheprovider tests/test_random_prefix_*.py`
  -> **65 passed in 28.24s** after the review fix. All are synthetic evidence.
- Actual sibling existing prefix loader/CLI tests excluding Notebook tests:
  **11 passed, 3 deselected**. Its existing Notebook modification is untouched.
- CLI root/run/verify help succeeded, both Bash runbook blocks passed bash -n,
  git diff --check passed; existing selector/config/vendor paths have no diff.
- Added 16 files: seven new package modules, seven test modules, this plan and
  the operational guide. Modified only docs/agent/{README,current-state,
  research-contract}.md. Deleted none. All changes remain uncommitted.
- P0-1 and real-data portion of P6 remain deferred: no lab hostname/data access,
  no authenticated actual selected CIDRs/counts/canonical paths, no real MAWI
  Random18 output or performance measurement. The shipped audit command checks
  these saved contracts on the lab PC and fails without correcting discrepancies.
