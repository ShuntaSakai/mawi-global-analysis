# Agurim prime implementation plan — 2026-10-30

The human's five-phase implementation request is the specification and authorization.
Work on existing main; no commit, branch, worktree, push, PR or overwrite of existing artifacts.
Baseline: clean main and clean submodule ab5c5cc80e9e1229bb66ec83bb25f186898d5e49.
Baseline pytest: 637 passed, 3 existing Notebook 06 failures (see final runbook).

## Decisions

- Preserve the original upstream submodule. Keep a parent-tracked patch fork under
  vendor/agurim-prime, with an isolated reproducible build. No remote fork/commit
  can be created under the explicit no-commit/no-push instruction. Record null
  fork_commit, upstream commit, patch identity and executable hash honestly; document
  migration to an immutable fork submodule commit after human publication.
- Canonical input includes IPv4 TCP/UDP only. One record per canonical bidirectional
  flow, retaining first-observed endpoint orientation; no reverse copy. Validate
  unique IDs and direction-independent keys (no timeout); reject uint32 overflow.
- Prototype uses one packet per canonical row; formal flow mode retains actual byte
  and packet counters, adds independent uint64 flow state throughout RLS. Retain
  original integer percentage thresholds and heuristics. Always -n 0, no top-k.
- Control modes byte/packet consume the same canonical records; unit-packet is
  explicitly a probe. Raw-PCAP original Agurim remains a separate condition.
- Reuse corrected ledger, chunked build_membership and normalized24 aggregation,
  HistogramSpec and renderer. New successful run manifests supply method/lineage.

## Tasks and interfaces

1. Test canonical conversion, malformed/duplicate input, real compiled flow/packet/
   byte/probe E2E, cache corruption, HTML no-overwrite and shared axes. Confirm red.
   Implement agurim_prime/input.py::convert_flows(flows, output, unit_packets=False,
   allow_segments=False) -> audit. Stream rows; disk-backed uniqueness; 56-byte
   network-order aguri_flow; atomic new-file publication.
2. Implement C fork and builder (one coherent delegated task), with compiled tests:
   weights 1 vs 100, RLS residual conservation, probe equivalence, byte/packet
   old-vs-fork regressions, truncated input. Contract: -F -m flow -t 1..100 -n 0
   [-D [-D]], CSV discounted_flow_count (not exact cohort size).
3. agurim_prime/stage.py::run_prime(root,dataset,run,flows,executable,mode='flow',
   threshold=1,heuristics=0,chunksize=100000)->run_manifest. Immutable fingerprinted
   caches include flow and CSV/manifest identity, source/build/executable identity,
   basis/options/threshold, converter source/version. Use separate artifacts/runs.
4. Generalize normalized24 selection provenance for prime/control/probe runs,
   validating binding to producer and cache. Keep existing public API and default
   Agurim runs compatible. Add CLI python -m mawi_global_analysis.agurim_prime with
   optional new HTML output, same offline search/sort/details.
5. Exercise synthetic PCAP -> canonical flows -> modes -> /24 HTML and contrast
   with original PCAP Agurim; report capture filtering/orientation and byte-unit
   effects, remaining MAWI validation boundary. Run focused then full pytest,
   diff check, independent review, fixes with regression tests, final documentation.

## Verification

.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_agurim_prime.py tests/test_agurim_prime_fork.py tests/test_normalized24.py
.venv/bin/python -m pytest -q -p no:cacheprovider
 git diff --check

No generated synthetic fixture output is evidence of real MAWI validation.

## Execution ledger

- Tasks 1–4 implemented; canonical converter red→green, real C fork red→green,
  shared method provenance red→green. No edits to upstream submodule.
- Task 5: both original PCAP and canonical modes generated Raw /24 exports;
  weighted 101-flow contrast isolates weight from input representation.
- Independent review identified missing complete canonical-schema validation and
  stage executed/reused records; both reproduced red, fixed and closure reviewed.
- Fixture and browser verification only. Real MAWI and scale benchmarking deferred.
- No history operations, branches, worktrees, push or PR; main retained.
- Final verification: focused 84 passed; full 686 passed, 3 unchanged baseline
  Notebook 06 failures. git diff --check passed. No new suite failures.
