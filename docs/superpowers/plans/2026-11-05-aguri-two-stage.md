# Canonical two-stage Aguri implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline, test-driven-development and one final independent review. User approved implementation of the design. Work on main, leave uncommitted; no further stage approvals required.

**Goal:** Reuse pinned Aguri3→Agurim RLS with canonical packet/byte/flow weights, verified residual transport, immutable runs and shared exact evaluation.
**Architecture:** Upstream + existing prime patch + independent two-stage delta. Strict framed binary residual transport; native/normalized statistics and existing HTML reused through a dedicated validator/adapter.
**Tech Stack:** C, Python, SQLite, existing pandas chunk membership, vanilla offline HTML.
**Spec:** ../specs/2026-11-05-aguri-two-stage-design.md (approved by user).

## Global constraints
- main85f8de87c27d248fcd44a0871c0337db4c0ae0db; preserve existing design document and unrelated edits; no commit/push/worktree.
- Both stages threshold1, disable_heuristics0 by default, intervals0, no top-k; same mode in both stages.
- Independent flow count=one canonical bidirectional IPv4 TCP/UDP row, no duplication; old uint32 input counts retained.
- Legacy RLS search unchanged; quickmerge packet heuristic fixed in all modes. Protocol deficits audited, never new HHH candidates; old no-label wildcard fallback retained.
- No real MAWI locally: compiled synthetic and regression verification only, manual commands delivered.

## Review focus
- Mixed labeled protocol + deficit across repeated blocks must not acquire a new absorbing wildcard (Task1).
- Early-summary/EOF block loss and truncated/forged counters must fail (Task1/2).
- Mode, binary/build/source/patch and input lineage must bind both actual commands (Task2).
- Run/cache collisions, unsafe output paths and failure cleanup must preserve existing files (Task2/3).
- Dedicated comparison contract must reject direct/legacy runs, preserve exact native statistics, empty/null/offline UI (Task3).

### Task 1 — compiled regression and exact transport (Phases2/3)
Files: vendor/agurim-two-stage/two-stage.patch, scripts/build_agurim_two_stage.py, tests/test_aguri_two_stage_c.py; C additions reside in patch.
Interfaces: build(output, root=None)->Path(build_manifest); aguri3/agurim -W -m packet|byte|flow|combination -t integer [-D...]; stage1 accepts -H; both stdin/stdout.
- [x] RED builder/legacy packet byte combination regression tests.
- [x] Build pinned source plus existing flow patch, new delta; preserve legacy path. Verify both stage outputs against upstream.
- [x] RED wire/flow/EOF/underflow/mode-separation tests; add strict AGWGT001 framed transport and Python wire inspector in Task2.
- [x] GREEN exact counters, residual propagation, protocol audit/fallback, repeated blocks, corruption and deterministic difference from direct RLS.

### Task 2 — canonical pipeline and dedicated provenance (Phase4)
Files: aguri_two_stage/{wire,stage,validation}.py, tests/test_aguri_two_stage_pipeline.py.
Interfaces: inspect_wire(path,expected=None)->dict; run_two_stage(root,dataset,run,flows,build_dir,mode,threshold=1,heuristics=0,max_hashentries=1000000,chunksize=100000)->Path; validate_runs(root,dataset,packet_run,byte_run,flow_run,chunksize=100000)->dict.
- [x] RED streaming canonical/run/cache/changed-input/identity/failure tests.
- [x] Reuse converter/_source; reject timeout/segments; record both commands, audit wire, immutable cache, corrected ledger and chunked membership; final manifest last.
- [x] GREEN dedicated method lineage; verify actual files and intermediate/canonical records; no false prime identity/validator skip.

### Task 3 — shared statistics, UI, CLI (Phase5)
Files: aguri_two_stage/{comparison,cli,__init__,__main__}.py, tests/test_aguri_two_stage_comparison.py; minimal normalized24 dispatch; guide/index/contract.
Interfaces: generate_comparison(...)->Path, verify_manifest(path)->dict; CLI run/compare with validate-only.
- [x] RED comparison exact native/normalized/per-prefix/Overall/coverage/KS/Jaccard/read-only/hash tests.
- [x] Reuse existing normalized export/native analysis/renderer with dedicated lineage, templates adapted only to two-stage experiment vocabulary. New bundle; preserve existing generators/validators.
- [x] GREEN synthetic and empty CLI/end-to-end tests, offline browser and SVG controls. Include manual commands/schemas/performance limits.

### Task 4 — final review and evidence
- [x] Focused compiled/pipeline/comparison tests plus related/full regression against baseline874pass/3Notebook06 failures.
- [x] One independent reviewer; material findings reproduced RED→GREEN.
- [x] Report added/modified/deleted, old and synthetic evidence, wire/heuristics differences, manual MAWI command, residual risks; no commit/push.

## Ledger
Plan/spec interfaces reviewed: Task1 wire matches Task2 inspector; Task2 lineage supplies Task3 dedicated adapter; no direct comparator acceptance bypass.
Ruling: inline execution preserves approved phase ordering and completes all authorized tasks without another confirmation.

Ruling: low-H repeated tests reproduced legacy buffer reuse before consumer processing, changing block boundaries by scheduling (not just EOF). New -W path uses per-buffer ready/empty condition-variable rendezvous; legacy path retains original scheduling. The RLS/check_flowtime/hash-limit decision is unchanged; only completed empty buffers are reused. Strict old numeric regression applies at ordinary/default H; tiny-H old runs are audited for totals and scheduling differences are reported rather than normalized away. Cost: new deterministic H boundaries need not equal a particular old scheduling realization.

Final evidence: user-approved Phases2–5 complete. Legacy packet/byte/combination default-H and >1000-port controls matched; tiny-H legacy scheduling discrepancy is explained above. New wire/flow/parent residual/mixed-protocol/fallback/threshold/format tests passed, including directly observable difference from direct RLS. Cache/input/command binding, rejected corruption, shared native/normalized exact statistics, chunksize/display invariance and immutable comparison were tested. Final full suite:925passed/3same pre-existing Notebook06 failures in163.35s versus baseline874/3. All51 new tests passed. Populated/empty final standalone HTMLs passed existing Playwright smoke tests offline (6 tabs, exact tables, individual max5 curves, scope comparison, zoom/hover/SVG, no JS errors). Both21-artifact final example bundles and current implementation hashes verified. CLI run/validate/verify exercised. Independent whole-feature review: no material findings; subsequent Makefile linking and manifest-run binding self-findings reproduced RED→GREEN and independently closure-reviewed (2tests passed). No actual MAWI. No commit/push.
