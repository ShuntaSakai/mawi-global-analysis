# Native prefix comparison implementation plan

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development. Work on main, leave uncommitted.

**Goal:** Add native prefix evaluation and a native-vs-normalized24 scope comparison using fixed saved packet/byte/flow selections.
**Architecture:** Validate the existing runs and optional comparison bundle. Load canonical facts once into SQLite; validate both saved membership scopes using endpoint ranges and completeness counts. Reuse normalized24._summarize, exact ECDF/KS/Jaccard helpers and bounded individual display data. Keep the existing normalized dashboard/artifacts unchanged in a new bundle; add native exports and an independently readable native HTML using shared rendering.
**Tech Stack:** Python/SQLite/CSV, shared vanilla HTML/JS/SVG, optional Playwright verification.
**Spec:** User's Native Prefix evaluation request, 2026-11-05, this chat.

## Global constraints

- Same successful three runs, canonical IPv4 TCP/UDP, corrected src OR dst; no selection, PCAP, or RLS execution.
- Native uses analysis_scope=native exactly, without /24 expansion. Unique prefix+flow_id edges; union unique flow_id.
- Quantiles linear (n-1)*q and all totals/nulls identical to normalized24 conventions.
- Native union must be a flow_id subset of same-mode normalized union, with count/packet/byte monotonicity.
- Existing comparison bundle read-only; new manifest last; no overwrite of runs/cache/data/results.
- Main baseline37fd4ad, clean at start; no commits, pushes, branches or worktrees.

## Design decisions

Use --include-native with run arguments. Optional --from-comparison copies a verified matching normalized bundle, preserving dashboard.html and every existing research artifact byte-for-byte. Without it, reuse generate_comparison in private staging. Add native_extension with separate schemas/evaluation definition to comparison manifest v1; old manifests remain accepted. A native-extension verifier requires all native files when extension is present. Native HTML shares the existing renderer/template via a controlled scope adapter; normalized rendering remains unchanged. Direct scope view shows Overall plus same-mode native/normalized union, not reselection or equal counts.

## Review focus

- /32 and /28 with short flows elsewhere in the containing /24 must produce different populations.
- Same flow in two prefixes and both endpoints in one prefix must never inflate union or prefix counts.
- Correct hashes do not make missing/wrong membership edges correct; reject incomplete or wrong edges.
- Empty scopes, large integer byte totals, chunk/display limit changes must retain exact semantics.
- Bundle/run mismatch, native artifact removal, failure during publication and protected destinations must fail closed.

### Task 1: Native facts and exact statistics

New native_analysis.py and tests/test_rls_native_comparison.py. Interface analyze_native_runs(infos: dict, normalized_base: Path, output: Path, *, chunksize, scratch_dir, max_ecdf_points) -> dict.
- [x] Write/run RED tests for /32-/28 vs parent, edge uniqueness/completeness, subset, exact totals/quantiles, identical cross-mode distributions, empty and chunksize/display invariance.
- [x] Load canonical facts once and source scopes as saved edges, validate expected OR membership through 24..32 prefix-index lookup.
- [x] Reuse _summarize and exact metrics/export helpers; save native mode summaries/frequencies and CSVs; verify normalized stats/frequencies against saved baseline.
- [x] GREEN focused backend tests.

### Task 2: Bundle generation / native UI

New native_generation.py, native_dashboard.py, native_scope.html/js. Modify cli.py, __init__.py, generation.py verifier, prefix_ecdf.py generic adapter and dashboard.py optional template.
- [x] RED integration/render/browser tests: source preserved, old artifacts unchanged, native schema completeness, mismatch, failure cleanup, native labels and 6 accessible tabs, individual and scope plots offline.
- [x] Implement generate_native_comparison and --include-native; preserve normalized source byte-for-byte, revalidate inputs and publish last.
- [x] Render native views using shared template/controller with explicit scope labels and direct scope comparison; preserve CSP escaping and native semantics.
- [x] GREEN related tests and populated/empty browsers.

### Task 3: Evidence and review

New guide; maintain docs/agent entry points if needed.
- [x] Record schema, commands, UI, disk/RAM/runtime limits and synthetic evidence.
- [x] Run related and full tests; record known Notebook06 failures separately.
- [x] One independent review; fix material findings with RED→GREEN tests.
- [x] Diff/status check; final report and suggested commit message. Leave changes uncommitted.

## Progress / review fixes

2026-11-05: Backend7 RED→GREEN; UI/integration14 and related174 pass. Initial full825 passed / 3 existing Notebook06 failures. Populated, empty and synthetic /32-/28 native HTML pass browser offline with zero errors. Independent review: manifest downgrade/contradictions, current-root scratch guard, independent parent mapping + actual input provenance, and protocol integer spelling. Twelve reproductions RED confirmed; fixes in one pass with test provenance rebinding so corrupt edges are still exercised. Quantile fixture KS corrected to hand-derived1/6 (not1/4); no production metric change. No source selection or membership definitions changed. No commits/push.

Complete: review fixes28 focused passed, related186 passed, final full837 passed / 3 unchanged Notebook06 failures58.42s. Final native/normalized/empty/narrow browser checks all offline, zero errors; native table row link verified. Original13 artifacts byte-identical, all26 output artifacts and producer hashes verified. No review issues deferred. Main/HEAD unchanged; git diff --check passed; no commits/push. Outputs/report in chat workspace outputs/rls-native-comparison-20261105.
