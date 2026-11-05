# Per-prefix ECDF implementation plan

> **For agentic workers:** Use superpowers:executing-plans with test-first checks.

**Goal:** Add offline interactive individual normalized /24 ECDF comparisons without changing research outputs or conditions.
**Architecture:** Reuse per-mode exact frequency CSVs and summaries. Validate shared prefixes on disk, retain bounded genuine points once per /24, decode only selected curves in the browser. Support a saved-comparison-only refresh into a new output bundle.
**Tech Stack:** Existing Python/SQLite/CSV and dependency-free HTML/JS/SVG.
**Spec:** User's 2026-11-05 per-prefix ECDF request in this chat.

## Global constraints

- Work on main, preserve human changes, leave all changes uncommitted; no push.
- No changes to RLS, canonical converter, phase-2 aggregation, selection, membership, baseline or core CSV schemas.
- No PCAP or RLS execution; refresh reads verified comparison artifacts only.
- Exact CSVs remain authoritative; sampled display points are genuine cumulative values with explicit bounds.
- Independent /24 distributions may share flows; never merge/average their ECDFs.

## Design decisions / alternatives

Full per-prefix point embedding scales with all distinct sizes. Loading external files on demand conflicts with standalone offline viewing. Use bounded samples in self-contained HTML: at most 200 points per /24, adapt to 200,000 points overall, with a two-endpoint minimum (thus upper bound max(200000,2*N)). One copy per unique /24. Encode point arrays as JSON strings and parse only selected curves; evict deselected points. Exact frequencies remain in unchanged mode CSVs. Display approximation is annotated per curve. This is the implementer's choice within the requested tradeoff.

## Review focus

- Shared /24s with same totals but different frequency shapes must be rejected.
- Empty/missing display payloads must keep every screen usable.
- Both-endpoint membership must retain phase-2 flow_id deduplication.
- Display budget changes must not change exact CSVs or existing four curves.
- Refresh must preserve source files, validate hashes before/after, and publish manifest last.

### Task 1: Frequency-backed display data and saved-bundle refresh

Files: new prefix_ecdf.py, refresh.py; generation.py, metrics.py, cli.py, __init__.py; new test_rls_weight_prefix_ecdf.py.
Interfaces: build_prefix_ecdfs(base: Path, prefixes: list, *, scratch_dir=None) -> dict; refresh_dashboard(manifest_path: Path, output_dir: Path, *, scratch_dir=None) -> Path.
- [x] Write/run failing tests for exact sums/endpoints/cross-mode shape, budget/nulls, readonly refresh and artifact integrity.
- [x] Reuse ECDF sampler in metrics; load prefix frequencies into temporary SQLite; validate rows/count/packet totals/mode identity; build bounded display curves.
- [x] Add refresh API/CLI --from-comparison and integrate display builder into normal generation. Keep old argument behavior.
- [x] Run focused backend and existing generation tests.

### Task 2: Interactive offline section

Files: dashboard.html, existing browser runner, renderer tests.
- [x] Add browser assertions before UI implementation: search, mode changes, max five prefix curves, separate reference toggles, deselection, exact tables, hover/zoom/SVG/null/offline behavior.
- [x] Add fifth section with paged search results and five individual curves plus optional Overall/current selected_union. Keep original four-curve code unchanged. Share existing geometry/formatting helpers.
- [x] Browser-test populated, empty and reduced/high-prefix-count fixtures; compare existing CSV/JSON/ECDF payloads.

### Task 3: Documentation / final verification

Files: guide, plan progress; evidence outside repository.
- [x] Document commands, controls, additive display schema, sampling/data-size tradeoffs.
- [x] Run related suite and full pytest suite; report pre-existing failures separately.
- [x] One independent review of correctness/provenance/UI boundaries; fix material findings with regression tests.
- [x] Review diff/status, report changed files/tests/limitations and suggested commit message; no commit/push.

## Progress / evidence

2026-11-05: Task 1 complete (8 new tests RED→GREEN, 24 backend tests passed). Task 2 complete (browser missing fifth tab RED→GREEN; populated and empty saved bundles offline, zero errors). Related suite 151 passed. Initial full suite 797 passed with the same 3 pre-existing Notebook06 failures as phase 3. New canonical dedup and source-mutation tests added after that full run; final full run pending. No commits performed.

Independent review found path aliases allowing staging traversal, transient live-source edits contaminating display, and incomplete protected-root/scratch guards. All three fixed in one pass: strict canonical relative artifact names, manifest byte snapshot + independently copied/hash-verified source snapshot, lexical recorded/current root guards and read-only source scratch rejection. Seven reproductions RED→GREEN; backend36 passed. No findings deferred.

Task 3 complete: related158 passed; final full809 passed / 3 unchanged Notebook06 failures (46.93s). Populated/empty/missing/stress browser checks passed offline, zero errors; stress max-five and paging passed. Independent review material findings all fixed with seven RED→GREEN regression cases, plus producer-helper/CLI hashes RED→GREEN. Main/HEAD unchanged, git diff --check passed, no commits/push. Report and synthetic outputs saved in chat workspace outputs/rls-per-prefix-ecdf-20261105.
