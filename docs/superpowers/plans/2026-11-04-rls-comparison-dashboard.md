# RLS Comparison Dashboard Implementation Plan

> Execute the user-approved phase 3, test-first, directly on main with uncommitted changes. Repository rules override worktree/commit defaults. Use one isolated dashboard implementer for the independent renderer/UI contract below and one final independent reviewer; do not duplicate implementations.

**Goal:** Compare existing packet/byte/flow runs with exact saved statistics and an offline interactive dashboard.

**Architecture:** validate_comparison first; reuse export_raw_statistics once per mode in an unpublished comparison workspace. Compare saved exact frequency tables and existing membership IDs with disk-backed SQLite. Stream ECDF CSV and compute exact rational KS distances, coverage and Jaccard. Render a bounded-data standalone HTML; publish checksum-verified artifacts and comparison_manifest.json last.

**Spec:** User request in `/Users/shunta/.codex/attachments/144771f4-f71d-47fa-a545-03a6da491c5d/貼り付けたテキスト.txt`.

## Constraints and decisions

- Baseline main e8cca22, clean; stages 1/2 committed. No input/run/cache/data/results edits, C/converter/prefix/membership/baseline changes, history operations or automatic PCAP/RLS execution.
- Natural selection sizes, threshold1%, -D -D, corrected normalized /24 Raw OR membership, deduplicated union.
- Undefined ratios (denominator0), both-empty Jaccard, and KS involving an empty distribution are null; nonempty-denominator empty selection coverage is0.
- Python integer arithmetic for totals and ratio numerators; exact KS numerator/denominator retained. Floating ratios are presentation values, not p-values.
- Frequencies and cumulative integer counts are exact and streamed. Browser curves use at most 2000 points by default, CLI-configurable 2..50000. If simplified, selected points are actual ECDF observations; the right-step interpolation is explicitly a lower bound and the next-point upper bound is shown as an envelope, with maximum bound width recorded. No claim of exact intermediate shape.
- No external JavaScript/CSS dependencies. Vanilla SVG/canvas interactions; standalone file works without fetch/CDN.
- HTML cannot contain its own hash or the final manifest hash recursively. It shows hashes for other artifacts and explains that dashboard.html's hash is recorded in the external completion manifest.
- Large total integers are decimal strings in browser payload, exact integers in research JSON/CSV. packet_count and cumulative counts in chart points are always decimal strings.

## Shared dashboard data contract (v1)

Renderer interface: `rls_weight_comparison.dashboard.render_dashboard(payload: dict) -> str`.
No filesystem writes in renderer. Backend calls it after exact computations.

```text
schema_version: 'rls-weight-comparison-dashboard-v1'
dataset_id: str
evidence: str (clearly descriptive; synthetic samples labelled)
conditions: validate_comparison()['common']
runs: validate_comparison()['runs']
modes: {packet|byte|flow: {
  selected_native_prefix_count: int, normalized_prefix_count: int,
  stats: {flow_count,packet_total,byte_total,mean_packet_count,median,p95,one_packet_rate},
  coverage: {flow: float|null,packet: float|null,byte: float|null},
  ks_distance: float|null, ks_numerator: decimal-string|null,ks_denominator: decimal-string|null
}}
overall: {stats: same stats object}
jaccard: [{mode_a,mode_b,set_kind: 'normalized24'|'flow_id',intersection_count,union_count,jaccard}]
prefixes: [{prefix_24: str,modes: ['packet',...],native_prefixes: {mode:[native,...]},stats: same object}]
ecdf: {overall_ipv4|packet|byte|flow: {
 total_flow_count: decimal-string,exact_point_count:int,displayed_point_count:int,
 simplified:bool,error_bound:float|null,
 points:[{packet_count:decimal-string,frequency:decimal-string,cumulative_count:decimal-string,cumulative_fraction:float}]
}}
provenance: {validation:dict,inputs:dict,implementation:dict,artifacts:{relative-path:{sha256,row_count|record_count}},display:dict}
```

Four UI tabs: Overview comparison + exact Jaccard numbers/heatmap; Flow Size Distribution (4 right-continuous log-x ECDFs, legend toggles, tooltips, zoom/reset/download, stats+KS and reduction explanation); Prefix Analysis (search/mode filter/all-column sort/pagination, merged mode overlap, log scatter with canonical stats); Experiment Details (inputs/options/schemas/hashes, definitions and caveats). DOM textContent/escaped JSON, no untrusted innerHTML, graceful null/missing-data panels.

## Work and ownership

1. Parent: add tests for exact metrics and real saved-run comparison, then implement metrics.py + generation.py, CLI and public API. Own all backend files, generation tests, user guide and docs updates.
2. Dashboard implementer: own ONLY new dashboard.py, dashboard.html, tests/test_rls_weight_comparison_dashboard.py and optionally scripts/test_rls_weight_dashboard_browser.js. Read this contract and user UI requirements. Write renderer tests first; implement UI without changing backend/CLI.
3. Parent integration: generate synthetic differing-cohort runs, verify CSV/hash/coverage/KS, run browser interaction tests including offline/file access, safe payload, nulls and large display data. Resolve contract mismatches explicitly.
4. Independent final review of all changes; material findings reproduced with tests. Focused/full regression; report existing Notebook06 failures separately.

## Output schema v1

- dashboard.html
- selected_native_prefixes.csv: mode,native_prefix,prefix_length,normalized_prefix_24
- selected_normalized24.csv: mode,prefix_24
- selection_summary.csv: mode,selected_native_prefix_count,normalized_prefix_count, all stats,flow_coverage,packet_coverage,byte_coverage,ks_distance,ks_numerator,ks_denominator
- pairwise_jaccard.csv: mode_a,mode_b,set_kind,intersection_count,union_count,jaccard
- prefix24_stats.csv: mode,prefix_24,native_prefixes (JSON list), all stats
- ecdf_counts.csv: distribution,packet_count,frequency,cumulative_count,total_flow_count,cumulative_fraction
- modes/<mode>/{summary.json,frequencies.csv}: unchanged phase2 export API
- comparison_manifest.json: schema/status, validation snapshot and final revalidation, input/run identities, implementation hashes, all other artifact hashes/counts, display conditions. No self hash.

## Test checklist

- [x] Mismatched runs produce no comparison output; validate-only remains read-only.
- [x] Real synthetic t1/h2 runs and hand-calculated disk sets/frequencies check coverage/Jaccard/KS, overlap, empty ratios and exact cumulative counts.
- [x] Three Overalls identical; identical selected sets imply identical union counts/statistics; chunksize and display reduction do not change exact outputs.
- [x] Streaming export/hash verification, no overwrite, input mutation and generation/publication failure leave no success manifest.
- [x] Offline renderer security, browser tabs/toggles/hover/zoom/reset/table/scatter/nulls and bounded display data.
- [x] Related/full tests, final review, synthetic example and completion report; uncommitted.

## Execution ledger

- Start: main e8cca22 clean. Detailed phase-3 request authorizes implementation; no additional design approval needed.
- Backend RED: metrics absent (4 tests); saved-run generation absent (1 acceptance test). Implemented exact metrics and generation, then GREEN. One readonly test was corrected to exclude its intentionally created output directory from the input snapshot.
- Dashboard implementer: renderer/security RED→GREEN,8 tests. Recursive browser-only integer conversion added after a failing >2**53 regression. Parent owns all files after handoff.
- Ruling: Review graded missing aggregation schema display Minor, but it is an explicit user requirement, so fixed now. Failing schema regression then GREEN; actual Experiment Details confirms normalized24-raw-v2 and export/frequency schemas.
- Browser RED→GREEN: actual full run records made Overview show provenance JSON rather than run names. Added a failing browser assertion, changed only the Overview label to run_name; full provenance remains in Details.
- Tests: focused138 passed (33.63s); final UI/backend24 passed (4.51s); final full789 passed /3 known Notebook06 failures (57.48s), baseline765/3 (62.31s). No warnings in final cache-disabled run.
- Independent review: no unresolved findings;500 randomized exact-Fraction KS/retained-bound checks passed. No real-MAWI or production-scale claims.
- Browser: actual populated/empty generated HTMLs passed offline interaction harness with zero errors. Direct file:// is blocked by automation policy; localhost load followed by offline operation verified instead. No external CDN/resources.
- Render stress:20000 prefix rows +4x100000 exact ECDF values reduced to4x2000 points,6.84MB HTML; observed DOMContentLoaded~173ms, search~18ms,25 visible table rows, offline paging and no errors. Render-only fixture, not RLS output or a general performance guarantee.
- Final scope: C/converter/prefix/membership/baseline and phase-2 implementations untouched; no commit/push/history operations; stage4 not started.
