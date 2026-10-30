# Normalized /24 Raw Dashboard Implementation Plan

**Goal:** Experiment 1's agurim selected-/24 dashboard, using canonical flows and validated normalized membership.

**Architecture:** Reuse saved-run identity checks and bounded CSV readers from `flow_length.py`, adding an explicit Raw inspection mode while preserving its default scan-analysis contract. A separate `normalized24.py` aggregates exact packet-count frequencies on temporary SQLite storage. A method-independent histogram specification and renderer consume the resulting small payload. Only the agurim adapter is implemented.

**Constraints:** Work on existing main; no branches, worktrees, staging, commits, push or PR. Preserve existing dashboard, notebooks, caches and results. No PCAP processing or scan removal. Synthetic verification is not real-data validation.

## Design decisions

- Flow size means canonical `packet_count`, matching the existing flow-length dashboard.
- Read selected native rows and validate their recorded `normalized_prefix_24` against the actual containing /24; deduplicate the normalized set, retaining every /24 including empty ones.
- Validate every normalized edge's identity and endpoint flags. During the canonical flow stream count expected edges using endpoint /24 lookups; uniqueness, correct edges and equal cardinalities prove completeness without silently generating missing edges.
- Individual distributions join each validated /24's edges; union uses EXISTS against unique canonical flow IDs. Overall reference is all canonical IPv4 flows.
- Exact integer frequencies determine linear-interpolated median and p95; undefined statistics are JSON null. Fixed shared integer intervals include a terminal overflow bin. Shared count axes depend only on overall IPv4 flow count; percent axes are [0,100]. Specification may be supplied to subsequent methods.
- Self-contained HTML embeds data, specification and provenance; rendering makes no external requests. Output publication refuses existing files and protected data/cache/run locations.

## Tasks

1. Add `tests/test_normalized24.py`: synthetic baseline saved run, duplicate normalized siblings, outside-native/full-/24 traffic, cross-/24 flow, zero-flow prefix, unselected and IPv6 traffic, independent statistics, chunk invariance, corrupt membership and identities, no overwrite, offline export and CLI. Observe missing-feature failures.
2. Extend `inspect_run(..., raw_only=False)` and implement `analyze_agurim_run` plus `HistogramSpec` in `src/mawi_global_analysis/normalized24.py`; run focused tests.
3. Add `normalized24_dashboard.py`, `.html`, `scripts/export_normalized24_dashboard.py` and guide. Test real HTML browser interactions offline and run complete suite.
4. Review research semantics, provenance, bounded memory and regressions with a fresh reviewer; fix material findings and record final verification.

## Review focus

- Missing normalized edges with unchanged row count; duplicate edges hiding omissions.
- Stale producer/checksum records, malformed normalization and modified inputs during analysis.
- Empty selections, all-zero distributions and undefined percent statistics.
- Histogram bin/axis settings reused across methods without truncation.
- New output location cannot overwrite or pollute existing caches/artifacts.

## Progress

- Read repository instructions, docs/agent, baseline config, prefix/membership/flow_length/dashboard implementations and related tests.
- User's detailed scope and request to confirm the approach then implement authorize inline execution; no extra design approval or Git operations.
- Task 1 complete: synthetic tests first failed for missing normalized aggregation/export; independent NumPy references cover exact statistics.
- Task 2 complete: explicit Raw inspection, normalized cohort validation, streaming SQLite ingestion and exact frequency summaries.
- Task 3 complete: standalone offline cards/search/sort/details, CLI and guide; browser interaction checks passed after going offline, including mobile width.
- Task 4 complete: one fresh reviewer reproduced two provenance/output-boundary findings. Added failing regressions, then fixed recorded Aguri-binding contradictions and protection for external manifest-bearing caches. Historical absent bindings remain explicitly labeled; historical Aguri files/executables are not revalidated.
- Final focused verification: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_normalized24.py` → 34 passed.
- Final full suite: `.venv/bin/python -m pytest -q -p no:cacheprovider` → 636 passed, 3 pre-existing Notebook failures (same as the 602-pass baseline); names and evidence limits are in the guide.
- `git diff --check` passed; work remains uncommitted on existing `main`. Existing dashboards, notebooks and caches unchanged. No real-data verification or large-scale benchmark claimed.
