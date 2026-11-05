# Aguri A/B/C selection comparison implementation plan

> **For agentic workers:** Use executing-plans and test-driven-development; leave all changes uncommitted on main.

**Goal:** Validate legacy Aguri unfiltered A / IPv4 TCP+UDP B / canonical packet Agurim-prime C and compare fixed native selections and exact contributions.
**Architecture:** Dedicated validation (not packet/byte/flow validation), shared checked SQLite membership ingestion and normalized24._summarize, exact metric helpers. A new standalone five-tab dashboard and new immutable bundle; existing dashboards unchanged.
**Spec:** User's A/B/C request; subsequent clarification: no real data locally, implementation/synthetic verification only, human executes MAWI manually.
**Baseline:** main d1e6e6e5ad771d9e138e81d4cd43441a994e2ffd, clean at start.

## Global constraints

- No PCAP/Aguri/RLS execution; source runs/cache/data/results read-only.
- Same canonical IPv4 TCP/UDP Raw, corrected native src OR dst, unique flow_id union; no /24 expansion.
- Prove A/B recorded selector difference is only BPF; preserve differing selection/caches, reject semantic mismatches.
- C changes first aggregation and input format too: B→C is not a pure RLS implementation comparison.
- Stream canonical inputs; exact integer frequencies, current linear (n-1)*q quantiles, null when undefined.
- Exclusion rebuilds union from remaining native edges, preserving flows shared with other prefixes.
- Synthetic evidence clearly separated; MAWI execution is out of scope by user clarification.

## Design / review focus

- Older Aguri manifests lack raw-output historical hashes: bind candidates to recorded producers, reparse saved rendered output, record evidence limits explicitly; do not fabricate historical bindings.
- Distinguish exact target candidate, covering concrete IPv4 candidate, selected target, standalone target cohort, and target∩union share.
- Native-prefix-set change is exact CIDR set change, not IP-space difference. Export A-only/B-only/common flow components and added-prefix union.
- Historical Notebook reconstruction requires its bound reference IDs/frequencies; static algorithm agreement is not historical reproduction.
- Empty cohorts, both-endpoint/shared flows, hash/code lineage mismatches, protected destinations and failure cleanup must be tested.

### Task 1 — Dedicated input contract
New validation.py, tests/test_aguri_selection_comparison.py synthetic saved-run builder.
- [x] RED tests for valid three run contracts, BPF-only A/B, canonical/config/candidate mismatch, read-only validation.
- [x] Validate actual hashes and producer/cache bindings, corrected ledger reconstruction, old commands, C lineage/options/audit. Use no executable invocation.
- [x] GREEN focused tests.

### Task 2 — Exact native unions and contribution
New analysis.py, legacy.py. Shared native_analysis._ingest only generalizes canonical-first lookup from literal packet to first ordered condition.
- [x] RED tests hand counts/ECDF/coverage/Jaccard, exact prefix counts, shared-flow exclusion, empty/null, chunk/display independence, corrupt edges, optional historical reference.
- [x] Reuse ingestion/_summarize/ECDF/KS; disk sets A/B/C, prefix degrees, exact sensitivities, A/B components, target probe.
- [x] GREEN focused tests.

### Task 3 — New bundle and offline UI
New generation.py, dashboard.py/html/js, cli.py/__main__.py/__init__.py. New browser smoke script.
- [x] RED generation/hash/publication/protected-output tests and renderer safety tests.
- [x] New CSV/JSON exact files, provenance/input+output hashes, final manifest last; validation-only has no writes.
- [x] Five tabs: Overview, Flow Size Distribution, Selection Changes, Prefix Contribution, Experiment Details. Shared plot controller for exact/simplified right-continuous ECDF, toggles/hover/zoom/reset/SVG; search/filter/page prefix tables.
- [x] Browser synthetic/empty/offline checks; existing dashboard regressions.

### Task 4 — Verification/report
- [x] Guide, commands and manual legacy reference export, schemas, static Notebook audit and limitations.
- [x] Related/full tests; separate pre-existing Notebook06 failures.
- [x] One fresh independent review; material findings RED→GREEN.
- [x] Report files/CLI/artifacts/tests, synthetic facts vs unresolved real-data causes; no commits/push.

## Resumption / progress record

Initial implementation: dedicated validation, exact sets/contributions, bundle/CLI and 5-tab HTML complete; related204 passed, full855 passed /3 known Notebook06 failures; populated/empty offline browser checks passed. No actual MAWI per user clarification.

Independent reviewer delivered six material findings, then stopped due to service usage limit; whole-review completion was not available. Findings: canonical.bin not bound to rows/weights, hidden getopt filters, overclaiming historical reference match, gzip input evidence, incomplete fork/build verification, IPv6 wildcard crash. Eleven reproductions RED→GREEN. Canonical records now stream-checked using existing ABI/scalar helpers; no new binary generated. Added mismatch ID/frequency samples, strict manifest binding and hash-bearing static Notebook audit; two additional self-review reproductions RED→GREEN. Positive missing-build/gzip boundary checks and explicit synthetic evidence included. Focused34 pass. Final related/full/browser checks and report pending.

Ruling: historical_reproduction_verified remains false even for an exact supplied-export match; supplied_reference_matches reports the measurable result. An original conference execution is not authenticated by a newly supplied CSV. Cost: human provenance inspection remains necessary for the original publication claim.

Final verification: independent reviewer completed the remaining review. Two further findings (last-bit floating statistic mismatches; manifest target/dataset metadata not bound to summary) reproduced in three tests RED→GREEN. Integers/IDs/frequencies remain exact; derived float statistics permit at most four ULPs with every accepted difference retained. Focused37 passed; full874 passed /3 unchanged pre-existing Notebook06 failures in63.40s. Synthetic and empty standalone HTML browser checks passed offline, including hover/zoom/drag/wheel/search/filter/exclusion/SVG. Both exact-preview and display-simplification-boundary bundles verified (17 artifacts each). No actual MAWI execution; manual guide and workspace report delivered; changes remain uncommitted.
