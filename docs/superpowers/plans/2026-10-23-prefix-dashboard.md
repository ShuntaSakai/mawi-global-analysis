# MAWI Prefix Flow Length Dashboard Implementation Plan

> Execute inline using superpowers:executing-plans. The user's detailed implementation request is the approved specification; no additional design approval is needed.

**Goal:** Export an offline, standalone HTML dashboard from an existing validated flow-length cache.

**Architecture:** Read through load_cached_run only. Validate cached summaries and common-bin histograms without recomputing observations. Render Matplotlib images using Agg; embed all data, images, CSS and JavaScript. Prefix cards and separate references select a persistent two-column detail panel. Notes are scoped by dataset/run/prefix and rendered as text.

**Tech Stack:** Existing Python 3.12, pandas, NumPy, Matplotlib; standard-library HTML/JSON; vanilla JavaScript. No new dependencies.

**Spec:** User request “MAWI Prefix Flow Length Dashboard の実装”, 2026-10-23, sections 1–9.

## Global Constraints

- Never generate flows, classify scans, aggregate source CSVs, overwrite caches or change scientific semantics.
- Use existing bin_edges and deduplicated selected_union; Raw = removed + retained per target and bin.
- Detail count axis symlog(linthresh=1); proportions linear 0–100%, each group's full N as denominator.
- Blue Raw, red removed, green retained; empty/NaN groups and arbitrary selected counts supported.
- Export only on the explicitly requested feature branch; create a PR without merging.

## Review Focus

- Corrupt/tampered cached tables: reject inconsistent counts, bin boundaries, proportions and summary rates before output.
- Cache/source/output aliasing: refuse any output that can overwrite source artifacts, manifests, caches or existing files.
- Untrusted note strings including script closing tags: JSON-safe embedding, textContent-only display.
- Zero/small groups and NaNs: render undefined rates as a dash, never coerce missing rates to scientific conclusions.
- UI state: all group statistics/images update, selected detail persists through sorting/search, references remain separate.

## Tasks

- [x] 1. Add tests/test_prefix_dashboard.py against synthetic saved cache: offline output, immutable inputs, integrity failures, empty groups, 31+ prefixes, notes scope and CLI. Observe failure before implementation.
- [x] 2. Implement prefix_dashboard.py: validate result, load scoped notes, render comparison/small images, assemble self-contained HTML, safe exclusive output. Test data payload and actual Matplotlib axes/bar values.
- [x] 3. Add packaged HTML template with responsive accessible cards, tooltip, search/sort/group controls, persistent details and references. Add thin scripts/export_prefix_dashboard.py CLI; verify file:// browsing and no network.
- [x] 4. Add sample JSON and dedicated guide; link README. Run focused and full tests, compare baseline failures, independent review, fix material findings, create and attach PR.

## Execution ledger

- Repository cloned at c07f3d0; clean main verified, then feature/prefix-flow-length-dashboard created as explicitly requested.
- Existing analysis modules/notebook will remain unchanged. Existing stale notebook tests will be reported separately if reproduced at baseline; no scientific or unrelated notebook edits will be made to hide them.

- Baseline: PYTHONPATH=src pytest -q (before dashboard) => 509 passed, 3 existing notebook failures; same failures after feature. No existing analysis code/test changed.
- Review: fixed nested cache symlink output alias; regression test failed before fix and passed after.
- Independent review: impossible median > p95 accepted; regression test failed before guard. NaN quantiles remain undefined as requested.
- Browser verification: Chrome file:// with offline=true; group/search/sort/tooltip/detail/zoom/empty/union operations passed, 0 HTTP requests and 0 JS errors. Desktop 1440x1080, mobile 390x844, plus 35-prefix export (3.6 MB) and selection verified.

- Final verification: focused 25 passed; full suite 534 passed, same 3 baseline notebook failures; wheel build succeeded and contains prefix_dashboard.html. Reviewer finding fixed (RED→GREEN), no deferred new findings.
- Integration decision: publish a draft feature PR with the three baseline failures named explicitly; no merge/main push. This keeps the requested deliverable reviewable without unrelated notebook/test changes.
