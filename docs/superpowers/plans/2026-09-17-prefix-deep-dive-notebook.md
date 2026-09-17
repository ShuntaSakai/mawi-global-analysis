# Prefix Deep-Dive Notebook Implementation Plan

> **For agentic workers:** Implement this plan inline with test-first checks; do not create a branch, worktree, commit, or push. Repository `AGENTS.md` overrides the generic Git workflow.

**Goal:** Move the fixed four-prefix Broad-removal inspection out of the main comparison notebook into a manifest-driven notebook that analyzes one selected native prefix.

**Architecture:** `03_prefix_deep_dive.ipynb` will use the existing `load_run` and `build_comparison_flow_inclusion` APIs. It will filter native membership for `TARGET_PREFIX` before any flow join, then derive Raw, Broad removed, and Broad remaining views from one validated target-flow table. Research aggregation and plotting remain visible in the notebook.

**Tech Stack:** Jupyter, pandas, NumPy, Matplotlib, pytest.

**Spec:** User-approved design in the 2026-09-17 Codex task; `docs/superpowers/specs/2026-08-26-mawi-global-analysis-design.md`.

## Global Constraints

- Work directly on `main`; leave all changes uncommitted.
- Read only successful manifest-recorded artifacts; never run the PCAP pipeline from the notebook.
- Keep analysis scope fixed to `native`; never mix normalized `/24` membership.
- Canonical `src`/`dst` and membership direction are not initiator/responder facts.
- Broad labels must be enabled in the saved run config; otherwise fail clearly.
- Preserve research aggregation and plotting in the notebook; do not add a deep-dive Python module.

### Task 1: Establish notebook contracts

**Files:**
- Create: `tests/unit/test_notebook_prefix_deep_dive.py`
- Modify: `tests/unit/test_notebook_main_prefix_comparison_3_2.py`

- [ ] Write static source contracts for manifest loading, native target-membership filtering before joins, flow-ID validation, Broad inclusion helper use, SYN receiver facts, cautious service candidates, prefix-not-found diagnostics, removed-flow audit, and no fixed four-prefix array.
- [ ] Change the main-notebook contract so it protects the retained overview logic while asserting that the detailed four-prefix section is absent.
- [ ] Run the focused tests and observe them fail because the new notebook does not yet exist and the old detailed section remains.

### Task 2: Add the single-prefix deep-dive notebook

**Files:**
- Create: `notebooks/03_prefix_deep_dive.ipynb`

- [ ] Add Japanese overview and settings cells with `DATASET_ID`, `RUN_NAME`, `TARGET_PREFIX`, `TOP_N_PORTS`, and `TOP_N_TARGETS`.
- [ ] Reuse the main notebook's root resolution and `MAWI_ANALYSIS_ROOT` override, then call `load_run`.
- [ ] Display concise manifest provenance, parse the saved config text, and reject runs without `scan.broad.enabled`.
- [ ] Validate selected native prefixes, provide the available list on target absence, filter target membership first, validate flow IDs/joins, and derive Raw/Broad groups with `build_comparison_flow_inclusion`.
- [ ] Add visible tables/plots for the approved statistics, TCP patterns, SYN receiver ports/targets, byte-duration-payload facts, SYN roles, removed-flow audit, and non-causal summary.

### Task 3: Remove duplicated responsibility from 02

**Files:**
- Modify: `notebooks/02_main_prefix_comparison_3_2.ipynb`

- [ ] Remove only the markdown and code cells beginning at the existing detailed four-prefix Broad-removal section.
- [ ] Retain all overview Raw/Broad tables, plots, and all-prefix comparison cells.

### Task 4: Verify

**Files:**
- Verify: notebooks and relevant tests

- [ ] Validate changed notebooks are parseable JSON.
- [ ] Run focused notebook tests, then the full pytest suite and `git diff --check`.
- [ ] Attempt a clean-kernel notebook execution only if a successful requested run manifest with all required artifacts exists. Otherwise record that only static/unit verification was possible.
