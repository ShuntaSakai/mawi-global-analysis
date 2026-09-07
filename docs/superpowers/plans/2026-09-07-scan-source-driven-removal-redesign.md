# Scan Source-Driven Removal Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve M4's threshold-free evidence while preparing the main analysis to identify scan-like sources only from strict positive evidence and expand removal to `syn_only_observed` only for those sources.

**Architecture:** M4 continues to emit reusable threshold-free source-window facts and neutral labels. The pre-M5 configuration carries only strict thresholds and a boolean broad-expansion toggle; it still rejects any enabled scan classification. After human approval, M5 will derive strict windows, then scan-like sources, and finally capture-wide removal labels without removing unrelated source traffic.

**Tech Stack:** Python 3.12, Pydantic v2, pandas, PyYAML, pytest, uv.

**Spec:** `docs/superpowers/specs/2026-08-26-mawi-global-analysis-design.md`

## Implementation Status (2026-09-07)

- M5 source-driven strict removal and optional broad-evidence expansion are implemented.
- Human-approved provisional thresholds are `N_strict = 20` and `M_strict = 10` in `configs/scan_source_driven_removal.yaml`; threshold changes remain config-driven and are not final scientific thresholds.
- Scan-label cache identity is separated from threshold-free flow and scan-stat identities.
- A raw MAWI experimental run remains pending. M6 and the final Raw/Strict/Broad comparison have not started.

## Global Constraints

- Work directly and uncommitted on `main`; do not run Git history or publication operations.
- Keep `scan_patterns.py` limited to `none`, `syn_to_rst`, `syn_synack_rst`, and `syn_only_observed`.
- Identify sources only from `syn_to_rst` and `syn_synack_rst` counts and target diversity in 60 s / 10 s capture-anchored `[start,end)` windows.
- Do not choose or infer `N_strict` or `M_strict`; quantiles remain candidate guides only.
- `syn_only_observed` is broad removal-expansion evidence, never independent source-detection evidence.
- Never remove every flow from a scan-like source; established/payload TCP, UDP, mid-connection, no-plain-SYN, and other non-probe-like flows remain.
- Enforce `strict_removed_flow_ids ⊆ broad_removed_flow_ids`.

---

### Task 1: Record the approved source-driven semantics

**Files:**
- Modify: `AGENTS.md`, `docs/superpowers/specs/2026-08-26-mawi-global-analysis-design.md`
- Modify: `docs/superpowers/plans/2026-08-26-mawi-global-analysis-m0-m4-implementation.md`
- Create: `docs/superpowers/plans/2026-09-07-scan-source-driven-removal-redesign.md`

**Interfaces:** Documents define the same terms: strict evidence, scan-like source, broad removal expansion, and M4 human gate.

- [ ] State that only `syn_to_rst` and `syn_synack_rst` are strict positive evidence.
- [ ] State that a source with at least one strict window is scan-like and that removal is evaluated across the full capture.
- [ ] State that `syn_only_observed` may expand removal only for an already scan-like source; remove `N_broad`/`M_broad` from the main design.
- [ ] State that M4 selects only `N_strict`/`M_strict`, remains threshold-free, and cannot enable M5 classification/removal.
- [ ] Add a superseding note to the historical M0–M4 plan without rewriting completed-task history.
- [ ] Review all changed documentation for contradictory phrases such as “broad detector,” “behavioral scan window,” and `N_broad`/`M_broad`.

### Task 2: Make broad configuration a threshold-free expansion toggle

**Files:**
- Modify: `src/mawi_global_analysis/config.py`
- Modify: `configs/baseline.yaml`, `configs/threshold_exploration.yaml`
- Modify: `tests/unit/test_config.py`

**Interfaces:** `BroadScanConfig(enabled: bool)` accepts no independent numeric fields. `StrictScanConfig` retains `min_pattern_count` and `min_unique_targets`, required only when strict is enabled.

- [ ] Write a failing test loading `broad: {enabled: true}` without broad thresholds.
- [ ] Run `uv run pytest tests/unit/test_config.py::test_broad_enabled_is_a_threshold_free_removal_expansion_toggle -q` and confirm it fails because the old model requires broad thresholds.
- [ ] Remove `min_syn_initiated_flows` and broad `min_unique_targets` from `BroadScanConfig`; retain strict validation unchanged.
- [ ] Write a test that rejects the removed broad threshold keys through the strict `extra="forbid"` model contract.
- [ ] Run the two focused configuration tests and confirm they pass.
- [ ] Keep M4 configs with `strict.enabled: false` and `broad.enabled: false`.

### Task 3: Preserve pre-M5 artifacts and the human gate

**Files:**
- Inspect: `src/mawi_global_analysis/scan_patterns.py`, `scan_windows.py`, `scan_labels.py`, `pipeline.py`
- Modify: `tests/unit/test_scan_windows.py`, `tests/unit/test_scan_labels.py`, `tests/integration/test_pipeline_m4.py` only if a changed expectation requires it

**Interfaces:** `build_source_scan_windows(...)` remains threshold-free; `build_pre_m5_flow_labels(flows, config)` emits all-false labels only when both modes are disabled and otherwise raises `ScanThresholdApprovalRequiredError`.

- [ ] Confirm with unit tests that only the two strict patterns contribute to `high_confidence_probe_pattern_count` and `unique_high_confidence_targets`; `syn_only_observed` contributes only to threshold-free `no_observed_response_count`.
- [ ] Confirm M4 labels remain all false with both modes disabled.
- [ ] Confirm either enabled mode, including broad expansion alone, raises the M5 approval error before pipeline reuse or execution.
- [ ] Do not add source classification, threshold selection, removal logic, new packet facts, or new observed TCP patterns.
- [ ] Run focused scan unit/integration tests and correct only regressions caused by the config-model revision.

### Task 4: M4 threshold review and hard stop

**Files:**
- Inspect: `configs/threshold_exploration.yaml`, `notebooks/01_scan_threshold_exploration.ipynb`, `source_scan_windows.csv` schema tests

**Interfaces:** The M4 review plot uses `x=unique_high_confidence_targets`, `y=high_confidence_probe_pattern_count`; all existing threshold-free columns remain available as context.

- [ ] Verify the config disables both strict classification and broad expansion.
- [ ] Verify the source-window artifact retains `syn_initiated_flow_count`, `unique_targets`, `unique_dst_ips`, `unique_dst_ports`, and `no_observed_response_count` without presenting them as broad-detector thresholds.
- [ ] Stop for human selection of numeric `N_strict` and `M_strict`; do not derive values from quantiles or raw data.

### Task 5: Deferred M5 implementation after explicit human approval

**Files:**
- Modify after approval: `src/mawi_global_analysis/scan_labels.py`, `pipeline.py`, approved M5 config(s)
- Test after approval: `tests/unit/test_scan_labels.py`, `tests/integration/test_pipeline_m4.py` or an M5-specific integration test

**Interfaces:** An approved configuration will provide strict `min_pattern_count=N_strict`, strict `min_unique_targets=M_strict`, and `broad.enabled` as the optional expansion toggle.

- [ ] Implement strict scan-window classification from the two high-confidence source-window fields.
- [ ] Derive scan-like sources as sources with one or more strict scan windows.
- [ ] Label strict removal capture-wide for only `syn_to_rst` and `syn_synack_rst` flows from scan-like sources.
- [ ] When broad expansion is enabled, add only `syn_only_observed` flows from those same sources to broad removal.
- [ ] Add fixture cases proving window-external strict evidence from a scan-like source is removed, while established/payload TCP, UDP, mid-connection, and other non-probe-like traffic remain.
- [ ] Add and run an invariant test asserting every strict removed flow is also broad removed.

### Task 6: Deferred Raw-versus-removed comparison after M5 verification

**Files:**
- Modify after approval: `notebooks/02_main_prefix_comparison.ipynb` or a dedicated comparison notebook
- Test after approval: notebook execution and artifact-loading tests

**Interfaces:** The fixed raw-derived prefix set is reused across Raw, strict-removal, and broad-expansion conditions.

- [ ] Load one provenance-backed run per condition and report removed flow, packet, and byte volume.
- [ ] Compare the same overall/native/normalized-prefix scopes across all conditions without rerunning Aguri for the main comparison.
- [ ] Execute the notebook from a clean kernel and retain the M5 config hashes in displayed provenance.

## Verification for This Pre-M5 Revision

- [ ] Run `uv run python -m compileall -q src tests`.
- [ ] Run `uv run pytest -q`.
- [ ] Run `git diff --check`.
- [ ] Confirm no numeric `N_strict`/`M_strict` values, M5 classification implementation, or M5 removal implementation has been added.
