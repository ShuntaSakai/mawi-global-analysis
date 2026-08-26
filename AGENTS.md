# AGENTS.md

This file defines repository-wide guardrails for Codex and other agentic contributors working in `mawi-global-analysis`.

## Source of truth

Before implementing or modifying research logic, read these files first:

- `docs/superpowers/specs/2026-08-26-mawi-global-analysis-design.md`
- `docs/superpowers/plans/2026-08-26-mawi-global-analysis-m0-m4-implementation.md`

The **design spec is the highest-level authority**. The implementation plan is the execution guide derived from it. If the two appear to conflict, follow the design spec and record the discrepancy in the implementation ledger.

Do not infer research semantics from code alone when the spec defines them explicitly.

## Development workflow

For M0–M4 implementation, use the approved Superpowers workflow:

1. Create or verify an isolated worktree / feature branch with `superpowers:using-git-worktrees`.
2. Execute the implementation plan with `superpowers:subagent-driven-development`.
3. Use a fresh implementer subagent per meaningful task.
4. After each task, perform both spec-compliance review and code-quality review.
5. Fix findings and re-review before moving to the next task.
6. Follow TDD where the plan specifies it: failing test → minimal implementation → passing test.
7. Keep a progress ledger so completed tasks are not re-dispatched after context loss.
8. Commit meaningful, independently testable changes task by task.
9. Perform a whole-branch review after the planned milestone set is complete.

Do **not** implement directly on `main` unless the human explicitly approves that exception.
Do **not** merge, push to a shared branch, publish, or perform other external side effects without explicit approval.

## Core research guardrails

### Canonical flow semantics

- TCP/UDP flows are bidirectional 5-tuples.
- Canonical `src_ip` / `dst_ip` preserve the **first observed packet direction**.
- Never equate canonical `src_ip` / `dst_ip` with initiator/responder, client/server, outgoing/incoming, or benign/malicious roles.
- For TCP initiation analysis, use `initial_syn_sender_*` / `initial_syn_receiver_*`, populated only when a plain SYN (`SYN=1, ACK=0`) is actually observed.
- Baseline flow timeout is disabled unless an experiment config explicitly enables it.
- `byte_count` remains the legacy-compatible Ethernet-frame byte total and must equal `frame_byte_count`; also retain IP bytes and TCP/UDP payload bytes.

### Corrected prefix analysis

The corrected baseline must preserve all of the following:

- Build the candidate pool from **both** Aguri `src_prefix` and `dst_prefix`.
- Main analysis is IPv4.
- Eligible selected prefixes have prefix length `>= 24`.
- Resolve containment by preferring the broader eligible prefix; selected prefixes must not contain one another.
- Do **not** impose a top-k limit in the corrected baseline.
- Corrected prefix membership is:

  `src_ip ∈ prefix OR dst_ip ∈ prefix`

- Preserve `src_match` and `dst_match` as observation-direction facts.
- Keep both native-prefix analysis and true normalized `/24` analysis.
- A normalized `/24` analysis must recompute membership for the full `/24`; never relabel a `/25` or `/26` subset and call it `/24` traffic.
- Do **not** use short-flow ratio, tiny-flow ratio, scan-like ratio, or similar flow outcomes as corrected-baseline prefix preselection filters.
- Do not reintroduce legacy score/top-k behavior into corrected baseline unless it is an explicitly named legacy/sensitivity experiment.

### Legacy reproduction

- Keep `paper_legacy` behavior separate from corrected `baseline` behavior.
- `paper_legacy.yaml` exists to reproduce the old repository's actual result-generation behavior, including known legacy choices such as destination-side membership and ranking/plot filtering where required by the golden reference.
- Do not "fix" legacy behavior inside the legacy mode just because corrected baseline uses different rules.
- Conversely, do not distort corrected baseline merely to match legacy outputs.

### Scan-like analysis

- A single SYN, failed connection, or positive probe pattern is **not** enough to label a scan.
- Missing responses are weak negative evidence in MAWI because observation can be asymmetric.
- A plain SYN with no observed response may contribute to **broad source-behavior statistics**, but it is not high-confidence evidence by itself.
- Scan source identity is `initial_syn_sender_ip`, not canonical `src_ip`.
- Strict/high-confidence evidence is based on positive observed TCP patterns plus repeated source-level behavior.
- Broad behavioral removal must never mean "this source is suspicious, so delete all of its flows."
- Broad removal is limited to **probe-like flows inside behavioral scan windows**.
- Observed established payload traffic should remain by default in broad removal.
- Preserve the invariant:

  `strict_removed_flow_ids ⊆ broad_removed_flow_ids`

- Keep threshold-free facts separate from thresholded labels.

### M4 threshold gate

M0–M4 may proceed autonomously according to the implementation plan.

At M4:

- Generate `source_scan_windows.csv` using threshold-free source-window statistics.
- Use 60 s windows, 10 s step, capture-start anchoring, and `[start, end)` membership unless an experiment config explicitly changes those values.
- Explore `syn_initiated_flow_count × unique_targets` and `high_confidence_probe_pattern_count × unique_high_confidence_targets`.
- Quantiles such as Q99/Q99.5/Q99.9 may be used only as **candidate guides** for inspection.
- Do **not** automatically set scan thresholds from quantiles.
- Do **not** invent `N_strict`, `M_strict`, `N_broad`, or `M_broad` to continue implementation.
- Stop at the M4 human-review gate before implementing M5 Strict/Broad removal behavior that depends on chosen numeric thresholds.

## Data and artifact separation

Keep expensive PCAP-derived facts separate from run-specific interpretation.

Dataset/flow-profile artifacts belong under `data/<dataset>/processed/` and are reusable when their semantic fingerprint matches.
Run-specific classification and analysis artifacts belong under `results/<dataset>/<run-name>/`.

In particular:

- `flows.csv` contains PCAP-derived observations and stable derived facts.
- `flow_labels.csv` contains run-specific classifications.
- `source_scan_windows.csv` is threshold-free observation data.
- `prefixes.csv` is a candidate/selection ledger, not just a selected-prefix list.
- `flow_prefix_membership.csv` stores flow-to-prefix mappings.
- `run_manifest.json` records exact run provenance.

Do not copy run-specific scan labels back into the shared canonical `flows.csv`.

## Caching, provenance, and reproducibility

- Flow cache identity must change when flow generation changes, such as enabling/changing inactive timeout.
- Scan threshold changes must **not** invalidate the flow cache.
- Aguri cache identity must include input checksum, pinned source/version or commit, executable checksum, and relevant options.
- Do not bypass fingerprint checks to make a run "work."
- Save config content and hash in the run manifest.
- Record input checksum, flow fingerprint, Aguri fingerprint, code/git identity, executed/reused stages, and generated artifacts.
- Existing runs with the same run name but different input/config identity must not be silently overwritten.

## Aguri

For legacy reproduction, use the Aguri lineage pinned by the prior repository:

`necoma/agurim@ab5c5cc80e9e1229bb66ec83bb25f186898d5e49`

Prefer the repository-pinned submodule/binary. A PATH fallback may be supported only if the executable path/version/checksum is recorded and a warning is emitted.

Do not silently change Aguri version during legacy reproduction.

## Error handling

Silent fallback is prohibited for conditions that affect research semantics.

Fail clearly on cases such as:

- invalid configuration,
- malformed/unreadable PCAP,
- missing required CSV columns,
- checksum mismatch,
- required Aguri executable unavailable,
- missing upstream artifacts when partial execution explicitly skips their generation.

Use warnings only for unusual but valid data conditions such as zero selected prefixes or zero qualifying SYN-initiated flows.

## Notebook boundaries

- Pipeline code should emit general-purpose canonical CSVs, not plot-specific pre-aggregated files.
- Research aggregation, medians, quantiles, ECDF/CCDF, and plotting remain visible in notebooks.
- Do not bake one final paper figure's axis/filter choices into the canonical pipeline.

## Research wording

Use cautious labels and claims:

- Prefer `scan-like`, `probe-like`, `candidate`, `consistent with`, and `suggests` where appropriate.
- Do not turn an observed TCP pattern into proof of malicious intent.
- Do not claim that a selected prefix is equivalent to one end host or one application unless external evidence establishes that separately.

## Scope discipline

Follow YAGNI.
Do not add Docker, workflow engines, ML-based scan detection, automatic threshold selection, or unrelated refactors unless a separately approved design calls for them.

If a proposed change alters research semantics, experiment comparability, cache identity, or the M4 human-review gate, treat it as a design change rather than a routine refactor.
