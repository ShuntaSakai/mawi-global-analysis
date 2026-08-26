# mawi-global-analysis M0–M4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the reproducible MAWI analysis foundation through M4: environment/configuration, canonical flow extraction, pinned Aguri integration, legacy reproduction, corrected raw prefix analysis, and threshold-free scan-window exploration.

**Architecture:** Core logic lives under `src/mawi_global_analysis/`; root CLIs remain thin. Expensive PCAP-derived facts are cached under `data/<dataset>/processed/` using semantic fingerprints, while run-specific interpretation is written under `results/<dataset>/<run-name>/`. M4 ends at a human threshold-review gate; no production strict/broad threshold is selected or applied in this plan.

**Tech Stack:** Python 3.12, uv, dpkt, pandas, numpy, matplotlib, PyYAML, Pydantic v2, pytest, Jupyter/ipykernel, Aguri/Agurim pinned to `necoma/agurim@ab5c5cc80e9e1229bb66ec83bb25f186898d5e49`.

**Spec:** `docs/superpowers/specs/2026-08-26-mawi-global-analysis-design.md`

## Global Constraints

- Corrected prefix membership is `src_ip ∈ prefix OR dst_ip ∈ prefix`.
- Corrected baseline uses IPv4 overall traffic and every eligible non-overlapping Aguri-derived IPv4 prefix with prefix length >= 24; no top-k limit.
- Corrected prefix selection does not use short/tiny/scan-derived flow features as selection filters.
- Canonical `src_ip`/`dst_ip` preserve first-observed packet direction and are not initiator/responder labels.
- Populate `initial_syn_sender_*` only after observing a plain TCP SYN (`SYN=1, ACK=0`).
- Baseline flow timeout is disabled. Enabling/changing timeout must change the flow fingerprint.
- `byte_count == frame_byte_count` for legacy compatibility; also store IP bytes and TCP/UDP payload bytes.
- Aguri runs on raw traffic for the main experiment.
- Scan windows are 60 s wide, 10 s step, capture-start anchored, with `[start,end)` membership.
- `source_scan_windows.csv` is threshold-free observation data. Quantiles may guide inspection but must never automatically become scan thresholds.
- Before M5, strict/broad removal remains disabled; no implementation agent may invent thresholds to continue.
- Missing tools, invalid config, malformed captures, checksum mismatches, and missing required upstream artifacts are fatal rather than silently skipped.
- Keep `data/`, `results/`, and generated notebook output out of git.
- TDD for every behavior: failing test -> verify failure -> minimal implementation -> verify pass -> commit.

---

## Task 1: Bootstrap Python 3.12 and Strict Experiment Configuration

**Files:**
- Create `pyproject.toml`, `.python-version`, `.gitignore`
- Create `src/mawi_global_analysis/__init__.py`, `src/mawi_global_analysis/config.py`
- Create `configs/paper_legacy.yaml`, `configs/baseline.yaml`, `configs/threshold_exploration.yaml`
- Create `tests/unit/test_config.py`, `tests/fixtures/configs/invalid_window.yaml`

**Interfaces:** `load_config(path: Path) -> ExperimentConfig`; strict Pydantic models with `extra="forbid"`.

- [ ] Write config tests asserting baseline loads with timeout disabled, `src_or_dst`, `top_k is None`, 60/10 window; invalid negative window and unknown keys raise `ValidationError`.
- [ ] Run `uv run pytest tests/unit/test_config.py -v` and confirm imports fail before implementation.
- [ ] Add `pyproject.toml` with Python `>=3.12,<3.13`, `dpkt>=1.9.8,<2`, `numpy>=2,<3`, `pandas>=2.2,<3`, `matplotlib>=3.9,<4`, `PyYAML>=6,<7`, `pydantic>=2.8,<3`, `jupyter>=1,<2`, `ipykernel>=6,<7`, and dev `pytest>=8,<9`.
- [ ] Implement config models. `AguriConfig` has `aguri3_executable`, `agurim_executable`, and `options`. Strict scan config uses `min_pattern_count` + `min_unique_targets`; broad config uses `min_syn_initiated_flows` + `min_unique_targets`. Enabled modes require explicit thresholds.
- [ ] Create self-contained YAMLs. `baseline.yaml`: IPv4, candidate sources `[src_prefix,dst_prefix]`, min length 24, prefer broader containment, `src_or_dst`, normalized /24 enabled, no top-k, strict/broad disabled. `threshold_exploration.yaml`: same corrected flow/prefix setup, strict/broad disabled. `paper_legacy.yaml`: legacy destination-side behavior and IPv4+IPv6 overall scope; exact legacy selection fields are finalized in Task 8.
- [ ] Run `uv lock && uv sync && uv run pytest tests/unit/test_config.py -v`.
- [ ] Commit `chore: bootstrap strict experiment configuration`.

---

## Task 2: Add Stable Hashing, Run Manifests, and CLI Contract

**Files:** `src/mawi_global_analysis/hashing.py`, `manifests.py`, `pipeline.py`, root `run_pipeline.py`; unit tests for hashing/manifest/CLI.

**Interfaces:**
`sha256_file(Path)->str`; `stable_json_hash(mapping)->str`; `RunManifest.start(path,dataset_id,config_path,config_text,config_hash,git_commit)`; `set_input`; `record_stage`; `record_artifact`; success/failure finalization; `build_parser()`.

- [ ] Test JSON hash independence from mapping order.
- [ ] Test a failure manifest persists status `failed`, error type/message, and already-completed stage records.
- [ ] Test `--dataset` and `--input` are mutually exclusive and one is required.
- [ ] Run tests and confirm failure.
- [ ] Implement SHA256 file hashing and stable sorted compact JSON hashing.
- [ ] Implement atomic manifest writes using a sibling temporary file + `replace`. Manifest fields include full config text, config hash/path, git commit, input path/SHA when known, stages, artifacts with row counts, timestamps, and failure metadata.
- [ ] Add CLI arguments: `--dataset`, `--input`, `--dataset-id`, `--config`, `--run-name`, `--from`, `--to`, `--force`, `--dry-run`, `--redownload`. Visible stage order: input, flows, aguri, scan-stats, scan-labels, prefixes, membership, manifest.
- [ ] Run tests and commit `feat: add reproducibility manifests and cli contract`.

---

## Task 3: Resolve Local Inputs and MAWI Dataset IDs

**Files:** `src/mawi_global_analysis/models.py`, `dataset.py`, `tests/unit/test_dataset.py`, `tests/integration/test_downloader.py`.

**Interfaces:** `InputContext(dataset_id,path,sha256,size_bytes)`; `resolve_local_input(path,dataset_id=None)`; `MawiResolver.resolve(dataset_id)`; `MawiDownloader.fetch(dataset_id,redownload=False)`.

- [ ] Test local IDs are deterministic from filename+checksum when `--dataset-id` is absent; explicit IDs are preserved.
- [ ] Test malformed dataset IDs fail before network access.
- [ ] Test `202604081400` resolves to `https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/202604081400.pcap.gz`.
- [ ] Implement resolver as the only module that knows MAWI archive URL layout. Downloader writes through a temporary file, hashes the finished file, and then atomically moves it to `data/<dataset>/raw/`.
- [ ] Make `--redownload` explicit; normal runs reuse a valid local raw file.
- [ ] Run tests and commit `feat: resolve and cache mawi input traces`.

---

## Task 4: Implement Bidirectional Flow Keys and Packet/Byte Accounting

**Files:** `src/mawi_global_analysis/flow.py`, unit tests, `tests/fixtures/pcaps/build_fixture.py`, generated fixture `tcp_patterns.pcap` and `.pcap.gz`.

**Interfaces:** `FlowKey.from_packet(...)`; `parse_pcap(path,timeout)->list[dict]`.

Synthetic fixture must contain deterministic scenarios: A SYN->responder RST; B SYN->SYNACK->initiator RST; C SYN->SYNACK->ACK->payload; D SYN-only; E mid-connection ACK+payload with no observed SYN; F same 5-tuple with a >60s gap for timeout tests.

- [ ] Test A->B and B->A produce the same normalized `FlowKey`.
- [ ] Test canonical output `src/dst` retain first-observed direction.
- [ ] Test `byte_count == frame_byte_count >= ip_byte_count >= transport_payload_byte_count`.
- [ ] Test parsing `.pcap.gz` produces the same flow count as the uncompressed fixture.
- [ ] Run tests and verify failure.
- [ ] Implement Ethernet IPv4/IPv6 TCP/UDP parsing with `dpkt`. For `.gz`, use `gzip.open(...,"rb")`; otherwise normal binary open. Frame bytes use raw buffer length, IP bytes use decoded IP packet length, payload bytes use `len(tcp.data)`/`len(udp.data)`.
- [ ] Do not infer initiator/responder in this task.
- [ ] Run tests and commit `feat: add canonical bidirectional packet accounting`.

---

## Task 5: Add Inactive Timeout Semantics and TCP Control Facts

**Files:** modify `flow.py`; create `scan_patterns.py`; tests `test_flow_timeout.py`, `test_tcp_control.py`.

**Interfaces:** flow rows gain initial SYN endpoints, directional SYN/SYNACK/RST counts and ordered timestamps, `ack_after_synack_observed`, `non_syn_response_observed`, `transport_payload_observed`; `classify_observed_tcp_pattern(row)` returns `none`, `syn_to_rst`, `syn_synack_rst`, or `syn_only_observed`.

- [ ] Test D sets `initial_syn_sender_ip`; E leaves it null.
- [ ] Test A -> `syn_to_rst`, B -> `syn_synack_rst`, D -> `syn_only_observed`, C -> `none` because established payload traffic is present.
- [ ] Test F produces one flow with timeout disabled and two flows with timeout enabled at 60 seconds because its gap is strictly greater than 60 seconds.
- [ ] Run tests and confirm failure.
- [ ] Track TCP direction relative to the actually observed plain SYN. Never infer an initiator from canonical src/dst or SYNACK alone.
- [ ] Set `non_syn_response_observed` whenever responder traffic beyond a mere SYN retransmission is visible. `syn_only_observed` requires initiator SYN(s), no responder SYNACK/RST, no non-SYN response, and no payload.
- [ ] Pattern ordering: responder RST must be after first SYN; half-open positive evidence requires `first_syn <= first_responder_synack <= first_initiator_rst`.
- [ ] Timeout: maintain `last_seen` per normalized key; if enabled and `timestamp-last_seen > inactive_seconds`, finalize old instance and start another deterministic instance.
- [ ] Run all flow/TCP tests and commit `feat: preserve tcp control facts and timeout semantics`.

---

## Task 6: Build Semantic Flow Cache and `flow_manifest.json`

**Files:** `flow_stage.py`, hashing updates, pipeline hook, integration test.

**Interfaces:** `flow_fingerprint(input_sha256,cfg,schema_version="flows-v1")`; `run_flow_stage(ctx,cfg,force=False)->Path`.

- [ ] Test two identical runs reuse exactly the same cached `flows.csv` path.
- [ ] Test changing scan settings does not alter flow fingerprint; changing timeout does.
- [ ] Implement fingerprint from input SHA, flow schema version, selected protocols, timeout semantics, and any parser setting that changes canonical rows.
- [ ] Output `data/<dataset>/processed/flows/<profile>-<hash10>/flows.csv` and `flow_manifest.json` with input SHA, fingerprint, row count, flow config, schema version.
- [ ] Before CSV write, derive `observed_tcp_pattern` from stable TCP facts for TCP rows; UDP uses `none`. This is a deterministic observed-pattern descriptor, not a maliciousness label.
- [ ] Run unit/integration tests and commit `feat: cache canonical flow artifacts by semantic fingerprint`.

---

## Task 7: Pin Aguri and Isolate It Behind One Adapter

**Files:** git submodule `vendor/agurim/`; `src/mawi_global_analysis/aguri.py`; parser/integration tests; generated real parser fixture under `tests/fixtures/aguri/`.

**Interfaces:** `AguriBinaries`; `resolve_aguri_binaries`; `parse_aguri_output`; `run_aguri_stage`.

- [ ] Add submodule `https://github.com/necoma/agurim.git`, checkout exact SHA `ab5c5cc80e9e1229bb66ec83bb25f186898d5e49`, commit `.gitmodules` and gitlink.
- [ ] Build with `make -C vendor/agurim/src`.
- [ ] Generate parser fixture from the synthetic PCAP using the real pinned commands: `aguri3 -r <pcap> -w <agr>` then `agurim -w <txt> <agr>`.
- [ ] Port text parsing behavior from verified legacy `mawi-dpkt-analysis/scripts/aguri/parse_agurim.py`. Preserve at least aggregate ID, src/dst prefix, bytes/packets and ratios, TCP/UDP ratios, protocol breakdown.
- [ ] Resolve each binary in order: explicit config path -> `vendor/agurim/src/{aguri3,agurim}` -> PATH. PATH fallback emits a warning and is recorded, never silent.
- [ ] For gz input, decompress to a temporary capture before invoking Aguri.
- [ ] Fingerprint uses input SHA, exact submodule SHA, executable SHA256s, and command options. Cache under `data/<dataset>/processed/aguri/<fingerprint>/` with raw `.agr`, text output, normalized candidate CSV, and `aguri_manifest.json` containing exact commands, checksums, exit information, stdout/stderr context, and fallback status.
- [ ] Run tests and commit `feat: pin and isolate aguri candidate extraction`.

---

## Task 8: Reproduce the Old Paper Pipeline Before Correcting It

**Files:** extend config; `prefix.py`; `scripts/export_legacy_goldens.py`; `scripts/validate_legacy.py`; legacy fixture README and verified JSON; integration test; `notebooks/00_paper_legacy_reproduction.ipynb`.

**Interfaces:** `legacy_select_prefixes(aguri_df,flows,cfg)`; golden export/validation helpers.

Verified legacy contract to encode before implementation:

```text
flow: TCP/UDP bidirectional 5-tuple, first-observed src/dst, no timeout
prefix matching: destination side in old code
prefix_len=24
min_flows=100; min_packets=1000; min_bytes=100000
max_short=0.8; max_tiny=0.8; max_syn_only_like=0.5; max_rst=0.8
short threshold=1.0s; tiny threshold=3 packets; top_k=10
score weights: flow=.20 packet=.20 byte=.20 low_short=.15 low_tiny=.15 low_syn=.10
paper notebook: dataset 202604081400; displayed prefix flow_count>=1000; sort flow_count; max 10
coarse overall sanity: median packets=1, frame bytes=58, duration=0s
```

- [ ] Write failing tests that encode this legacy contract separately from corrected baseline behavior.
- [ ] Add a `legacy` config block used only by `paper_legacy.yaml` with the exact fields above and `plot_min_flow_count=1000`.
- [ ] Implement legacy strategy in an isolated path: parse `dst_prefix`; destination membership only; IPv4 and prefixlen >=24; compute old short/tiny/SYN-only-like/RST ratios; apply filters; percentile-rank flow/packet/byte volume; weighted score; select top 10 by legacy score; apply paper display filter `flow_count>=1000` and sort by flow count for the reproduction notebook.
- [ ] Export exact prefix-level golden values from the old repo/result artifacts for `202604081400`. Do not treat rounded paper values alone as goldens.
- [ ] `validate_legacy.py` exact-matches integer/count/prefix/membership fields and uses a tight explicit tolerance for floating values only where necessary. Any mismatch must be investigated, not hidden by widening tolerance.
- [ ] Build `00_paper_legacy_reproduction.ipynb` to reproduce the old figure/statistics from new legacy outputs and display manifest provenance.
- [ ] Run full legacy validation; do not proceed to M3 interpretation until unexplained differences are resolved.
- [ ] Commit `feat: reproduce legacy paper analysis`.

---

## Task 9: Implement Corrected Aguri Candidate Union and Containment

**Files:** corrected path in `prefix.py`; `tests/unit/test_prefix_candidates.py`; integration stage test.

**Interfaces:** `build_corrected_prefix_ledger(aguri_df,cfg)->DataFrame`.

- [ ] Fixture candidates must cover repeated src/dst sightings, `/23`, parent `/24`, descendants `/25`/`/26`, sibling `/25`s, invalid/wildcard entries, and optional IPv6.
- [ ] Test identical `src_prefix` and `dst_prefix` candidates dedupe but retain `seen_as_src_prefix`, `seen_as_dst_prefix`, occurrence counts.
- [ ] Test IPv4 prefixlen <24 is retained in ledger but unselected with reason `broader_than_24`.
- [ ] Test eligible parent wins containment: if `/24`, `/25`, `/26` overlap, select `/24` and mark descendants `covered_by_parent` with `covered_by_prefix`.
- [ ] Test non-overlapping siblings can both remain selected.
- [ ] Test corrected baseline has no top-k and no flow-feature selection filter.
- [ ] Produce ledger fields: prefix, prefix_length, normalized_prefix_24, provenance counts/flags, selected_for_analysis, exclusion_reason, covered_by_prefix.
- [ ] Run tests and commit `feat: select corrected non-overlapping aguri prefixes`.

---

## Task 10: Implement Native and True Normalized-/24 Membership

**Files:** `membership.py`; unit and integration tests.

**Interfaces:** `build_membership(flows,prefixes)->DataFrame`, uniqueness key `(flow_id,analysis_scope,analysis_prefix)`.

- [ ] Test source-only match, destination-only match, both endpoints, neither endpoint.
- [ ] Test native `/25` excludes an address outside that `/25`, while normalized `/24` includes the same address by recomputing membership against the full `/24` network.
- [ ] Test multiple native prefixes mapping to one /24 produce one normalized /24 analysis scope.
- [ ] Output only matching flows with columns `flow_id`, `analysis_scope` (`native|normalized_24`), `analysis_prefix`, `src_match`, `dst_match`.
- [ ] Never reinterpret `src_match/dst_match` as outgoing/incoming or initiator/responder.
- [ ] Run tests and commit `feat: add native and true normalized prefix membership`.

---

## Task 11: Wire the M0–M3 Pipeline, Cache Decisions, and Run Conflict Protection

**Files:** pipeline + root CLI; integration stage tests; small end-to-end test.

**Interfaces:** `run_pipeline(args)->int`; stage dependencies through M3: input->flows, input->aguri->prefixes, flows+prefixes->membership, manifest finalization.

- [ ] Test `--dry-run` creates no result artifacts and reports planned reuse/execute decisions.
- [ ] Test same run name with same input/config identity may resume; same run name with different input SHA or config hash raises `RunConflictError` showing existing/requested values.
- [ ] Test `--from membership` fails if required upstream artifacts are absent; do not silently rebuild excluded stages.
- [ ] End-to-end test uses synthetic PCAP and monkeypatches only `pipeline.run_aguri_stage` to copy a committed `sample_candidates.csv`; assert success manifest, cached flows, `prefixes.csv`, and `flow_prefix_membership.csv` exist.
- [ ] Use a dependency table, not nested ad-hoc conditionals. `--force flows` invalidates downstream flow-dependent outputs; `--force aguri` invalidates prefixes/membership. `--redownload` is separate from analysis cache force.
- [ ] At run start write status `running`; record full config text/hash/path, git commit, input SHA/path, stage states. Every generated artifact is registered in manifest as `{path,row_count}`. Finalize success/failure explicitly.
- [ ] After M2 passes, run corrected `baseline.yaml` on `202604081400`; inspect selected-prefix count, exclusion reasons, and source-only/destination-only/both membership counts before interpreting research differences.
- [ ] Run fast suite and commit `feat: orchestrate reproducible m0-m3 pipeline stages`.

---

## Task 12: Generate Threshold-Free 60s/10s Scan Statistics and Neutral Pre-M5 Labels

**Files:** `scan_windows.py`, `scan_labels.py`, unit/integration tests, pipeline/CLI updates.

**Interfaces:** `build_source_scan_windows(flows,dataset_id,size_seconds,step_seconds,capture_start)`; neutral pre-M5 `flow_labels.csv`.

Required scan-window columns:
`dataset`, `initial_syn_sender_ip`, `window_start`, `window_end`, `syn_initiated_flow_count`, `unique_targets`, `unique_dst_ips`, `unique_dst_ports`, `syn_to_rst_pattern_count`, `syn_synack_rst_pattern_count`, `high_confidence_probe_pattern_count`, `unique_high_confidence_targets`, `no_observed_response_count`.

- [ ] Test `[0,60)` includes t=0 and t=59.999 but excludes exactly t=60; windows anchor at capture start and advance 10 s.
- [ ] Test `unique_targets` counts `(receiver_ip,receiver_port)` pairs and differs from repeated SYNs to one endpoint.
- [ ] Only rows with an observed plain-SYN initiator participate; zero-activity source/window combinations are not materialized.
- [ ] High-confidence count includes only `syn_to_rst` and `syn_synack_rst`; SYN-only contributes to broad behavioral observations but not high-confidence positive evidence.
- [ ] Implement `source_scan_summary.csv` over the full capture: initiated-flow count, unique targets/IPs/ports, total high-confidence pattern count. Do not add strict/broad window counts before M5.
- [ ] Implement pre-M5 label behavior: if strict/broad are disabled, write `flow_labels.csv` with each flow ID and all removal/scan-like booleans false. If either mode is enabled in this M0–M4 code path, fail with a clear gate error instructing the executor to stop for M5 threshold approval.
- [ ] Wire formal dependency `flows -> scan-stats -> scan-labels`. `source_scan_windows.csv` remains threshold-free observation data.
- [ ] Run tests and commit `feat: generate threshold-free scan behavior windows`.

---

## Task 13: Create Run Loader, Threshold Notebook, and Corrected Main Notebook

**Files:** `src/mawi_global_analysis/io.py`; notebooks `01_scan_threshold_exploration.ipynb`, `02_main_prefix_comparison.ipynb`; run-loader integration test.

**Interfaces:** `RunData` exposes `flows`, `labels`, `prefixes`, `membership`, optional scan windows/summary, and manifest; `load_run(dataset_id,run_name,root=Path("."))`.

- [ ] Test loader reads flow path from manifest artifact `flows_csv.path` and run-local labels/prefix/membership tables.
- [ ] Threshold notebook starts by displaying dataset, run name, config hash, input SHA, git commit. Plot `syn_initiated_flow_count` vs `unique_targets`, and high-confidence count vs unique high-confidence targets. Add ECDF/CCDF, log histograms, and Q99/Q99.5/Q99.9 tables as candidate guides only. Show rows above/near/below exploratory cutoffs for manual source/flow inspection. End with an explicit markdown gate stating no production threshold has been chosen automatically.
- [ ] Main corrected notebook starts with IPv4 overall, Raw, native prefix scope, all selected prefixes. It derives aggregations from canonical CSVs rather than graph-specific pipeline CSVs. Include initial TCP/UDP packet-count flow-length distributions, per-prefix traffic-volume vs median packet/byte/duration scatterplots, and duration ECDF/CCDF. Keep median plus distribution/tail views.
- [ ] Ensure notebooks use the run loader and show provenance near the top.
- [ ] Execute both notebooks from a clean kernel with `jupyter nbconvert --execute`.
- [ ] Commit `feat: add corrected baseline and threshold exploration notebooks`.

---

## Task 14: Add Research Guardrails, Reproduction Docs, and M4 Gate Verification

**Files:** `AGENTS.md`, `README.md`, guardrail config test, documentation updates.

- [ ] Test `baseline.yaml` cannot silently become top-k or destination-only: assert top_k null, mode `src_or_dst`, candidate sources exactly src+dst, overall IPv4.
- [ ] `AGENTS.md` must state: facts vs classification separation; canonical src/dst not initiator/responder; never delete all flows from scan-like source; corrected membership src OR dst; no corrected top-k; do not reintroduce short/tiny/scan prefix filters without explicit new experiment; never bypass fingerprints; no silent tool/input fallback; do not auto-select scan thresholds; use cautious scan-like/probe-like wording.
- [ ] README quick path: clone with submodules, `uv sync`, `uv run pytest`, run `paper_legacy`, `baseline`, and `threshold_exploration` on `202604081400`. Explain legacy vs corrected modes, cache/results layout, manifests, and M4 stop gate.
- [ ] Run full M0–M4 verification: `uv sync`; full pytest; `scripts/validate_legacy.py` against verified golden JSON; baseline and threshold-exploration dry-runs; execute notebooks 00, 01, 02 with `nbconvert --execute`.
- [ ] Confirm checklist: legacy exact match; corrected src+dst candidate union; all eligible non-overlapping /24-or-more-specific prefixes; no corrected top-k/short/tiny/scan selection; native + true /24 membership; IPv4 main overall while canonical flows retain IPv6; timeout fingerprint behavior; frame/IP/payload and TCP facts tested; 60/10 `[start,end)` windows; no numeric production scan threshold; threshold notebook exposes manual inspection; manifests capture input/config/cache/code identity.
- [ ] Commit `docs: document reproducible m0-m4 workflow and research guardrails`.

---

## M4 Human Gate and Deferred Plan

Stop after M4. A researcher must inspect the real `source_scan_windows.csv` distribution and raw/flow records around candidate cutoffs. Only after concrete `N_strict`, `M_strict`, `N_broad`, and `M_broad` values are approved should a second implementation plan be written.

That post-M4 plan covers M5–M8 only: strict/broad scan-window classification and probe-like flow removal, the Raw/Strict/Broad sensitivity notebook, `run_batch.py` dataset×config matrix execution, multi-dataset validation, and final hardening. This split is intentional: implementation must not invent thresholds just to continue.