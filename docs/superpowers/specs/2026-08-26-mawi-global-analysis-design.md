# mawi-global-analysis Design Specification

- Date: 2026-08-26
- Status: Approved design
- Target repository: `mawi-global-analysis` (new repository, separate from `mawi-dpkt-analysis`)
- Source basis:
  - Existing repository: `ShuntaSakai/mawi-dpkt-analysis`
  - Paper: 「広域トラフィックと IP プレフィックス単位トラフィックにおけるフロー特徴量の差異分析」
  - Related MAWI papers used as methodological background: *Seven Years and One Day*, *MAWILab Anomaly Detectors*, *Scaling in Internet Traffic*

## 1. Purpose and Scope

`mawi-global-analysis` is a reproducible research pipeline for re-analyzing MAWI backbone traffic and comparing global backbone traffic with traffic associated with IP prefixes that serve as proxies for more localized communication entities.

The repository has two explicit goals:

1. Reproduce the result-generation behavior of the existing `mawi-dpkt-analysis` repository so that legacy paper figures and statistics can be treated as a regression baseline.
2. Provide a corrected and extensible analysis baseline that removes known implementation/method mismatches, supports scan-like traffic sensitivity analysis, supports multiple datasets, and preserves enough low-level facts to permit reclassification without re-parsing PCAP files whenever possible.

The repository is not intended to hard-code one final plot. The pipeline produces general-purpose flow-, prefix-, and scan-analysis CSVs. Statistical aggregation and visualization remain in Jupyter notebooks.

### 1.1 Primary research comparison

The main corrected baseline compares:

- Overall IPv4 traffic observed at the MAWI measurement point.
- Traffic associated with every selected non-overlapping IPv4 prefix produced from Aguri candidates, where prefix membership is defined as:

`src_ip ∈ prefix OR dst_ip ∈ prefix`

The main corrected baseline does not limit analysis to a top-10 prefix set.

### 1.2 Legacy reproduction versus corrected baseline

The project must keep legacy reproduction and corrected analysis conceptually separate.

- `paper_legacy.yaml` reproduces the behavior that actually generated the prior repository's paper figures and statistics, including known implementation-specific choices.
- `baseline.yaml` implements the newly agreed corrected methodology.

A difference between these two modes is not automatically a bug. The legacy mode is a regression target; the corrected baseline is the research target.

### 1.3 Scientific guardrails

The code and documentation must preserve the distinction between observation and interpretation.

- A prefix is a proxy for a communication entity, not proof that the traffic represents a single host or application.
- `src_ip`/`dst_ip` in canonical flows reflect the first observed packet direction and must not be silently interpreted as initiator/responder.
- A single SYN, a single failed connection, or a single positive probe pattern must not by itself be labeled a scan.
- MAWI observation asymmetry means missing response packets are weak negative evidence. Absence of an observed response must not be used as a high-confidence scan criterion by itself.
- Prefix traffic is a subset of overall traffic, so future inferential statistics must not assume the samples are independent without justification.
- Capture-length truncation can affect flow duration and must be considered when interpreting 15-minute traces.

## 2. Architecture Decision

Three architectural approaches were considered.

| Option | Structure | Advantages | Disadvantages |
|---|---|---|---|
| A. Script-centered | Sequential `scripts/*.py` programs | Simple and similar to the existing repository | Shared logic tends to scatter, testing and partial reruns become harder |
| **B. Python package + stage CLI** | Core logic under `src/mawi_global_analysis/`; thin CLI orchestrators | **Strong reuse, testing, caching, partial execution, and experiment comparison** | Slightly more initial structure |
| C. Workflow engine | Snakemake or similar dependency graph | Strong for very large job graphs | Unnecessary complexity for the current research scale; research logic risks spreading into workflow definitions |

**Decision: Option B.**

The project is designed for reproducibility and re-analysis from the beginning, while implementation proceeds incrementally from legacy reproduction to corrected and extended analyses.

### 2.1 Responsibility boundaries

- Dataset layer: resolve, download, validate, and identify input PCAPs.
- Flow layer: derive canonical observations from PCAP.
- Aguri layer: run and parse Aguri as a versioned external dependency.
- Scan layer: derive TCP control patterns, source-window statistics, and run-specific scan-like labels.
- Prefix layer: create candidate sets, resolve containment, create native and normalized analysis scopes, and map flows to prefixes.
- Pipeline layer: orchestrate stage dependencies, caching, partial execution, and manifests.
- Notebook layer: perform research aggregation, statistics, and plots.

`run_pipeline.py` and `run_batch.py` must remain thin orchestrators rather than containers for research logic.

## 3. Repository and Artifact Model

The repository separates expensive dataset-common facts from experiment-specific classifications.

```text
mawi-global-analysis/
├── configs/
├── datasets/
├── src/mawi_global_analysis/
├── notebooks/
├── tests/
├── scripts/
├── vendor/
├── docs/superpowers/specs/
├── data/       # gitignored
├── results/    # gitignored
├── run_pipeline.py
├── run_batch.py
├── pyproject.toml
├── uv.lock
├── .python-version
├── README.md
└── AGENTS.md
```

### 3.1 Dataset-common artifacts

```text
data/
└── <dataset>/
    ├── raw/
    │   └── <pcap-file>
    └── processed/
        ├── flows/
        │   └── <flow-profile>-<fingerprint>/
        │       ├── flows.csv
        │       └── flow_manifest.json
        └── aguri/
            └── <aguri-fingerprint>/
                ├── raw.agr
                ├── raw.agurim.txt
                ├── aguri_candidates.csv
                └── aguri_manifest.json
```

### 3.2 Run-specific artifacts

```text
results/
└── <dataset>/
    └── <run-name>/
        ├── flow_labels.csv
        ├── prefixes.csv
        ├── flow_prefix_membership.csv
        ├── source_scan_windows.csv
        ├── source_scan_summary.csv
        ├── run_manifest.json
        └── run.log
```

### 3.3 Artifact responsibility table

| Artifact | Meaning | Regeneration rule |
|---|---|---|
| `flows.csv` | PCAP-derived flow observations and stable derived facts | Regenerate only when input or flow-generation configuration changes |
| `flow_manifest.json` | Input and flow-generation provenance | Regenerate with `flows.csv` |
| `aguri_candidates.csv` | Aguri candidate observations from raw traffic | Regenerate when input, Aguri version/binary, or Aguri options change |
| `flow_labels.csv` | Run-specific classification such as strict/broad scan removal labels | Regenerate when scan/classification config changes |
| `prefixes.csv` | Full Aguri candidate ledger plus corrected analysis-selection decisions | Regenerate when candidate/selection config changes |
| `flow_prefix_membership.csv` | Flow-to-analysis-prefix membership | Regenerate when flow cache or selected prefix scopes change |
| `source_scan_windows.csv` | Threshold-free source × window observation statistics | Regenerate when flow facts or window definition changes |
| `source_scan_summary.csv` | Source-level 15-minute summary plus run-level scan summary where enabled | Regenerate when source-window/scan config changes |
| `run_manifest.json` | Complete run provenance and artifact inventory | Created at run start and finalized on success/failure |

The central rule is:

> PCAP-derived observations belong to the dataset/flow profile. Researcher-selected interpretation and classification belong to a run.

## 4. Canonical Flow Model

### 4.1 Flow definition

Baseline compatibility uses the existing repository semantics:

- TCP and UDP only.
- Bidirectional 5-tuple aggregation.
- A→B and B→A belong to the same normalized flow key.
- Output `src`/`dst` retain the direction of the first observed packet rather than the normalized endpoint order.
- Baseline flow timeout is disabled, so a normalized 5-tuple is aggregated through the capture unless the timeout experiment explicitly enables splitting.

When inactive timeout is enabled, a gap greater than the configured inactivity threshold begins a new flow instance. Flow IDs must remain deterministic within a parse for a fixed input and flow configuration.

### 4.2 Byte definitions

For compatibility and future analysis, the canonical flow row stores:

- `byte_count`: compatibility alias equal to Ethernet-frame bytes.
- `frame_byte_count`: explicit Ethernet-frame byte total.
- `ip_byte_count`: total IP packet bytes observed for the flow.
- `transport_payload_byte_count`: total TCP/UDP payload bytes observed for the flow.

The existing paper result used the legacy frame-byte behavior, so `paper_legacy.yaml` must preserve it.

### 4.3 Minimum canonical columns

Canonical `flows.csv` should contain at least:

```text
flow_id
ip_version
protocol
start_time
end_time
duration
src_ip
src_port
dst_ip
dst_port
packet_count
byte_count
frame_byte_count
ip_byte_count
transport_payload_byte_count
packets_from_src
packets_from_dst
bytes_from_src
bytes_from_dst
```

The flow row also keeps TCP control facts for TCP flows. UDP rows leave TCP-specific fields null/zero as defined by the schema.

### 4.4 TCP control facts

The purpose of the TCP control summary is to support the anticipated scan-like reclassifications without storing every TCP packet event.

At minimum, retain:

```text
initial_syn_sender_ip
initial_syn_sender_port
initial_syn_receiver_ip
initial_syn_receiver_port
first_syn_time
syn_from_initiator
syn_from_responder
synack_from_initiator
synack_from_responder
rst_from_initiator
rst_from_responder
first_responder_synack_time
first_responder_rst_time
first_initiator_rst_time
ack_after_synack_observed
transport_payload_observed
```

`initial_syn_sender_*` is derived only when a plain SYN (`SYN=1, ACK=0`) is actually observed. The implementation must not infer an initiator solely from a SYN+ACK or from the canonical `src_ip` field. If no plain SYN is observed, the initial-SYN fields remain null.

This summary is intentionally not a general-purpose packet-sequence archive. Future analyses requiring arbitrary sequence reconstruction may still require PCAP reprocessing.

## 5. Pipeline Stages and Dependencies

The formal stage order is:

```text
input
├── flows
│   ├── scan-stats
│   │   └── scan-labels
│   └── membership
└── aguri
    └── prefixes
        └── membership

all completed/failed stages → manifest finalization
```

The CLI-visible stage names are:

```text
input
flows
aguri
scan-stats
scan-labels
prefixes
membership
manifest
```

### 5.1 Input stage

Two mutually exclusive input modes are supported:

```bash
python run_pipeline.py --dataset 202604081400 --config configs/baseline.yaml
```

or

```bash
python run_pipeline.py --input /path/to/sample.pcap.gz --config configs/baseline.yaml
```

`--dataset` uses the MAWI dataset resolver and downloader. The resolver owns the mapping from a 12-digit dataset ID to the official MAWI archive location and must fail clearly when the requested trace cannot be resolved; URL assumptions must not leak into other modules.

`--input` bypasses download. A local input receives a deterministic internal dataset identifier based on its filename and checksum unless `--dataset-id` is supplied.

The input stage records the resolved path, size, checksum, and dataset identity.

### 5.2 Flows stage

`flows` parses the PCAP and produces the cached canonical flow CSV and flow manifest. Flow cache identity is based on the input checksum plus only those configuration fields that affect flow generation, plus a schema/code compatibility identifier.

A scan threshold change must not change the flow fingerprint. A timeout change must.

### 5.3 Aguri stage

Aguri always runs on the raw input traffic for the main experiment. Scan removal must not silently change the main analysis prefix set.

Aguri cache identity includes:

- Input PCAP checksum.
- Aguri source/version or submodule commit.
- Executable checksum.
- Relevant Aguri options.

The stage stores raw output and a normalized `aguri_candidates.csv`.

### 5.4 Scan-stats stage

This stage uses canonical flow facts and creates threshold-free source-window statistics. It does not declare a source or flow malicious.

The default window geometry is:

- Window size: 60 seconds.
- Step: 10 seconds.
- Window membership: half-open intervals `[window_start, window_end)`.
- Window anchor: capture start; windows begin at `capture_start + k * step`.
- A source-window row is emitted only when at least one qualifying plain-SYN-initiated TCP flow for that source falls in the window; zero-activity source-window combinations are not materialized.

This definition is configurable through YAML.

### 5.5 Scan-labels stage

This stage applies run-specific thresholds and flow-removal rules to the threshold-free window statistics and canonical TCP facts. Its principal persistent output is `flow_labels.csv`. Window-level decisions may be summarized in `source_scan_summary.csv`; `source_scan_windows.csv` remains an observation-statistics file.

### 5.6 Prefixes stage

This stage creates the corrected candidate ledger and selected analysis-prefix set from Aguri candidates. It does not depend on scan removal in the main experiment.

### 5.7 Membership stage

This stage maps canonical flows to each selected native and normalized analysis prefix using `src OR dst` membership for the corrected baseline.

### 5.8 Manifest lifecycle

A skeleton `run_manifest.json` is written at run start with status `running`. On success it is finalized with stage/artifact summaries and status `success`. If a fatal exception occurs, the failure handler updates the same manifest with status `failed`, completed stages, and error metadata before returning a non-zero exit status whenever possible.

## 6. Prefix Candidate, Selection, and Membership Design

### 6.1 Candidate pool

Aguri `src_prefix` and `dst_prefix` observations are merged into one normalized prefix candidate pool. Identical prefixes are deduplicated, while provenance is retained:

```text
seen_as_src_prefix
seen_as_dst_prefix
aguri_src_occurrence_count
aguri_dst_occurrence_count
aguri_occurrence_count
```

Invalid/wildcard entries are not treated as concrete prefix candidates.

### 6.2 IPv4 analysis scope

Canonical flows retain both IPv4 and IPv6. The corrected main prefix analysis is IPv4-only.

For baseline corrected prefix selection:

- IPv4 prefixes with prefix length smaller than 24 are not selected.
- `/24`, `/25`, `/26`, ... remain eligible.
- If Aguri yields IPv6 candidates and the parser supports them, they may be retained in the candidate ledger but are marked unselected for the IPv4 baseline rather than silently discarded.

### 6.3 Containment resolution

The corrected main analysis must avoid selected prefixes that contain one another.

When eligible candidates have an ancestor/descendant relationship, the broader eligible candidate is selected and contained descendants are excluded.

Example:

```text
202.244.127.0/24       selected
202.244.127.128/25     excluded: covered_by_parent
202.244.127.192/26     excluded: covered_by_parent
```

Two sibling prefixes that do not overlap can both be selected.

No top-k limit is applied to the corrected baseline. Every selected, non-overlapping Aguri-derived prefix is an analysis target.

### 6.4 `prefixes.csv`

`prefixes.csv` is a candidate ledger, not just a selected-prefix list. Minimum fields include:

```text
prefix
prefix_length
normalized_prefix_24
seen_as_src_prefix
seen_as_dst_prefix
aguri_occurrence_count
aguri_src_occurrence_count
aguri_dst_occurrence_count
selected_for_analysis
exclusion_reason
covered_by_prefix
```

Corrected-baseline selection must not filter prefixes based on short-flow ratio, tiny-flow ratio, scan-like ratio, or other flow features. Those quantities describe selected traffic; they must not mechanically create the difference the study later reports.

For the corrected baseline, flow-derived prefix statistics are computed from `flows.csv` plus membership in notebooks instead of being baked into `prefixes.csv`.

Legacy mode may compute the exact legacy score/filter columns needed for regression compatibility.

### 6.5 Native versus normalized `/24` scope

Both of the following must be analyzable:

- `native`: the original selected Aguri prefix, e.g. `/25` or `/26`.
- `normalized_24`: the containing `/24` as an actual traffic scope.

Normalization must not merely rename a `/25` row as `/24`. When `/24` analysis is requested, membership is recomputed against the full `/24` address block.

Multiple native candidates mapping to the same `/24` produce one normalized `/24` analysis prefix.

### 6.6 `flow_prefix_membership.csv`

The uniqueness key is:

`(flow_id, analysis_scope, analysis_prefix)`

Minimum columns:

```text
flow_id
analysis_scope          # native | normalized_24
analysis_prefix
src_match
dst_match
```

A flow that matches both endpoints produces one membership row with both booleans true.

For the corrected baseline, membership is true when:

`src_match OR dst_match`

`src_match` and `dst_match` are observation-direction facts. They must not be renamed or interpreted as outgoing/incoming or initiator/responder traffic.

## 7. Scan-like Analysis Design

The scan-like system is deliberately hierarchical:

```text
flow-level observed TCP facts
        ↓
source × time-window behavior statistics
        ↓
strict / broad scan-like classification
        ↓
flow-level removal labels
```

It must never implement “source labeled malicious → delete every flow from that source.”

### 7.1 Scan source identity

The scan source key is:

`initial_syn_sender_ip`

not canonical `src_ip`.

The target endpoint is:

`(initial_syn_receiver_ip, initial_syn_receiver_port)`

### 7.2 Flow-level observed probe patterns

Flow-level patterns represent evidence, not final scan labels.

High-confidence positive patterns for the initial implementation are:

- Closed-port-like probe: initiator plain SYN followed by responder RST or RST+ACK.
- Half-open-like positive probe: initiator plain SYN → responder SYN+ACK → initiator RST.

The implementation must verify event ordering using the stored directional TCP facts/timestamps. A single matching flow does not establish scan behavior.

A plain SYN with no observed response is not a high-confidence pattern because observation asymmetry may hide the response.

### 7.3 Threshold-free behavioral metrics

For each active `initial_syn_sender_ip × window`, `source_scan_windows.csv` contains at least:

```text
dataset
initial_syn_sender_ip
window_start
window_end
syn_initiated_flow_count
unique_targets
unique_dst_ips
unique_dst_ports
syn_to_rst_pattern_count
syn_synack_rst_pattern_count
high_confidence_probe_pattern_count
unique_high_confidence_targets
no_observed_response_count
```

`unique_targets` means unique `(initial_syn_receiver_ip, initial_syn_receiver_port)` pairs. It is the main diversity measure because it distinguishes repeated retransmission to one endpoint from probing many endpoints.

### 7.4 Strict classification

A strict scan window requires repeated positive evidence at source level:

- `high_confidence_probe_pattern_count` meets the configured strict count threshold.
- `unique_high_confidence_targets` meets the configured strict diversity threshold.

No numeric threshold is authorized by this design document. The values must be selected after the M4 empirical threshold-exploration gate and then written explicitly into the experiment YAML used for M5 onward.

A strict scan-like flow is a high-confidence probe-pattern flow whose initial SYN time belongs to at least one strict scan window for its initial SYN sender.

### 7.5 Broad behavioral classification

A broad behavioral scan window is based on repeated connection-initiation behavior regardless of response visibility:

- `syn_initiated_flow_count` meets the configured broad count threshold.
- `unique_targets` meets the configured broad diversity threshold.

Again, no numeric default is authorized before the M4 manual review.

Broad removal must be narrower than “all SYN-started flows in a suspicious window.” A flow is removed through the behavioral branch only when it is also `probe_like_flow`.

The baseline probe-like set is deliberately conservative:

- Plain SYN(s) observed with no non-SYN response/establishment evidence (`syn_only_observed`). Retransmitted initiator SYNs may still belong to this category.
- SYN → responder RST/RST+ACK.
- SYN → SYN+ACK → initiator RST.

A flow with observed handshake completion and transport payload is kept by the behavioral branch.

Ambiguous incomplete-handshake categories such as SYN → SYN+ACK with no observed final ACK/RST are retained as facts and are not removed by the initial broad baseline unless a later sensitivity config explicitly opts into such a rule. This keeps the default broad detector conservative under asymmetric observation.

### 7.6 Strict is contained in broad removal

The final broad-removal label is defined so that:

`strict_removed_flows ⊆ broad_removed_flows`

Conceptually:

`broad_scan_like_flow = strict_scan_like_flow OR (behavioral_scan_window_match AND probe_like_flow)`

This invariant is enforced by automated tests.

### 7.7 Source-level summary

`source_scan_summary.csv` contains per-source 15-minute supporting statistics such as:

```text
initial_syn_sender_ip
syn_initiated_flow_count
unique_targets
unique_dst_ips
unique_dst_ports
high_confidence_probe_pattern_count
strict_scan_window_count
behavioral_scan_window_count
first_scan_window
last_scan_window
```

The full-capture summary is supporting evidence, not a substitute for the time-window classification logic.

### 7.8 Threshold exploration workflow

Threshold selection is explicitly separated from main analysis:

1. Run `threshold_exploration.yaml` with thresholding/removal disabled.
2. Inspect `syn_initiated_flow_count × unique_targets` and `high_confidence_probe_pattern_count × unique_high_confidence_targets`.
3. Inspect ECDF/CCDF, log-scale histograms, and upper-tail quantiles such as Q99, Q99.5, and Q99.9 as candidate guides, not truth labels.
4. Inspect flows/sources above, near, and below candidate cutoffs.
5. Choose baseline thresholds from empirical structure plus manual inspection.
6. Encode the chosen values into self-contained experiment YAMLs.
7. Run sensitivity configurations and compare removed flow/packet/byte volume plus the main overall-vs-prefix results.

The pipeline must not automatically choose “Q99 = scan threshold.”

## 8. Raw, Strict, and Broad Experimental Comparison

The main scan sensitivity experiment uses a prefix set selected exactly once from raw traffic.

```text
Raw PCAP
  ↓
Aguri
  ↓
Corrected selected Prefix set P
  ↓
  ├── Raw traffic analysis on P
  ├── Strict removal analysis on P
  └── Broad removal analysis on P
```

The same analysis prefixes are used across these conditions so that changes in flow features are attributable to traffic removal rather than to changing which prefixes are compared.

Re-running Aguri after scan removal is scientifically meaningful as a separate question—whether scan-like traffic changes which prefixes appear heavy—but it is not part of the initial main-pipeline Definition of Done. If implemented later, it must be a separately named experiment and must not replace the fixed-prefix main comparison.

## 9. Experiment Configuration

### 9.1 One experiment condition = one YAML

Configuration files are self-contained. The initial design does not use YAML inheritance, because a historical run should be interpretable from one saved config.

Recommended set:

```text
configs/
├── paper_legacy.yaml
├── baseline.yaml
├── threshold_exploration.yaml
├── scan_positive_evidence.yaml
├── scan_behavioral_baseline.yaml
├── scan_behavioral_loose.yaml
└── scan_behavioral_conservative.yaml
```

The full YAML text and its hash are copied into `run_manifest.json` so later edits to the config file do not erase run provenance.

### 9.2 Conceptual schema

```yaml
experiment:
  name: baseline
  description: Corrected raw analysis

flow:
  protocols: [tcp, udp]
  timeout:
    enabled: false
    inactive_seconds: 60
  byte_metrics:
    frame: true
    ip: true
    transport_payload: true

aguri:
  enabled: true

prefix:
  ip_version: 4
  candidate_sources: [src_prefix, dst_prefix]
  min_prefix_length: 24
  containment:
    enabled: true
    strategy: prefer_broader
  membership:
    mode: src_or_dst
  normalized_24:
    enabled: true
  selection:
    top_k: null
    score_filter:
      enabled: false

scan:
  enabled: true
  window:
    size_seconds: 60
    step_seconds: 10
  strict:
    enabled: false
  broad:
    enabled: false

analysis:
  overall_ip_scope: ipv4

output:
  write_source_scan_windows: true
  write_source_scan_summary: true
```

The implementation may refine key names, but it must preserve these responsibility boundaries.

### 9.3 `paper_legacy.yaml`

Purpose: reproduce the old repository's actual result-generation behavior, not silently “correct” it to match the paper prose.

Legacy compatibility includes the verified old behavior required for golden regression, including legacy destination-side prefix matching and legacy prefix ranking/plot filtering where applicable. The exact golden behavior is established from the old repository outputs, not inferred only from rounded values in the paper.

The old paper result provides a coarse sanity check: overall medians were 1 packet, 58 B, and 0 s, with selected prefixes showing larger medians. Exact prefix-level golden values must come from the old repository outputs.

### 9.4 `baseline.yaml`

Purpose: corrected raw analysis.

- Aguri `src_prefix + dst_prefix` candidate union.
- IPv4, `/24` or more specific.
- Prefer broader eligible candidate under containment.
- No top-k limit.
- No short/tiny/scan-derived selection filter.
- Membership uses `src OR dst`.
- Overall comparison uses IPv4.
- No scan removal.

### 9.5 Threshold and removal configs

`threshold_exploration.yaml` generates source-window statistics but does not authorize removal.

After manual M4 threshold selection:

- `scan_positive_evidence.yaml` enables strict positive-evidence removal.
- `scan_behavioral_baseline.yaml` enables strict plus the baseline behavioral branch.
- `scan_behavioral_loose.yaml` and `scan_behavioral_conservative.yaml` vary thresholds for sensitivity analysis.

The terms “strict detector” and “strict threshold” must not be conflated in names or documentation.

### 9.6 Validation

Configuration is strictly validated, preferably with Pydantic.

Validation must reject:

- Unknown keys unless explicitly supported.
- Type mismatches.
- Missing required values.
- Negative/zero invalid window settings.
- Mutually contradictory conditions.
- A scan removal mode that requires thresholds when those thresholds are absent.

Silent fallback is prohibited.

## 10. Caching and Fingerprints

### 10.1 Flow fingerprint

The flow fingerprint is based only on factors that can change canonical flow generation, including:

- Input checksum.
- Flow schema version.
- Supported protocol selection.
- Timeout enabled/seconds.
- Any parser option that changes packet/byte/control-fact aggregation.

Changing scan thresholds or prefix containment settings must not invalidate `flows.csv`.

### 10.2 Aguri fingerprint

The Aguri fingerprint is based on:

- Input checksum.
- Aguri pinned commit/version.
- Executable checksum.
- Aguri command options.

### 10.3 Stale dependency behavior

`--force <stage>` invalidates that stage and downstream artifacts that depend on it.

Examples:

- Changing only `min_unique_targets` reuses flows and Aguri but regenerates scan labels and dependent run outputs.
- Enabling a 60-second inactive flow timeout creates a new flow fingerprint and therefore regenerates all flow-dependent downstream outputs.

## 11. CLI and Batch Interface

### 11.1 Single-dataset command

```bash
python run_pipeline.py \
  --dataset 202604081400 \
  --config configs/baseline.yaml
```

or

```bash
python run_pipeline.py \
  --input /path/to/sample.pcap.gz \
  --config configs/baseline.yaml
```

`--dataset` and `--input` are mutually exclusive and one is required.

`--run-name` may override `experiment.name`, but routine use should keep them aligned.

### 11.2 Stage control

Supported controls:

```text
--from <stage>
--to <stage>
--force <stage...>
--force all
--dry-run
--redownload
```

`--dry-run` reports stage execution/reuse decisions without modifying files.

`--redownload` concerns raw input retrieval and is separate from analysis-cache invalidation.

When `--from` skips required missing upstream artifacts, the pipeline fails clearly rather than rebuilding unspecified stages behind the user's back.

### 11.3 Run-name conflict protection

If `results/<dataset>/<run-name>` already exists:

- If the existing manifest identifies the same input/config identity, resume/reuse is allowed.
- If the config or input identity differs, the command fails and requires a different run name.

A historical run must never be silently overwritten because a config file was edited later.

### 11.4 Batch command

`run_batch.py` is a thin controller over the single-dataset pipeline.

Single config:

```bash
python run_batch.py \
  --datasets datasets/validation_days.txt \
  --config configs/baseline.yaml
```

Dataset × config matrix:

```bash
python run_batch.py \
  --datasets datasets/validation_days.txt \
  --configs \
    configs/baseline.yaml \
    configs/scan_positive_evidence.yaml \
    configs/scan_behavioral_baseline.yaml \
  --batch-name multi-day-scan-comparison
```

Default batch behavior is continue-on-error. A failed job is recorded and subsequent jobs continue. The final batch process returns non-zero if any job failed. `--fail-fast` provides the opposite behavior.

### 11.5 Batch manifest

```text
results/batches/<batch-name>/
├── batch_manifest.json
└── batch.log
```

The manifest records dataset list/hash, config paths/hashes, the job matrix, job status, linked run manifests, execution times, and failure summaries.

## 12. Logging and Error Handling

Terminal output is concise and human-oriented:

```text
[INFO] Dataset 202604081400
[REUSE] flows: no_timeout-a81f3c
[REUSE] aguri
[RUN] scan-stats
[DONE] scan-stats: 4.2 s
```

`run.log` is more detailed and contains timestamps, stage names, paths, fingerprints, cache decisions, durations, external command output/error context, and tracebacks.

Warnings represent unusual but valid data conditions; errors represent conditions under which results should not be trusted.

Examples of warnings:

- Zero selected prefixes.
- Zero plain-SYN-initiated TCP flows.
- An expected optional data category absent from a trace.

Examples of fatal errors:

- Invalid config.
- Missing required CSV schema columns.
- Input checksum mismatch.
- Malformed/unreadable PCAP.
- Required Aguri binary unavailable.

Silent skipping of required stages is prohibited.

## 13. Notebook and Analysis Design

The pipeline does not create graph-specific pre-aggregated CSVs. Notebooks read canonical CSVs and perform the research-specific aggregation needed for each question.

### 13.1 Notebook set

```text
notebooks/
├── 00_paper_legacy_reproduction.ipynb
├── 01_scan_threshold_exploration.ipynb
├── 02_main_prefix_comparison.ipynb
├── 03_scan_removal_sensitivity.ipynb
└── 04_multi_dataset_validation.ipynb
```

### 13.2 Run loader

The package provides I/O convenience, not research aggregation. A notebook-level helper can load a run and expose:

```text
flows
labels
prefixes
membership
scan_windows
scan_summary
manifest
```

Grouping, medians, quantiles, ECDF/CCDF, and plot choices remain visible in notebooks.

### 13.3 Main corrected comparison

The initial main notebook starts with:

- IPv4 overall traffic.
- Raw scan condition.
- `native` selected prefix scope.
- All selected prefixes, not top 10.

Because the selected-prefix count may be large, “one prefix = one observation” distributions/scatters are preferred over a huge bar chart.

### 13.4 Required initial plot families

1. TCP and UDP flow-length distributions, where flow length is `packet_count` per flow. Histogram, ECDF, CCDF, and log-scale variants may be explored from the same canonical data.
2. Prefix traffic volume versus flow-feature scatterplots, with one point per prefix. Candidate x-axes include flow count, packet count, frame bytes, and IP bytes. Candidate y-axes include median packet count, byte count, and duration.
3. Flow-duration ECDF/CCDF, with duration on the x-axis and cumulative probability on the y-axis.

The pipeline must not be redesigned around any one of these final plot choices.

### 13.5 Distribution beyond medians

Legacy medians remain important, but notebooks should permit inspection of Q25/Q75, Q90/Q99, ECDF/CCDF, and log-tail behavior to distinguish median shifts from broader distribution changes.

### 13.6 Raw / strict / broad comparison

For each fixed prefix P, notebooks can compare the same traffic scope under:

- Raw.
- Strict positive-evidence removal.
- Broad behavioral removal.

The notebook must also report removal volume:

- Removed flow ratio.
- Removed packet ratio.
- Removed frame-byte ratio.

The main scientific comparison is whether the overall-vs-prefix difference persists, shrinks, or changes under these removal conditions. A shrinking difference is treated as an informative causal clue, not a failed study.

### 13.7 Difference metrics

No single difference metric is hard-coded. Notebooks may use absolute difference, ratio, or log-ratio where appropriate. Metrics with a zero overall baseline, such as a zero median duration, must not use invalid ratios.

### 13.8 Multi-dataset validation

After the single-dataset analysis is stable, multiple MAWI days are summarized using the same experiment configs. The multi-dataset notebook compares selected-prefix counts, overall feature statistics, prefix-feature distributions, scan-removal volume, and overall-vs-prefix differences across days.

### 13.9 Notebook reproducibility

Each notebook must display its dataset, run name, analysis scope, config hash, input checksum, and code/git identity near the start.

Core notebooks must execute successfully from a clean kernel using Run All / `nbconvert --execute`.

Generated data/results/figures are normally gitignored. Explicit paper artifacts may later be exported to a dedicated tracked location if needed.

## 14. Environment and External Dependencies

### 14.1 Python project

Use `pyproject.toml` plus a lock file, with `uv` as the primary environment/package workflow.

Typical dependencies:

```text
dpkt
pandas
numpy
matplotlib
PyYAML
pydantic
jupyter
ipykernel
pytest
```

The code remains a normal Python package rather than depending on `uv` APIs.

The project must pin one Python major/minor version in `.python-version` and project metadata. M0 begins with a dependency compatibility check; Python 3.12 is the preferred candidate, but the implementer may select another single common supported minor only if compatibility evidence requires it, and must record that choice in the initial repository setup. Floating across minor versions is not permitted for the reproducibility baseline.

### 14.2 Aguri pinning

Aguri is managed separately from Python dependencies. The preferred baseline is a Git submodule under:

```text
vendor/agurim/
```

The initial legacy-reproduction setup should pin the same Aguri lineage/commit used by the old repository when available, then record the exact commit and executable checksum.

Executable resolution order:

1. Explicit config path.
2. Pinned repository `vendor/agurim` binary.
3. PATH binary as a fallback.

Using a PATH fallback emits a warning and records executable path, version, and checksum.

### 14.3 Aguri adapter

External invocation is isolated behind an adapter such as:

```text
src/mawi_global_analysis/aguri/
├── runner.py
├── parser.py
└── models.py
```

The rest of the pipeline must not scatter direct Aguri subprocess calls throughout the codebase.

### 14.4 Containerization

Docker/devcontainer support is optional future work. The primary development/reproduction path is pinned Python + lock file + pinned Aguri. Containerization is not part of the initial Definition of Done.

## 15. Repository Layout

Target responsibility-oriented structure:

```text
mawi-global-analysis/
├── README.md
├── AGENTS.md
├── pyproject.toml
├── uv.lock
├── .python-version
├── .gitignore
│
├── configs/
│   ├── paper_legacy.yaml
│   ├── baseline.yaml
│   ├── threshold_exploration.yaml
│   ├── scan_positive_evidence.yaml
│   ├── scan_behavioral_baseline.yaml
│   ├── scan_behavioral_loose.yaml
│   └── scan_behavioral_conservative.yaml
│
├── datasets/
│   └── validation_days.txt
│
├── src/
│   └── mawi_global_analysis/
│       ├── config/
│       ├── dataset/
│       ├── flow/
│       ├── aguri/
│       ├── scan/
│       ├── prefix/
│       ├── pipeline/
│       ├── io/
│       └── manifest/
│
├── run_pipeline.py
├── run_batch.py
│
├── notebooks/
│   ├── 00_paper_legacy_reproduction.ipynb
│   ├── 01_scan_threshold_exploration.ipynb
│   ├── 02_main_prefix_comparison.ipynb
│   ├── 03_scan_removal_sensitivity.ipynb
│   └── 04_multi_dataset_validation.ipynb
│
├── tests/
│   ├── fixtures/
│   ├── unit/
│   ├── integration/
│   └── test_end_to_end.py
│
├── scripts/
│   └── validate_legacy.py
│
├── vendor/
│   └── agurim/
│
├── docs/
│   └── superpowers/specs/
│
├── data/
└── results/
```

This is a responsibility map, not an instruction to scaffold empty files. YAGNI applies: begin with the smallest set of modules needed for the current milestone and split modules only as responsibilities grow.

## 16. AGENTS.md Guardrails

The new repository should explicitly instruct future Codex/agent work to preserve at least these rules:

```text
Keep PCAP-derived facts separate from run-specific classification.
Do not interpret canonical src/dst as initiator/responder.
Do not delete all flows from a scan-like source.
Corrected prefix membership is src OR dst.
Corrected baseline has no top-k prefix limit.
Do not reintroduce short/tiny/scan filters into corrected prefix selection without an explicit experiment config.
Do not bypass cache fingerprint validation.
Do not silently fall back when a required external tool or input is missing.
Do not automatically select scan thresholds from quantiles.
Preserve cautious research wording; labels such as scan-like/probe-like are not proof of malicious intent.
```

## 17. Testing and Verification

Testing is layered:

```text
unit tests
→ stage integration tests
→ paper legacy regression
→ end-to-end fixture
→ notebook/full MAWI validation
```

### 17.1 Required unit coverage

At minimum test:

- Bidirectional flow-key equivalence.
- First-observed output direction.
- Timeout disabled/enabled behavior.
- Frame/IP/transport-payload byte counts.
- Initial SYN sender extraction without inferring from canonical src/dst.
- SYN→RST and SYN→SYNACK→RST direction/order recognition.
- Observed handshake/payload facts.
- Broad probe-like retention of established payload connections.
- `src OR dst` prefix matching.
- Prefix containment resolution.
- True `/24` membership recomputation rather than relabeling.
- Config validation.
- Flow and Aguri fingerprints.
- Cache invalidation dependency behavior.

### 17.2 Synthetic PCAP fixture

A small PCAP fixture should include at least:

```text
A: SYN → responder RST
B: SYN → SYNACK → initiator RST
C: SYN → SYNACK → ACK → payload
D: SYN with no observed response
E: flow observed only from a mid-connection ACK/data packet
```

Expected interpretation:

- A/B: positive probe pattern facts.
- C: observed establishment/payload, not removed by the broad behavioral baseline.
- D: broad source-behavior evidence but not high-confidence by itself.
- E: initial SYN sender unknown and excluded from SYN-initiation source statistics.

### 17.3 Window boundary test

Explicitly test `[start, end)` behavior around 60-second boundaries and the 10-second step anchor.

### 17.4 Strict/broad invariant

Automated tests must enforce:

`strict_removed_flow_ids ⊆ broad_removed_flow_ids`

They must also verify that normal window-external traffic and observed established payload traffic from the same scan-like source remain present.

### 17.5 Prefix integration fixture

An Aguri mock plus synthetic flows must cover:

- Source-only membership.
- Destination-only membership.
- Both endpoints matching.
- Neither endpoint matching.
- Parent/child prefix containment.
- Sibling non-overlapping prefixes.
- Native versus normalized `/24` membership.

### 17.6 Legacy regression

The first major full-data acceptance test is:

```text
dataset = 202604081400
config  = paper_legacy.yaml
```

Compare exact values against golden outputs derived from `mawi-dpkt-analysis`. Integer/count/membership values are exact-match. Floating-point values use a tight explicit tolerance only where numerical representation requires it; tolerance must not hide unexplained logic differences.

The old paper's rounded overall medians are a sanity check, not sufficient golden coverage.

### 17.7 Fast CI versus full MAWI validation

Ordinary `pytest` uses small fixtures and should remain fast. Full MAWI regression is invoked explicitly, for example through `scripts/validate_legacy.py`, and is not required for every tiny development iteration.

### 17.8 Manifest verification

Tests verify that:

- Declared output files exist.
- Manifest row counts match CSV row counts.
- Config hashes match the actual saved config.
- Failure manifests correctly record failed status where possible.

### 17.9 Notebook verification

Core notebooks must execute from a clean kernel without manual cell ordering.

## 18. Implementation Milestones

| Milestone | Goal | Gate to proceed |
|---|---|---|
| **M0 Foundation** | Repository/config/test/manifest foundation | Environment sync, config validation, CLI help, basic tests pass |
| **M1 Flow Pipeline** | PCAP → canonical `flows.csv` | Flow/byte/TCP-control/timeout fixture tests pass |
| **M2 Paper Legacy Reproduction** | Reproduce old paper result-generation behavior | `202604081400` golden values match old repository |
| **M3 Corrected Baseline** | Corrected raw prefix comparison | src OR dst, all eligible non-overlapping prefixes, native + `/24` membership pass |
| **M4 Scan Exploration** | Threshold-free scan window statistics | Threshold notebook can inspect real distributions; no cutoff auto-selected |
| **M5 Scan Removal** | Strict and broad flow-removal labels | Normal traffic retained; strict removal is subset of broad |
| **M6 Analysis Notebooks** | Main plots and scan sensitivity | Core notebooks Run All successfully |
| **M7 Multi-dataset** | Dataset × config validation | Batch matrix runs and records successes/failures |
| **M8 Hardening** | Reproducibility/documentation verification | Tests, legacy validation, baseline run, notebooks, batch smoke test pass |

### 18.1 M0 — Foundation

Create only the infrastructure needed to support subsequent milestones: `pyproject.toml`, locked environment, config schema, logging, manifest/fingerprint foundation, tests, thin CLI entry point, and pinned Aguri dependency. Do not scaffold the entire final tree with empty files.

### 18.2 M1 — Flow correctness

Complete canonical TCP/UDP bidirectional flow generation and new byte/TCP-control facts before implementing scan logic.

### 18.3 M2 — Legacy reproduction gate

Do not proceed to interpreting corrected-baseline differences until legacy reproduction is explained and passing. This gate distinguishes intentional method changes from accidental parser regressions.

### 18.4 M3 — Corrected baseline gate

Implement the corrected candidate union, containment rule, no-top-k selection, `src OR dst` membership, and native/normalized scopes. Scan removal remains disabled.

### 18.5 M4 — Human threshold gate

Generate real `source_scan_windows.csv` distributions and stop. A researcher reviews upper tails and nearby flows before numeric scan thresholds are authorized.

Codex must not invent thresholds to move forward automatically.

### 18.6 M5 — Scan removal

After threshold approval, implement strict and broad classifications exactly as defined in this spec and verify the subset/retention invariants.

### 18.7 M6–M8

Only after the pipeline semantics are stable should the final analysis notebooks, multi-dataset runs, and repository hardening become the focus.

## 19. Definition of Done

`mawi-global-analysis` is complete for the initial research scope when all of the following are true:

1. A new environment can reproduce the pipeline from dataset ID or local PCAP plus one self-contained YAML.
2. Input checksum, flow fingerprint, Aguri fingerprint, config hash, and git/code identity are traceable from manifests.
3. `paper_legacy.yaml` reproduces verified golden outputs from the old repository.
4. `baseline.yaml` follows the corrected methodology: IPv4 main comparison, Aguri src/dst candidate union, `/24` or more-specific eligibility, broader-prefix containment preference, no top-k, and `src OR dst` membership.
5. Native and true normalized `/24` analyses are both available.
6. Threshold exploration occurs before thresholded scan removal.
7. Strict and broad scan-like removal act on relevant probe-like flows rather than deleting every flow from a source.
8. The same raw-derived selected prefix set is used across Raw/Strict/Broad main comparisons.
9. Core fixture/unit/integration tests pass.
10. Core notebooks execute from a clean kernel and regenerate the intended analysis views.
11. `run_batch.py` can execute multiple datasets and multiple configs as a matrix with complete batch/run provenance.
12. README and AGENTS.md document reproduction steps and the scientific/implementation guardrails.

## 20. Explicit Non-Goals for the Initial Implementation

The initial plan deliberately does not require:

- Docker/devcontainer support.
- A workflow engine such as Snakemake/Airflow.
- Automatic scan-threshold selection.
- General machine-learning scan classification.
- Automatic attribution of prefixes to specific end hosts/applications.
- Re-running Aguri on scan-filtered PCAP as part of the main experiment.
- Arbitrary TCP packet-sequence reconstruction from the canonical flow summary.
- A pipeline stage dedicated to each final paper figure.

These may be added later only as separately designed extensions.

## 21. Key Design Rationale

The design intentionally moves away from selecting only prefixes that already have fewer short/tiny flows. The old approach was useful for producing a manageable set, but it risks making the reported difference partly a consequence of the selection rule itself. The corrected baseline therefore lets Aguri define the candidate population, resolves only address-scope constraints/overlap, and uses flow characteristics as outcomes to describe rather than filters to preselect the population.

Similarly, scan-like filtering is treated as a sensitivity analysis rather than as a claim to perfectly identify attacks. Positive TCP evidence and source behavior are stored separately so the study can ask whether the global-vs-prefix difference survives conservative and broader removals. This makes the result interpretable whether the difference persists or shrinks.

Finally, the repository treats reproducibility as a first-class research requirement: expensive facts are cached by semantic fingerprints, experiment interpretation is isolated in run outputs, the legacy result remains reproducible, and notebooks remain free to evolve without forcing PCAP reprocessing.
