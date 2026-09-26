# Research Contract

This document records research semantics that are implemented and tested in the
current repository. Change them only through an explicit research/design
decision, with corresponding configuration, implementation, test, cache, and
provenance updates where applicable.

## Flow observations

- TCP and UDP flows use a bidirectional, direction-independent 5-tuple key.
- Canonical `src_*` and `dst_*` fields retain the direction of the first
  observed packet. They do not establish initiator/responder, client/server,
  traffic direction, or intent.
- TCP initiation facts use `initial_syn_sender_*` and
  `initial_syn_receiver_*`. They are populated only after an observed plain
  SYN (`SYN=1`, `ACK=0`).
- `byte_count` is the Ethernet-frame total and equals `frame_byte_count`.
  IP bytes and transport-payload bytes remain separately recorded.

## Prefix analysis

- The corrected IPv4 experiment builds candidates from both Aguri
  `src_prefix` and `dst_prefix` fields, selects eligible prefixes of length
  `/24` or longer, and uses `src_ip in prefix OR dst_ip in prefix` membership.
- `src_match` and `dst_match` are retained as first-observed-direction facts;
  they must not be converted into endpoint roles.
- Native selected-prefix analysis and normalized `/24` analysis are distinct.
  A normalized `/24` recomputes membership over the full containing `/24`; it
  is not a relabelled narrower subnet.
- `paper_legacy` is a separate reproduction mode with its own configured
  candidate and membership behavior. Do not alter corrected behavior merely to
  reproduce legacy output, or alter legacy behavior merely to make it
  corrected.

## Scan-like classification and removal

- Use cautious terms such as *scan-like*, *probe-like*, and *observed
  pattern*. An observed TCP pattern alone is not proof of malicious intent.
- MAWI observation can be asymmetric. Missing responses are therefore weak
  negative evidence.
- Threshold-free scan-window observations are separate from thresholded
  labels. Source identity for SYN-initiated patterns is
  `initial_syn_sender_ip`, not canonical `src_ip`.
- Strict window classification uses pattern-specific positive evidence:
  repeated `syn_to_rst` with configured target diversity, or an observed
  `syn_synack_rst`. `syn_only_observed` is broad expansion evidence, not an
  independent source detector.
- Removal applies only to permitted observed patterns from sources identified
  in strict windows. It does not remove all traffic from an identified source.
  The implemented invariant is `strict_removed_flow_ids` a subset of
  `broad_removed_flow_ids`.

## Artifact boundaries and reproducibility

- Raw-PCAP-derived canonical observations are reusable dataset artifacts under
  `data/<dataset>/processed/`. Run-specific interpretation belongs under
  `results/<dataset>/<run-name>/`.
- `flows.csv` stores canonical observations and stable derived facts.
  Run-specific scan labels belong in `flow_labels.csv`, not in `flows.csv`.
  Prefix selection and membership are recorded separately.
- Cache identity must include every setting that changes the cached data. Flow
  generation changes, including the inactive timeout, change the flow cache;
  scan thresholds do not.
- Run and cache provenance record input checksums, relevant fingerprints,
  configuration content and hash, code identity, executed/reused stages, and
  generated artifacts. Do not bypass identity checks or silently overwrite a
  run whose identity differs.
- Aguri execution is provenance-bearing: the repository pins an Agurim
  lineage, and executable path, version, checksum, input, and options are
  recorded for cache identity.

## Evidence boundary

Passing fixtures, tests, or verified golden artifacts establishes
implementation verification only. It does not establish real-data validation
or a scientific conclusion. State those evidence levels separately in reports
and documentation.
