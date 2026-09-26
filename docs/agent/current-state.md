# Current State

This is an intentionally maintained factual snapshot of the repository. It
does not infer scientific conclusions from code, fixtures, generated files, or
notebooks.

## Evidence labels

- **Implemented** means code and repository artifacts for a capability exist.
- **Implementation verified** means tests, fixtures, or verified golden
  artifacts cover stated behavior; it is not real-data validation.
- **Real-data validated** means a documented raw-capture end-to-end execution
  has been completed and reviewed.
- **Scientific conclusion** requires research interpretation beyond software
  implementation or execution. None is asserted here.

## Implemented

The current experiment configs are:

- `baseline`: corrected IPv4 raw analysis with both Aguri prefix sides,
  `src_or_dst` membership, normalized `/24` output, and no scan removal.
- `paper_legacy`: separate legacy reproduction configuration with
  destination-only prefix membership and configured legacy filtering/ranking.
- `threshold_exploration`: corrected IPv4 configuration that emits
  threshold-free scan-window observations without removal.
- `scan_source_driven_removal`: corrected IPv4 configuration with strict and
  broad source-driven removal enabled; its current configured `syn_to_rst`
  thresholds are pattern count 3 and unique targets 2.

The pipeline implements input resolution, canonical TCP/UDP flow extraction,
flow and Aguri cache validation, corrected and legacy prefix stages,
source-window and source-summary statistics, run-specific flow labels,
membership mappings, manifests, and batch planning/execution. It records
Raw/Strict/Broad inclusion decisions for comparison.

The primary notebooks currently present are legacy reproduction, scan-threshold
exploration, several main prefix-comparison variants, prefix deep-dive,
multi-dataset validation, and society-presentation figures.

## Implementation verified

Unit and integration tests cover flow construction, byte accounting, config
validation, cache and manifest identity, prefix and membership semantics,
scan-window facts and labels, pipeline stages, batch behavior, legacy
validation, and notebook structure/provenance expectations. Fixture captures
and legacy golden artifacts are present for selected validation paths.

This document does not claim a fresh full-suite run; consult current CI or run
the relevant verification command before reporting test status for a change.

## Real-data validated

No completed raw-PCAP end-to-end validation is recorded here. The existing
real-data execution runbook states that the `202604081400` workflow was
deferred on the current machine because local storage was insufficient during
canonical-flow generation. A full raw-data run remains separate work and must
be reported with its actual environment, inputs, manifest, and review result.

## Provisional decisions and attention points

- The strict and broad removal configuration exists and is executable. Its
  current provisional thresholds are pattern count 3 and unique targets 2.
  They are experiment settings, not scientific conclusions.
- Historical plans and milestone documents remain in the repository for
  context but are not current specification authority.
- Existing result artifacts and executed notebooks are evidence to inspect,
  not by themselves proof of real-data validation or scientific findings.
