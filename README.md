# MAWI Global Analysis

Reproducible MAWI flow and prefix analysis through M4. The repository keeps
the legacy paper-reproduction path separate from the corrected IPv4 baseline
and threshold-free scan exploration.

## Quick path

Clone the pinned Aguri submodule, build the Python environment, and run the
fixture-backed verification suite:

```bash
git clone --recurse-submodules <repository-url> mawi-global-analysis
cd mawi-global-analysis
uv sync
uv run pytest
```

If the pinned Aguri executables have not already been built, build them before
an execution that reaches the Aguri stage:

```bash
make -C vendor/agurim/src
```

The dataset commands below request the MAWI trace only when it is not already
available in `data/`. They all use dataset `202604081400`, but represent
different research conditions:

```bash
# Reproduce the old result-generation behavior.
uv run python run_pipeline.py --dataset 202604081400 --config configs/paper_legacy.yaml

# Run the corrected IPv4 raw baseline.
uv run python run_pipeline.py --dataset 202604081400 --config configs/baseline.yaml

# Produce threshold-free source-window observations for manual M4 review.
uv run python run_pipeline.py --dataset 202604081400 --config configs/threshold_exploration.yaml
```

### Validate an actual legacy pipeline output

After a completed raw-PCAP legacy run has written its run-local
`prefixes.csv`, compare that generated output with the verified golden JSON:

```bash
uv run python scripts/validate_legacy.py \
  --actual results/202604081400/paper_legacy/prefixes.csv \
  --golden tests/fixtures/legacy/202604081400/legacy_golden.json
```

Do not describe this comparison as complete until `--actual` is a generated
raw-PCAP pipeline output. Without one, only fixture and golden-derived
validator smoke coverage has run; a true pipeline-output-to-golden comparison
remains deferred.

Use `--dry-run` with either corrected configuration to inspect planned cache
reuse/execution without downloading a trace or writing run artifacts:

```bash
uv run python run_pipeline.py --dataset 202604081400 --config configs/baseline.yaml --dry-run
uv run python run_pipeline.py --dataset 202604081400 --config configs/threshold_exploration.yaml --dry-run
```

## Experiment modes

`paper_legacy.yaml` is a regression mode: it preserves the old repository's
destination-side membership and legacy ranking/plot behavior. It is not the
corrected scientific baseline.

`baseline.yaml` is the corrected raw comparison: its candidate pool is the
union of Aguri `src_prefix` and `dst_prefix`, it analyzes IPv4 overall traffic,
selects every eligible non-overlapping `/24`-or-more-specific prefix without a
top-k limit, and uses `src_ip ∈ prefix OR dst_ip ∈ prefix` membership. Native
prefix scopes and true recomputed normalized `/24` scopes are both retained.

`threshold_exploration.yaml` uses the same corrected prefix semantics while
writing threshold-free 60-second, 10-second-step source-window facts. It is an
inspection aid, not a scan classifier.

## Outputs and provenance

PCAP-derived facts are cached under `data/<dataset>/processed/`: canonical
flows and their flow manifest, plus Aguri candidates and their Aguri manifest.
These caches are reusable only when their semantic fingerprints match.

Run-specific outputs live under `results/<dataset>/<run-name>/`, including
`flow_labels.csv`, `prefixes.csv`, `flow_prefix_membership.csv`,
`source_scan_windows.csv`, `source_scan_summary.csv`, and `run_manifest.json`.
The run manifest records saved configuration text/hash, input checksum, cache
fingerprints, code identity, stage decisions, and artifact row counts. A run
name cannot silently overwrite a different input/config identity.

## M4 stop gate

At M4, inspect `source_scan_windows.csv` and nearby raw/flow evidence before
choosing any numeric scan thresholds. Q99/Q99.5/Q99.9 are candidate guides only;
they are never automatic thresholds. Do not invent `N_strict`, `M_strict`,
`N_broad`, or `M_broad`, and do not enable M5 strict/broad classification or
removal until a researcher has approved explicit values.

Fixture tests and golden-derived validator smoke coverage validate M0–M4
contracts. They are distinct from a generated pipeline-output-to-golden
comparison and full raw-PCAP `202604081400` E2E validation. If that trace is
not already available locally, leave both deferred rather than downloading it
solely for verification; this is not a Task 14 blocker.
