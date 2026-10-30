# Experiment 1: Raw agurim normalized-/24 dashboard

This command implements only the existing agurim selection method. It reads a
successful corrected IPv4 run's canonical `flows.csv`, `prefixes.csv` and
`flow_prefix_membership.csv` through the saved manifest. It does not parse
PCAPs, invoke agurim, read flow labels, remove scan-like traffic, or reuse the
native-prefix distribution cache.

From the repository root:

```sh
uv run python scripts/export_normalized24_dashboard.py \
  --root /path/to/analysis-root \
  --dataset 202604081400 \
  --run baseline \
  --output /path/to/new-exports/agurim-24-raw.html \
  --scratch-dir /path/to/existing-large-local-disk \
  --chunksize 100000
```

`--root` contains `results/<dataset>/<run>/run_manifest.json`. The run's
manifest, config hash, canonical flow schema/fingerprint, recorded producer
bindings, optional artifact checksums, and streamed row counts are validated.
Corrected runs with scan settings are also accepted, but only their original
Raw flows are analyzed. `flow_labels.csv` is neither required nor consulted.
Legacy selection settings are rejected. Manifest paths are used as recorded;
absolute paths are never silently redirected.

Available prefix/Aguri candidate/cache producer fingerprints and candidate
checksums must agree. Contradictory records stop the export. Older runs may
genuinely omit Aguri bindings; that absence is recorded explicitly in
`provenance.aguri_lineage`. This check establishes consistency of saved
records, without rerunning or claiming independent verification of the Aguri
executables or historical upstream files. Ancestor directories containing a
`*manifest.json` or `exact_counts.sqlite` are protected output locations,
including external Aguri/context/behavior caches.

The output must be a new `.html` file outside source data, run directories,
notebooks and existing caches. Existing files, caches and notebooks are never
overwritten. The complete HTML is published atomically only after validation
succeeds. It can be copied to another computer and opened directly, offline,
with JavaScript enabled. No Python server, CDN, external font or network
connection is required.

## Selection and exact aggregation

- Select native rows where `selected_for_analysis=True`.
- Validate each selected row's `normalized_prefix_24` against its containing
  IPv4 /24; deduplicate the normalized /24 set. Keep all /24s, including ones
  with zero flows. No flow-count, median, byte-count, top-k or display cutoff.
- Read the `normalized_24` membership edges, checking unique `(prefix,flow_id)`,
  existing canonical IDs and exact source/destination endpoint flags.
- Independently count expected edges from canonical endpoint /24s during the
  flow stream. Correct edges, unique keys and equal per-/24 counts establish
  completeness. Missing, duplicate, incorrect or unknown edges stop the export.
  Native membership rows are not used or validated as a cohort in this command.
- Aggregate each full /24 from its validated membership and canonical flows;
  never sum native subnet summaries. A flow crossing selected /24s appears in
  each individual distribution. In `selected_union` it appears once, by
  canonical `flow_id`. Both endpoints in the same /24 also count once.
- `overall_ipv4` includes all canonical IPv4 flows, including flows outside the
  selected set. IPv6 does not enter either reference or the /24 distributions.

Flow size is `packet_count` (packets per bidirectional flow), as in the
existing Prefix Flow Length Dashboard. Median and p95 use exact integer
frequencies, with linear interpolation at zero-based rank `(n-1)*q` (matching
NumPy's default quantile). One-packet rate is count(packet_count=1) divided by
the target's full Raw flow count. Empty targets have count 0, all-zero bins,
and null/NA median, p95 and one-packet rate.

## Shared comparison specification

`HistogramSpec` in `normalized24.py` defines fixed integer intervals beginning
`[1,2), [2,3), [3,4), [4,8), [8,16), ...`, followed by `[1048576,2**63)`
as the terminal overflow interval. Packet counts must be positive int64
integers. Bins are drawn at equal visual widths, not as a numeric density axis.

All cards and details use the same count axis, `log(1+n)`, and the same percent
axis `[0,100]`. The default count upper bound is the next decimal power above
the overall IPv4 population; it depends on the common dataset, not the selected
cohort. Zero counts remain visible on the axis; empty percent statistics are
NA, while empty bars have height zero. The detail table exposes every bin.

To reuse exactly the same specification in a future method, save the embedded
payload's `histogram_spec` object as JSON and pass `--histogram-spec spec.json`.
Supplied axes that would clip data are rejected. `summarize_frequencies` consumes
the method-independent SQLite `dist(target,packets,n)` contract; the renderer
consumes the small summary/count payload. Future agurim-prime and Random
selection adapters can use those interfaces. No such adapters are implemented
by this change.

Search matches /24 and contributing selected native prefixes. Sorting affects
only card order. Selecting a card changes the detail view. Search and sorting
never redefine the selected-set union reference.

## Memory, scratch and provenance

Flows and membership are read in bounded chunks. Working canonical IDs and
membership live in a temporary SQLite database, with a 32 MiB page cache and
disk-backed sorting. Memory scales with chunk size, selected prefix metadata,
and the small histogram output, not total flows. Expected membership counting
uses endpoint /24 lookups rather than a per-prefix scan of every flow. Disk
space scales with canonical IDs, membership rows, exact frequency tables and
SQLite sorting; supply a sufficiently large local scratch disk. Working files
are removed on both failure and success. Tens of millions of flows have not
been benchmarked or validated by this implementation task.

The HTML embeds SHA-256 hashes of all three CSV inputs, the run manifest and
flow manifest, original capture hash, saved run/config, selected native and
normalized sets, method, exact aggregation specification, histogram/axis
specification, row audit and implementation/template hashes. CSVs are hashed
again after aggregation to detect concurrent changes. For older runs without
recorded CSV checksums, these hashes identify the bytes analyzed now; they do
not establish byte identity with a past historical execution.

## Verification evidence

`tests/test_normalized24.py` uses synthetic artifacts to exercise normalization,
full-/24 membership, exact statistics, union deduplication, empty targets and
selection, no top-k, chunk invariance, malformed inputs, fail-closed membership,
shared histogram settings, provenance consistency, scratch cleanup, safe HTML,
CLI behavior and no overwrites. This is implementation verification only.
No real MAWI data run, real-data validation or research conclusion is claimed.

Verification on 2026-10-30 (Python 3.12 repository environment):

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_normalized24.py
# 34 passed
.venv/bin/python -m pytest -q -p no:cacheprovider
# 636 passed, 3 failed
git diff --check
# passed
```

The three full-suite failures were reproduced before this change (baseline:
602 passed, the same three failed). They concern the existing Notebook 06 and
were left unchanged to preserve the requested Notebook boundary:

- `tests/unit/test_flow_length.py::test_failed_notebook_rerun_cannot_display_or_export_previous_results`
- `tests/unit/test_flow_length_individual.py::test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports`
- `tests/unit/test_flow_length_individual.py::test_eighteen_ledger_prefixes_display_twenty_inline_targets_without_files`

A synthetic HTML was loaded through a temporary localhost preview, then the
browser was put offline. Search by native prefix, sorting, zero-flow details,
the union and IPv4 references, detail collapse/expand and mobile width were
verified; no application errors or additional requests occurred. Direct
`file://` navigation was blocked by the browser automation tool, so this is
offline interaction verification after initial document loading, rather than
an automated direct-file navigation check.

One independent review identified missing contradictory Aguri-producer checks
and external Aguri-cache output protection. Both were reproduced with failing
tests and fixed; the final test counts above include those regressions.

Files added: `src/mawi_global_analysis/normalized24.py`,
`src/mawi_global_analysis/normalized24_dashboard.py`,
`src/mawi_global_analysis/normalized24_dashboard.html`,
`scripts/export_normalized24_dashboard.py`, `tests/test_normalized24.py`,
this guide, and `docs/superpowers/plans/2026-10-30-normalized-24-dashboard.md`.
Modified: `src/mawi_global_analysis/flow_length.py` (additive explicit Raw
inspection mode; existing default preserved). Deleted: none. Existing
dashboards, notebooks and caches were not changed. Changes remain uncommitted
on `main`; no staging, commit, push or PR was performed.
