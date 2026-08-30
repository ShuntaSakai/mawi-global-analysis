# Verified legacy golden

`legacy_golden.json` was exported from the unrounded result artifacts in the
local `mawi-dpkt-analysis` checkout for dataset `202604081400` using
`scripts/export_legacy_goldens.py` on 2026-08-30.

It records the old `selected_prefixes.csv` rows and the old comparison
summary's overall medians. It is a regression target, not a corrected-method
baseline. The provenance paths and source dataset identifier are embedded in
the JSON so a regeneration can be audited.
