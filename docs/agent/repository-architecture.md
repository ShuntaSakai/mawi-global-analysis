# Repository Architecture

The repository separates reusable packet-derived observations from
experiment-specific interpretation and notebook analysis.

| Directory | Responsibility |
| --- | --- |
| `configs/` | Self-contained YAML definitions for named experiments. |
| `data/` | Local raw captures and reusable processed/cache artifacts by dataset. |
| `datasets/` | Dataset-selection inputs used by batch workflows. |
| `docs/` | Maintained documentation, including this AI documentation and historical material. |
| `notebooks/` | Visible research aggregation, inspection, and visualization. |
| `results/` | Run-specific artifacts, manifests, and batch outputs. |
| `scripts/` | Focused operational and validation utilities. |
| `src/` | Python package implementing pipeline stages and artifact contracts. |
| `tests/` | Unit, integration, fixture, and golden-validation coverage. |
| `vendor/` | Repository-vendored external source, including Agurim. |

## Data flow

```text
raw data
  -> reusable processed/cache artifacts
  -> run-specific results
  -> notebook analysis and visualization
```

Raw captures are resolved into dataset inputs. The pipeline derives canonical
flows and Aguri artifacts that can be reused when their semantic identities
match. A named run then writes interpretation artifacts such as scan labels,
prefix ledgers, membership mappings, and a run manifest under `results/`.
Notebooks load those artifacts to make aggregations and visualizations explicit
rather than embedding figure-specific aggregation in the pipeline.
