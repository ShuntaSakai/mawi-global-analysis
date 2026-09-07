from pathlib import Path

import pandas as pd

from mawi_global_analysis import pipeline
from mawi_global_analysis.config import load_config
from mawi_global_analysis.models import InputContext


ROOT = Path(__file__).parents[2]
CONTEXT = InputContext("fixture", Path("fixture.pcap"), "a" * 64, 1)


def test_scan_label_identity_separates_thresholds_and_broad_toggle() -> None:
    m5 = load_config(ROOT / "configs" / "scan_source_driven_removal.yaml")
    stricter = m5.model_copy(
        update={
            "scan": m5.scan.model_copy(
                update={
                    "strict": m5.scan.strict.model_copy(
                        update={"min_pattern_count": 30, "min_unique_targets": 15}
                    )
                }
            )
        }
    )
    broad_disabled = m5.model_copy(
        update={
            "scan": m5.scan.model_copy(
                update={"broad": m5.scan.broad.model_copy(update={"enabled": False})}
            )
        }
    )

    assert pipeline._scan_stats_cache_metadata(CONTEXT, m5) == pipeline._scan_stats_cache_metadata(
        CONTEXT, stricter
    )
    assert pipeline._scan_label_cache_metadata(
        CONTEXT, m5
    ) != pipeline._scan_label_cache_metadata(CONTEXT, stricter)
    assert pipeline._scan_label_cache_metadata(
        CONTEXT, m5
    ) != pipeline._scan_label_cache_metadata(CONTEXT, broad_disabled)


def test_m5_label_artifact_is_not_reused_for_different_classification_config(
    tmp_path: Path,
) -> None:
    m5 = load_config(ROOT / "configs" / "scan_source_driven_removal.yaml")
    stricter = m5.model_copy(
        update={
            "scan": m5.scan.model_copy(
                update={
                    "strict": m5.scan.strict.model_copy(
                        update={"min_pattern_count": 30, "min_unique_targets": 15}
                    )
                }
            )
        }
    )
    broad_disabled = m5.model_copy(
        update={
            "scan": m5.scan.model_copy(
                update={"broad": m5.scan.broad.model_copy(update={"enabled": False})}
            )
        }
    )
    flows_path = tmp_path / "flows.csv"
    labels_path = tmp_path / "flow_labels.csv"
    pd.DataFrame({"flow_id": [1]}).to_csv(flows_path, index=False)
    pd.DataFrame(
        {
            "flow_id": [1],
            "strict_scan_like": [True],
            "broad_scan_like": [True],
            "strict_removed": [True],
            "broad_removed": [True],
        }
    ).to_csv(labels_path, index=False)
    existing = {
        "artifacts": {"flow_labels": {"row_count": 1}},
        "cache": {"scan-labels": pipeline._scan_label_cache_metadata(CONTEXT, m5)},
    }

    assert pipeline._valid_scan_label_artifact(
        labels_path, existing, flows_path, CONTEXT, m5
    )
    assert not pipeline._valid_scan_label_artifact(
        labels_path, existing, flows_path, CONTEXT, stricter
    )
    assert not pipeline._valid_scan_label_artifact(
        labels_path, existing, flows_path, CONTEXT, broad_disabled
    )
