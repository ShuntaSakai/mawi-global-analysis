from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.config import load_config


ROOT = Path(__file__).parents[2]


def test_pre_m5_labels_are_neutral_when_both_modes_are_disabled() -> None:
    from mawi_global_analysis.scan_labels import (
        FLOW_LABEL_COLUMNS,
        build_pre_m5_flow_labels,
    )

    config = load_config(ROOT / "configs" / "baseline.yaml")
    labels = build_pre_m5_flow_labels(pd.DataFrame({"flow_id": [11, 12]}), config)

    assert tuple(labels.columns) == FLOW_LABEL_COLUMNS
    assert labels["flow_id"].tolist() == [11, 12]
    assert labels.drop(columns="flow_id").eq(False).all().all()


def test_enabled_scan_modes_stop_at_the_m5_threshold_approval_gate() -> None:
    from mawi_global_analysis.scan_labels import (
        ScanThresholdApprovalRequiredError,
        build_pre_m5_flow_labels,
    )

    baseline = load_config(ROOT / "configs" / "baseline.yaml")
    config = baseline.model_copy(
        update={
            "scan": baseline.scan.model_copy(
                update={
                    "strict": baseline.scan.strict.model_copy(
                        update={"enabled": True, "min_pattern_count": 2, "min_unique_targets": 2}
                    )
                }
            )
        }
    )

    with pytest.raises(ScanThresholdApprovalRequiredError, match="M5 threshold approval"):
        build_pre_m5_flow_labels(pd.DataFrame({"flow_id": [11]}), config)
