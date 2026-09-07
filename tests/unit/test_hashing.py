from pathlib import Path

from mawi_global_analysis.config import load_config
from mawi_global_analysis.flow_stage import FLOW_SCHEMA_VERSION
from mawi_global_analysis.hashing import flow_fingerprint, stable_json_hash


ROOT = Path(__file__).parents[2]


def test_stable_json_hash_ignores_mapping_order() -> None:
    """Changing insertion order must not change a provenance fingerprint."""
    first = {"input": {"path": "trace.pcap", "size": 12}, "version": 1}
    second = {"version": 1, "input": {"size": 12, "path": "trace.pcap"}}

    assert stable_json_hash(first) == stable_json_hash(second)


def test_flow_fingerprint_tracks_flow_generation_but_not_scan_settings() -> None:
    """Scan-window interpretation must reuse the same canonical flow cache."""
    baseline = load_config(ROOT / "configs" / "baseline.yaml")
    changed_scan = baseline.model_copy(
        update={
            "scan": baseline.scan.model_copy(
                update={
                    "window_size_seconds": 120,
                    "window_step_seconds": 30,
                }
            )
        }
    )
    changed_timeout = baseline.model_copy(
        update={
            "flow": baseline.flow.model_copy(update={"inactive_timeout_seconds": 60.0})
        }
    )
    tcp_only = baseline.model_copy(
        update={"flow": baseline.flow.model_copy(update={"protocols": ["tcp"]})}
    )

    baseline_fingerprint = flow_fingerprint("a" * 64, baseline)

    assert flow_fingerprint("a" * 64, changed_scan) == baseline_fingerprint
    assert flow_fingerprint("a" * 64, changed_timeout) != baseline_fingerprint
    assert flow_fingerprint("a" * 64, tcp_only) != baseline_fingerprint


def test_flow_fingerprint_ignores_m5_strict_thresholds_and_broad_toggle() -> None:
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

    fingerprint = flow_fingerprint("a" * 64, m5)

    assert flow_fingerprint("a" * 64, stricter) == fingerprint
    assert flow_fingerprint("a" * 64, broad_disabled) == fingerprint


def test_flow_schema_version_bumps_when_canonical_columns_change() -> None:
    """Legacy TCP flag totals are canonical facts and must invalidate old caches."""
    baseline = load_config(ROOT / "configs" / "baseline.yaml")

    assert FLOW_SCHEMA_VERSION == "flows-v3"
    assert flow_fingerprint("a" * 64, baseline, "flows-v1") != flow_fingerprint(
        "a" * 64, baseline, "flows-v3"
    )
