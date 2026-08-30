from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]
VALIDATOR = ROOT / "scripts" / "validate_legacy.py"


def _write_actual(path: Path, *, score: str = "0.5000000001") -> None:
    path.write_text(
        "aggregate_id,src_prefix,dst_prefix,normalized_dst_prefix,match_status,ip_version,prefix_length,prefix_is_broader_than_target,flow_count,packet_count,byte_count,passes_filters,selected,score\n"
        f"7,*,192.0.2.0/24,192.0.2.0/24,matched,4,24,False,100,1000,100000,True,True,{score}\n",
        encoding="utf-8",
    )


def _write_golden(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "dataset_id": "fixture",
                "selected_prefixes": [
                    {
                        "aggregate_id": "7",
                        "src_prefix": "*",
                        "dst_prefix": "192.0.2.0/24",
                        "normalized_dst_prefix": "192.0.2.0/24",
                        "match_status": "matched",
                        "ip_version": 4,
                        "prefix_length": 24,
                        "prefix_is_broader_than_target": False,
                        "flow_count": 100,
                        "packet_count": 1000,
                        "byte_count": 100000,
                        "passes_filters": True,
                        "selected": True,
                        "score": 0.5,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_legacy_validator_allows_only_explicit_tight_float_tolerance(tmp_path: Path) -> None:
    actual = tmp_path / "prefixes.csv"
    golden = tmp_path / "golden.json"
    _write_actual(actual)
    _write_golden(golden)

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--actual", str(actual), "--golden", str(golden)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "legacy validation passed" in result.stdout


def test_legacy_validator_rejects_integer_mismatch(tmp_path: Path) -> None:
    actual = tmp_path / "prefixes.csv"
    golden = tmp_path / "golden.json"
    _write_actual(actual)
    _write_golden(golden)
    actual.write_text(
        actual.read_text(encoding="utf-8").replace(",1000,", ",1001,"),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--actual", str(actual), "--golden", str(golden)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "packet_count" in result.stderr
