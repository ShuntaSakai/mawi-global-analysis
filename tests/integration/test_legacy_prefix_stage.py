from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd

from mawi_global_analysis.pipeline import run_legacy_prefixes
ROOT = Path(__file__).parents[2]


def test_legacy_prefix_stage_writes_output_that_validator_can_consume(tmp_path: Path) -> None:
    flows_path = tmp_path / "flows.csv"
    aguri_path = tmp_path / "aguri.csv"
    output_path = tmp_path / "prefixes.csv"
    pd.DataFrame(
        [
            {
                "flow_id": flow_id,
                "dst_ip": "192.0.2.10",
                "protocol": 6,
                "duration": 2.0,
                "packet_count": 10,
                "byte_count": 1000,
                "syn_count": 0,
                "ack_count": 0,
                "rst_count": 0,
            }
            for flow_id in range(100)
        ]
    ).to_csv(flows_path, index=False)
    pd.DataFrame(
        [{"aggregate_id": "7", "src_prefix": "*", "dst_prefix": "192.0.2.0/24"}]
    ).to_csv(aguri_path, index=False)
    golden_path = tmp_path / "golden.json"
    golden_path.write_text(
        json.dumps(
            {
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
                        "score": 1.0,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    run_legacy_prefixes(flows_path, aguri_path, ROOT / "configs" / "paper_legacy.yaml", output_path)

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_legacy.py"),
            "--actual",
            str(output_path),
            "--golden",
            str(golden_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
