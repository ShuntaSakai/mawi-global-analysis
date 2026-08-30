from __future__ import annotations

from pathlib import Path

import pandas as pd

from mawi_global_analysis.config import load_config
from mawi_global_analysis import prefix


ROOT = Path(__file__).parents[2]


def test_corrected_prefix_stage_writes_the_full_candidate_ledger(tmp_path: Path) -> None:
    """A stage must persist exclusions as well as selected corrected candidates."""
    aguri_path = tmp_path / "aguri_candidates.csv"
    output_path = tmp_path / "prefixes.csv"
    pd.DataFrame(
        [
            {"src_prefix": "192.0.2.0/24", "dst_prefix": "192.0.2.128/25"},
            {"src_prefix": "198.51.100.0/23", "dst_prefix": "198.51.101.0/25"},
        ]
    ).to_csv(aguri_path, index=False)

    returned_path = prefix.run_corrected_prefix_stage(
        aguri_path, load_config(ROOT / "configs" / "baseline.yaml"), output_path
    )

    assert returned_path == output_path
    ledger = pd.read_csv(output_path).set_index("prefix")
    assert bool(ledger.loc["192.0.2.0/24", "selected_for_analysis"])
    assert ledger.loc["192.0.2.128/25", "exclusion_reason"] == "covered_by_parent"
    assert ledger.loc["198.51.100.0/23", "exclusion_reason"] == "broader_than_24"
    assert bool(ledger.loc["198.51.101.0/25", "selected_for_analysis"])
