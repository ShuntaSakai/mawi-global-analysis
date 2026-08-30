"""Shared command-line contract for the staged analysis pipeline."""

import argparse
from pathlib import Path

from mawi_global_analysis.flow_stage import run_flow_stage
from mawi_global_analysis.config import load_config
from mawi_global_analysis.prefix import run_legacy_prefix_stage


STAGE_NAMES = (
    "input",
    "flows",
    "aguri",
    "scan-stats",
    "scan-labels",
    "prefixes",
    "membership",
    "manifest",
)


def run_legacy_prefixes(
    flows_path: Path, aguri_path: Path, config_path: Path, output_path: Path
) -> Path:
    """Execute the paper-legacy prefixes stage from its upstream CSV artifacts."""
    return run_legacy_prefix_stage(
        flows_path, aguri_path, load_config(config_path), output_path
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the pipeline parser without starting a run."""
    parser = argparse.ArgumentParser(description="Run the MAWI global analysis pipeline.")
    input_mode = parser.add_mutually_exclusive_group(required=True)
    input_mode.add_argument("--dataset", help="MAWI dataset identifier to resolve")
    input_mode.add_argument("--input", type=Path, help="Local PCAP or PCAP.gz input path")
    parser.add_argument("--dataset-id", help="Dataset identifier for a local input")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/baseline.yaml"),
        help="Experiment configuration YAML (default: configs/baseline.yaml)",
    )
    parser.add_argument("--run-name", help="Override the configured experiment name")
    parser.add_argument("--from", dest="from_stage", choices=STAGE_NAMES)
    parser.add_argument("--to", dest="to_stage", choices=STAGE_NAMES)
    parser.add_argument(
        "--force",
        nargs="+",
        choices=(*STAGE_NAMES, "all"),
        metavar="STAGE",
        help="Invalidate one or more stages, or all stages",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--redownload", action="store_true")
    return parser
