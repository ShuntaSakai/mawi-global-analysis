"""Thin command-line entry point for one-packet context analysis."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from mawi_global_analysis.one_packet_context_run import run_one_packet_context_analysis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one-packet context analysis.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--source-run", required=True)
    parser.add_argument("--full-capture", required=True, type=Path)
    parser.add_argument("--context-run-name", required=True)
    parser.add_argument("--root", default=Path("."), type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_one_packet_context_analysis(
        args.dataset, args.source_run, args.full_capture, args.context_run_name,
        root=args.root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
