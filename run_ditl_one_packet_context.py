"""Thin CLI for safe sequential DITL one-packet-context orchestration."""
from __future__ import annotations
import argparse
from collections.abc import Sequence
from pathlib import Path
from mawi_global_analysis.ditl_context import run_ditl_one_packet_context

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build one-packet context from one DITL day sequentially.")
    for name in ("dataset", "source-run", "date", "target-chunk", "url-template", "context-run-name"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--target-chunk-path", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--backoff-seconds", type=float, default=1.0)
    parser.add_argument("--delay-seconds", type=float, default=0.0)
    return parser

def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    run_ditl_one_packet_context(a.dataset, a.source_run, a.date, a.target_chunk, a.target_chunk_path,
        a.url_template, a.context_run_name, root=a.root, timeout=a.timeout, retries=a.retries,
        backoff_seconds=a.backoff_seconds, delay_seconds=a.delay_seconds)
    return 0
if __name__ == "__main__": raise SystemExit(main())
