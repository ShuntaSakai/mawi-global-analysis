"""Acquire one DITL chunk through the shared safe streaming downloader."""

from __future__ import annotations
import argparse
from collections.abc import Sequence
from pathlib import Path

from mawi_global_analysis.ditl_chunks import render_chunk_url, validate_chunk_id
from mawi_global_analysis.ditl_downloader import download_chunk

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Download one DITL capture chunk.")
    parser.add_argument("--chunk-id", required=True)
    parser.add_argument("--url-template", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--backoff-seconds", type=float, default=1.0)
    return parser

def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    chunk_id = validate_chunk_id(args.chunk_id)
    download_chunk(chunk_id, render_chunk_url(args.url_template, chunk_id), args.output_directory,
                   timeout=args.timeout, retries=args.retries, backoff_seconds=args.backoff_seconds)
    return 0

if __name__ == "__main__": raise SystemExit(main())
