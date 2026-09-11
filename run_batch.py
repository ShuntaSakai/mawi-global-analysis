"""Thin command-line entry point for MAWI analysis batches."""

from collections.abc import Sequence

from mawi_global_analysis.batch import build_batch_parser, run_batch


def main(argv: Sequence[str] | None = None) -> int:
    """Parse batch CLI arguments and delegate to the package controller."""
    return run_batch(build_batch_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
