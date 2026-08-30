"""Thin command-line entry point for the MAWI analysis pipeline."""

from collections.abc import Sequence

from mawi_global_analysis.pipeline import build_parser, run_pipeline


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and delegate to the package orchestrator."""
    return run_pipeline(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
