"""Thin command-line entry point for the MAWI analysis pipeline."""

from collections.abc import Sequence

from mawi_global_analysis.pipeline import build_parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate the shared CLI contract; stage execution is added incrementally."""
    build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
