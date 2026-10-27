"""Add a run-matched host summary to existing dashboard data without reanalysis."""
from __future__ import annotations
import argparse
from pathlib import Path
from mawi_global_analysis.prefix_dashboard import enrich_dashboard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True, help='Existing trusted dashboard HTML')
    parser.add_argument('--host-summary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New HTML path')
    args = parser.parse_args(argv)
    try:
        output = enrich_dashboard(args.input, args.host_summary, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'HTMLを生成できません: {exc}\n')
    print(f'HTML: {output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
