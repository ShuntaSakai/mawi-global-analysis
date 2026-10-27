"""Export an offline prefix dashboard from an existing matching cache only."""
from __future__ import annotations

import argparse
from pathlib import Path

from mawi_global_analysis.prefix_dashboard import export_dashboard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='Saved analysis root')
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--cache-dir', type=Path, required=True, help='Exact-cache base directory used by 06 Notebook')
    parser.add_argument('--output', type=Path, required=True, help='New .html file outside the cache')
    parser.add_argument('--notes', type=Path, help='Optional experiment-scoped notes JSON')
    parser.add_argument('--host-summary', type=Path, help='Optional run-matched prefix host summary CSV')
    parser.add_argument('--ip-behavior-bundle', type=Path, help='Validated IP behavior bundle directory')
    args = parser.parse_args(argv)
    try:
        output = export_dashboard(args.root, args.dataset, args.run, args.cache_dir,
                                  args.output, notes=args.notes, host_summary=args.host_summary,
                                  ip_behavior_bundle=args.ip_behavior_bundle)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'HTMLを生成できません: {exc}\n再集計・cache上書きは行っていません。\n')
    print(f'HTML: {output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
