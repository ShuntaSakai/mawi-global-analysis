"""Extract one timezone-explicit interval from a PCAP, PCAP.gz, or PCAPNG."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from mawi_global_analysis.capture_window import CaptureWindowError, extract_capture_window


def _parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {value}") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise argparse.ArgumentTypeError(
            f"timestamp must include a timezone offset: {value}"
        )
    return timestamp


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, dest="source")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--start", required=True, type=_parse_timestamp)
    parser.add_argument("--end", required=True, type=_parse_timestamp)
    arguments = parser.parse_args()

    try:
        manifest = extract_capture_window(
            arguments.source, arguments.output, arguments.start, arguments.end
        )
    except CaptureWindowError as exc:
        parser.error(str(exc))
    print(
        f"extracted {manifest.packet_count} packets to {manifest.output_path}; "
        f"manifest: {arguments.output.parent / 'window_manifest.json'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
