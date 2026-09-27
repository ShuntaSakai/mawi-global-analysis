"""Streaming extraction of timestamp-bounded packet captures."""

from __future__ import annotations

import gzip
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import dpkt

from mawi_global_analysis.flow import (
    PcapParseError,
    _PCAPNG_MAGIC,
    _open_capture,
    _strict_pcap_packets,
    _strict_pcapng_packets,
)
from mawi_global_analysis.hashing import sha256_file


class CaptureWindowError(ValueError):
    """Raised when a requested extraction window or source capture is invalid."""


@dataclass(frozen=True, slots=True)
class CaptureWindowManifest:
    """Provenance recorded for one extracted standard-PCAP subcapture."""

    source_capture_path: str
    source_sha256: str
    output_path: str
    output_sha256: str
    window_start: str
    window_end: str
    packet_count: int


def _validate_window(window_start: datetime, window_end: datetime) -> None:
    if window_start.tzinfo is None or window_start.utcoffset() is None:
        raise CaptureWindowError("window_start must be timezone-aware")
    if window_end.tzinfo is None or window_end.utcoffset() is None:
        raise CaptureWindowError("window_end must be timezone-aware")
    if window_start >= window_end:
        raise CaptureWindowError("window_start must be before window_end")


def _temporary_path(directory: Path, prefix: str) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(dir=directory, prefix=prefix, suffix=".tmp")
    os.close(descriptor)
    return Path(temporary_name)


def extract_capture_window(
    source_capture_path: Path,
    output_path: Path,
    window_start: datetime,
    window_end: datetime,
) -> CaptureWindowManifest:
    """Write packets in ``[window_start, window_end)`` to a standard PCAP.

    The input is parsed record-by-record using the same strict PCAP/PCAPNG
    readers as canonical flow extraction.  The output contains original packet
    bytes in their original capture order and is published only after the
    complete input has been read successfully.
    """
    _validate_window(window_start, window_end)
    source = Path(source_capture_path)
    destination = Path(output_path)
    manifest_path = destination.parent / "window_manifest.json"
    if source.resolve() == destination.resolve():
        raise CaptureWindowError("source_capture_path and output_path must differ")
    if destination.exists():
        raise CaptureWindowError(f"output capture already exists: {destination}")
    if manifest_path.exists():
        raise CaptureWindowError(f"window manifest already exists: {manifest_path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_capture = _temporary_path(destination.parent, f".{destination.name}.")
    temporary_manifest: Path | None = None
    start_timestamp = window_start.timestamp()
    end_timestamp = window_end.timestamp()
    packet_count = 0

    try:
        try:
            with _open_capture(source) as capture, temporary_capture.open("wb") as raw_output:
                try:
                    capture_magic = capture.read(len(_PCAPNG_MAGIC))
                    capture.seek(0)
                    if capture_magic == _PCAPNG_MAGIC:
                        reader = dpkt.pcapng.Reader(capture)
                        packets = _strict_pcapng_packets(capture, reader)
                    else:
                        reader = dpkt.pcap.Reader(capture)
                        packets = _strict_pcap_packets(capture, reader)
                except (dpkt.dpkt.Error, ValueError) as exc:
                    raise CaptureWindowError(
                        f"malformed or unreadable PCAP/PCAPNG header: {source}"
                    ) from exc

                writer = dpkt.pcap.Writer(raw_output, linktype=reader.datalink())
                for timestamp, frame, _, _ in packets:
                    if start_timestamp <= timestamp < end_timestamp:
                        writer.writepkt(frame, ts=timestamp)
                        packet_count += 1
                writer.close()
        except PcapParseError as exc:
            raise CaptureWindowError(str(exc)) from exc
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            raise CaptureWindowError(f"unreadable PCAP: {source}: {exc}") from exc

        os.replace(temporary_capture, destination)
        manifest = CaptureWindowManifest(
            source_capture_path=str(source),
            source_sha256=sha256_file(source),
            output_path=str(destination),
            output_sha256=sha256_file(destination),
            window_start=window_start.isoformat(),
            window_end=window_end.isoformat(),
            packet_count=packet_count,
        )
        temporary_manifest = _temporary_path(
            destination.parent, f".{manifest_path.name}."
        )
        temporary_manifest.write_text(
            json.dumps(asdict(manifest), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_manifest, manifest_path)
        return manifest
    finally:
        temporary_capture.unlink(missing_ok=True)
        if temporary_manifest is not None:
            temporary_manifest.unlink(missing_ok=True)
