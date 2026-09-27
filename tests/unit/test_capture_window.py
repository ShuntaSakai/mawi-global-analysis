"""Tests for streaming capture-window extraction."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import dpkt
import pandas as pd
import pytest

from mawi_global_analysis.hashing import sha256_file


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "pcaps"
PCAP_PATH = FIXTURE_DIR / "tcp_patterns.pcap"
GZIP_PATH = FIXTURE_DIR / "tcp_patterns.pcap.gz"


def _time(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, UTC)


def _frames(path: Path) -> list[bytes]:
    with path.open("rb") as capture:
        return [frame for _, frame in dpkt.pcap.Reader(capture)]


def _write_pcapng(source: Path, destination: Path) -> None:
    with source.open("rb") as input_file, destination.open("wb") as output_file:
        reader = dpkt.pcap.Reader(input_file)
        writer = dpkt.pcapng.Writer(output_file, linktype=reader.datalink())
        for timestamp, frame in reader:
            writer.writepkt(frame, ts=timestamp)


def test_extract_includes_start_excludes_end_and_preserves_order(tmp_path: Path) -> None:
    """Changing either boundary comparison must fail this exact-frame contract."""
    from mawi_global_analysis.capture_window import extract_capture_window

    output = tmp_path / "window.pcap"
    manifest = extract_capture_window(
        PCAP_PATH, output, window_start=_time(2.0), window_end=_time(3.2)
    )

    assert _frames(output) == _frames(PCAP_PATH)[2:7]
    assert manifest.packet_count == 5


def test_extract_accepts_an_empty_window(tmp_path: Path) -> None:
    """Treating a valid empty selection as an error must fail this test."""
    from mawi_global_analysis.capture_window import extract_capture_window

    output = tmp_path / "empty.pcap"
    manifest = extract_capture_window(
        PCAP_PATH, output, window_start=_time(10.0), window_end=_time(11.0)
    )

    assert _frames(output) == []
    assert manifest.packet_count == 0


def test_extract_records_hashes_and_window_manifest(tmp_path: Path) -> None:
    """Omitting provenance fields or hashing a different file must fail this test."""
    from mawi_global_analysis.capture_window import extract_capture_window

    output = tmp_path / "window.pcap"
    result = extract_capture_window(
        PCAP_PATH, output, window_start=_time(1.0), window_end=_time(1.1)
    )
    saved = json.loads((tmp_path / "window_manifest.json").read_text())

    assert result.source_sha256 == sha256_file(PCAP_PATH)
    assert result.output_sha256 == sha256_file(output)
    assert saved == {
        "source_capture_path": str(PCAP_PATH),
        "source_sha256": sha256_file(PCAP_PATH),
        "output_path": str(output),
        "output_sha256": sha256_file(output),
        "window_start": "1970-01-01T00:00:01+00:00",
        "window_end": "1970-01-01T00:00:01.100000+00:00",
        "packet_count": 1,
    }


@pytest.mark.parametrize("source", [PCAP_PATH, GZIP_PATH])
def test_extract_supports_existing_pcap_and_gzip_inputs(
    tmp_path: Path, source: Path
) -> None:
    """Dropping either established PCAP input mode must fail this test."""
    from mawi_global_analysis.capture_window import extract_capture_window

    output = tmp_path / f"{source.name}.pcap"
    extract_capture_window(source, output, window_start=_time(1.0), window_end=_time(1.1))

    assert _frames(output) == _frames(PCAP_PATH)[:1]


def test_extract_supports_pcapng_input(tmp_path: Path) -> None:
    """Dropping the established PCAPNG reader path must fail this test."""
    from mawi_global_analysis.capture_window import extract_capture_window

    source = tmp_path / "source.pcapng"
    _write_pcapng(PCAP_PATH, source)
    output = tmp_path / "window.pcap"

    extract_capture_window(source, output, window_start=_time(1.0), window_end=_time(1.1))

    assert _frames(output) == _frames(PCAP_PATH)[:1]


def test_extracted_subcapture_preserves_nanosecond_target_identity_for_context(
    tmp_path: Path,
) -> None:
    """A context scan must match a target back to its nanosecond full-capture record."""
    from mawi_global_analysis.capture_window import extract_capture_window
    from mawi_global_analysis.one_packet_context import scan_one_packet_context

    tcp = dpkt.tcp.TCP(sport=40000, dport=443, flags=dpkt.tcp.TH_SYN)
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=b"\xc6\x33\x64\x01", dst=b"\xc0\x00\x02\x01",
        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp,
    )
    ip.len = len(ip)
    frame = bytes(dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x01" * 6,
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    ))
    source = tmp_path / "full-nanosecond.pcap"
    target_timestamp = 10.000000123
    with source.open("wb") as output:
        writer = dpkt.pcap.Writer(output, nano=True)
        writer.writepkt(frame, ts=target_timestamp)
        writer.close()

    subcapture = tmp_path / "window.pcap"
    extract_capture_window(source, subcapture, _time(10), _time(11))
    with subcapture.open("rb") as capture:
        extracted_timestamp, _ = next(iter(dpkt.pcap.Reader(capture)))
    cohort = pd.DataFrame([{
        "source_flow_id": 1, "target_timestamp": extracted_timestamp,
        "protocol": 6, "src_ip": "198.51.100.1", "src_port": 40000,
        "dst_ip": "192.0.2.1", "dst_port": 443,
    }])

    context = scan_one_packet_context(source, cohort)

    assert context.loc[0, "target_timestamp"] == float(extracted_timestamp)


def test_extract_rejects_truncated_input_without_a_successful_output(tmp_path: Path) -> None:
    """Silently accepting a short record must fail this test."""
    from mawi_global_analysis.capture_window import (
        CaptureWindowError,
        extract_capture_window,
    )

    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(PCAP_PATH.read_bytes()[:-1])
    output = tmp_path / "window.pcap"

    with pytest.raises(CaptureWindowError, match="truncated"):
        extract_capture_window(
            truncated, output, window_start=_time(0.0), window_end=_time(100.0)
        )

    assert not output.exists()
    assert not (tmp_path / "window_manifest.json").exists()


def test_extract_rejects_source_as_its_own_output(tmp_path: Path) -> None:
    """Replacing the source would make the recorded source checksum false."""
    from mawi_global_analysis.capture_window import (
        CaptureWindowError,
        extract_capture_window,
    )

    source = tmp_path / "source.pcap"
    source.write_bytes(PCAP_PATH.read_bytes())
    source_hash = sha256_file(source)

    with pytest.raises(CaptureWindowError, match="must differ"):
        extract_capture_window(source, source, window_start=_time(1.0), window_end=_time(1.1))

    assert sha256_file(source) == source_hash


@pytest.mark.parametrize("existing", ["window.pcap", "window_manifest.json"])
def test_extract_rejects_existing_output_artifacts(
    tmp_path: Path, existing: str
) -> None:
    """Overwriting a provenance-bearing artifact must fail instead of replacing it."""
    from mawi_global_analysis.capture_window import (
        CaptureWindowError,
        extract_capture_window,
    )

    existing_path = tmp_path / existing
    existing_path.write_bytes(b"preserve me")

    with pytest.raises(CaptureWindowError, match="already exists"):
        extract_capture_window(
            PCAP_PATH, tmp_path / "window.pcap", window_start=_time(1.0), window_end=_time(1.1)
        )

    assert existing_path.read_bytes() == b"preserve me"


@pytest.mark.parametrize(
    ("window_start", "window_end", "message"),
    [
        (datetime(1970, 1, 1), _time(1.0), "timezone-aware"),
        (_time(1.0), datetime(1970, 1, 1), "timezone-aware"),
        (_time(1.0), _time(1.0), "before"),
        (_time(2.0), _time(1.0), "before"),
    ],
)
def test_extract_rejects_ambiguous_or_invalid_windows(
    tmp_path: Path, window_start: datetime, window_end: datetime, message: str
) -> None:
    """Accepting naive or non-increasing windows must fail this test."""
    from mawi_global_analysis.capture_window import (
        CaptureWindowError,
        extract_capture_window,
    )

    with pytest.raises(CaptureWindowError, match=message):
        extract_capture_window(PCAP_PATH, tmp_path / "window.pcap", window_start, window_end)
