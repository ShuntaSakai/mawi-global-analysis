import gzip
from pathlib import Path

import pytest

from mawi_global_analysis.dataset import MawiResolver, resolve_local_input
from mawi_global_analysis.hashing import sha256_file


PCAP_HEADER = bytes.fromhex(
    "d4c3b2a1" "02000400" "00000000" "00000000" "ffff0000" "01000000"
)
PCAPNG_HEADER = bytes.fromhex(
    "0a0d0d0a" "1c000000" "4d3c2b1a" "01000000"
    "ffffffffffffffff" "1c000000"
)


def test_local_input_derives_a_stable_id_from_filename_and_checksum(tmp_path: Path) -> None:
    """Changing either identity component must change the generated dataset ID."""
    capture = tmp_path / "sample.trace.pcap.gz"
    payload = gzip.compress(PCAP_HEADER)
    capture.write_bytes(payload)

    first = resolve_local_input(capture)
    second = resolve_local_input(capture)

    assert first.dataset_id == f"sample.trace-{sha256_file(capture)[:12]}"
    assert second == first
    assert first.path == capture
    assert first.size_bytes == len(payload)


def test_local_input_id_changes_for_filename_and_content_variations(tmp_path: Path) -> None:
    """Derived IDs must distinguish both a renamed and modified capture."""
    first_path = tmp_path / "first.pcap"
    renamed_path = tmp_path / "renamed.pcap"
    first_path.write_bytes(PCAP_HEADER)
    renamed_path.write_bytes(PCAP_HEADER)

    first_id = resolve_local_input(first_path).dataset_id
    renamed_id = resolve_local_input(renamed_path).dataset_id
    first_path.write_bytes(PCAP_HEADER + b"changed content")
    changed_id = resolve_local_input(first_path).dataset_id

    assert first_id != renamed_id
    assert first_id != changed_id


def test_local_input_preserves_an_explicit_dataset_id(tmp_path: Path) -> None:
    """An explicit ID must be usable for stable researcher-selected naming."""
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(PCAP_HEADER)

    context = resolve_local_input(capture, dataset_id="lab-repeat-a")

    assert context.dataset_id == "lab-repeat-a"
    assert context.sha256 == sha256_file(capture)


def test_local_input_accepts_all_safe_explicit_dataset_id_characters(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(PCAP_HEADER)

    context = resolve_local_input(capture, dataset_id="AZaz09_.-")

    assert context.dataset_id == "AZaz09_.-"


@pytest.mark.parametrize(
    "dataset_id",
    ["", "   ", ".", "..", "nested/id", r"nested\id", "/absolute", "unsafe id"],
)
def test_local_input_rejects_unsafe_explicit_dataset_ids(
    tmp_path: Path, dataset_id: str
) -> None:
    """Local IDs must be safe single path components, never paths themselves."""
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(PCAP_HEADER)

    with pytest.raises(ValueError, match="safe local identifier"):
        resolve_local_input(capture, dataset_id=dataset_id)


@pytest.mark.parametrize(
    ("case", "filename", "payload", "error"),
    [
        ("A", "valid.pcap", PCAP_HEADER, None),
        ("B", "invalid.pcap", b"not a capture", "PCAP or PCAPNG"),
        ("C", "valid.pcapng", PCAPNG_HEADER, None),
        ("D", "invalid.pcapng", b"not a capture", "PCAP or PCAPNG"),
        ("E", "valid.pcap.gz", gzip.compress(PCAP_HEADER), None),
        ("F", "invalid.pcap.gz", b"not a gzip stream", "invalid gzip"),
        (
            "G",
            "invalid-content.pcap.gz",
            gzip.compress(b"ordinary text"),
            "PCAP or PCAPNG",
        ),
        ("H", "valid.pcapng.gz", gzip.compress(PCAPNG_HEADER), None),
    ],
)
def test_local_input_validates_supported_capture_encodings(
    tmp_path: Path,
    case: str,
    filename: str,
    payload: bytes,
    error: str | None,
) -> None:
    """Cases A-H catch missing, gzip-only, or extension-only validation."""
    capture = tmp_path / filename
    capture.write_bytes(payload)

    if error is None:
        context = resolve_local_input(capture, dataset_id=f"case-{case}")
        assert context.path == capture
        assert context.sha256 == sha256_file(capture)
        assert context.size_bytes == len(payload)
    else:
        with pytest.raises(ValueError, match=error):
            resolve_local_input(capture, dataset_id=f"case-{case}")


def test_resolver_rejects_malformed_ids_before_any_archive_lookup() -> None:
    """Invalid IDs must fail at validation, before a downloader can use a URL."""
    resolver = MawiResolver()

    with pytest.raises(ValueError, match="12-digit MAWI timestamp"):
        resolver.resolve("not-a-dataset")


def test_resolver_builds_the_samplepoint_f_archive_url() -> None:
    """A valid MAWI timestamp must map to the documented archive location."""
    assert MawiResolver().resolve("202604081400") == (
        "https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/202604081400.pcap.gz"
    )
