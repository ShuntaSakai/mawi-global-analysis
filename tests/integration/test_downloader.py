import gzip
from io import BytesIO
from pathlib import Path

import pytest

from mawi_global_analysis.dataset import MawiDownloader
from mawi_global_analysis.hashing import sha256_file


PCAP_HEADER = bytes.fromhex(
    "d4c3b2a1" "02000400" "00000000" "00000000" "ffff0000" "01000000"
)
PCAPNG_HEADER = bytes.fromhex(
    "0a0d0d0a" "1c000000" "4d3c2b1a" "01000000"
    "ffffffffffffffff" "1c000000"
)


def gzip_capture(header: bytes) -> bytes:
    return gzip.compress(header)


class BytesResponse:
    """Minimal streaming response used to exercise downloader file handling."""

    def __init__(self, content: bytes) -> None:
        self._buffer = BytesIO(content)

    def __enter__(self) -> "BytesResponse":
        return self

    def __exit__(self, *_: object) -> None:
        self._buffer.close()

    def read(self, size: int = -1) -> bytes:
        return self._buffer.read(size)


class StaticResolver:
    """Resolver fixture that selects a cache filename without network lookup."""

    def __init__(self, filename: str) -> None:
        self.filename = filename

    def resolve(self, _: str) -> str:
        return f"https://captures.example/{self.filename}"


@pytest.mark.parametrize("capture_header", [PCAP_HEADER, PCAPNG_HEADER])
def test_downloader_writes_hashes_and_atomically_caches_valid_capture(
    tmp_path: Path, capture_header: bytes
) -> None:
    """A completed download must become the raw cache file with its final hash."""
    payload = gzip_capture(capture_header)
    requested_urls: list[str] = []

    def open_url(url: str) -> BytesResponse:
        requested_urls.append(url)
        return BytesResponse(payload)

    context = MawiDownloader(root=tmp_path, open_url=open_url).fetch("202604081400")

    assert requested_urls == [
        "https://mawi.wide.ad.jp/mawi/samplepoint-F/2026/202604081400.pcap.gz"
    ]
    assert context.path == tmp_path / "data/202604081400/raw/202604081400.pcap.gz"
    assert context.path.read_bytes() == payload
    assert context.sha256 == sha256_file(context.path)
    assert context.size_bytes == len(payload)
    assert list(context.path.parent.glob("*.tmp")) == []


def test_downloader_reuses_a_valid_raw_file_without_opening_the_network(
    tmp_path: Path,
) -> None:
    """A normal fetch must reuse an already-cached valid raw capture."""
    raw_path = tmp_path / "data/202604081400/raw/202604081400.pcap.gz"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_bytes(gzip_capture(PCAP_HEADER))

    def fail_if_opened(_: str) -> BytesResponse:
        raise AssertionError("network must not be used for a valid cached raw file")

    context = MawiDownloader(root=tmp_path, open_url=fail_if_opened).fetch("202604081400")

    assert context.path == raw_path
    assert context.sha256 == sha256_file(raw_path)


def test_downloader_reuses_a_valid_uncompressed_raw_file_without_network(
    tmp_path: Path,
) -> None:
    """A valid raw PCAP cache must not be misclassified as a gzip failure."""
    raw_path = tmp_path / "data/local/raw/local.pcap"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_bytes(PCAP_HEADER)

    def fail_if_opened(_: str) -> BytesResponse:
        raise AssertionError("network must not be used for a valid raw PCAP cache")

    context = MawiDownloader(
        root=tmp_path,
        resolver=StaticResolver("local.pcap"),
        open_url=fail_if_opened,
    ).fetch("local")

    assert context.path == raw_path
    assert context.sha256 == sha256_file(raw_path)
    assert context.size_bytes == len(PCAP_HEADER)


def test_invalid_uncompressed_raw_cache_is_explicit_and_unchanged(
    tmp_path: Path,
) -> None:
    """Invalid raw caches are fatal, never redownloaded or mutated implicitly."""
    raw_path = tmp_path / "data/local/raw/local.pcap"
    raw_path.parent.mkdir(parents=True)
    cached_payload = b"nonempty but invalid capture"
    raw_path.write_bytes(cached_payload)
    requested_urls: list[str] = []

    def record_network_use(url: str) -> BytesResponse:
        requested_urls.append(url)
        return BytesResponse(gzip_capture(PCAP_HEADER))

    with pytest.raises(ValueError, match="invalid raw cache for dataset local"):
        MawiDownloader(
            root=tmp_path,
            resolver=StaticResolver("local.pcap"),
            open_url=record_network_use,
        ).fetch("local")

    assert requested_urls == []
    assert raw_path.read_bytes() == cached_payload


def test_downloader_rejects_a_corrupt_raw_cache_without_opening_the_network(
    tmp_path: Path,
) -> None:
    """A corrupt raw cache is fatal rather than being silently redownloaded."""
    raw_path = tmp_path / "data/202604081400/raw/202604081400.pcap.gz"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_bytes(gzip.compress(b"not a PCAP capture"))

    def fail_if_opened(_: str) -> BytesResponse:
        raise AssertionError("network must not be used for a corrupt raw cache")

    with pytest.raises(ValueError, match="invalid raw cache"):
        MawiDownloader(root=tmp_path, open_url=fail_if_opened).fetch("202604081400")


def test_redownload_replaces_a_valid_raw_file(tmp_path: Path) -> None:
    """The explicit redownload flag must bypass ordinary raw-cache reuse."""
    raw_path = tmp_path / "data/202604081400/raw/202604081400.pcap.gz"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_bytes(gzip_capture(PCAP_HEADER))
    replacement = gzip_capture(PCAPNG_HEADER)

    context = MawiDownloader(
        root=tmp_path, open_url=lambda _: BytesResponse(replacement)
    ).fetch("202604081400", redownload=True)

    assert context.path.read_bytes() == replacement


def test_empty_redownload_preserves_existing_raw_file_and_cleans_staging(
    tmp_path: Path,
) -> None:
    """An invalid staged response must not replace a valid raw cache entry."""
    raw_path = tmp_path / "data/202604081400/raw/202604081400.pcap.gz"
    raw_path.parent.mkdir(parents=True)
    cached_payload = gzip_capture(PCAP_HEADER)
    raw_path.write_bytes(cached_payload)

    with pytest.raises(ValueError, match="empty download"):
        MawiDownloader(
            root=tmp_path, open_url=lambda _: BytesResponse(b"")
        ).fetch("202604081400", redownload=True)

    assert raw_path.read_bytes() == cached_payload
    assert list(raw_path.parent.glob("*.tmp")) == []


@pytest.mark.parametrize(
    ("download", "message"),
    [
        (b"not a gzip stream", "invalid gzip download"),
        (gzip.compress(b"ordinary text"), "PCAP or PCAPNG"),
        (gzip.compress(PCAP_HEADER[:4]), "truncated PCAP header"),
    ],
)
def test_invalid_capture_redownload_preserves_existing_raw_file_and_cleans_staging(
    tmp_path: Path, download: bytes, message: str
) -> None:
    """Only a readable gzip containing a capture header may replace the cache."""
    raw_path = tmp_path / "data/202604081400/raw/202604081400.pcap.gz"
    raw_path.parent.mkdir(parents=True)
    cached_payload = gzip_capture(PCAP_HEADER)
    raw_path.write_bytes(cached_payload)

    with pytest.raises(ValueError, match=message):
        MawiDownloader(
            root=tmp_path, open_url=lambda _: BytesResponse(download)
        ).fetch("202604081400", redownload=True)

    assert raw_path.read_bytes() == cached_payload
    assert list(raw_path.parent.glob("*.tmp")) == []


def test_downloader_validates_dataset_id_before_opening_the_network(tmp_path: Path) -> None:
    """Malformed input must not reach the downloader's external dependency."""
    def fail_if_opened(_: str) -> BytesResponse:
        raise AssertionError("network must not be used for malformed dataset IDs")

    with pytest.raises(ValueError, match="12-digit MAWI timestamp"):
        MawiDownloader(root=tmp_path, open_url=fail_if_opened).fetch("2026bad")
