"""Resolve local captures and retrieve MAWI archive inputs."""

import gzip
import re
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from urllib.request import urlopen

from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.models import InputContext


_SAFE_LOCAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # big-endian PCAP, microsecond timestamps
    b"\xd4\xc3\xb2\xa1",  # little-endian PCAP, microsecond timestamps
    b"\xa1\xb2\x3c\x4d",  # big-endian PCAP, nanosecond timestamps
    b"\x4d\x3c\xb2\xa1",  # little-endian PCAP, nanosecond timestamps
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_GZIP_MAGIC = b"\x1f\x8b"


class MawiResolver:
    """Map MAWI timestamp IDs to their official samplepoint-F archive URLs."""

    _DATASET_ID_PATTERN = re.compile(r"^\d{12}$")

    def resolve(self, dataset_id: str) -> str:
        """Validate a dataset ID and return its MAWI archive URL."""
        if not self._DATASET_ID_PATTERN.fullmatch(dataset_id):
            raise ValueError("dataset ID must be a 12-digit MAWI timestamp")
        try:
            timestamp = datetime.strptime(dataset_id, "%Y%m%d%H%M")
        except ValueError as error:
            raise ValueError("dataset ID must be a valid 12-digit MAWI timestamp") from error
        return (
            "https://mawi.wide.ad.jp/mawi/samplepoint-F/"
            f"{timestamp.year}/{dataset_id}.pcap.gz"
        )


def resolve_local_input(path: Path, dataset_id: str | None = None) -> InputContext:
    """Return an input context for a local capture, hashing its final contents."""
    if not path.is_file():
        raise FileNotFoundError(f"local input is not a readable file: {path}")
    if dataset_id is not None:
        _validate_local_dataset_id(dataset_id)

    _validate_capture(path, f"local input {path}")
    return _build_input_context(path, dataset_id)


def _build_input_context(path: Path, dataset_id: str | None) -> InputContext:
    checksum = sha256_file(path)
    resolved_dataset_id = dataset_id if dataset_id is not None else _derived_dataset_id(path, checksum)
    return InputContext(
        dataset_id=resolved_dataset_id,
        path=path,
        sha256=checksum,
        size_bytes=path.stat().st_size,
    )


class MawiDownloader:
    """Download MAWI inputs into the raw dataset cache."""

    def __init__(
        self,
        root: Path = Path("."),
        resolver: MawiResolver | None = None,
        open_url: Callable[[str], BinaryIO] = urlopen,
    ) -> None:
        self.root = root
        self.resolver = resolver or MawiResolver()
        self.open_url = open_url

    def fetch(self, dataset_id: str, redownload: bool = False) -> InputContext:
        """Reuse or fetch a MAWI raw capture, returning its content identity."""
        url = self.resolver.resolve(dataset_id)
        raw_path = self.root / "data" / dataset_id / "raw" / _archive_filename(url)

        if not redownload and raw_path.exists():
            _validate_raw_cache(raw_path, dataset_id)
            return _build_input_context(raw_path, dataset_id)

        raw_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=raw_path.parent,
                prefix=f".{raw_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                with self.open_url(url) as response:
                    while chunk := response.read(1024 * 1024):
                        temporary_file.write(chunk)
                temporary_file.flush()

            size_bytes = temporary_path.stat().st_size
            if size_bytes == 0:
                raise ValueError(f"empty download for dataset {dataset_id}")
            _validate_capture(
                temporary_path,
                f"download for dataset {dataset_id}",
                path_hint=raw_path,
            )
            checksum = sha256_file(temporary_path)
            temporary_path.replace(raw_path)
            temporary_path = None
            return InputContext(dataset_id, raw_path, checksum, size_bytes)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()


def _derived_dataset_id(path: Path, checksum: str) -> str:
    filename = path.name
    if filename.endswith(".pcap.gz"):
        filename = filename[: -len(".pcap.gz")]
    elif filename.endswith(".pcap"):
        filename = filename[: -len(".pcap")]
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", filename).strip(".-")
    return f"{safe_name or 'local'}-{checksum[:12]}"


def _validate_local_dataset_id(dataset_id: str) -> None:
    if dataset_id in {".", ".."} or not _SAFE_LOCAL_ID_PATTERN.fullmatch(dataset_id):
        raise ValueError(
            "dataset ID must be a safe local identifier using only "
            "letters, digits, underscore, dot, and hyphen"
        )


def _archive_filename(url: str) -> str:
    return url.rsplit("/", maxsplit=1)[-1]


def _validate_capture(path: Path, description: str, path_hint: Path | None = None) -> None:
    """Validate a raw or gzip-compressed PCAP/PCAPNG binary header."""
    try:
        with path.open("rb") as raw_file:
            raw_magic = raw_file.read(len(_GZIP_MAGIC))
    except OSError as error:
        raise ValueError(f"unreadable {description}") from error

    indicated_path = path_hint or path
    is_gzip = indicated_path.name.lower().endswith(".gz") or raw_magic == _GZIP_MAGIC
    if is_gzip:
        try:
            with gzip.open(path, "rb") as capture_file:
                header = capture_file.read(28)
                while capture_file.read(1024 * 1024):
                    pass
        except (EOFError, OSError) as error:
            raise ValueError(f"invalid gzip {description}") from error
    else:
        try:
            with path.open("rb") as capture_file:
                header = capture_file.read(28)
        except OSError as error:
            raise ValueError(f"unreadable {description}") from error

    _validate_capture_header(header, description)


def _validate_capture_header(header: bytes, description: str) -> None:
    magic = header[:4]
    if magic not in _PCAP_MAGICS and magic != _PCAPNG_MAGIC:
        raise ValueError(f"{description} does not contain a PCAP or PCAPNG header")
    if magic in _PCAP_MAGICS and len(header) < 24:
        raise ValueError(f"truncated PCAP header in {description}")
    if magic == _PCAPNG_MAGIC and len(header) < 28:
        raise ValueError(f"truncated PCAPNG header in {description}")


def _validate_raw_cache(path: Path, dataset_id: str) -> None:
    if not path.is_file():
        raise ValueError(f"invalid raw cache for dataset {dataset_id}: path is not a file")
    try:
        _validate_capture(path, f"raw cache for dataset {dataset_id}")
    except ValueError as error:
        raise ValueError(f"invalid raw cache for dataset {dataset_id}") from error
