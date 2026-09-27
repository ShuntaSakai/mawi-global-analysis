"""Sequential streaming download and narrowly proven raw-file deletion."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from mawi_global_analysis.ditl_chunks import validate_chunk_id
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.manifests import write_json_atomically


class DownloadError(RuntimeError):
    """A capture could not be acquired as a complete owned raw file."""


def raw_path_for(spool_root: Path, chunk_id: str) -> Path:
    return Path(spool_root).resolve() / f"{validate_chunk_id(chunk_id)}.pcap.gz"


def ownership_path(raw_path: Path) -> Path:
    raw_path = Path(raw_path)
    return raw_path.with_name(raw_path.name.removesuffix(".pcap.gz") + ".download.json")


def download_chunk(chunk_id: str, source_url: str, spool_root: Path, *, timeout: float = 60.0,
                   retries: int = 3, backoff_seconds: float = 1.0,
                   opener: Callable[..., Any] = urlopen) -> dict[str, Any]:
    """Download one capture serially via a fsynced ``.part`` checkpoint."""
    parsed = urlparse(source_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("source_url must be an absolute http or https URL")
    if timeout <= 0 or retries < 1 or backoff_seconds < 0:
        raise ValueError("timeout must be positive; retries >= 1; backoff non-negative")
    raw = raw_path_for(spool_root, chunk_id)
    raw.parent.mkdir(parents=True, exist_ok=True)
    if raw.exists():
        return validate_owned_raw(raw, raw.parent, expected_chunk_id=chunk_id, expected_source_url=source_url)
    part = raw.with_name(raw.name + ".part")
    # A prior partial response is never input data and is deliberately restarted.
    if part.exists():
        part.unlink()
    request = Request(source_url, headers={"User-Agent": "mawi-global-analysis/ditl-context"})
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with opener(request, timeout=timeout) as response:
                headers = response.headers
                length = _header(headers, "Content-Length")
                if length is not None:
                    try: expected = int(length)
                    except ValueError as error: raise DownloadError("invalid Content-Length") from error
                    if expected < 0: raise DownloadError("invalid Content-Length")
                    if shutil.disk_usage(raw.parent).free < expected:
                        raise DownloadError("insufficient free disk space for advertised Content-Length")
                with part.open("wb") as output:
                    while block := response.read(1024 * 1024):
                        output.write(block)
                    output.flush(); os.fsync(output.fileno())
                if length is not None and part.stat().st_size != expected:
                    raise DownloadError("download size does not match Content-Length")
                os.replace(part, raw)
                return write_ownership_record(raw, chunk_id, source_url, http_metadata={
                    key: _header(headers, key) for key in ("ETag", "Last-Modified", "Content-Length") if _header(headers, key) is not None
                })
        except HTTPError as error:
            if error.code < 500:
                raise DownloadError(f"HTTP {error.code} downloading {source_url}") from error
            last_error = error
        except (URLError, TimeoutError, OSError, DownloadError) as error:
            last_error = error
        finally:
            if part.exists(): part.unlink()
        if attempt + 1 < retries:
            time.sleep(backoff_seconds * (2 ** attempt))
    raise DownloadError(f"download failed after {retries} attempts: {source_url}") from last_error


def write_ownership_record(raw_path: Path, chunk_id: str, source_url: str, *, http_metadata: dict[str, str] | None = None) -> dict[str, Any]:
    raw = Path(raw_path).resolve()
    if not raw.is_file(): raise FileNotFoundError(raw)
    record: dict[str, Any] = {"chunk_id": validate_chunk_id(chunk_id), "source_url": source_url,
                              "local_path": str(raw), "sha256": sha256_file(raw), "size_bytes": raw.stat().st_size,
                              "downloaded_by_tool": True}
    if http_metadata: record["http"] = http_metadata
    write_json_atomically(ownership_path(raw), record)
    return record


def load_ownership_record(raw_path: Path) -> dict[str, Any]:
    try: record = json.loads(ownership_path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error: raise ValueError("missing or unreadable downloader ownership record") from error
    if not isinstance(record, dict): raise ValueError("invalid downloader ownership record")
    return record


def validate_owned_raw(raw_path: Path, spool_root: Path, *, expected_chunk_id: str | None = None,
                       expected_source_url: str | None = None) -> dict[str, Any]:
    raw, spool = Path(raw_path).resolve(), Path(spool_root).resolve()
    if raw.parent != spool: raise ValueError("raw file is not directly inside downloader spool root")
    record = load_ownership_record(raw)
    required = ("chunk_id", "source_url", "local_path", "sha256", "size_bytes", "downloaded_by_tool")
    if any(key not in record for key in required) or record["downloaded_by_tool"] is not True: raise ValueError("invalid downloader ownership metadata")
    filename_chunk = raw.name.removesuffix(".pcap.gz")
    if record["chunk_id"] != filename_chunk or validate_chunk_id(str(record["chunk_id"])) != record["chunk_id"]:
        raise ValueError("downloader ownership chunk_id does not match raw filename")
    parsed = urlparse(str(record["source_url"]))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("downloader ownership source_url is invalid")
    if expected_chunk_id is not None and record["chunk_id"] != validate_chunk_id(expected_chunk_id):
        raise ValueError("downloader ownership chunk_id does not match requested chunk")
    if expected_source_url is not None and record["source_url"] != expected_source_url:
        raise ValueError("downloader ownership source_url does not match requested URL")
    if record["local_path"] != str(raw) or not raw.is_file() or record["size_bytes"] != raw.stat().st_size or record["sha256"] != sha256_file(raw):
        raise ValueError("downloader ownership metadata does not match raw file")
    return record


def delete_owned_raw_after_checkpoint(raw_path: Path, spool_root: Path, checkpoint: Any, *,
                                      expected_cohort_identity: str, expected_chunk_id: str,
                                      expected_source_url: str | None = None) -> bool:
    """Delete only an owned, checksummed raw after a validated cache is supplied."""
    raw = Path(raw_path).resolve()
    record = validate_owned_raw(raw, spool_root, expected_chunk_id=expected_chunk_id,
                                expected_source_url=expected_source_url)
    metadata = getattr(checkpoint, "metadata", None)
    artifacts = metadata.get("artifacts") if isinstance(metadata, dict) else None
    if not isinstance(metadata, dict) or not isinstance(artifacts, dict):
        raise ValueError("deletion requires a disk-backed Phase 5A checkpoint")
    # Do not trust an in-memory metadata dict: re-open every cache artifact and
    # validate its schema, code/cohort identities, checksums, and row counts.
    from mawi_global_analysis.one_packet_context_chunks import _load_chunk
    target_artifact = artifacts.get("target_observations")
    if not isinstance(target_artifact, dict) or not isinstance(target_artifact.get("path"), str):
        raise ValueError("deletion requires complete Phase 5A artifact provenance")
    revalidated = _load_chunk(Path(target_artifact["path"]).resolve().parent, expected_cohort_identity, require_success=True)
    source = revalidated.metadata.get("source")
    if (revalidated.metadata.get("chunk_id") != validate_chunk_id(expected_chunk_id)
            or not isinstance(source, dict)
            or source.get("sha256") != record["sha256"] or source.get("size_bytes") != record["size_bytes"]):
        raise ValueError("validated chunk cache does not record raw ownership checksum")
    raw.unlink()
    ownership_path(raw).unlink(missing_ok=True)
    return True


def _header(headers: Any, name: str) -> str | None:
    return headers.get(name) if hasattr(headers, "get") else None
