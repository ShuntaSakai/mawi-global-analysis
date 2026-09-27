from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


def test_download_writes_ownership_record_and_final_file(tmp_path: Path) -> None:
    from mawi_global_analysis.ditl_downloader import download_chunk, load_ownership_record

    body = b"small synthetic capture"
    def opener(request, timeout):
        class Response:
            headers = {"Content-Length": str(len(body)), "ETag": "test"}
            def read(self, size=-1):
                nonlocal body
                if size == -1:
                    return body
                result, body = body[:size], body[size:]
                return result
            def __enter__(self): return self
            def __exit__(self, *args): return False
        return Response()

    record = download_chunk("202604081400", "https://example.test/202604081400.pcap.gz", tmp_path, opener=opener)
    raw = tmp_path / "202604081400.pcap.gz"
    assert raw.read_bytes() == b"small synthetic capture"
    assert not raw.with_suffix(raw.suffix + ".part").exists()
    assert record["sha256"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert load_ownership_record(raw)["source_url"] == "https://example.test/202604081400.pcap.gz"


def test_http_failure_never_publishes_final_file(tmp_path: Path) -> None:
    from urllib.error import HTTPError
    from mawi_global_analysis.ditl_downloader import DownloadError, download_chunk

    def opener(request, timeout):
        raise HTTPError(request.full_url, 404, "missing", {}, None)

    with pytest.raises(DownloadError):
        download_chunk("202604081400", "https://example.test/x", tmp_path, opener=opener, retries=1)
    assert not (tmp_path / "202604081400.pcap.gz").exists()


def test_owned_deletion_requires_disk_backed_checkpoint_and_spool_root(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from mawi_global_analysis.ditl_downloader import delete_owned_raw_after_checkpoint, write_ownership_record

    spool = tmp_path / "spool"; spool.mkdir()
    raw = spool / "202604081400.pcap.gz"; raw.write_bytes(b"raw")
    digest = hashlib.sha256(b"raw").hexdigest()
    write_ownership_record(raw, "202604081400", "https://example.test/x")
    checkpoint = SimpleNamespace(metadata={"status": "success", "source": {"sha256": digest, "size_bytes": 3}, "artifacts": {}})
    with pytest.raises(ValueError, match="disk-backed|complete"):
        delete_owned_raw_after_checkpoint(raw, spool, checkpoint, expected_cohort_identity="cohort", expected_chunk_id="202604081400")
    assert raw.exists()

    outside = tmp_path / "human.pcap.gz"; outside.write_bytes(b"raw")
    write_ownership_record(outside, "202604081400", "https://example.test/x")
    with pytest.raises(ValueError, match="spool"):
        delete_owned_raw_after_checkpoint(outside, spool, checkpoint, expected_cohort_identity="cohort", expected_chunk_id="202604081400")


def test_reuse_rejects_ownership_chunk_or_url_mismatch(tmp_path: Path) -> None:
    from mawi_global_analysis.ditl_downloader import download_chunk, write_ownership_record
    raw = tmp_path / "202604081400.pcap.gz"; raw.write_bytes(b"raw")
    write_ownership_record(raw, "202604081400", "https://example.test/old")
    with pytest.raises(ValueError, match="source_url"):
        download_chunk("202604081400", "https://example.test/new", tmp_path)
    record = json.loads(raw.with_name("202604081400.download.json").read_text())
    record["chunk_id"] = "202604080000"
    raw.with_name("202604081400.download.json").write_text(json.dumps(record))
    with pytest.raises(ValueError, match="chunk_id"):
        download_chunk("202604081400", "https://example.test/old", tmp_path)


def test_downloader_rejects_non_http_source_url(tmp_path: Path) -> None:
    from mawi_global_analysis.ditl_downloader import download_chunk
    with pytest.raises(ValueError, match="http"):
        download_chunk("202604081400", "file:///not-a-capture", tmp_path)
