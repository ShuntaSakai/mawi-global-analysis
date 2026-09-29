from __future__ import annotations

import pytest
from pathlib import Path
from types import SimpleNamespace


def test_day_plan_has_exactly_96_quarter_hour_chunk_ids() -> None:
    from mawi_global_analysis.ditl_chunks import expected_chunk_ids

    chunks = expected_chunk_ids("2026-04-08")
    assert len(chunks) == 96
    assert chunks[:2] == ("202604080000", "202604080015")
    assert chunks[-1] == "202604082345"


@pytest.mark.parametrize("template", ["ftp://example/{chunk_id}", "https://x/no-slot", "https://x/{chunk_id}/{chunk_id}"])
def test_url_template_is_strict_and_http_only(template: str) -> None:
    from mawi_global_analysis.ditl_chunks import DITLPlanError, render_chunk_url

    with pytest.raises(DITLPlanError):
        render_chunk_url(template, "202604081400")


def test_target_must_belong_to_requested_day() -> None:
    from mawi_global_analysis.ditl_chunks import DITLPlanError, validate_target_chunk

    with pytest.raises(DITLPlanError):
        validate_target_chunk("20260408", "202604091400")


def test_orchestrator_processes_target_checkpoint_before_other_slots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import mawi_global_analysis.ditl_context as orchestration

    target = tmp_path / "202604081400.pcap.gz"; target.write_bytes(b"target")
    digest = __import__("hashlib").sha256(b"target").hexdigest()
    seen: list[str] = []
    all_chunks = tuple(f"20260408{hour:02d}{minute:02d}" for hour in range(24) for minute in (0, 15, 30, 45))
    monkeypatch.setattr(orchestration, "expected_chunk_ids", lambda day: all_chunks)
    monkeypatch.setattr(orchestration, "load_run", lambda *a, **k: SimpleNamespace(manifest={"input": {"sha256": digest, "path": str(target)}}))
    monkeypatch.setattr(orchestration, "build_one_packet_cohort_from_run", lambda run: object())
    monkeypatch.setattr(orchestration, "cohort_identity", lambda cohort: "cohort")
    cache_root = tmp_path / "data" / "dataset" / "processed" / "one_packet_context_chunks" / "cohort"
    for chunk_id in all_chunks:
        directory = cache_root / chunk_id; directory.mkdir(parents=True)
        (directory / "chunk_metadata.json").write_text("{}")
    def load_cache(root, chunk_id, cohort):
        seen.append(chunk_id)
        return SimpleNamespace(metadata={"source": {"sha256": digest, "size_bytes": 6}, "status": "success", "artifacts": {}, "target_observation_row_count": 0, "source_syn_observation_row_count": 0}, target_packets=None, source_syn_packets=None)
    monkeypatch.setattr(orchestration, "load_completed_chunk_observations", load_cache)
    ingested: list[str] = []
    class FakeAggregator:
        def __init__(self, *args, **kwargs): self.ingested_chunks = []
        def validate_ingestion_ledger(self, expected): pass
        def ingest_frames(self, target, source, **kwargs): ingested.append("chunk")
        def compute(self): pass
        def close(self, **kwargs): pass
    monkeypatch.setattr(orchestration, "SQLiteContextAggregator", FakeAggregator)
    monkeypatch.setattr(orchestration, "write_one_packet_context_chunk_run_streaming", lambda *a, **k: tmp_path / "result")

    orchestration.run_ditl_one_packet_context("dataset", "source", "20260408", "202604081400", target,
        "https://example.test/{chunk_id}.pcap.gz", "context", root=tmp_path)

    assert seen[0] == "202604081400"
    assert seen[1:96] == [chunk_id for chunk_id in all_chunks if chunk_id != "202604081400"]
    assert len(ingested) == 96
