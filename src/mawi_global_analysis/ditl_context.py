"""Safe sequential DITL acquisition around Phase 5A observation checkpoints."""

from __future__ import annotations

from pathlib import Path
import logging

from mawi_global_analysis.ditl_chunks import expected_chunk_ids, render_chunk_url, validate_target_chunk
from mawi_global_analysis.ditl_downloader import (
    delete_owned_raw_after_checkpoint, download_chunk, ownership_path, raw_path_for, validate_owned_raw,
)
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.io import load_one_packet_context, load_run
from mawi_global_analysis.one_packet_context import aggregate_one_packet_context_chunks, build_one_packet_cohort_from_run
from mawi_global_analysis.one_packet_context_chunks import (
    ChunkCacheConflictError, cohort_identity, extract_one_packet_chunk_observations,
    load_completed_chunk_observations,
)
from mawi_global_analysis.one_packet_context_run import write_one_packet_context_chunk_run


LOGGER = logging.getLogger(__name__)


def run_ditl_one_packet_context(
    dataset_id: str, source_run_name: str, day: str, target_chunk_id: str, target_chunk_path: Path,
    url_template: str, context_run_name: str, *, root: Path = Path("."), timeout: float = 60.0,
    retries: int = 3, backoff_seconds: float = 1.0, delay_seconds: float = 0.0,
) -> Path:
    """Execute the approved serial checkpoint-before-delete workflow.

    The existing source pipeline is intentionally not called here.  This only
    accepts its successful output and its already-local target capture.
    """
    import time

    root = Path(root).resolve()
    if (not context_run_name or Path(context_run_name).name != context_run_name
            or context_run_name in {".", ".."}):
        raise ValueError("context_run_name must be one non-special path component")
    target_chunk_id = validate_target_chunk(day, target_chunk_id)
    chunk_ids = expected_chunk_ids(day)
    # Validate template before touching data or performing network I/O.
    for chunk_id in (target_chunk_id, chunk_ids[0]): render_chunk_url(url_template, chunk_id)
    run = load_run(dataset_id, source_run_name, root=root)
    cohort = build_one_packet_cohort_from_run(run)
    target_path = Path(target_chunk_path).resolve()
    source_input = run.manifest.get("input")
    if not isinstance(source_input, dict) or not isinstance(source_input.get("sha256"), str):
        raise ValueError("successful source run has no usable input checksum provenance")
    if (not isinstance(source_input.get("path"), str) or Path(source_input["path"]).resolve() != target_path
            or not target_path.is_file() or sha256_file(target_path) != source_input["sha256"]):
        raise ValueError("target chunk checksum does not match source-run input provenance")

    cache_root = root / "data" / dataset_id / "processed" / "one_packet_context_chunks" / cohort_identity(cohort)
    data_root = (root / "data").resolve()
    spool_base = (data_root / dataset_id / "raw" / "ditl_stream").resolve()
    if not spool_base.is_relative_to(data_root):
        raise ValueError("dataset-derived spool must remain under the analysis data root")
    spool_root = (spool_base / context_run_name).resolve()
    if spool_root.parent != spool_base:
        raise ValueError("context-run spool must remain under the DITL stream root")
    source_manifest = root / "results" / dataset_id / source_run_name / "run_manifest.json"
    # Keep only validated metadata after each checkpoint.  A ChunkObservations
    # value owns both observation DataFrames and must never survive an
    # acquisition iteration.
    validated_by_id: dict[str, dict[object, object]] = {}
    # The source-derived target is always checkpointed before any network work.
    processing_order = (target_chunk_id, *(chunk_id for chunk_id in chunk_ids if chunk_id != target_chunk_id))
    for index, chunk_id in enumerate(processing_order):
        url = render_chunk_url(url_template, chunk_id)
        raw: Path | None = target_path if chunk_id == target_chunk_id else raw_path_for(spool_root, chunk_id)
        metadata_path = cache_root / chunk_id / "chunk_metadata.json"
        reused = metadata_path.exists()
        if reused:
            # Existing cache evidence must validate, never be overwritten/repaired.
            checkpoint = load_completed_chunk_observations(cache_root, chunk_id, cohort)
        else:
            checkpoint = None
        if checkpoint is None:
            if chunk_id != target_chunk_id:
                if raw.exists():
                    validate_owned_raw(raw, spool_root, expected_chunk_id=chunk_id, expected_source_url=url)
                else:
                    download_chunk(chunk_id, url, spool_root, timeout=timeout, retries=retries, backoff_seconds=backoff_seconds)
            assert raw is not None
            # This reloads and fully validates before returning successful metadata.
            extract_one_packet_chunk_observations(raw, cohort, cache_root, chunk_id, source_url=url)
            checkpoint = load_completed_chunk_observations(cache_root, chunk_id, cohort)
        if chunk_id == target_chunk_id and checkpoint.metadata["source"]["sha256"] != source_input["sha256"]:
            raise ValueError("target durable cache checksum does not match source-run input provenance")
        metadata = checkpoint.metadata
        validated_by_id[chunk_id] = metadata
        # Target remains until final aggregate + final loader succeeds.
        if chunk_id != target_chunk_id and raw is not None and raw.exists():
            delete_owned_raw_after_checkpoint(raw, spool_root, checkpoint,
                expected_cohort_identity=cohort_identity(cohort), expected_chunk_id=chunk_id,
                expected_source_url=checkpoint.metadata["source"].get("url"))
        # DataFrames are no longer reachable once the validation/deletion
        # prerequisite has completed.
        del checkpoint
        LOGGER.info("[%d/%d] %s %s", index + 1, len(chunk_ids), "reused" if reused else "extracted", chunk_id)
        if delay_seconds > 0 and index + 1 < len(chunk_ids) and chunk_id != target_chunk_id:
            time.sleep(delay_seconds)

    # A list from the fixed expected plan makes a missing cache impossible to hide.
    if len(validated_by_id) != 96:
        raise ValueError("all 96 expected DITL chunk caches are required")
    # TODO: replace the legacy all-chunk aggregation below with the SQLite
    # streaming publication path.  Metadata remains deliberately lightweight.
    validated = [load_completed_chunk_observations(cache_root, chunk_id, cohort) for chunk_id in chunk_ids]
    context, source_context = aggregate_one_packet_context_chunks(cohort, validated)
    run_dir = write_one_packet_context_chunk_run(
        dataset_id, source_run_name, validated, target_chunk_id, context_run_name, cohort,
        context, source_context, source_manifest, root=root,
    )
    # Final output must be reloadable independently of every raw capture.
    load_one_packet_context(dataset_id, context_run_name, root=root)
    if target_path.exists() and target_path.parent == spool_root.resolve() and ownership_path(target_path).exists():
        # An owned target within this spool is deleted only after final loading;
        # a corrupt ownership/cache proof is a failure, not a reason to hide it.
        target_checkpoint = load_completed_chunk_observations(cache_root, target_chunk_id, cohort)
        delete_owned_raw_after_checkpoint(target_path, spool_root, target_checkpoint,
            expected_cohort_identity=cohort_identity(cohort), expected_chunk_id=target_chunk_id,
            expected_source_url=validated_by_id[target_chunk_id]["source"].get("url"))
        del target_checkpoint
    return run_dir
