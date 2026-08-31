"""M0--M3 orchestration, cache decisions, and durable run provenance."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from mawi_global_analysis.aguri import (
    AGURI_CANDIDATE_COLUMNS,
    inspect_aguri_cache,
    run_aguri_stage,
)
from mawi_global_analysis.config import ExperimentConfig, load_config
from mawi_global_analysis.dataset import MawiDownloader, MawiResolver, resolve_local_input
from mawi_global_analysis.flow import capture_start_timestamp
from mawi_global_analysis.flow_stage import FLOW_COLUMNS, FLOW_SCHEMA_VERSION, run_flow_stage
from mawi_global_analysis.hashing import flow_fingerprint, sha256_file, stable_json_hash
from mawi_global_analysis.manifests import RunManifest
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS, build_membership
from mawi_global_analysis.models import InputContext
from mawi_global_analysis.prefix import (
    CORRECTED_LEDGER_COLUMNS,
    LEGACY_OUTPUT_COLUMNS,
    run_corrected_prefix_stage,
    run_legacy_prefix_stage,
)
from mawi_global_analysis.scan_labels import (
    FLOW_LABEL_COLUMNS,
    build_pre_m5_flow_labels,
    ensure_pre_m5_labels_allowed,
)
from mawi_global_analysis.scan_windows import (
    SCAN_SUMMARY_COLUMNS,
    SCAN_WINDOW_COLUMNS,
    build_source_scan_summary,
    build_source_scan_windows,
)


STAGE_NAMES = (
    "input",
    "flows",
    "aguri",
    "scan-stats",
    "scan-labels",
    "prefixes",
    "membership",
    "manifest",
)

M0_M4_STAGES = (
    "input",
    "flows",
    "aguri",
    "scan-stats",
    "scan-labels",
    "prefixes",
    "membership",
)
SCAN_STATS_SCHEMA_VERSION = "scan-stats-v2"
SCAN_STATS_CAPTURE_ANCHOR = "raw_first_packet_timestamp"
NEUTRAL_LABEL_SCHEMA_VERSION = "neutral-labels-v1"
STAGE_DEPENDENCIES = {
    "input": (),
    "flows": ("input",),
    "aguri": ("input",),
    "scan-stats": ("flows",),
    "scan-labels": ("flows", "scan-stats"),
    "prefixes": ("aguri",),
    "membership": ("flows", "prefixes"),
}
FORCE_INVALIDATES = {
    "input": frozenset(M0_M4_STAGES),
    "flows": frozenset(("flows", "scan-stats", "scan-labels", "membership")),
    "aguri": frozenset(("aguri", "prefixes", "membership")),
    "scan-stats": frozenset(("scan-stats", "scan-labels")),
    "scan-labels": frozenset(("scan-labels",)),
    "prefixes": frozenset(("prefixes", "membership")),
    "membership": frozenset(("membership",)),
}
LEGACY_STAGE_DEPENDENCIES = {
    "input": (),
    "flows": ("input",),
    "aguri": ("input",),
    "scan-stats": ("flows",),
    "scan-labels": ("flows", "scan-stats"),
    "prefixes": ("flows", "aguri"),
}
LEGACY_FORCE_INVALIDATES = {
    "input": frozenset(("input", "flows", "aguri", "scan-stats", "scan-labels", "prefixes")),
    "flows": frozenset(("flows", "scan-stats", "scan-labels", "prefixes")),
    "aguri": frozenset(("aguri", "prefixes")),
    "scan-stats": frozenset(("scan-stats", "scan-labels")),
    "scan-labels": frozenset(("scan-labels",)),
    "prefixes": frozenset(("prefixes",)),
}
DOWNSTREAM_RUN_RECORDS = {
    "flows": {
        "scan-stats": (
            frozenset(("source_scan_windows", "source_scan_summary")),
            frozenset(("scan-stats",)),
        ),
        "scan-labels": (
            frozenset(("flow_labels",)),
            frozenset(("scan-labels",)),
        ),
        "membership": (frozenset(("flow_prefix_membership",)), frozenset()),
    },
    "aguri": {
        "prefixes": (frozenset(("prefixes",)), frozenset()),
        "membership": (frozenset(("flow_prefix_membership",)), frozenset()),
    },
    "scan-stats": {
        "scan-labels": (
            frozenset(("flow_labels",)),
            frozenset(("scan-labels",)),
        ),
    },
    "prefixes": {
        "membership": (frozenset(("flow_prefix_membership",)), frozenset()),
    },
}


class RunConflictError(ValueError):
    """Raised when an existing run name belongs to different provenance."""


class MissingUpstreamArtifactError(FileNotFoundError):
    """Raised when a partial run excludes an artifact it needs."""


@dataclass(frozen=True)
class RunPaths:
    """Run-specific output locations, kept separate from dataset caches."""

    run_dir: Path
    manifest: Path
    scan_windows: Path
    scan_summary: Path
    labels: Path
    prefixes: Path
    membership: Path


@dataclass(frozen=True)
class InputResolution:
    """Resolved input plus whether the input stage reused an existing raw file."""

    context: InputContext
    stage_status: str


def run_legacy_prefixes(
    flows_path: Path, aguri_path: Path, config_path: Path, output_path: Path
) -> Path:
    """Execute the paper-legacy prefixes stage from its upstream CSV artifacts."""
    return run_legacy_prefix_stage(
        flows_path, aguri_path, load_config(config_path), output_path
    )


def run_pipeline(args: argparse.Namespace) -> int:
    """Execute the implemented M0--M4 DAG or print a non-mutating plan.

    Stage relationships are defined by ``STAGE_DEPENDENCIES``.  This keeps
    partial execution strict: an omitted dependency must already exist rather
    than being rebuilt as an unrequested side effect.
    """
    config_path = args.config.resolve()
    config_text = config_path.read_text(encoding="utf-8")
    config_hash = sha256_file(config_path)
    config = load_config(config_path)
    run_name = args.run_name or config.experiment.name
    selected_stages = _selected_stages(args, config)
    forced_stages = _forced_stages(args.force, config)
    _ensure_forced_stages_are_selected(forced_stages, selected_stages)
    ensure_pre_m5_labels_allowed(config)

    provisional_paths = _provisional_run_paths(args, run_name)
    manifest: RunManifest | None = None
    existing: dict[str, Any] | None = None
    if provisional_paths is not None:
        existing = _load_existing_manifest(provisional_paths.manifest)
        if existing is not None:
            _ensure_existing_config_identity(existing, config_hash)

    try:
        input_resolution = _resolve_input(args, dry_run=args.dry_run)
    except Exception as error:
        if not args.dry_run and existing is None and provisional_paths is not None:
            code_identity = _code_identity()
            manifest = RunManifest.start(
                provisional_paths.manifest,
                provisional_paths.run_dir.parent.name,
                config_path,
                config_text,
                config_hash,
                code_identity["git_commit"],
                code_identity,
            )
            manifest.record_stage("input", "running")
        if manifest is not None:
            manifest.record_stage("input", "failed")
            manifest.finalize_failure(error)
        raise

    context = input_resolution.context
    paths = _run_paths(context.dataset_id, run_name)
    if provisional_paths != paths or (existing is None and manifest is None):
        existing = _load_existing_manifest(paths.manifest)
        manifest = None
    try:
        _ensure_run_identity(existing, context, config_hash)
    except Exception as error:
        if manifest is not None:
            manifest.record_stage("input", "failed")
            manifest.finalize_failure(error)
        raise

    if args.dry_run:
        dry_run_artifacts = _existing_artifacts(existing, config, context)
        _add_valid_dataset_cache_artifacts(dry_run_artifacts, context, config)
        if context.sha256 and context.path.is_file():
            dry_run_artifacts["input"] = context.path
        for stage in selected_stages:
            if stage != "input":
                _require_omitted_dependencies(
                    stage, selected_stages, dry_run_artifacts, config, existing, context
                )
        for stage, decision in _planned_decisions(
            selected_stages, forced_stages, context, config, paths, existing
        ):
            print(f"[{decision.upper()}] {stage}")
        return 0

    if manifest is None:
        code_identity = _code_identity()
        manifest = (
            RunManifest.resume(paths.manifest, code_identity["git_commit"], code_identity)
            if existing is not None
            else RunManifest.start(
                paths.manifest,
                context.dataset_id,
                config_path,
                config_text,
                config_hash,
                code_identity["git_commit"],
                code_identity,
            )
        )
        manifest.record_stage("input", "running")
    artifacts = _existing_artifacts(existing, config, context)
    _add_valid_dataset_cache_artifacts(artifacts, context, config)
    current_stage = "input"
    effective_forced_stages = set(forced_stages)
    try:
        manifest.set_input(context.path, context.sha256, context.size_bytes)
        manifest.record_stage("input", input_resolution.stage_status)
        artifacts["input"] = context.path
        manifest.record_artifact("input_pcap", context.path, row_count=1)

        for stage in selected_stages:
            if stage == "input":
                continue
            current_stage = stage
            _require_omitted_dependencies(
                stage, selected_stages, artifacts, config, existing, context
            )
            manifest.record_stage(stage, "running")
            if stage == "flows":
                forced = stage in effective_forced_stages
                flow_cache = _inspect_flow_cache(context, config)
                was_cached = flow_cache[0] and not forced
                flows_path = run_flow_stage(context, config, force=forced)
                artifacts["flows"] = flows_path
                manifest.record_stage("flows", "reused" if was_cached else "completed")
                flow_metadata = {
                    "fingerprint": flow_fingerprint(
                        context.sha256, config, FLOW_SCHEMA_VERSION
                    ),
                    "manifest_path": str(flows_path.parent / "flow_manifest.json"),
                }
                flow_producer = _flow_artifact_producer(flows_path)
                flow_artifact_producer = _reuse_or_produce_artifact_producer(
                    existing,
                    "flows",
                    flow_producer,
                    code_identity if not was_cached else None,
                )
                manifest.record_artifact(
                    "flows",
                    flows_path,
                    _csv_row_count(flows_path),
                    flow_artifact_producer,
                )
                manifest.record_cache(
                    "flows", {**flow_metadata, "producer": flow_artifact_producer}
                )
                if not was_cached or _artifact_producer_rebound(
                    existing, "flows", flow_artifact_producer
                ):
                    _deactivate_excluded_downstream_records(
                        manifest, "flows", config, selected_stages
                    )
                    effective_forced_stages.update(
                        {"scan-stats", "scan-labels", "membership"}
                        | ({"prefixes"} if _is_legacy(config) else set())
                    )
            elif stage == "aguri":
                aguri_cache = _inspect_aguri_cache_if_available(context, config)
                aguri_path = run_aguri_stage(
                    context, config, force=stage in forced_stages
                )
                artifacts["aguri"] = aguri_path
                aguri_reused = (
                    aguri_cache is not None
                    and aguri_cache.valid
                    and stage not in forced_stages
                )
                aguri_producer = _aguri_artifact_producer(aguri_path)
                aguri_artifact_producer = _reuse_or_produce_artifact_producer(
                    existing,
                    "aguri_candidates",
                    aguri_producer,
                    code_identity if not aguri_reused else None,
                )
                manifest.record_stage("aguri", "reused" if aguri_reused else "completed")
                manifest.record_artifact(
                    "aguri_candidates",
                    aguri_path,
                    _csv_row_count(aguri_path),
                    aguri_artifact_producer,
                )
                _record_aguri_cache(manifest, aguri_path, aguri_artifact_producer)
                if not aguri_reused or _artifact_producer_rebound(
                    existing, "aguri_candidates", aguri_artifact_producer
                ):
                    _deactivate_excluded_downstream_records(
                        manifest, "aguri", config, selected_stages
                    )
                    effective_forced_stages.update({"prefixes", "membership"})
            elif stage == "scan-stats":
                if stage in effective_forced_stages or not _valid_scan_stats_artifacts(
                    paths, existing, context, config
                ):
                    _write_scan_statistics(
                        artifacts["flows"],
                        context.dataset_id,
                        config,
                        context.path,
                        paths.scan_windows,
                        paths.scan_summary,
                    )
                    stage_status = "completed"
                    effective_forced_stages.add("scan-labels")
                else:
                    stage_status = "reused"
                artifacts["scan-stats"] = paths.scan_windows
                manifest.record_stage("scan-stats", stage_status)
                manifest.record_artifact(
                    "source_scan_windows",
                    paths.scan_windows,
                    _csv_row_count(paths.scan_windows),
                    {
                        "flow_fingerprint": flow_fingerprint(
                            context.sha256, config, FLOW_SCHEMA_VERSION
                        ),
                        "code_identity": code_identity,
                    }
                    if stage_status == "completed"
                    else None,
                )
                manifest.record_artifact(
                    "source_scan_summary",
                    paths.scan_summary,
                    _csv_row_count(paths.scan_summary),
                    {
                        "flow_fingerprint": flow_fingerprint(
                            context.sha256, config, FLOW_SCHEMA_VERSION
                        ),
                        "code_identity": code_identity,
                    }
                    if stage_status == "completed"
                    else None,
                )
                if stage_status == "completed":
                    manifest.record_cache(
                        "scan-stats",
                        {**_scan_stats_cache_metadata(context, config), "code_identity": code_identity},
                    )
                    _deactivate_excluded_downstream_records(
                        manifest, "scan-stats", config, selected_stages
                    )
            elif stage == "scan-labels":
                if stage in effective_forced_stages or not _valid_neutral_label_artifact(
                    paths.labels, existing, artifacts["flows"], context, config
                ):
                    _write_pre_m5_labels(artifacts["flows"], config, paths.labels)
                    stage_status = "completed"
                else:
                    stage_status = "reused"
                artifacts["scan-labels"] = paths.labels
                manifest.record_stage("scan-labels", stage_status)
                manifest.record_artifact(
                    "flow_labels",
                    paths.labels,
                    _csv_row_count(paths.labels),
                    {
                        "flow_fingerprint": flow_fingerprint(
                            context.sha256, config, FLOW_SCHEMA_VERSION
                        ),
                        "code_identity": code_identity,
                    }
                    if stage_status == "completed"
                    else None,
                )
                if stage_status == "completed":
                    manifest.record_cache(
                        "scan-labels",
                        {**_neutral_label_cache_metadata(context, config), "code_identity": code_identity},
                    )
            elif stage == "prefixes":
                aguri_path = artifacts["aguri"]
                prefix_producer = _prefix_artifact_producer(
                    context, config, aguri_path, code_identity
                )
                if stage in effective_forced_stages or not _valid_run_artifact(
                    paths.prefixes, existing, "prefixes", config, prefix_producer
                ):
                    if _is_legacy(config):
                        run_legacy_prefix_stage(
                            artifacts["flows"], aguri_path, config, paths.prefixes
                        )
                    else:
                        run_corrected_prefix_stage(aguri_path, config, paths.prefixes)
                    stage_status = "completed"
                else:
                    stage_status = "reused"
                artifacts["prefixes"] = paths.prefixes
                manifest.record_stage("prefixes", stage_status)
                manifest.record_artifact(
                    "prefixes",
                    paths.prefixes,
                    _csv_row_count(paths.prefixes),
                    prefix_producer
                    if stage_status == "completed"
                    else None,
                )
                if stage_status == "completed":
                    _deactivate_excluded_downstream_records(
                        manifest, "prefixes", config, selected_stages
                    )
            elif stage == "membership":
                membership_producer = _membership_artifact_producer(
                    context, config, paths.prefixes, code_identity
                )
                if stage in effective_forced_stages or not _valid_run_artifact(
                    paths.membership, existing, "membership", config, membership_producer
                ):
                    _write_membership(
                        artifacts["flows"], artifacts["prefixes"], paths.membership
                    )
                    stage_status = "completed"
                else:
                    stage_status = "reused"
                artifacts["membership"] = paths.membership
                manifest.record_stage("membership", stage_status)
                manifest.record_artifact(
                    "flow_prefix_membership",
                    paths.membership,
                    _csv_row_count(paths.membership),
                    membership_producer
                    if stage_status == "completed"
                    else None,
                )

        manifest.record_stage("manifest", "completed")
        manifest.finalize_success()
        return 0
    except Exception as error:
        manifest.record_stage(current_stage, "failed")
        manifest.finalize_failure(error)
        raise


def _selected_stages(args: argparse.Namespace, config: ExperimentConfig) -> tuple[str, ...]:
    """Convert an inclusive CLI range to the M0--M4 stages it authorizes."""
    from_stage = args.from_stage or "input"
    to_stage = args.to_stage or ("prefixes" if _is_legacy(config) else "membership")
    if to_stage == "manifest":
        to_stage = "prefixes" if _is_legacy(config) else "membership"
    if from_stage == "manifest":
        raise ValueError("manifest is finalized by M0--M4 runs, not executable")
    stages = _pipeline_stages(config)
    if from_stage not in stages or to_stage not in stages:
        raise ValueError(
            f"{config.experiment.name} does not implement requested stage range "
            f"{from_stage!r} to {to_stage!r}"
        )
    start = stages.index(from_stage)
    end = stages.index(to_stage)
    if start > end:
        raise ValueError("--from must not follow --to")
    selected = stages[start : end + 1]
    return selected


def _forced_stages(
    forced: Iterable[str] | None, config: ExperimentConfig
) -> frozenset[str]:
    """Apply force invalidation from the explicit stage dependency table."""
    values = set(forced or ())
    available_stages = (
        _pipeline_stages(config)
    )
    invalidation = LEGACY_FORCE_INVALIDATES if _is_legacy(config) else FORCE_INVALIDATES
    if "all" in values:
        return frozenset(available_stages)
    unsupported = values & {"manifest"}
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise ValueError(f"manifest cannot be forced as an executable stage: {names}")
    invalidated: set[str] = set()
    for stage in values:
        if stage not in invalidation:
            raise ValueError(f"cannot force stage: {stage}")
        invalidated.update(invalidation[stage])
    return frozenset(invalidated)


def _resolve_input(args: argparse.Namespace, *, dry_run: bool) -> InputResolution:
    if args.input is not None:
        return InputResolution(
            resolve_local_input(args.input.resolve(), args.dataset_id), "reused"
        )
    if args.dataset_id is not None:
        raise ValueError("--dataset-id is only valid with --input")
    if dry_run:
        MawiResolver().resolve(args.dataset)
        cached_path = (
            Path.cwd() / "data" / args.dataset / "raw" / f"{args.dataset}.pcap.gz"
        )
        if cached_path.is_file():
            return InputResolution(resolve_local_input(cached_path, args.dataset), "reused")
        # An uncached dry-run has no raw checksum to fingerprint.  The empty
        # checksum is deliberately planning-only and never reaches a stage.
        return InputResolution(InputContext(args.dataset, cached_path, "", 0), "completed")
    raw_path = Path.cwd() / "data" / args.dataset / "raw" / f"{args.dataset}.pcap.gz"
    reused = raw_path.is_file() and not args.redownload
    return InputResolution(
        MawiDownloader(root=Path.cwd()).fetch(args.dataset, redownload=args.redownload),
        "reused" if reused else "completed",
    )


def _run_paths(dataset_id: str, run_name: str) -> RunPaths:
    run_dir = Path.cwd() / "results" / dataset_id / run_name
    return RunPaths(
        run_dir=run_dir,
        manifest=run_dir / "run_manifest.json",
        scan_windows=run_dir / "source_scan_windows.csv",
        scan_summary=run_dir / "source_scan_summary.csv",
        labels=run_dir / "flow_labels.csv",
        prefixes=run_dir / "prefixes.csv",
        membership=run_dir / "flow_prefix_membership.csv",
    )


def _load_existing_manifest(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunConflictError(f"existing run manifest is unreadable: {path}") from error
    if not isinstance(loaded, dict):
        raise RunConflictError(f"existing run manifest is not an object: {path}")
    return loaded


def _ensure_run_identity(
    existing: dict[str, Any] | None, context: InputContext, config_hash: str
) -> None:
    if existing is None:
        return
    existing_input = existing.get("input") or {}
    existing_sha = existing_input.get("sha256")
    existing_config_hash = (existing.get("config") or {}).get("hash")
    mismatches: list[str] = []
    input_was_never_resolved = existing.get("status") == "failed" and existing.get("input") is None
    if context.sha256 and existing_sha != context.sha256 and not input_was_never_resolved:
        mismatches.append(
            f"existing input_sha256={existing_sha!r}; requested input_sha256={context.sha256!r}"
        )
    if existing_config_hash != config_hash:
        mismatches.append(
            "existing config_hash="
            f"{existing_config_hash!r}; requested config_hash={config_hash!r}"
        )
    if mismatches:
        raise RunConflictError("run identity conflict: " + "; ".join(mismatches))


def _ensure_existing_config_identity(
    existing: dict[str, Any], config_hash: str
) -> None:
    existing_config_hash = (existing.get("config") or {}).get("hash")
    if existing_config_hash != config_hash:
        raise RunConflictError(
            "run identity conflict: existing config_hash="
            f"{existing_config_hash!r}; requested config_hash={config_hash!r}"
        )


def _provisional_run_paths(args: argparse.Namespace, run_name: str) -> RunPaths | None:
    dataset_id = args.dataset if args.dataset is not None else args.dataset_id
    return _run_paths(dataset_id, run_name) if dataset_id is not None else None


def _is_legacy(config: ExperimentConfig) -> bool:
    return config.experiment.name == "paper_legacy"


def _pipeline_stages(config: ExperimentConfig) -> tuple[str, ...]:
    if _is_legacy(config):
        return ("input", "flows", "aguri", "scan-stats", "scan-labels", "prefixes")
    return M0_M4_STAGES


def _deactivate_excluded_downstream_records(
    manifest: RunManifest,
    stage: str,
    config: ExperimentConfig,
    selected_stages: tuple[str, ...],
) -> None:
    downstream = dict(DOWNSTREAM_RUN_RECORDS.get(stage, {}))
    if stage == "flows" and _is_legacy(config):
        downstream["prefixes"] = (frozenset(("prefixes",)), frozenset())
    artifacts: set[str] = set()
    caches: set[str] = set()
    for downstream_stage, (stage_artifacts, stage_caches) in downstream.items():
        if downstream_stage not in selected_stages:
            artifacts.update(stage_artifacts)
            caches.update(stage_caches)
    manifest.deactivate_records(artifacts=artifacts, caches=caches)


def _stage_dependencies(config: ExperimentConfig) -> dict[str, tuple[str, ...]]:
    return LEGACY_STAGE_DEPENDENCIES if _is_legacy(config) else STAGE_DEPENDENCIES


def _ensure_forced_stages_are_selected(
    forced: frozenset[str], selected: tuple[str, ...]
) -> None:
    excluded = sorted(forced - set(selected))
    if excluded:
        raise MissingUpstreamArtifactError(
            "forced stage(s) are excluded by --from/--to: " + ", ".join(excluded)
        )


def _existing_artifacts(
    existing: dict[str, Any] | None,
    config: ExperimentConfig,
    context: InputContext | None = None,
) -> dict[str, Path]:
    if existing is None:
        return {}
    artifacts: dict[str, Path] = {}
    flow_artifact = ((existing.get("artifacts") or {}).get("flows") or {})
    flow_path = flow_artifact.get("path")
    if isinstance(flow_path, str) and _valid_csv_artifact(
        Path(flow_path), flow_artifact.get("row_count"), FLOW_COLUMNS
    ):
        artifacts["flows"] = Path(flow_path)
    aguri_artifact = ((existing.get("artifacts") or {}).get("aguri_candidates") or {})
    aguri_path = aguri_artifact.get("path")
    if isinstance(aguri_path, str) and _valid_csv_artifact(
        Path(aguri_path), aguri_artifact.get("row_count"), AGURI_CANDIDATE_COLUMNS
    ):
        artifacts["aguri"] = Path(aguri_path)
    for manifest_name, stage_name in (
        ("flow_labels", "scan-labels"),
        ("prefixes", "prefixes"),
        ("flow_prefix_membership", "membership"),
    ):
        artifact = ((existing.get("artifacts") or {}).get(manifest_name) or {})
        path = artifact.get("path")
        if isinstance(path, str) and _valid_csv_artifact(
            Path(path), artifact.get("row_count"), _run_artifact_columns(stage_name, config)
        ):
            artifacts[stage_name] = Path(path)
    if context is not None and _valid_scan_stats_artifacts_from_manifest(
        existing, context, config
    ):
        windows_path = ((existing.get("artifacts") or {}).get("source_scan_windows") or {}).get(
            "path"
        )
        assert isinstance(windows_path, str)
        artifacts["scan-stats"] = Path(windows_path)
    return artifacts


def _add_valid_dataset_cache_artifacts(
    artifacts: dict[str, Path], context: InputContext, config: ExperimentConfig
) -> None:
    flow_valid, flow_path = _inspect_flow_cache(context, config)
    if flow_valid:
        artifacts["flows"] = flow_path
    aguri_cache = _inspect_aguri_cache_if_available(context, config)
    if aguri_cache is not None and aguri_cache.valid:
        artifacts["aguri"] = aguri_cache.candidates_path


def _require_omitted_dependencies(
    stage: str,
    selected: tuple[str, ...],
    artifacts: dict[str, Path],
    config: ExperimentConfig,
    existing: dict[str, Any] | None,
    context: InputContext,
) -> None:
    missing = [
        dependency
        for dependency in _stage_dependencies(config)[stage]
        if dependency not in selected
        and (
            dependency not in artifacts
            or not _valid_omitted_dependency(
                dependency, artifacts, existing, context, config
            )
        )
    ]
    if missing:
        raise MissingUpstreamArtifactError(
            f"{stage} requires current upstream artifacts excluded by --from: "
            + ", ".join(missing)
        )


def _planned_decisions(
    selected: tuple[str, ...],
    forced: frozenset[str],
    context: InputContext,
    config: ExperimentConfig,
    paths: RunPaths,
    existing: dict[str, Any] | None,
) -> list[tuple[str, str]]:
    """Return non-mutating execute/reuse decisions for a local dry-run."""
    existing_artifacts = _existing_artifacts(existing, config, context)
    _add_valid_dataset_cache_artifacts(existing_artifacts, context, config)
    decisions: list[tuple[str, str]] = []
    effective_forced = set(forced)
    code_identity = _code_identity()
    for stage in selected:
        if stage == "input":
            decision = "reuse" if context.sha256 else "execute"
        elif stage == "flows":
            decision = "reuse" if stage not in effective_forced and "flows" in existing_artifacts else "execute"
            if decision == "execute":
                effective_forced.update(
                    {"scan-stats", "scan-labels", "membership"}
                    | ({"prefixes"} if _is_legacy(config) else set())
                )
        elif stage == "aguri":
            decision = "reuse" if stage not in effective_forced and "aguri" in existing_artifacts else "execute"
            if decision == "execute":
                effective_forced.update({"prefixes", "membership"})
        elif stage == "scan-stats":
            decision = (
                "reuse"
                if stage not in effective_forced
                and _valid_scan_stats_artifacts(paths, existing, context, config)
                else "execute"
            )
            if decision == "execute":
                effective_forced.add("scan-labels")
        elif stage == "scan-labels":
            decision = (
                "reuse"
                if stage not in effective_forced
                and (flows_path := existing_artifacts.get("flows")) is not None
                and _valid_neutral_label_artifact(
                    paths.labels, existing, flows_path, context, config
                )
                else "execute"
            )
        elif stage == "prefixes":
            aguri_path = existing_artifacts.get("aguri")
            decision = (
                "reuse"
                if stage not in effective_forced
                and aguri_path is not None
                and _valid_run_artifact(
                    paths.prefixes,
                    existing,
                    "prefixes",
                    config,
                    _prefix_artifact_producer(context, config, aguri_path, code_identity),
                )
                else "execute"
            )
        else:
            decision = (
                "reuse"
                if stage not in effective_forced
                and _valid_run_artifact(
                    paths.membership,
                    existing,
                    "membership",
                    config,
                    _membership_artifact_producer(
                        context, config, paths.prefixes, code_identity
                    ),
                )
                else "execute"
            )
        decisions.append((stage, decision))
    return decisions


def _flow_cache_path(context: InputContext, config: ExperimentConfig) -> Path:
    protocols = "-".join(sorted(config.flow.protocols))
    timeout = config.flow.inactive_timeout_seconds
    timeout_name = "no-timeout" if timeout is None else f"timeout-{timeout:g}s"
    fingerprint = flow_fingerprint(context.sha256, config, FLOW_SCHEMA_VERSION)
    return (
        Path.cwd()
        / "data"
        / context.dataset_id
        / "processed"
        / "flows"
        / f"{protocols}-{timeout_name}-{fingerprint[:10]}"
        / "flows.csv"
    )


def _inspect_flow_cache(context: InputContext, config: ExperimentConfig) -> tuple[bool, Path]:
    path = _flow_cache_path(context, config)
    manifest_path = path.parent / "flow_manifest.json"
    if not path.is_file() or not manifest_path.is_file():
        return False, path
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, path
    fingerprint = flow_fingerprint(context.sha256, config, FLOW_SCHEMA_VERSION)
    if (
        manifest.get("input_sha256") != context.sha256
        or manifest.get("fingerprint") != fingerprint
        or manifest.get("schema_version") != FLOW_SCHEMA_VERSION
    ):
        return False, path
    return _valid_csv_artifact(path, manifest.get("row_count"), FLOW_COLUMNS), path


def _inspect_aguri_cache_if_available(
    context: InputContext, config: ExperimentConfig
):
    if not context.sha256:
        return None
    try:
        return inspect_aguri_cache(context, config)
    except FileNotFoundError:
        return None


def _record_aguri_cache(
    manifest: RunManifest, candidates_path: Path, producer: dict[str, Any]
) -> None:
    manifest_path = candidates_path.parent / "aguri_manifest.json"
    try:
        aguri_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    fingerprint = aguri_manifest.get("fingerprint")
    if isinstance(fingerprint, str):
        manifest.record_cache(
            "aguri",
            {
                "fingerprint": fingerprint,
                "manifest_path": str(manifest_path),
                "producer": producer,
            },
        )


def _run_artifact_columns(stage: str, config: ExperimentConfig) -> tuple[str, ...]:
    if stage == "scan-labels":
        return FLOW_LABEL_COLUMNS
    if stage == "prefixes":
        return LEGACY_OUTPUT_COLUMNS if _is_legacy(config) else CORRECTED_LEDGER_COLUMNS
    if stage == "membership":
        return MEMBERSHIP_COLUMNS
    raise ValueError(f"no run-local CSV schema registered for stage {stage!r}")


def _valid_run_artifact(
    path: Path,
    existing: dict[str, Any] | None,
    stage: str,
    config: ExperimentConfig,
    expected_producer: dict[str, Any] | None = None,
) -> bool:
    artifact_name = {
        "scan-labels": "flow_labels",
        "prefixes": "prefixes",
        "membership": "flow_prefix_membership",
    }[stage]
    artifact = ((existing or {}).get("artifacts") or {}).get(artifact_name) or {}
    is_valid = _valid_csv_artifact(
        path, artifact.get("row_count"), _run_artifact_columns(stage, config)
    )
    if not is_valid:
        return False
    return expected_producer is None or artifact.get("producer") == expected_producer


def _reuse_or_produce_artifact_producer(
    existing: dict[str, Any] | None,
    artifact_name: str,
    cache_producer: dict[str, Any],
    producing_code_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    if producing_code_identity is not None:
        return {**cache_producer, "code_identity": producing_code_identity}
    existing_producer = (((existing or {}).get("artifacts") or {}).get(artifact_name) or {}).get(
        "producer"
    )
    if isinstance(existing_producer, dict) and all(
        existing_producer.get(key) == value for key, value in cache_producer.items()
    ):
        return existing_producer
    return cache_producer


def _artifact_producer_rebound(
    existing: dict[str, Any] | None,
    artifact_name: str,
    producer: dict[str, Any],
) -> bool:
    """Whether resuming selected a different upstream artifact producer."""
    previous = (((existing or {}).get("artifacts") or {}).get(artifact_name) or {}).get(
        "producer"
    )
    return isinstance(previous, dict) and previous != producer


def _cache_manifest_producer(path: Path, *, fingerprint_key: str) -> dict[str, Any]:
    manifest_path = path.parent / (
        "flow_manifest.json" if fingerprint_key == "flow_fingerprint" else "aguri_manifest.json"
    )
    producer: dict[str, Any] = {
        "cache_manifest_path": str(manifest_path),
        "cache_manifest_sha256": sha256_file(manifest_path) if manifest_path.is_file() else None,
        fingerprint_key: None,
    }
    if not manifest_path.is_file():
        return producer
    try:
        cache_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return producer
    fingerprint = cache_manifest.get("fingerprint")
    if isinstance(fingerprint, str):
        producer[fingerprint_key] = fingerprint
    return producer


def _flow_artifact_producer(flows_path: Path) -> dict[str, Any]:
    return _cache_manifest_producer(flows_path, fingerprint_key="flow_fingerprint")


def _aguri_artifact_producer(candidates_path: Path) -> dict[str, Any]:
    producer = _cache_manifest_producer(
        candidates_path, fingerprint_key="aguri_fingerprint"
    )
    producer["aguri_candidates_sha256"] = sha256_file(candidates_path)
    return producer


def _valid_omitted_dependency(
    dependency: str,
    artifacts: dict[str, Path],
    existing: dict[str, Any] | None,
    context: InputContext,
    config: ExperimentConfig,
) -> bool:
    manifest_artifacts = (existing or {}).get("artifacts") or {}
    if dependency == "flows":
        producer = (manifest_artifacts.get("flows") or {}).get("producer")
        return isinstance(producer, dict) and producer.get("flow_fingerprint") == flow_fingerprint(
            context.sha256, config, FLOW_SCHEMA_VERSION
        )
    if dependency == "aguri":
        producer = (manifest_artifacts.get("aguri_candidates") or {}).get("producer")
        expected = _aguri_artifact_producer(artifacts["aguri"])
        return isinstance(producer, dict) and all(
            producer.get(key) == expected[key]
            for key in ("aguri_fingerprint", "aguri_candidates_sha256")
        )
    if dependency == "prefixes":
        producer = (manifest_artifacts.get("prefixes") or {}).get("producer")
        if not isinstance(producer, dict) or "aguri" not in artifacts:
            return False
        aguri_producer = _aguri_artifact_producer(artifacts["aguri"])
        return (
            producer.get("aguri_fingerprint") == aguri_producer["aguri_fingerprint"]
            and producer.get("aguri_candidates_sha256")
            == aguri_producer["aguri_candidates_sha256"]
            and (
                not _is_legacy(config)
                or producer.get("flow_fingerprint")
                == flow_fingerprint(context.sha256, config, FLOW_SCHEMA_VERSION)
            )
        )
    return True


def _prefix_artifact_producer(
    context: InputContext,
    config: ExperimentConfig,
    aguri_path: Path,
    code_identity: dict[str, Any],
) -> dict[str, Any]:
    aguri_producer = _aguri_artifact_producer(aguri_path)
    return {
        "flow_fingerprint": flow_fingerprint(context.sha256, config, FLOW_SCHEMA_VERSION)
        if _is_legacy(config)
        else None,
        "aguri_fingerprint": aguri_producer["aguri_fingerprint"],
        "aguri_candidates_sha256": aguri_producer["aguri_candidates_sha256"],
        "code_identity": code_identity,
    }


def _membership_artifact_producer(
    context: InputContext,
    config: ExperimentConfig,
    prefixes_path: Path,
    code_identity: dict[str, Any],
) -> dict[str, Any]:
    return {
        "flow_fingerprint": flow_fingerprint(context.sha256, config, FLOW_SCHEMA_VERSION),
        "prefixes_sha256": sha256_file(prefixes_path),
        "code_identity": code_identity,
    }


def _valid_csv_artifact(
    path: Path, expected_row_count: object, columns: tuple[str, ...]
) -> bool:
    if not isinstance(expected_row_count, int) or expected_row_count < 0:
        return False
    try:
        with path.open(encoding="utf-8", newline="") as csv_file:
            reader = csv.reader(csv_file, strict=True)
            if tuple(next(reader, ())) != columns:
                return False
            return sum(1 for _ in reader) == expected_row_count
    except (OSError, UnicodeError, csv.Error):
        return False


def _write_membership(flows_path: Path, prefixes_path: Path, output_path: Path) -> None:
    membership = build_membership(pd.read_csv(flows_path), pd.read_csv(prefixes_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            membership.to_csv(output, index=False)
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _write_scan_statistics(
    flows_path: Path,
    dataset_id: str,
    config: ExperimentConfig,
    capture_path: Path,
    windows_path: Path,
    summary_path: Path,
) -> None:
    flows = pd.read_csv(flows_path)
    capture_start = capture_start_timestamp(capture_path)
    if capture_start is None:
        capture_start = 0.0
    windows = build_source_scan_windows(
        flows,
        dataset_id,
        config.scan.window_size_seconds,
        config.scan.window_step_seconds,
        capture_start,
    )
    summary = build_source_scan_summary(flows, dataset_id)
    _write_dataframe_atomically(windows, windows_path)
    _write_dataframe_atomically(summary, summary_path)


def _write_pre_m5_labels(
    flows_path: Path, config: ExperimentConfig, output_path: Path
) -> None:
    _write_dataframe_atomically(
        build_pre_m5_flow_labels(pd.read_csv(flows_path), config), output_path
    )


def _valid_neutral_label_artifact(
    path: Path,
    existing: dict[str, Any] | None,
    flows_path: Path,
    context: InputContext,
    config: ExperimentConfig,
) -> bool:
    artifact = ((existing or {}).get("artifacts") or {}).get("flow_labels") or {}
    if not _cache_metadata_matches(
        (existing or {}).get("cache", {}).get("scan-labels"),
        _neutral_label_cache_metadata(context, config),
    ) or not _valid_csv_artifact(
        path, artifact.get("row_count"), FLOW_LABEL_COLUMNS
    ):
        return False
    try:
        labels = pd.read_csv(path)
        flows = pd.read_csv(flows_path, usecols=["flow_id"])
    except (OSError, ValueError, pd.errors.ParserError):
        return False
    if labels["flow_id"].duplicated().any() or flows["flow_id"].duplicated().any():
        return False
    if set(labels["flow_id"].tolist()) != set(flows["flow_id"].tolist()):
        return False
    return labels.loc[:, FLOW_LABEL_COLUMNS[1:]].eq(False).all().all()


def _write_dataframe_atomically(frame: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            frame.to_csv(output, index=False)
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _scan_stats_cache_metadata(
    context: InputContext, config: ExperimentConfig
) -> dict[str, str]:
    return {
        "schema_version": SCAN_STATS_SCHEMA_VERSION,
        "capture_anchor": SCAN_STATS_CAPTURE_ANCHOR,
        "fingerprint": stable_json_hash(
            {
                "schema_version": SCAN_STATS_SCHEMA_VERSION,
                "capture_anchor": SCAN_STATS_CAPTURE_ANCHOR,
                "input_sha256": context.sha256,
                "flow_fingerprint": flow_fingerprint(
                    context.sha256, config, FLOW_SCHEMA_VERSION
                ),
                "window": {
                    "size_seconds": config.scan.window_size_seconds,
                    "step_seconds": config.scan.window_step_seconds,
                    "anchor": config.scan.window_anchor,
                    "membership": config.scan.window_membership,
                },
            }
        ),
    }


def _neutral_label_cache_metadata(
    context: InputContext, config: ExperimentConfig
) -> dict[str, str]:
    scan_stats = _scan_stats_cache_metadata(context, config)
    return {
        "schema_version": NEUTRAL_LABEL_SCHEMA_VERSION,
        "scan_stats_schema_version": scan_stats["schema_version"],
        "scan_stats_fingerprint": scan_stats["fingerprint"],
    }


def _valid_scan_stats_artifacts(
    paths: RunPaths,
    existing: dict[str, Any] | None,
    context: InputContext,
    config: ExperimentConfig,
) -> bool:
    artifacts = (existing or {}).get("artifacts") or {}
    windows = artifacts.get("source_scan_windows") or {}
    summary = artifacts.get("source_scan_summary") or {}
    cache = (existing or {}).get("cache") or {}
    return _cache_metadata_matches(
        cache.get("scan-stats"), _scan_stats_cache_metadata(context, config)
    ) and _valid_csv_artifact(
        paths.scan_windows, windows.get("row_count"), SCAN_WINDOW_COLUMNS
    ) and _valid_csv_artifact(
        paths.scan_summary, summary.get("row_count"), SCAN_SUMMARY_COLUMNS
    )


def _valid_scan_stats_artifacts_from_manifest(
    existing: dict[str, Any], context: InputContext, config: ExperimentConfig
) -> bool:
    artifacts = existing.get("artifacts") or {}
    windows = artifacts.get("source_scan_windows") or {}
    summary = artifacts.get("source_scan_summary") or {}
    windows_path = windows.get("path")
    summary_path = summary.get("path")
    return (
        isinstance(windows_path, str)
        and isinstance(summary_path, str)
        and _cache_metadata_matches(
            (existing.get("cache") or {}).get("scan-stats"),
            _scan_stats_cache_metadata(context, config),
        )
        and _valid_csv_artifact(Path(windows_path), windows.get("row_count"), SCAN_WINDOW_COLUMNS)
        and _valid_csv_artifact(Path(summary_path), summary.get("row_count"), SCAN_SUMMARY_COLUMNS)
    )


def _csv_row_count(path: Path) -> int:
    with path.open(encoding="utf-8", newline="") as csv_file:
        return sum(1 for _ in csv.reader(csv_file)) - 1


def _cache_metadata_matches(recorded: object, expected: dict[str, str]) -> bool:
    return isinstance(recorded, dict) and all(
        recorded.get(key) == value for key, value in expected.items()
    )


def _git_commit() -> str | None:
    repository_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _code_identity() -> dict[str, Any]:
    """Capture source identity for each invocation without relabeling prior outputs."""
    repository_root = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    for source_path in sorted((repository_root / "src" / "mawi_global_analysis").glob("*.py")):
        digest.update(source_path.relative_to(repository_root).as_posix().encode("utf-8"))
        digest.update(source_path.read_bytes())
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return {
        "git_commit": _git_commit(),
        "source_hash": digest.hexdigest(),
        "dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the pipeline parser without starting a run."""
    parser = argparse.ArgumentParser(description="Run the MAWI global analysis pipeline.")
    input_mode = parser.add_mutually_exclusive_group(required=True)
    input_mode.add_argument("--dataset", help="MAWI dataset identifier to resolve")
    input_mode.add_argument("--input", type=Path, help="Local PCAP or PCAP.gz input path")
    parser.add_argument("--dataset-id", help="Dataset identifier for a local input")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/baseline.yaml"),
        help="Experiment configuration YAML (default: configs/baseline.yaml)",
    )
    parser.add_argument("--run-name", help="Override the configured experiment name")
    parser.add_argument("--from", dest="from_stage", choices=STAGE_NAMES)
    parser.add_argument("--to", dest="to_stage", choices=STAGE_NAMES)
    parser.add_argument(
        "--force",
        nargs="+",
        choices=(*STAGE_NAMES, "all"),
        metavar="STAGE",
        help="Invalidate one or more stages, or all stages",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--redownload", action="store_true")
    return parser
