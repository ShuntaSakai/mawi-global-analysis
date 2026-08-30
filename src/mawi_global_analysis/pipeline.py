"""M0--M3 orchestration, cache decisions, and durable run provenance."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from mawi_global_analysis.aguri import inspect_aguri_cache, run_aguri_stage
from mawi_global_analysis.config import ExperimentConfig, load_config
from mawi_global_analysis.dataset import MawiDownloader, MawiResolver, resolve_local_input
from mawi_global_analysis.flow_stage import FLOW_COLUMNS, FLOW_SCHEMA_VERSION, run_flow_stage
from mawi_global_analysis.hashing import flow_fingerprint, sha256_file
from mawi_global_analysis.manifests import RunManifest
from mawi_global_analysis.membership import MEMBERSHIP_COLUMNS, build_membership
from mawi_global_analysis.models import InputContext
from mawi_global_analysis.prefix import (
    CORRECTED_LEDGER_COLUMNS,
    LEGACY_OUTPUT_COLUMNS,
    run_corrected_prefix_stage,
    run_legacy_prefix_stage,
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

M0_M3_STAGES = ("input", "flows", "aguri", "prefixes", "membership")
STAGE_DEPENDENCIES = {
    "input": (),
    "flows": ("input",),
    "aguri": ("input",),
    "prefixes": ("aguri",),
    "membership": ("flows", "prefixes"),
}
FORCE_INVALIDATES = {
    "input": frozenset(M0_M3_STAGES),
    "flows": frozenset(("flows", "membership")),
    "aguri": frozenset(("aguri", "prefixes", "membership")),
    "prefixes": frozenset(("prefixes", "membership")),
    "membership": frozenset(("membership",)),
}
LEGACY_STAGE_DEPENDENCIES = {
    "input": (),
    "flows": ("input",),
    "aguri": ("input",),
    "prefixes": ("flows", "aguri"),
}
LEGACY_FORCE_INVALIDATES = {
    "input": frozenset(("input", "flows", "aguri", "prefixes")),
    "flows": frozenset(("flows", "prefixes")),
    "aguri": frozenset(("aguri", "prefixes")),
    "prefixes": frozenset(("prefixes",)),
}


class RunConflictError(ValueError):
    """Raised when an existing run name belongs to different provenance."""


class MissingUpstreamArtifactError(FileNotFoundError):
    """Raised when a partial run excludes an artifact it needs."""


class UnsupportedStageError(ValueError):
    """Raised for CLI-visible stages intentionally deferred past M3."""


@dataclass(frozen=True)
class RunPaths:
    """Run-specific output locations, kept separate from dataset caches."""

    run_dir: Path
    manifest: Path
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
    """Execute the implemented M0--M3 DAG or print a non-mutating plan.

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

    provisional_paths = _provisional_run_paths(args, run_name)
    manifest: RunManifest | None = None
    existing: dict[str, Any] | None = None
    if not args.dry_run and provisional_paths is not None:
        existing = _load_existing_manifest(provisional_paths.manifest)
        if existing is None:
            manifest = RunManifest.start(
                provisional_paths.manifest,
                provisional_paths.run_dir.parent.name,
                config_path,
                config_text,
                config_hash,
                _git_commit(),
            )
            manifest.record_stage("input", "running")
        else:
            _ensure_existing_config_identity(existing, config_hash)
            manifest = RunManifest.resume(provisional_paths.manifest, _git_commit())
            manifest.record_stage("input", "running")

    try:
        input_resolution = _resolve_input(args, dry_run=args.dry_run)
    except Exception as error:
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
        for stage, decision in _planned_decisions(
            selected_stages, forced_stages, context, config, paths, existing
        ):
            print(f"[{decision.upper()}] {stage}")
        return 0

    if manifest is None:
        manifest = (
            RunManifest.resume(paths.manifest, _git_commit())
            if existing is not None
            else RunManifest.start(
                paths.manifest,
                context.dataset_id,
                config_path,
                config_text,
                config_hash,
                _git_commit(),
            )
        )
        manifest.record_stage("input", "running")
    artifacts = _existing_artifacts(existing, config)
    _add_valid_dataset_cache_artifacts(artifacts, context, config)
    current_stage = "input"
    try:
        manifest.set_input(context.path, context.sha256, context.size_bytes)
        manifest.record_stage("input", input_resolution.stage_status)
        artifacts["input"] = context.path
        manifest.record_artifact("input_pcap", context.path, row_count=1)

        for stage in selected_stages:
            if stage == "input":
                continue
            current_stage = stage
            _require_omitted_dependencies(stage, selected_stages, artifacts, config)
            manifest.record_stage(stage, "running")
            if stage == "flows":
                forced = stage in forced_stages
                flow_cache = _inspect_flow_cache(context, config)
                was_cached = flow_cache[0] and not forced
                flows_path = run_flow_stage(context, config, force=forced)
                artifacts["flows"] = flows_path
                manifest.record_stage("flows", "reused" if was_cached else "completed")
                manifest.record_artifact("flows", flows_path, _csv_row_count(flows_path))
                manifest.record_cache(
                    "flows",
                    {
                        "fingerprint": flow_fingerprint(
                            context.sha256, config, FLOW_SCHEMA_VERSION
                        ),
                        "manifest_path": str(flows_path.parent / "flow_manifest.json"),
                    },
                )
            elif stage == "aguri":
                aguri_cache = _inspect_aguri_cache_if_available(context, config)
                aguri_path = run_aguri_stage(
                    context, config, force=stage in forced_stages
                )
                artifacts["aguri"] = aguri_path
                manifest.record_stage(
                    "aguri",
                    "reused"
                    if aguri_cache is not None
                    and aguri_cache.valid
                    and stage not in forced_stages
                    else "completed",
                )
                manifest.record_artifact(
                    "aguri_candidates", aguri_path, _csv_row_count(aguri_path)
                )
                _record_aguri_cache(manifest, aguri_path)
            elif stage == "prefixes":
                if stage in forced_stages or not _valid_run_artifact(
                    paths.prefixes, existing, "prefixes", config
                ):
                    aguri_path = artifacts["aguri"]
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
                    "prefixes", paths.prefixes, _csv_row_count(paths.prefixes)
                )
            elif stage == "membership":
                if stage in forced_stages or not _valid_run_artifact(
                    paths.membership, existing, "membership", config
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
                )

        manifest.record_stage("manifest", "completed")
        manifest.finalize_success()
        return 0
    except Exception as error:
        manifest.record_stage(current_stage, "failed")
        manifest.finalize_failure(error)
        raise


def _selected_stages(args: argparse.Namespace, config: ExperimentConfig) -> tuple[str, ...]:
    """Convert an inclusive CLI range to the M0--M3 stages it authorizes."""
    from_stage = args.from_stage or "input"
    to_stage = args.to_stage or ("prefixes" if _is_legacy(config) else "membership")
    unsupported = {from_stage, to_stage} & {"scan-stats", "scan-labels"}
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise UnsupportedStageError(f"Task 11 implements M0--M3 only; deferred: {names}")
    if to_stage == "manifest":
        to_stage = "membership"
    if from_stage == "manifest":
        raise UnsupportedStageError("manifest is finalized by M0--M3 runs, not executable")
    start = M0_M3_STAGES.index(from_stage)
    end = M0_M3_STAGES.index(to_stage)
    if start > end:
        raise ValueError("--from must not follow --to")
    selected = M0_M3_STAGES[start : end + 1]
    if _is_legacy(config) and "membership" in selected:
        raise UnsupportedStageError(
            "paper_legacy has no corrected flow-prefix membership stage"
        )
    return selected


def _forced_stages(
    forced: Iterable[str] | None, config: ExperimentConfig
) -> frozenset[str]:
    """Apply force invalidation from the explicit stage dependency table."""
    values = set(forced or ())
    available_stages = (
        ("input", "flows", "aguri", "prefixes") if _is_legacy(config) else M0_M3_STAGES
    )
    invalidation = LEGACY_FORCE_INVALIDATES if _is_legacy(config) else FORCE_INVALIDATES
    if "all" in values:
        return frozenset(available_stages)
    unsupported = values & {"scan-stats", "scan-labels", "manifest"}
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise UnsupportedStageError(f"Task 11 cannot force deferred stage(s): {names}")
    invalidated: set[str] = set()
    for stage in values:
        if stage not in invalidation:
            raise UnsupportedStageError(f"Task 11 cannot force stage: {stage}")
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
    if context.sha256 and existing_sha != context.sha256:
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
    existing: dict[str, Any] | None, config: ExperimentConfig
) -> dict[str, Path]:
    if existing is None:
        return {}
    artifacts: dict[str, Path] = {}
    for manifest_name, stage_name in (
        ("prefixes", "prefixes"),
        ("flow_prefix_membership", "membership"),
    ):
        artifact = ((existing.get("artifacts") or {}).get(manifest_name) or {})
        path = artifact.get("path")
        if isinstance(path, str) and _valid_csv_artifact(
            Path(path), artifact.get("row_count"), _run_artifact_columns(stage_name, config)
        ):
            artifacts[stage_name] = Path(path)
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
) -> None:
    missing = [
        dependency
        for dependency in _stage_dependencies(config)[stage]
        if dependency not in selected and dependency not in artifacts
    ]
    if missing:
        raise MissingUpstreamArtifactError(
            f"{stage} requires upstream artifacts excluded by --from: {', '.join(missing)}"
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
    existing_artifacts = _existing_artifacts(existing, config)
    _add_valid_dataset_cache_artifacts(existing_artifacts, context, config)
    decisions: list[tuple[str, str]] = []
    for stage in selected:
        if stage == "input":
            decision = "reuse" if context.sha256 else "execute"
        elif stage == "flows":
            decision = "reuse" if stage not in forced and "flows" in existing_artifacts else "execute"
        elif stage == "aguri":
            decision = "reuse" if stage not in forced and "aguri" in existing_artifacts else "execute"
        elif stage == "prefixes":
            decision = (
                "reuse"
                if stage not in forced
                and _valid_run_artifact(paths.prefixes, existing, "prefixes", config)
                else "execute"
            )
        else:
            decision = (
                "reuse"
                if stage not in forced
                and _valid_run_artifact(paths.membership, existing, "membership", config)
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


def _record_aguri_cache(manifest: RunManifest, candidates_path: Path) -> None:
    manifest_path = candidates_path.parent / "aguri_manifest.json"
    try:
        aguri_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    fingerprint = aguri_manifest.get("fingerprint")
    if isinstance(fingerprint, str):
        manifest.record_cache(
            "aguri",
            {"fingerprint": fingerprint, "manifest_path": str(manifest_path)},
        )


def _run_artifact_columns(stage: str, config: ExperimentConfig) -> tuple[str, ...]:
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
) -> bool:
    artifact_name = "prefixes" if stage == "prefixes" else "flow_prefix_membership"
    artifact = ((existing or {}).get("artifacts") or {}).get(artifact_name) or {}
    return _valid_csv_artifact(
        path, artifact.get("row_count"), _run_artifact_columns(stage, config)
    )


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


def _csv_row_count(path: Path) -> int:
    with path.open(encoding="utf-8", newline="") as csv_file:
        return sum(1 for _ in csv.reader(csv_file)) - 1


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
