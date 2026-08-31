from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.io import load_run
from mawi_global_analysis.manifests import RunManifest
from mawi_global_analysis import pipeline


ROOT = Path(__file__).parents[2]
PCAP_PATH = ROOT / "tests" / "fixtures" / "pcaps" / "tcp_patterns.pcap"
CANDIDATES_PATH = ROOT / "tests" / "fixtures" / "aguri" / "sample_candidates.csv"
CONFIG_PATH = ROOT / "configs" / "baseline.yaml"
LEGACY_CONFIG_PATH = ROOT / "configs" / "paper_legacy.yaml"


def _args(*arguments: str):
    return pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "fixture",
            "--config",
            str(CONFIG_PATH),
            *arguments,
        ]
    )


def _stub_aguri(monkeypatch, tmp_path: Path) -> None:
    def copy_candidates(ctx, cfg, force=False):
        target = tmp_path / "data" / ctx.dataset_id / "processed" / "aguri" / "stub"
        target.mkdir(parents=True, exist_ok=True)
        candidates = target / "aguri_candidates.csv"
        candidates.write_bytes(CANDIDATES_PATH.read_bytes())
        return candidates

    monkeypatch.setattr("mawi_global_analysis.pipeline.run_aguri_stage", copy_candidates)


def _configured_aguri_command(tmp_path: Path, dataset_id: str) -> tuple[list[str], Path]:
    aguri3 = tmp_path / f"{dataset_id}-aguri3"
    aguri3.write_text("#!/bin/sh\ncp \"$2\" \"$4\"\n", encoding="utf-8")
    aguri3.chmod(0o755)
    agurim = tmp_path / f"{dataset_id}-agurim"
    agurim.write_text(
        "#!/bin/sh\nprintf '%s\\n' '[ 1] 198.51.100.0/24 192.0.2.0/24: 100 (100.00%) 2 (100.00%)' '\t[6:40000:80] 100.00% 100.00%' > \"$2\"\n",
        encoding="utf-8",
    )
    agurim.chmod(0o755)
    config_path = tmp_path / f"{dataset_id}-baseline.yaml"
    config_path.write_text(
        CONFIG_PATH.read_text(encoding="utf-8")
        .replace("aguri3_executable: null", f"aguri3_executable: {aguri3}")
        .replace("agurim_executable: null", f"agurim_executable: {agurim}"),
        encoding="utf-8",
    )
    return (
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            dataset_id,
            "--config",
            str(config_path),
        ],
        agurim,
    )


def test_dry_run_reports_m0_m3_decisions_without_creating_artifacts(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Planning local M0--M3 work must not create result or cache paths."""
    monkeypatch.chdir(tmp_path)

    assert pipeline.run_pipeline(_args("--dry-run")) == 0

    output = capsys.readouterr().out
    assert "[REUSE] input" in output
    assert "[EXECUTE] flows" in output
    assert "[EXECUTE] aguri" in output
    assert "[EXECUTE] prefixes" in output
    assert "[EXECUTE] membership" in output
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "results").exists()


def test_dataset_dry_run_never_downloads_a_trace(tmp_path: Path, monkeypatch) -> None:
    """Planning an uncached MAWI dataset must not retrieve the raw capture."""
    monkeypatch.chdir(tmp_path)

    def unexpected_fetch(*args, **kwargs):
        raise AssertionError("dry-run must not call the downloader")

    monkeypatch.setattr(
        "mawi_global_analysis.pipeline.MawiDownloader.fetch", unexpected_fetch
    )
    args = pipeline.build_parser().parse_args(
        ["--dataset", "202604081400", "--config", str(CONFIG_PATH), "--dry-run"]
    )

    assert pipeline.run_pipeline(args) == 0
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize("stage", ["flows", "aguri"])
def test_local_input_dry_run_partial_upstream_stage_has_execution_dependency_parity(
    tmp_path: Path, monkeypatch, capsys, stage: str
) -> None:
    """A resolved local input satisfies partial dry-run dependencies without writes."""
    monkeypatch.chdir(tmp_path)

    assert pipeline.run_pipeline(
        _args("--dry-run", "--from", stage, "--to", stage)
    ) == 0

    assert f"[EXECUTE] {stage}" in capsys.readouterr().out
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "results").exists()


def test_existing_run_requires_matching_input_and_configuration_identity(
    tmp_path: Path, monkeypatch
) -> None:
    """A run name cannot overwrite a manifest created for other provenance."""
    monkeypatch.chdir(tmp_path)
    config_text = CONFIG_PATH.read_text(encoding="utf-8")
    manifest = RunManifest.start(
        tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json",
        dataset_id="fixture",
        config_path=CONFIG_PATH,
        config_text=config_text,
        config_hash=sha256_file(CONFIG_PATH),
        git_commit=None,
    )
    manifest.set_input(PCAP_PATH, "different-input-sha", PCAP_PATH.stat().st_size)
    manifest.finalize_success()

    with pytest.raises(
        pipeline.RunConflictError, match="existing input_sha256=.*requested"
    ):
        pipeline.run_pipeline(_args("--dry-run"))


def test_existing_run_requires_matching_configuration_hash(
    tmp_path: Path, monkeypatch
) -> None:
    """Changing a config behind the same run name must be an explicit conflict."""
    monkeypatch.chdir(tmp_path)
    config_text = CONFIG_PATH.read_text(encoding="utf-8")
    manifest = RunManifest.start(
        tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json",
        dataset_id="fixture",
        config_path=CONFIG_PATH,
        config_text=config_text,
        config_hash=sha256_file(CONFIG_PATH),
        git_commit=None,
    )
    manifest.set_input(PCAP_PATH, sha256_file(PCAP_PATH), PCAP_PATH.stat().st_size)
    manifest.finalize_success()
    changed_config = tmp_path / "changed-baseline.yaml"
    changed_config.write_text(
        config_text.replace("description: Corrected raw analysis", "description: Changed"),
        encoding="utf-8",
    )
    changed_args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "fixture",
            "--config",
            str(changed_config),
            "--dry-run",
        ]
    )

    with pytest.raises(pipeline.RunConflictError, match="existing config_hash=.*requested"):
        pipeline.run_pipeline(changed_args)


def test_membership_only_requires_existing_flow_and_prefix_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    """A partial request must not rebuild stages excluded by --from."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(
        pipeline.MissingUpstreamArtifactError, match="membership requires"
    ):
        pipeline.run_pipeline(_args("--from", "membership", "--to", "membership"))


@pytest.mark.parametrize(
    ("arguments", "forced_stage"),
    [
        (("--from", "membership", "--to", "membership", "--force", "flows"), "flows"),
        (("--from", "prefixes", "--to", "prefixes", "--force", "aguri"), "aguri"),
    ],
)
def test_force_rejects_an_upstream_stage_excluded_by_partial_execution(
    tmp_path: Path, monkeypatch, arguments: tuple[str, ...], forced_stage: str
) -> None:
    """A forced stage must not disappear merely because --from excludes it."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(pipeline.MissingUpstreamArtifactError, match=forced_stage):
        pipeline.run_pipeline(_args(*arguments, "--dry-run"))


def test_input_resolution_failure_finalizes_a_provisional_manifest(
    tmp_path: Path, monkeypatch
) -> None:
    """A dataset download error retains an input-stage failure record."""
    monkeypatch.chdir(tmp_path)

    def fail_fetch(*args, **kwargs):
        raise OSError("download unavailable")

    monkeypatch.setattr("mawi_global_analysis.pipeline.MawiDownloader.fetch", fail_fetch)
    args = pipeline.build_parser().parse_args(
        ["--dataset", "202604081400", "--config", str(CONFIG_PATH)]
    )

    with pytest.raises(OSError, match="download unavailable"):
        pipeline.run_pipeline(args)

    manifest = json.loads(
        (tmp_path / "results" / "202604081400" / "baseline" / "run_manifest.json").read_text()
    )
    assert manifest["status"] == "failed"
    assert manifest["stages"][-1] == {"name": "input", "status": "failed"}


def test_input_resolution_failure_does_not_mutate_successful_manifest_before_identity_check(
    tmp_path: Path, monkeypatch
) -> None:
    """A successful run is not reopened until a new input identity is resolved."""
    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json"
    manifest = RunManifest.start(
        manifest_path,
        "fixture",
        CONFIG_PATH,
        CONFIG_PATH.read_text(encoding="utf-8"),
        sha256_file(CONFIG_PATH),
        "historic-code",
    )
    manifest.set_input(PCAP_PATH, sha256_file(PCAP_PATH), PCAP_PATH.stat().st_size)
    manifest.finalize_success()

    def fail_resolution(*args, **kwargs):
        raise OSError("input disappeared")

    monkeypatch.setattr("mawi_global_analysis.pipeline.resolve_local_input", fail_resolution)

    with pytest.raises(OSError, match="input disappeared"):
        pipeline.run_pipeline(_args())

    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert persisted["status"] == "success"
    assert len(persisted["invocations"]) == 1


@pytest.mark.parametrize(
    ("artifact_name", "contents", "expected_stage"),
    [
        ("prefixes.csv", "broken,prefix,header\n", "prefixes"),
        (
            "flow_prefix_membership.csv",
            "flow_id,analysis_scope,analysis_prefix,src_match,dst_match\n",
            "membership",
        ),
    ],
)
def test_dry_run_rejects_corrupted_run_local_reuse(
    tmp_path: Path,
    monkeypatch,
    capsys,
    artifact_name: str,
    contents: str,
    expected_stage: str,
) -> None:
    """Dry-run must apply the execution-time CSV validation before reporting reuse."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    (tmp_path / "results" / "fixture" / "baseline" / artifact_name).write_text(
        contents, encoding="utf-8"
    )
    capsys.readouterr()

    assert pipeline.run_pipeline(_args("--dry-run")) == 0

    assert f"[EXECUTE] {expected_stage}" in capsys.readouterr().out


def test_dry_run_rejects_run_local_artifacts_without_producer_identity(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A header-valid table without its producer binding cannot be reused."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    manifest_path = tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["prefixes"].pop("producer")
    manifest["artifacts"]["flow_prefix_membership"].pop("producer")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert pipeline.run_pipeline(_args("--dry-run")) == 0

    output = capsys.readouterr().out
    assert "[EXECUTE] prefixes" in output
    assert "[EXECUTE] membership" in output


def test_dry_run_does_not_reuse_an_unvalidated_aguri_artifact(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """An arbitrary candidate CSV is not evidence of a semantic Aguri cache hit."""
    monkeypatch.chdir(tmp_path)
    cached = tmp_path / "data" / "fixture" / "processed" / "aguri" / "old"
    cached.mkdir(parents=True)
    candidate = cached / "aguri_candidates.csv"
    candidate.write_text("not,a,valid,aguri,header\n", encoding="utf-8")
    manifest = RunManifest.start(
        tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json",
        "fixture",
        CONFIG_PATH,
        CONFIG_PATH.read_text(encoding="utf-8"),
        sha256_file(CONFIG_PATH),
        None,
    )
    manifest.set_input(PCAP_PATH, sha256_file(PCAP_PATH), PCAP_PATH.stat().st_size)
    manifest.record_artifact("aguri_candidates", candidate, 1)
    manifest.finalize_success()

    assert pipeline.run_pipeline(_args("--dry-run")) == 0

    assert "[EXECUTE] aguri" in capsys.readouterr().out


def test_resumption_records_the_code_identity_and_cache_fingerprints(
    tmp_path: Path, monkeypatch
) -> None:
    """Each invocation must identify its executing code without erasing history."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    commits = iter(("first-code", "resumed-code"))
    monkeypatch.setattr("mawi_global_analysis.pipeline._git_commit", lambda: next(commits))

    assert pipeline.run_pipeline(_args()) == 0
    assert pipeline.run_pipeline(_args()) == 0

    manifest = json.loads(
        (tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json").read_text()
    )
    assert [entry["git_commit"] for entry in manifest["invocations"]] == [
        "first-code",
        "resumed-code",
    ]
    assert manifest["git_commit"] == "first-code"
    assert manifest["code_identity"]["git_commit"] == "first-code"
    assert [entry["code_identity"]["git_commit"] for entry in manifest["invocations"]] == [
        "first-code",
        "resumed-code",
    ]
    assert manifest["artifacts"]["flows"]["producer"]["code_identity"]["git_commit"] == "first-code"
    assert manifest["cache"]["flows"]["fingerprint"]
    assert manifest["cache"]["flows"]["manifest_path"].endswith("flow_manifest.json")


def _latest_stage_statuses(manifest: dict[str, object]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for stage in manifest["stages"]:  # type: ignore[index]
        statuses[stage["name"]] = stage["status"]  # type: ignore[index]
    return statuses


def test_semantic_flow_cache_change_rebuilds_included_dependents(
    tmp_path: Path, monkeypatch
) -> None:
    """New canonical-flow semantics cannot reuse run-local downstream tables."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0

    import mawi_global_analysis.flow_stage as flow_stage

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-next")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-next")
    assert pipeline.run_pipeline(_args()) == 0

    manifest = json.loads(
        (tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json").read_text()
    )
    statuses = _latest_stage_statuses(manifest)
    assert statuses["flows"] == "completed"
    assert statuses["scan-stats"] == "completed"
    assert statuses["scan-labels"] == "completed"
    assert statuses["membership"] == "completed"


def test_partial_executed_flow_deactivates_excluded_dependent_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    """A successful partial flow run cannot leave an old coherent run loadable."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    run_dir = tmp_path / "results" / "fixture" / "baseline"
    stale_files = (
        run_dir / "source_scan_windows.csv",
        run_dir / "source_scan_summary.csv",
        run_dir / "flow_labels.csv",
        run_dir / "flow_prefix_membership.csv",
    )
    assert all(path.is_file() for path in stale_files)

    import mawi_global_analysis.flow_stage as flow_stage

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-next")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-next")
    assert pipeline.run_pipeline(_args("--to", "flows")) == 0

    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "success"
    assert "prefixes" in manifest["artifacts"]
    assert not {
        "source_scan_windows",
        "source_scan_summary",
        "flow_labels",
        "flow_prefix_membership",
    } & set(manifest["artifacts"])
    assert not {"scan-stats", "scan-labels"} & set(manifest["cache"])
    assert all(path.is_file() for path in stale_files)

    with pytest.raises(
        FileNotFoundError, match="missing required artifact entry: flow_labels"
    ):
        load_run("fixture", "baseline", root=tmp_path)
    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="scan-stats"):
        pipeline.run_pipeline(
            _args("--dry-run", "--from", "scan-labels", "--to", "scan-labels")
        )


def test_executed_flow_rebinds_artifact_and_cache_to_the_new_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """Regenerated flows must not retain the prior cache producer identity."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    identities = iter(
        (
            {"git_commit": "old-code", "source_hash": "old", "dirty": False},
            {"git_commit": "new-code", "source_hash": "new", "dirty": True},
        )
    )
    monkeypatch.setattr(pipeline, "_code_identity", lambda: next(identities))
    assert pipeline.run_pipeline(_args()) == 0

    import mawi_global_analysis.flow_stage as flow_stage

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-next")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-next")
    assert pipeline.run_pipeline(_args()) == 0

    manifest = json.loads(
        (tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json").read_text()
    )
    expected_fingerprint = pipeline.flow_fingerprint(
        sha256_file(PCAP_PATH), pipeline.load_config(CONFIG_PATH), "flows-v-next"
    )
    producer = manifest["artifacts"]["flows"]["producer"]
    assert producer["flow_fingerprint"] == expected_fingerprint
    assert producer["code_identity"]["git_commit"] == "new-code"
    assert manifest["cache"]["flows"]["fingerprint"] == expected_fingerprint
    assert manifest["cache"]["flows"]["producer"] == producer
    monkeypatch.setattr(
        pipeline,
        "_code_identity",
        lambda: {"git_commit": "new-code", "source_hash": "new", "dirty": True},
    )
    assert pipeline.run_pipeline(
        _args("--from", "scan-stats", "--to", "scan-stats")
    ) == 0
    assert pipeline.run_pipeline(
        _args("--from", "scan-stats", "--to", "scan-stats", "--dry-run")
    ) == 0


def test_partial_scan_stats_rejects_a_stale_excluded_flow_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """A partial scan-stat run must not stamp old flows with a new fingerprint."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0

    import mawi_global_analysis.flow_stage as flow_stage

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-next")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-next")
    partial = _args("--from", "scan-stats", "--to", "scan-stats")

    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="flows"):
        pipeline.run_pipeline(partial)
    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="flows"):
        pipeline.run_pipeline(_args("--from", "scan-stats", "--to", "scan-stats", "--dry-run"))


def test_partial_membership_rejects_a_stale_excluded_prefix_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """Membership cannot consume prefixes made from a different Aguri identity."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    manifest_path = tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"]["prefixes"]["producer"]["aguri_fingerprint"] = "old-aguri"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="prefixes"):
        pipeline.run_pipeline(_args("--from", "membership", "--to", "membership"))
    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="prefixes"):
        pipeline.run_pipeline(
            _args("--from", "membership", "--to", "membership", "--dry-run")
        )


def test_fresh_run_records_reused_flow_cache_as_its_cache_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """A reused shared flow cache is not falsely attributed to the new run code."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args("--from", "flows", "--to", "flows")) == 0
    monkeypatch.setattr(
        pipeline,
        "_code_identity",
        lambda: {"git_commit": "new-run", "source_hash": "new", "dirty": True},
    )

    assert pipeline.run_pipeline(
        _args("--from", "flows", "--to", "flows", "--run-name", "fresh-flow")
    ) == 0
    manifest = json.loads(
        (tmp_path / "results" / "fixture" / "fresh-flow" / "run_manifest.json").read_text()
    )
    producer = manifest["artifacts"]["flows"]["producer"]
    assert producer["cache_manifest_sha256"]
    assert "code_identity" not in producer
    assert manifest["cache"]["flows"]["producer"] == producer


def test_resumed_run_rebinds_a_newer_reused_flow_cache_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """A resumed run must bind reuse to the selected shared flow cache."""
    monkeypatch.chdir(tmp_path)
    identities = iter(
        (
            {"git_commit": "old-code", "source_hash": "old", "dirty": False},
            {"git_commit": "builder-code", "source_hash": "builder", "dirty": False},
            {"git_commit": "resume-code", "source_hash": "resume", "dirty": True},
        )
    )
    monkeypatch.setattr(pipeline, "_code_identity", lambda: next(identities))
    partial = ("--from", "flows", "--to", "flows")
    assert pipeline.run_pipeline(_args(*partial)) == 0

    import mawi_global_analysis.flow_stage as flow_stage

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-next")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-next")
    assert pipeline.run_pipeline(
        _args(*partial, "--run-name", "new-flow-cache")
    ) == 0
    builder_manifest = json.loads(
        (
            tmp_path
            / "results"
            / "fixture"
            / "new-flow-cache"
            / "run_manifest.json"
        ).read_text(encoding="utf-8")
    )
    expected = dict(builder_manifest["artifacts"]["flows"]["producer"])
    expected.pop("code_identity")

    assert pipeline.run_pipeline(_args(*partial)) == 0

    resumed = json.loads(
        (
            tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert _latest_stage_statuses(resumed)["flows"] == "reused"
    assert resumed["artifacts"]["flows"]["producer"] == expected
    assert resumed["cache"]["flows"]["producer"] == expected
    assert resumed["cache"]["flows"]["manifest_path"] == expected["cache_manifest_path"]
    assert resumed["cache"]["flows"]["fingerprint"] == expected["flow_fingerprint"]
    assert "code_identity" not in resumed["artifacts"]["flows"]["producer"]


def test_reused_flow_rebind_rebuilds_included_dependents_and_deactivates_excluded_ones(
    tmp_path: Path, monkeypatch
) -> None:
    """A shared-flow producer rebind cannot leave successful mixed provenance."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0

    import mawi_global_analysis.flow_stage as flow_stage

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-next")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-next")
    partial = ("--from", "flows", "--to", "flows")
    assert pipeline.run_pipeline(_args(*partial, "--run-name", "new-flow-cache")) == 0

    assert pipeline.run_pipeline(_args()) == 0
    run_dir = tmp_path / "results" / "fixture" / "baseline"
    rebuilt = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    statuses = _latest_stage_statuses(rebuilt)
    assert statuses["flows"] == "reused"
    assert statuses["scan-stats"] == "completed"
    assert statuses["scan-labels"] == "completed"
    assert statuses["membership"] == "completed"
    load_run("fixture", "baseline", root=tmp_path)

    monkeypatch.setattr(pipeline, "FLOW_SCHEMA_VERSION", "flows-v-third")
    monkeypatch.setattr(flow_stage, "FLOW_SCHEMA_VERSION", "flows-v-third")
    assert pipeline.run_pipeline(_args(*partial, "--run-name", "third-flow-cache")) == 0
    assert pipeline.run_pipeline(_args("--to", "flows")) == 0

    rebound = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert rebound["status"] == "success"
    assert not {
        "source_scan_windows",
        "source_scan_summary",
        "flow_labels",
        "flow_prefix_membership",
    } & set(rebound["artifacts"])
    assert not {"scan-stats", "scan-labels"} & set(rebound["cache"])
    with pytest.raises(FileNotFoundError, match="missing required artifact entry: flow_labels"):
        load_run("fixture", "baseline", root=tmp_path)


def test_executed_aguri_rebuilds_included_prefix_dependents(
    tmp_path: Path, monkeypatch
) -> None:
    """A non-reused Aguri candidate artifact invalidates prefix-derived outputs."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    assert pipeline.run_pipeline(_args()) == 0

    manifest = json.loads(
        (tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json").read_text()
    )
    statuses = _latest_stage_statuses(manifest)
    assert statuses["aguri"] == "completed"
    assert statuses["prefixes"] == "completed"
    assert statuses["membership"] == "completed"


def test_input_conflict_does_not_mutate_successful_manifest_before_comparison(
    tmp_path: Path, monkeypatch
) -> None:
    """An incompatible resolved input must not relabel a prior successful run."""
    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json"
    manifest = RunManifest.start(
        manifest_path, "fixture", CONFIG_PATH, CONFIG_PATH.read_text(),
        sha256_file(CONFIG_PATH), "historic-code"
    )
    manifest.set_input(PCAP_PATH, "different-input-sha", PCAP_PATH.stat().st_size)
    manifest.finalize_success()
    before = manifest_path.read_text()

    with pytest.raises(pipeline.RunConflictError, match="existing input_sha256"):
        pipeline.run_pipeline(_args())

    assert manifest_path.read_text() == before


def test_pre_input_failed_manifest_allows_resolved_input_retry(
    tmp_path: Path, monkeypatch
) -> None:
    """A failed download with no checksum is not an incompatible historical input."""
    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "results" / "fixture" / "baseline" / "run_manifest.json"
    manifest = RunManifest.start(
        manifest_path, "fixture", CONFIG_PATH, CONFIG_PATH.read_text(),
        sha256_file(CONFIG_PATH), "failed-before-input"
    )
    manifest.finalize_failure(OSError("download unavailable"))
    _stub_aguri(monkeypatch, tmp_path)

    assert pipeline.run_pipeline(_args()) == 0
    persisted = json.loads(manifest_path.read_text())
    assert persisted["status"] == "success"
    assert persisted["input"]["sha256"] == sha256_file(PCAP_PATH)


def test_pipeline_reuses_a_fingerprint_valid_aguri_cache(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A valid dataset-wide Aguri manifest produces reuse decisions and stage history."""
    monkeypatch.chdir(tmp_path)
    aguri3 = tmp_path / "aguri3"
    aguri3.write_text("#!/bin/sh\ncp \"$2\" \"$4\"\n", encoding="utf-8")
    aguri3.chmod(0o755)
    agurim = tmp_path / "agurim"
    agurim.write_text(
        "#!/bin/sh\nprintf '%s\\n' '[ 1] 198.51.100.0/24 192.0.2.0/24: 100 (100.00%) 2 (100.00%)' '\t[6:40000:80] 100.00% 100.00%' > \"$2\"\n",
        encoding="utf-8",
    )
    agurim.chmod(0o755)
    config_path = tmp_path / "configured-baseline.yaml"
    config_path.write_text(
        CONFIG_PATH.read_text(encoding="utf-8")
        .replace("aguri3_executable: null", f"aguri3_executable: {aguri3}")
        .replace("agurim_executable: null", f"agurim_executable: {agurim}"),
        encoding="utf-8",
    )
    command = [
        "--input",
        str(PCAP_PATH),
        "--dataset-id",
        "aguri-cache-fixture",
        "--config",
        str(config_path),
    ]

    assert pipeline.run_pipeline(pipeline.build_parser().parse_args(command)) == 0
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args([*command, "--dry-run"])
    ) == 0
    assert "[REUSE] aguri" in capsys.readouterr().out
    assert pipeline.run_pipeline(pipeline.build_parser().parse_args(command)) == 0

    manifest = json.loads(
        (
            tmp_path
            / "results"
            / "aguri-cache-fixture"
            / "baseline"
            / "run_manifest.json"
        ).read_text()
    )
    assert manifest["cache"]["aguri"]["fingerprint"]
    assert [stage["status"] for stage in manifest["stages"] if stage["name"] == "aguri"][-1] == "reused"

    monkeypatch.setattr(
        pipeline,
        "_code_identity",
        lambda: {"git_commit": "new-run", "source_hash": "new", "dirty": True},
    )
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args(
            [*command, "--from", "aguri", "--to", "aguri", "--run-name", "fresh-aguri"]
        )
    ) == 0
    fresh = json.loads(
        (tmp_path / "results" / "aguri-cache-fixture" / "fresh-aguri" / "run_manifest.json").read_text()
    )
    producer = fresh["artifacts"]["aguri_candidates"]["producer"]
    assert producer["cache_manifest_sha256"]
    assert "code_identity" not in producer
    assert fresh["cache"]["aguri"]["producer"] == producer


def test_executed_aguri_rebinds_artifact_and_cache_to_the_new_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """A changed Aguri executable must replace old run-local producer metadata."""
    monkeypatch.chdir(tmp_path)
    command_args, agurim = _configured_aguri_command(
        tmp_path, "aguri-producer-fixture"
    )
    command = pipeline.build_parser().parse_args(command_args)
    identities = iter(
        (
            {"git_commit": "old-code", "source_hash": "old", "dirty": False},
            {"git_commit": "new-code", "source_hash": "new", "dirty": True},
        )
    )
    monkeypatch.setattr(pipeline, "_code_identity", lambda: next(identities))
    assert pipeline.run_pipeline(command) == 0
    old_manifest = json.loads(
        (
            tmp_path
            / "results"
            / "aguri-producer-fixture"
            / "baseline"
            / "run_manifest.json"
        ).read_text()
    )
    old_fingerprint = old_manifest["artifacts"]["aguri_candidates"]["producer"][
        "aguri_fingerprint"
    ]

    agurim.write_text(agurim.read_text() + "# changed executable identity\n")
    assert pipeline.run_pipeline(command) == 0

    manifest = json.loads(
        (
            tmp_path
            / "results"
            / "aguri-producer-fixture"
            / "baseline"
            / "run_manifest.json"
        ).read_text()
    )
    producer = manifest["artifacts"]["aguri_candidates"]["producer"]
    assert producer["aguri_fingerprint"] != old_fingerprint
    assert producer["code_identity"]["git_commit"] == "new-code"
    assert manifest["cache"]["aguri"]["fingerprint"] == producer["aguri_fingerprint"]
    assert manifest["cache"]["aguri"]["producer"] == producer
    monkeypatch.setattr(
        pipeline,
        "_code_identity",
        lambda: {"git_commit": "new-code", "source_hash": "new", "dirty": True},
    )
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args(
            [*command_args, "--from", "prefixes", "--to", "prefixes"]
        )
    ) == 0
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args(
            [
                *command_args,
                "--from",
                "prefixes",
                "--to",
                "prefixes",
                "--dry-run",
            ]
        )
    ) == 0


def test_resumed_run_rebinds_a_newer_reused_aguri_cache_producer(
    tmp_path: Path, monkeypatch
) -> None:
    """A resumed run must bind reuse to the selected shared Aguri cache."""
    monkeypatch.chdir(tmp_path)
    command, agurim = _configured_aguri_command(tmp_path, "aguri-rebind-fixture")
    identities = iter(
        (
            {"git_commit": "old-code", "source_hash": "old", "dirty": False},
            {"git_commit": "builder-code", "source_hash": "builder", "dirty": False},
            {"git_commit": "resume-code", "source_hash": "resume", "dirty": True},
        )
    )
    monkeypatch.setattr(pipeline, "_code_identity", lambda: next(identities))
    partial = ("--from", "aguri", "--to", "aguri")
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args([*command, *partial])
    ) == 0

    agurim.write_text(
        agurim.read_text(encoding="utf-8") + "# newer semantic cache\n",
        encoding="utf-8",
    )
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args(
            [*command, *partial, "--run-name", "new-aguri-cache"]
        )
    ) == 0
    builder_manifest = json.loads(
        (
            tmp_path
            / "results"
            / "aguri-rebind-fixture"
            / "new-aguri-cache"
            / "run_manifest.json"
        ).read_text(encoding="utf-8")
    )
    expected = dict(
        builder_manifest["artifacts"]["aguri_candidates"]["producer"]
    )
    expected.pop("code_identity")

    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args([*command, *partial])
    ) == 0

    resumed = json.loads(
        (
            tmp_path
            / "results"
            / "aguri-rebind-fixture"
            / "baseline"
            / "run_manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert _latest_stage_statuses(resumed)["aguri"] == "reused"
    assert resumed["artifacts"]["aguri_candidates"]["producer"] == expected
    assert resumed["cache"]["aguri"]["producer"] == expected
    assert resumed["cache"]["aguri"]["manifest_path"] == expected["cache_manifest_path"]
    assert resumed["cache"]["aguri"]["fingerprint"] == expected["aguri_fingerprint"]
    assert "code_identity" not in resumed["artifacts"]["aguri_candidates"]["producer"]


def test_reused_aguri_rebind_rebuilds_included_dependents_and_deactivates_excluded_ones(
    tmp_path: Path, monkeypatch
) -> None:
    """A shared-Aguri producer rebind cannot leave successful mixed provenance."""
    monkeypatch.chdir(tmp_path)
    command, agurim = _configured_aguri_command(tmp_path, "aguri-rebind-invalidation")
    assert pipeline.run_pipeline(pipeline.build_parser().parse_args(command)) == 0

    partial = ("--from", "aguri", "--to", "aguri")
    agurim.write_text(agurim.read_text(encoding="utf-8") + "# next cache\n", encoding="utf-8")
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args([*command, *partial, "--run-name", "new-aguri-cache"])
    ) == 0

    assert pipeline.run_pipeline(pipeline.build_parser().parse_args(command)) == 0
    run_dir = tmp_path / "results" / "aguri-rebind-invalidation" / "baseline"
    rebuilt = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    statuses = _latest_stage_statuses(rebuilt)
    assert statuses["aguri"] == "reused"
    assert statuses["prefixes"] == "completed"
    assert statuses["membership"] == "completed"
    load_run("aguri-rebind-invalidation", "baseline", root=tmp_path)

    agurim.write_text(agurim.read_text(encoding="utf-8") + "# third cache\n", encoding="utf-8")
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args([*command, *partial, "--run-name", "third-aguri-cache"])
    ) == 0
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args([*command, "--to", "aguri"])
    ) == 0

    rebound = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert rebound["status"] == "success"
    assert not {"prefixes", "flow_prefix_membership"} & set(rebound["artifacts"])
    with pytest.raises(FileNotFoundError, match="missing required artifact entry: prefixes"):
        load_run("aguri-rebind-invalidation", "baseline", root=tmp_path)


def test_generated_aguri_supports_partial_prefixes_and_rejects_semantic_staleness(
    tmp_path: Path, monkeypatch
) -> None:
    """Historical code metadata is allowed, but stale Aguri semantics are not."""
    monkeypatch.chdir(tmp_path)
    command, _ = _configured_aguri_command(tmp_path, "partial-aguri-fixture")
    assert pipeline.run_pipeline(pipeline.build_parser().parse_args(command)) == 0

    partial = pipeline.build_parser().parse_args(
        [*command, "--from", "prefixes", "--to", "prefixes"]
    )
    assert pipeline.run_pipeline(partial) == 0
    assert pipeline.run_pipeline(
        pipeline.build_parser().parse_args(
            [*command, "--from", "prefixes", "--to", "prefixes", "--dry-run"]
        )
    ) == 0

    manifest_path = (
        tmp_path
        / "results"
        / "partial-aguri-fixture"
        / "baseline"
        / "run_manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    producer = manifest["artifacts"]["aguri_candidates"]["producer"]
    assert "code_identity" in producer
    producer["aguri_fingerprint"] = "stale-aguri"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="aguri"):
        pipeline.run_pipeline(
            pipeline.build_parser().parse_args(
                [*command, "--from", "prefixes", "--to", "prefixes", "--dry-run"]
            )
        )
    with pytest.raises(pipeline.MissingUpstreamArtifactError, match="aguri"):
        pipeline.run_pipeline(partial)


def test_legacy_config_uses_legacy_prefix_stage_without_corrected_membership(
    tmp_path: Path, monkeypatch
) -> None:
    """Paper reproduction keeps its destination-side legacy ledger isolated."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    args = pipeline.build_parser().parse_args(
        [
            "--input",
            str(PCAP_PATH),
            "--dataset-id",
            "legacy-fixture",
            "--config",
            str(LEGACY_CONFIG_PATH),
        ]
    )

    assert pipeline.run_pipeline(args) == 0

    run_dir = tmp_path / "results" / "legacy-fixture" / "paper_legacy"
    prefixes = pd.read_csv(run_dir / "prefixes.csv")
    assert "aggregate_id" in prefixes.columns
    assert "selected_for_analysis" not in prefixes.columns
    assert not (run_dir / "flow_prefix_membership.csv").exists()


def test_corrupted_run_local_outputs_are_regenerated_instead_of_reused(
    tmp_path: Path, monkeypatch
) -> None:
    """Schema and row-count validation prevents truncated run outputs from reuse."""
    monkeypatch.chdir(tmp_path)
    _stub_aguri(monkeypatch, tmp_path)
    assert pipeline.run_pipeline(_args()) == 0
    run_dir = tmp_path / "results" / "fixture" / "baseline"
    prefixes_path = run_dir / "prefixes.csv"
    membership_path = run_dir / "flow_prefix_membership.csv"
    prefixes_path.write_text("broken,prefix,header\n", encoding="utf-8")
    membership_path.write_text(
        "flow_id,analysis_scope,analysis_prefix,src_match,dst_match\n",
        encoding="utf-8",
    )

    assert pipeline.run_pipeline(_args()) == 0

    assert "prefix" in prefixes_path.read_text(encoding="utf-8").splitlines()[0]
    assert len(membership_path.read_text(encoding="utf-8").splitlines()) > 1


def test_m0_m3_pipeline_writes_corrected_run_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    """The corrected path composes cached flows, candidates, ledger, and membership."""
    monkeypatch.chdir(tmp_path)

    _stub_aguri(monkeypatch, tmp_path)

    assert pipeline.run_pipeline(_args()) == 0

    run_dir = tmp_path / "results" / "fixture" / "baseline"
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "success"
    assert manifest["input"]["sha256"] == sha256_file(PCAP_PATH)
    assert (run_dir / "prefixes.csv").is_file()
    assert (run_dir / "flow_prefix_membership.csv").is_file()
    assert list((tmp_path / "data" / "fixture" / "processed" / "flows").glob("*/flows.csv"))
    assert set(manifest["artifacts"]) >= {
        "input_pcap",
        "flows",
        "aguri_candidates",
        "prefixes",
        "flow_prefix_membership",
    }

    # The same identity is resumable; the prior manifest is reopened rather
    # than rejected as a run-name collision.
    assert pipeline.run_pipeline(_args()) == 0
    resumed = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert resumed["status"] == "success"
