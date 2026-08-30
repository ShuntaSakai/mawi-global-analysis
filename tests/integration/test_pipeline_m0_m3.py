from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from mawi_global_analysis.hashing import sha256_file
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


def test_compatible_manifest_records_input_resolution_failure_as_new_invocation(
    tmp_path: Path, monkeypatch
) -> None:
    """A compatible historical run must not hide a later input-stage failure."""
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
    assert persisted["status"] == "failed"
    assert persisted["invocations"][0]["status"] == "success"
    assert persisted["invocations"][-1]["status"] == "failed"
    assert persisted["stages"][-1] == {"name": "input", "status": "failed"}


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
    assert manifest["cache"]["flows"]["fingerprint"]
    assert manifest["cache"]["flows"]["manifest_path"].endswith("flow_manifest.json")


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
