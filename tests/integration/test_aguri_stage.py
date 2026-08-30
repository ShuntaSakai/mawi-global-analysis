from __future__ import annotations

import json
import gzip
from pathlib import Path

import pytest

from mawi_global_analysis.aguri import AguriCacheValidationError, run_aguri_stage
from mawi_global_analysis.config import AguriConfig, load_config
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.models import InputContext


PCAP_PATH = Path("tests/fixtures/pcaps/tcp_patterns.pcap")


def test_run_aguri_stage_caches_normalized_candidates_and_provenance(tmp_path) -> None:
    aguri3 = _write_executable(
        tmp_path / "aguri3",
        "#!/bin/sh\ncp \"$2\" \"$4\"\n",
    )
    agurim = _write_executable(
        tmp_path / "agurim",
        "#!/bin/sh\nprintf '%s\\n' '[ 1] 192.0.2.0/24 198.51.100.0/24: 100 (100.00%) 2 (100.00%)' '\t[6:443:50123] 100.00% 100.00%' > \"$2\"\n",
    )
    cfg = load_config(Path("configs/baseline.yaml")).model_copy(
        update={
            "aguri": AguriConfig(
                aguri3_executable=str(aguri3),
                agurim_executable=str(agurim),
                options=[],
            ),
        }
    )
    ctx = InputContext("fixture", PCAP_PATH, sha256_file(PCAP_PATH), PCAP_PATH.stat().st_size)

    candidates_path = run_aguri_stage(ctx, cfg, root=tmp_path)

    assert candidates_path.parent.parent == tmp_path / "data" / "fixture" / "processed" / "aguri"
    assert candidates_path.read_text(encoding="utf-8").splitlines() == [
        "aggregate_id,src_prefix,dst_prefix,bytes,byte_ratio,packets,packet_ratio,tcp_byte_ratio,tcp_packet_ratio,udp_byte_ratio,udp_packet_ratio,protocol_breakdown",
        "1,192.0.2.0/24,198.51.100.0/24,100,100.00,2,100.00,100.00,100.00,0.00,0.00,[6:443:50123] 100.00% 100.00%",
    ]
    manifest = json.loads((candidates_path.parent / "aguri_manifest.json").read_text())
    assert manifest["input_sha256"] == ctx.sha256
    assert manifest["path_fallback_used"] is False
    assert [command["returncode"] for command in manifest["commands"]] == [0, 0]
    assert (candidates_path.parent / "raw.agr").is_file()
    assert candidates_path.name == "aguri_candidates.csv"
    assert (candidates_path.parent / "raw.agurim.txt").is_file()

    candidates_path.write_text(
        "aggregate_id,src_prefix,dst_prefix,bytes,byte_ratio,packets,packet_ratio,tcp_byte_ratio,tcp_packet_ratio,udp_byte_ratio,udp_packet_ratio,protocol_breakdown\n",
        encoding="utf-8",
    )
    with pytest.raises(AguriCacheValidationError, match="row count mismatch"):
        run_aguri_stage(ctx, cfg, root=tmp_path)
    candidates_path = run_aguri_stage(ctx, cfg, force=True, root=tmp_path)

    (candidates_path.parent / "raw.agr").unlink()
    with pytest.raises(AguriCacheValidationError, match="incomplete"):
        run_aguri_stage(ctx, cfg, root=tmp_path)


def test_run_aguri_stage_decompresses_gzip_input_before_invocation(tmp_path) -> None:
    compressed_pcap = tmp_path / "tcp_patterns.pcap.gz"
    with PCAP_PATH.open("rb") as source, gzip.open(compressed_pcap, "wb") as output:
        output.write(source.read())
    aguri3 = _write_executable(tmp_path / "aguri3", "#!/bin/sh\ncp \"$2\" \"$4\"\n")
    agurim = _write_executable(
        tmp_path / "agurim",
        "#!/bin/sh\nprintf '%s\\n' > \"$2\"\n",
    )
    cfg = load_config(Path("configs/baseline.yaml")).model_copy(
        update={
            "aguri": AguriConfig(
                aguri3_executable=str(aguri3),
                agurim_executable=str(agurim),
                options=[],
            )
        }
    )
    ctx = InputContext(
        "gzip-fixture",
        compressed_pcap,
        sha256_file(compressed_pcap),
        compressed_pcap.stat().st_size,
    )

    candidates_path = run_aguri_stage(ctx, cfg, root=tmp_path)

    assert (candidates_path.parent / "raw.agr").read_bytes() == PCAP_PATH.read_bytes()


def test_path_fallback_manifest_records_executable_versions(tmp_path, monkeypatch) -> None:
    aguri3 = _write_executable(
        tmp_path / "path-aguri3",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo fake-aguri3-1.0; exit 0; fi\ncp \"$2\" \"$4\"\n",
    )
    agurim = _write_executable(
        tmp_path / "path-agurim",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo fake-agurim-1.0; exit 0; fi\nprintf '%s\\n' > \"$2\"\n",
    )
    monkeypatch.setattr(
        "mawi_global_analysis.aguri.shutil.which",
        lambda name: str(aguri3 if name == "aguri3" else agurim),
    )
    cfg = load_config(Path("configs/baseline.yaml"))
    ctx = InputContext("path-fixture", PCAP_PATH, sha256_file(PCAP_PATH), PCAP_PATH.stat().st_size)

    with pytest.warns(RuntimeWarning, match="PATH fallback"):
        candidates_path = run_aguri_stage(ctx, cfg, root=tmp_path)

    manifest = json.loads((candidates_path.parent / "aguri_manifest.json").read_text())
    assert manifest["path_fallback_used"] is True
    assert manifest["executables"]["aguri3"]["version"] == "fake-aguri3-1.0"
    assert manifest["executables"]["agurim"]["version"] == "fake-agurim-1.0"


def _write_executable(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path
