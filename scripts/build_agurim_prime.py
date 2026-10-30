#!/usr/bin/env python3
"""Build the tracked local Agurim flow-mode fork without modifying the submodule.

The output directory must be new. The source is extracted from the pinned Git
object, never from possibly modified submodule working files. No network needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

UPSTREAM_COMMIT = "ab5c5cc80e9e1229bb66ec83bb25f186898d5e49"
SOURCES = ("agurim.c", "odflow.c", "hhh.c", "agurim_plot.c", "agurim_subr.c")
INPUTS = (*SOURCES, "agurim.h", "aguri_flow.h", "aguri3.c", "pcap_parse.c", "ip_parse.c", "ip_parse.h", "Makefile")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output: Path, root: Path | None = None) -> Path:
    """Publish a new source/binary/provenance bundle; refuse existing paths."""
    root = Path(root or Path(__file__).resolve().parents[1]).resolve()
    output = Path(output).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"build output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    patch = root / "vendor/agurim-prime/flow-mode.patch"
    patch_sha = digest(patch)
    identity = {"upstream_commit": UPSTREAM_COMMIT, "patch_sha256": patch_sha}
    with tempfile.TemporaryDirectory(prefix=".agurim-prime-", dir=output.parent) as temporary:
        work = Path(temporary)
        source = work / "src"
        source.mkdir()
        for name in INPUTS:
            content = subprocess.check_output(["git", "-C", str(root/"vendor/agurim"), "show", f"{UPSTREAM_COMMIT}:src/{name}"])
            (source/name).write_bytes(content)
        license_data = subprocess.check_output(["git", "-C", str(root/"vendor/agurim"), "show", f"{UPSTREAM_COMMIT}:LICENSE"])
        (work/"LICENSE").write_bytes(license_data)
        subprocess.run(["patch", "--batch", "-p1", "-i", str(patch)], cwd=work, check=True, capture_output=True)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        command = [*compiler, "-O2", "-Wall", "-DINET6", "-DNDEBUG", "-o", str(work/"agurim"),
                   *(str(source/name) for name in SOURCES), "-lm"]
        subprocess.run(command, check=True, capture_output=True)
        version = subprocess.check_output([*compiler, "--version"], text=True).splitlines()[0]
        manifest = {"schema_version": "agurim-prime-build-v1", **identity,
                    "fork_commit": None,
                    "fork_identity": hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                    "executable_sha256": digest(work/"agurim"),
                    "source_sha256": {name:digest(source/name) for name in INPUTS},
                    "compiler": version, "compiler_argv": command,
                    "license": "LICENSE", "status": "success"}
        (work/"build_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
        # Atomic rename cannot replace an existing non-empty build directory.
        if output.exists():
            raise FileExistsError(f"build output already exists: {output}")
        work.rename(output)
    return output/"agurim"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1]/"build/agurim-prime")
    args = parser.parse_args()
    try:
        result = build(args.output_dir)
    except (OSError, subprocess.CalledProcessError) as exc:
        parser.exit(2, f"Agurim prime build failed: {exc}\n")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
