"""Pinned Aguri invocation, parsing, and cache management."""

from __future__ import annotations

import re
import csv
import gzip
import json
import os
import shutil
import subprocess
import tempfile
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from mawi_global_analysis.config import ExperimentConfig
from mawi_global_analysis.hashing import sha256_file, stable_json_hash
from mawi_global_analysis.models import InputContext


PINNED_AGURIM_SHA = "ab5c5cc80e9e1229bb66ec83bb25f186898d5e49"
AGURI_SCHEMA_VERSION = "aguri-v1"
AGURI_CANDIDATE_COLUMNS = (
    "aggregate_id",
    "src_prefix",
    "dst_prefix",
    "bytes",
    "byte_ratio",
    "packets",
    "packet_ratio",
    "tcp_byte_ratio",
    "tcp_packet_ratio",
    "udp_byte_ratio",
    "udp_packet_ratio",
    "protocol_breakdown",
)


_AGGREGATE_RE = re.compile(
    r"^\[\s*(?P<id>\d+)\]\s+"
    r"(?P<src>\S+)\s+"
    r"(?P<dst>\S+):\s+"
    r"(?P<bytes>[\d,]+)\s+\((?P<byte_ratio>\d+(?:\.\d+)?)%\)\s+"
    r"(?P<packets>[\d,]+)\s+\((?P<packet_ratio>\d+(?:\.\d+)?)%\)\s*$"
)
_PROTOCOL_ENTRY_RE = re.compile(
    r"\[(?P<protocol>\d+):(?P<port_a>[^:\]]+):(?P<port_b>[^\]]+)\]\s+"
    r"(?P<byte_ratio>\d+(?:\.\d+)?)%\s+"
    r"(?P<packet_ratio>\d+(?:\.\d+)?)%"
)
_PROTOCOL_BREAKDOWN_RE = re.compile(
    r"^(?:\[\d+:[^:\]]+:[^\]]+\]\s+\d+(?:\.\d+)?%\s+\d+(?:\.\d+)?%)"
    r"(?:\s+\[\d+:[^:\]]+:[^\]]+\]\s+\d+(?:\.\d+)?%\s+\d+(?:\.\d+)?%)*$"
)


class _AguriConfigLike(Protocol):
    aguri3_executable: str | None
    agurim_executable: str | None


@dataclass(frozen=True)
class AguriBinaries:
    """Resolved executable locations and their provenance."""

    aguri3: Path
    agurim: Path
    aguri3_source: str
    agurim_source: str
    aguri3_version: str = "unavailable"
    agurim_version: str = "unavailable"

    @property
    def used_path_fallback(self) -> bool:
        return "path" in (self.aguri3_source, self.agurim_source)


class AguriCacheValidationError(ValueError):
    """Raised when an Aguri cache cannot prove its semantic identity."""


def resolve_aguri_binaries(
    config: _AguriConfigLike, *, root: Path | None = None
) -> AguriBinaries:
    """Resolve configured, repository-pinned, then PATH binaries in that order."""
    repository_root = (root or Path.cwd()).resolve()
    aguri3, aguri3_source = _resolve_binary(
        "aguri3", config.aguri3_executable, repository_root
    )
    agurim, agurim_source = _resolve_binary(
        "agurim", config.agurim_executable, repository_root
    )
    binaries = AguriBinaries(
        aguri3,
        agurim,
        aguri3_source,
        agurim_source,
        _read_executable_version(aguri3),
        _read_executable_version(agurim),
    )
    if binaries.used_path_fallback:
        warnings.warn(
            "Aguri PATH fallback in use; executable provenance is recorded in "
            "the Aguri manifest.",
            RuntimeWarning,
            stacklevel=2,
        )
    return binaries


def _resolve_binary(
    name: str, configured: str | None, repository_root: Path
) -> tuple[Path, str]:
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_absolute():
            configured_path = repository_root / configured_path
        if _is_executable(configured_path):
            return configured_path.resolve(), "configured"
        if "/" in configured or "\\" in configured:
            raise FileNotFoundError(
                f"configured {name} executable is unavailable or not executable: "
                f"{configured_path}"
            )

    vendor_path = repository_root / "vendor" / "agurim" / "src" / name
    if _is_executable(vendor_path):
        return vendor_path.resolve(), "vendor"

    path_candidate = shutil.which(configured or name) or shutil.which(name)
    if path_candidate:
        return Path(path_candidate).resolve(), "path"
    raise FileNotFoundError(
        f"required Aguri executable {name!r} was not found: configure an explicit "
        "executable path, build vendor/agurim/src, or install it on PATH"
    )


def _is_executable(path: Path) -> bool:
    return path.is_file() and path.stat().st_mode & 0o111 != 0


def _read_executable_version(path: Path) -> str:
    """Capture a reproducible version record even for tools without --version."""
    try:
        result = subprocess.run(
            [str(path), "--version"], check=False, capture_output=True, text=True
        )
    except OSError as error:
        return f"unavailable: {error}"
    output = (result.stdout or result.stderr).strip()
    if result.returncode == 0 and output:
        return output
    if output:
        return f"unavailable (exit {result.returncode}): {output}"
    return f"unavailable (exit {result.returncode})"


def parse_aguri_output(output: str | Iterable[str]) -> list[dict[str, str]]:
    """Normalize Agurim text output into portable aggregate candidate records."""
    lines = output.splitlines() if isinstance(output, str) else output
    rows: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    breakdown_parts: list[str] = []

    def finish_current() -> None:
        if current is None:
            return
        breakdown = " ".join(breakdown_parts)
        totals: dict[int, list[float]] = {}
        for protocol_match in _PROTOCOL_ENTRY_RE.finditer(breakdown):
            protocol = int(protocol_match.group("protocol"))
            values = totals.setdefault(protocol, [0.0, 0.0])
            values[0] += float(protocol_match.group("byte_ratio"))
            values[1] += float(protocol_match.group("packet_ratio"))
        tcp = totals.get(6, [0.0, 0.0])
        udp = totals.get(17, [0.0, 0.0])
        rows.append(
            {
                **current,
                "tcp_byte_ratio": f"{tcp[0]:.2f}",
                "tcp_packet_ratio": f"{tcp[1]:.2f}",
                "udp_byte_ratio": f"{udp[0]:.2f}",
                "udp_packet_ratio": f"{udp[1]:.2f}",
                "protocol_breakdown": breakdown,
            }
        )

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("%"):
            continue
        match = _AGGREGATE_RE.match(stripped)
        if match:
            finish_current()
            breakdown_parts = []
            current = {
                "aggregate_id": match.group("id"),
                "src_prefix": match.group("src"),
                "dst_prefix": match.group("dst"),
                "bytes": match.group("bytes").replace(",", ""),
                "byte_ratio": match.group("byte_ratio"),
                "packets": match.group("packets").replace(",", ""),
                "packet_ratio": match.group("packet_ratio"),
            }
        elif current is not None and line[:1].isspace():
            if not _PROTOCOL_BREAKDOWN_RE.fullmatch(stripped):
                raise ValueError(
                    f"unparsed Agurim output at line {line_number}: {line}"
                )
            breakdown_parts.append(stripped)
        else:
            raise ValueError(f"unparsed Agurim output at line {line_number}: {line}")
    finish_current()
    return rows


def run_aguri_stage(
    ctx: InputContext,
    cfg: ExperimentConfig,
    force: bool = False,
    *,
    root: Path | None = None,
) -> Path:
    """Run pinned Aguri once and cache portable parsed aggregate candidates."""
    repository_root = (root or Path.cwd()).resolve()
    binaries = resolve_aguri_binaries(cfg.aguri, root=repository_root)
    executable_checksums = {
        "aguri3": sha256_file(binaries.aguri3),
        "agurim": sha256_file(binaries.agurim),
    }
    fingerprint = stable_json_hash(
        {
            "schema_version": AGURI_SCHEMA_VERSION,
            "input_sha256": ctx.sha256,
            "agurim_submodule_sha": PINNED_AGURIM_SHA,
            "executable_sha256": executable_checksums,
            "options": cfg.aguri.options,
        }
    )
    stage_dir = (
        repository_root
        / "data"
        / ctx.dataset_id
        / "processed"
        / "aguri"
        / fingerprint
    )
    candidates_path = stage_dir / "aguri_candidates.csv"
    manifest_path = stage_dir / "aguri_manifest.json"
    if not force and (candidates_path.exists() or manifest_path.exists()):
        if not candidates_path.exists() or not manifest_path.exists():
            raise AguriCacheValidationError(
                f"incomplete Aguri cache at {stage_dir}; use force=True to rebuild it"
            )
        _validate_aguri_cache(
            manifest_path,
            candidates_path,
            raw_path=stage_dir / "raw.agr",
            rendered_path=stage_dir / "raw.agurim.txt",
            input_sha256=ctx.sha256,
            fingerprint=fingerprint,
            executable_checksums=executable_checksums,
            options=cfg.aguri.options,
        )
        return candidates_path

    stage_dir.mkdir(parents=True, exist_ok=True)
    raw_path = stage_dir / "raw.agr"
    rendered_path = stage_dir / "raw.agurim.txt"
    commands: list[dict[str, Any]] = []
    temporary_capture: Path | None = None
    manifest_base = _manifest_base(
        ctx,
        fingerprint,
        binaries,
        executable_checksums,
        cfg.aguri.options,
    )
    try:
        capture_path, temporary_capture = _aguri_input_path(ctx.path)
        aguri3_command = [
            str(binaries.aguri3),
            *cfg.aguri.options,
            "-r",
            str(capture_path),
            "-w",
            str(raw_path),
        ]
        _run_command(aguri3_command, commands)
        agurim_command = [str(binaries.agurim), "-w", str(rendered_path), str(raw_path)]
        _run_command(agurim_command, commands)
        rows = parse_aguri_output(rendered_path.read_text(encoding="utf-8"))
        _write_candidates(candidates_path, rows)
    except Exception:
        _write_manifest(
            manifest_path,
            {**manifest_base, "commands": commands, "status": "failed"},
        )
        raise
    finally:
        if temporary_capture is not None and temporary_capture.exists():
            temporary_capture.unlink()

    _write_manifest(
        manifest_path,
        {
            **manifest_base,
            "commands": commands,
            "candidate_count": len(rows),
            "artifacts": {
                "raw_agr": str(raw_path),
                "rendered_text": str(rendered_path),
                "candidates_csv": str(candidates_path),
            },
            "status": "success",
        },
    )
    return candidates_path


def _aguri_input_path(path: Path) -> tuple[Path, Path | None]:
    if path.suffix != ".gz":
        return path, None
    with gzip.open(path, "rb") as compressed, tempfile.NamedTemporaryFile(
        suffix=".pcap", delete=False
    ) as temporary:
        shutil.copyfileobj(compressed, temporary)
        return Path(temporary.name), Path(temporary.name)


def _run_command(command: list[str], commands: list[dict[str, Any]]) -> None:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    record = {
        "argv": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    commands.append(record)
    if result.returncode != 0:
        raise RuntimeError(
            f"Aguri command failed with exit code {result.returncode}: "
            f"{' '.join(command)}\n{result.stderr}"
        )


def _write_candidates(path: Path, rows: list[dict[str, str]]) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            writer = csv.DictWriter(output, fieldnames=AGURI_CANDIDATE_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _manifest_base(
    ctx: InputContext,
    fingerprint: str,
    binaries: AguriBinaries,
    executable_checksums: dict[str, str],
    options: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": AGURI_SCHEMA_VERSION,
        "input_sha256": ctx.sha256,
        "fingerprint": fingerprint,
        "agurim_submodule_sha": PINNED_AGURIM_SHA,
        "options": options,
        "executables": {
            "aguri3": {
                "path": str(binaries.aguri3),
                "sha256": executable_checksums["aguri3"],
                "source": binaries.aguri3_source,
                "version": binaries.aguri3_version,
            },
            "agurim": {
                "path": str(binaries.agurim),
                "sha256": executable_checksums["agurim"],
                "source": binaries.agurim_source,
                "version": binaries.agurim_version,
            },
        },
        "path_fallback_used": binaries.used_path_fallback,
    }


def _write_manifest(path: Path, contents: dict[str, Any]) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(contents, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _validate_aguri_cache(
    manifest_path: Path,
    candidates_path: Path,
    *,
    raw_path: Path,
    rendered_path: Path,
    input_sha256: str,
    fingerprint: str,
    executable_checksums: dict[str, str],
    options: list[str],
) -> None:
    missing_artifacts = [
        path.name for path in (raw_path, rendered_path, candidates_path) if not path.is_file()
    ]
    if missing_artifacts:
        raise AguriCacheValidationError(
            f"incomplete Aguri cache at {manifest_path.parent}: missing "
            + ", ".join(missing_artifacts)
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AguriCacheValidationError(
            f"unreadable Aguri manifest: {manifest_path}"
        ) from error
    expected = {
        "schema_version": AGURI_SCHEMA_VERSION,
        "input_sha256": input_sha256,
        "fingerprint": fingerprint,
        "agurim_submodule_sha": PINNED_AGURIM_SHA,
        "options": options,
        "status": "success",
    }
    mismatched = [key for key, value in expected.items() if manifest.get(key) != value]
    executable_data = manifest.get("executables", {})
    for name, checksum in executable_checksums.items():
        if executable_data.get(name, {}).get("sha256") != checksum:
            mismatched.append(f"executables.{name}.sha256")
    if mismatched:
        raise AguriCacheValidationError(
            f"Aguri cache manifest identity mismatch for {manifest_path}: "
            + ", ".join(mismatched)
        )
    try:
        with candidates_path.open(encoding="utf-8", newline="") as output:
            reader = csv.reader(output, strict=True)
            if tuple(next(reader, ())) != AGURI_CANDIDATE_COLUMNS:
                raise AguriCacheValidationError(
                    f"Aguri candidate CSV has an invalid header: {candidates_path}"
                )
            candidate_count = manifest.get("candidate_count")
            if not isinstance(candidate_count, int) or candidate_count < 0:
                raise AguriCacheValidationError(
                    f"Aguri manifest has invalid candidate_count: {manifest_path}"
                )
            actual_row_count = 0
            for line_number, row in enumerate(reader, start=2):
                if len(row) != len(AGURI_CANDIDATE_COLUMNS):
                    raise AguriCacheValidationError(
                        f"Aguri candidate CSV has {len(row)} columns at line "
                        f"{line_number}; expected {len(AGURI_CANDIDATE_COLUMNS)}: "
                        f"{candidates_path}"
                    )
                actual_row_count += 1
            if actual_row_count != candidate_count:
                raise AguriCacheValidationError(
                    f"Aguri candidate CSV row count mismatch for {candidates_path}: "
                    f"expected {candidate_count}, got {actual_row_count}"
                )
    except AguriCacheValidationError:
        raise
    except (OSError, UnicodeError, csv.Error) as error:
        raise AguriCacheValidationError(
            f"unreadable Aguri candidate CSV: {candidates_path}"
        ) from error
