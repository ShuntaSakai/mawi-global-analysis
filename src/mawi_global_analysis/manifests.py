"""Durable provenance records for one analysis run."""

import json
import os
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


class RunManifest:
    """Persist a run manifest after every state-changing operation."""

    def __init__(
        self, path: Path, data: dict[str, Any], current_code_identity: dict[str, Any] | None = None
    ) -> None:
        self.path = path
        self.data = data
        self.current_code_identity = current_code_identity

    @classmethod
    def start(
        cls,
        path: Path,
        dataset_id: str,
        config_path: Path,
        config_text: str,
        config_hash: str,
        git_commit: str | None,
        code_identity: dict[str, Any] | None = None,
    ) -> "RunManifest":
        """Create and persist a manifest in its initial running state."""
        now = _timestamp()
        manifest = cls(
            path,
            {
                "status": "running",
                "dataset_id": dataset_id,
                "config": {
                    "path": str(config_path),
                    "text": config_text,
                    "hash": config_hash,
                },
                "git_commit": git_commit,
                "code_identity": code_identity,
                "input": None,
                "stages": [],
                "artifacts": {},
                "cache": {},
                "invocations": [
                    {
                        "started_at": now,
                        "finished_at": None,
                        "git_commit": git_commit,
                        "code_identity": code_identity,
                        "status": "running",
                        "error": None,
                    }
                ],
                "started_at": now,
                "updated_at": now,
                "finished_at": None,
                "error": None,
            },
        )
        manifest._write()
        manifest.current_code_identity = code_identity
        return manifest

    @classmethod
    def resume(
        cls, path: Path, git_commit: str | None, code_identity: dict[str, Any] | None = None
    ) -> "RunManifest":
        """Reopen an identity-checked manifest while retaining its prior evidence."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"unreadable run manifest: {path}") from error
        manifest = cls(path, data, code_identity)
        manifest.data.setdefault("cache", {})
        manifest.data.setdefault(
            "invocations",
            [
                {
                    "started_at": manifest.data.get("started_at"),
                    "finished_at": manifest.data.get("finished_at"),
                    "git_commit": manifest.data.get("git_commit"),
                    "code_identity": manifest.data.get("code_identity"),
                    "status": manifest.data.get("status"),
                    "error": manifest.data.get("error"),
                }
            ],
        )
        now = _timestamp()
        manifest.data["status"] = "running"
        manifest.data["error"] = None
        manifest.data["finished_at"] = None
        manifest.data["invocations"].append(
            {
                "started_at": now,
                "finished_at": None,
                "git_commit": git_commit,
                "code_identity": code_identity,
                "status": "running",
                "error": None,
            }
        )
        manifest._write()
        return manifest

    def set_input(
        self, path: Path, sha256: str, size_bytes: int | None = None
    ) -> None:
        """Record the resolved input identity once it is available."""
        input_data: dict[str, Any] = {"path": str(path), "sha256": sha256}
        if size_bytes is not None:
            input_data["size_bytes"] = size_bytes
        self.data["input"] = input_data
        self._write()

    def record_stage(self, name: str, status: str) -> None:
        """Append a stage state record in execution order."""
        self.data["stages"].append({"name": name, "status": status})
        self._write()

    def record_artifact(
        self,
        name: str,
        path: Path,
        row_count: int | None,
        producer: dict[str, Any] | None = None,
    ) -> None:
        """Register an output artifact and its row count when applicable."""
        artifact: dict[str, Any] = {"path": str(path), "row_count": row_count}
        existing = self.data["artifacts"].get(name)
        if producer is not None:
            artifact["producer"] = producer
        elif isinstance(existing, dict) and "producer" in existing:
            artifact["producer"] = existing["producer"]
        self.data["artifacts"][name] = artifact
        self._write()

    def record_cache(self, name: str, details: dict[str, Any]) -> None:
        """Record the semantic cache identity used by a pipeline stage."""
        self.data.setdefault("cache", {})[name] = details
        self._write()

    def deactivate_records(
        self,
        *,
        artifacts: Iterable[str] = (),
        caches: Iterable[str] = (),
    ) -> None:
        """Remove invalidated outputs from the active run inventory."""
        artifact_records = self.data.setdefault("artifacts", {})
        cache_records = self.data.setdefault("cache", {})
        changed = False
        for name in artifacts:
            changed = artifact_records.pop(name, None) is not None or changed
        for name in caches:
            changed = cache_records.pop(name, None) is not None or changed
        if changed:
            self._write()

    def finalize_success(self) -> None:
        """Mark the run as successful and persist its completion time."""
        self._finalize("success", error=None)

    def finalize_failure(self, error: BaseException) -> None:
        """Mark the run as failed while retaining already-recorded evidence."""
        self._finalize(
            "failed",
            error={"type": type(error).__name__, "message": str(error)},
        )

    def _finalize(self, status: str, error: dict[str, str] | None) -> None:
        self.data["status"] = status
        self.data["error"] = error
        self.data["finished_at"] = _timestamp()
        invocations = self.data.get("invocations")
        if invocations:
            invocations[-1].update(
                {
                    "status": status,
                    "error": error,
                    "finished_at": self.data["finished_at"],
                }
            )
        self._write()

    def _write(self) -> None:
        self.data["updated_at"] = _timestamp()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(self.data, temporary_file, indent=2, sort_keys=True)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            temporary_path.replace(self.path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
