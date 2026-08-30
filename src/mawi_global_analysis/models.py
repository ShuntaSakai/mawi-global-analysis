"""Shared immutable data models for pipeline stages."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InputContext:
    """Resolved identity and location of a PCAP input."""

    dataset_id: str
    path: Path
    sha256: str
    size_bytes: int
