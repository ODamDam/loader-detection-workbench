"""Static PE analysis result contract."""

from __future__ import annotations

from dataclasses import dataclass

from loader_detection_workbench.domain.artifact import Artifact


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    characteristics: str


@dataclass(frozen=True, slots=True)
class StaticAnalysis:
    artifact: Artifact
    source_artifact_id: str
    source_sha256: str
    source_size_bytes: int
    analyzed_at: str
    tool_name: str
    tool_version: str
    status: str
    is_pe: bool
    architecture: str | None
    machine: str | None
    optional_header: str | None
    characteristics: str | None
    sections: tuple[Section, ...]
    error: str | None
