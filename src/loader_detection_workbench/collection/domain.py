"""Immutable contracts for one validated three-file Sysmon Collection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind


class CollectionArtifactRole(StrEnum):
    PROCESS_CREATE = "process-create"
    FILE_CREATE = "file-create"
    METADATA = "metadata"


@dataclass(frozen=True, slots=True)
class ValidatedCollectionFile:
    role: CollectionArtifactRole
    filename: str
    kind: ArtifactKind
    sha256: str
    size_bytes: int
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        expected = hashlib.sha256(self.data).hexdigest()
        if self.sha256 != expected or self.size_bytes != len(self.data):
            raise ValueError("validated Collection file identity is inconsistent")


@dataclass(frozen=True, slots=True)
class ValidatedSysmonCollection:
    process_create: ValidatedCollectionFile
    file_create: ValidatedCollectionFile
    metadata: ValidatedCollectionFile

    def files_in_registration_order(self) -> tuple[ValidatedCollectionFile, ...]:
        return (self.process_create, self.file_create, self.metadata)


@dataclass(frozen=True, slots=True)
class CollectionIngestionResult:
    status: str
    case_display_id: str
    process_artifact: Artifact
    file_artifact: Artifact
    metadata_artifact: Artifact
    created_count: int
    reused_count: int
