"""Immutable Artifact metadata; filenames are not content identity."""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, CaseId, ProjectId
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.time import require_utc


class ArtifactKind(StrEnum):
    SAMPLE = "sample"
    STATIC = "static"
    SYSMON = "sysmon"
    PROCMON = "procmon"
    NETWORK = "network"
    NORMALIZED = "normalized"
    EVIDENCE = "evidence"
    RULE = "rule"
    REPORT = "report"
    OTHER = "other"

    @classmethod
    def parse(cls, value: str) -> "ArtifactKind":
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_KIND, "unsupported artifact kind"
            ) from exc


def canonical_path(sha256: str) -> ProjectRelativePath:
    if re.fullmatch(r"[0-9a-f]{64}", sha256, re.ASCII) is None:
        raise DomainError(
            DomainErrorCode.INVALID_ARTIFACT_RECORD,
            "artifact hash must be lowercase SHA-256",
        )
    return ProjectRelativePath.parse(f"artifacts/sha256/{sha256[:2]}/{sha256}")


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: ArtifactId
    project_id: str
    case_id: str | None
    kind: ArtifactKind
    relative_path: ProjectRelativePath
    sha256: str
    size_bytes: int
    created_at: datetime

    def __post_init__(self) -> None:
        ProjectId(self.project_id, "PRJ-0001")
        if self.case_id is not None:
            CaseId(self.case_id, "CASE-0001")
        if (
            not isinstance(self.kind, ArtifactKind)
            or self.relative_path != canonical_path(self.sha256)
            or type(self.size_bytes) is not int
            or self.size_bytes < 0
        ):
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_RECORD, "artifact metadata is invalid"
            )
        object.__setattr__(self, "created_at", require_utc(self.created_at))
