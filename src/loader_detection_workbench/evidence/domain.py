"""Manual evidence provenance without changing the generic Artifact model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId

MANUAL_EVIDENCE_MAX_BYTES = 4 * 1024 * 1024
MANUAL_EVIDENCE_EXTENSIONS = frozenset(
    {".txt", ".log", ".json", ".xml", ".csv", ".md", ".yml", ".yaml"}
)


class EvidenceType(StrEnum):
    ANALYST_NOTE = "analyst_note"
    EVENT_EXPORT = "event_export"
    CONFIGURATION = "configuration"
    TOOL_OUTPUT = "tool_output"
    INDICATOR_LIST = "indicator_list"
    OTHER = "other"

    @classmethod
    def parse(cls, value: str) -> EvidenceType:
        try:
            return cls(value)
        except (TypeError, ValueError) as exc:
            raise DomainError(
                DomainErrorCode.INVALID_EVIDENCE_TYPE,
                "unsupported manual evidence type",
            ) from exc


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.INVALID_ARTIFACT_PROVENANCE, message)


def validate_original_filename(value: str) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or value.endswith((" ", "."))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _invalid("original filename is invalid")


def validate_source(value: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 512:
        raise _invalid("manual evidence source must contain 1 to 512 characters")


def validate_description(value: str | None) -> None:
    if value is not None and (
        not isinstance(value, str) or not 1 <= len(value) <= 2000
    ):
        raise _invalid("manual evidence description must contain 1 to 2000 characters")


@dataclass(frozen=True, slots=True)
class ArtifactProvenance:
    artifact_id: str
    original_filename: str
    source: str
    description: str | None
    evidence_type: EvidenceType

    def __post_init__(self) -> None:
        ArtifactId(self.artifact_id, "ART-000001")
        validate_original_filename(self.original_filename)
        validate_source(self.source)
        validate_description(self.description)
        if not isinstance(self.evidence_type, EvidenceType):
            raise _invalid("manual evidence type is invalid")


@dataclass(frozen=True, slots=True)
class ManualEvidence:
    artifact: Artifact
    provenance: ArtifactProvenance

    def __post_init__(self) -> None:
        if (
            self.provenance.artifact_id != self.artifact.artifact_id.ulid
            or self.artifact.kind is not ArtifactKind.EVIDENCE
        ):
            raise _invalid("provenance does not identify its Artifact")
