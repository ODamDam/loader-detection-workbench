"""Minimal Sysmon results; source identity remains in the Artifact store."""

import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.domain.time import require_utc


@dataclass(frozen=True, slots=True)
class ProcessCreateEvent:
    timestamp: datetime
    event_id: int
    process_guid: str
    process_id: int
    image: str
    command_line: str
    source_artifact_id: ArtifactId
    source_record_id: str

    def __post_init__(self) -> None:
        if (
            type(self.event_id) is not int
            or self.event_id != 1
            or type(self.process_id) is not int
            or self.process_id < 0
            or not self.image.strip()
            or not self.command_line.strip()
            or re.fullmatch(r"[0-9]+", self.source_record_id) is None
            or not isinstance(self.source_artifact_id, ArtifactId)
        ):
            raise DomainError(
                DomainErrorCode.INVALID_PROCESS_CREATE,
                "process create fields or source reference are invalid",
            )
        try:
            UUID(self.process_guid)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_PROCESS_CREATE, "process GUID is invalid"
            ) from exc
        object.__setattr__(self, "timestamp", require_utc(self.timestamp))


@dataclass(frozen=True, slots=True)
class FileCreateEvent:
    timestamp: datetime
    event_id: int
    process_guid: str
    process_id: int
    image: str
    target_filename: str
    creation_utc_time: datetime
    source_artifact_id: ArtifactId
    source_record_id: str

    def __post_init__(self) -> None:
        if (
            type(self.event_id) is not int
            or self.event_id != 11
            or type(self.process_id) is not int
            or self.process_id < 0
            or not self.image.strip()
            or not self.target_filename.strip()
            or re.fullmatch(r"[0-9]+", self.source_record_id) is None
            or not isinstance(self.source_artifact_id, ArtifactId)
        ):
            raise DomainError(
                DomainErrorCode.INVALID_FILE_CREATE,
                "file create fields or source reference are invalid",
            )
        try:
            UUID(self.process_guid)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_FILE_CREATE, "process GUID is invalid"
            ) from exc
        object.__setattr__(self, "timestamp", require_utc(self.timestamp))
        object.__setattr__(
            self, "creation_utc_time", require_utc(self.creation_utc_time)
        )


type NormalizedSysmonEvent = ProcessCreateEvent | FileCreateEvent
