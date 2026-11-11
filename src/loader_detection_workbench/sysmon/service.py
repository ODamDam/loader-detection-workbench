"""Read-only normalization of a Sysmon Artifact attached to an existing Case."""

import re
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import (
    FileCreateEvent,
    NormalizedSysmonEvent,
    ProcessCreateEvent,
)
from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.sysmon.normalizer import (
    MAX_XML_BYTES,
    normalize_sysmon_event,
)
from loader_detection_workbench.sysmon.records import (
    MAX_RECORD_XML_BYTES,
    SysmonRecord,
    parse_sysmon_records,
    parse_sysmon_time,
)


class SysmonService:
    def __init__(self, root: Path) -> None:
        self._root = root

    def normalize(
        self, case_display_id: str, artifact_display_id: str
    ) -> list[NormalizedSysmonEvent]:
        ArtifactId("00000000000000000000000000", artifact_display_id)
        artifacts = ArtifactService(self._root).list_artifacts(case_display_id)
        artifact = next(
            (a for a in artifacts if a.artifact_id.display_id == artifact_display_id),
            None,
        )
        if artifact is None:
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_ATTACHED,
                "requested artifact is not attached to this case",
            )
        if artifact.kind is not ArtifactKind.SYSMON:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_KIND, "a Sysmon artifact is required"
            )
        data = ArtifactStore(self._root).read_verified(
            artifact.relative_path,
            (artifact.sha256, artifact.size_bytes),
            max_bytes=MAX_XML_BYTES,
        )
        return normalize_sysmon_event(data, artifact.artifact_id)

    def normalize_all(
        self, case_display_id: str, artifact_display_id: str
    ) -> tuple[list[NormalizedSysmonEvent], list[SysmonRecord]]:
        """Typed Event ID 1/11 observations plus all other Sysmon records.

        Single-event ID 1/11 documents keep the original strict normalizer and
        its error codes. Multi-event ``<Events>`` exports and other Event IDs are
        read with the generic record parser; their ID 1/11 records are still
        converted to typed observations with the same field requirements.
        """
        ArtifactId("00000000000000000000000000", artifact_display_id)
        artifact = self._attached(case_display_id, artifact_display_id)
        failure: DomainError | None = None
        if artifact.size_bytes <= MAX_XML_BYTES:
            try:
                return self.normalize(case_display_id, artifact_display_id), []
            except DomainError as exc:
                failure = exc
        data = ArtifactStore(self._root).read_verified(
            artifact.relative_path,
            (artifact.sha256, artifact.size_bytes),
            max_bytes=MAX_RECORD_XML_BYTES,
        )
        if (
            failure is not None
            and failure.code is not DomainErrorCode.UNSUPPORTED_SYSMON_EVENT
            and not _is_container(data)
        ):
            raise failure
        typed: list[NormalizedSysmonEvent] = []
        other: list[SysmonRecord] = []
        for record in parse_sysmon_records(data, artifact.artifact_id):
            if record.event_id in (1, 11):
                typed.append(typed_event(record, artifact.artifact_id))
            else:
                other.append(record)
        return typed, other

    def _attached(self, case_display_id: str, artifact_display_id: str) -> Artifact:
        artifacts = ArtifactService(self._root).list_artifacts(case_display_id)
        artifact = next(
            (a for a in artifacts if a.artifact_id.display_id == artifact_display_id),
            None,
        )
        if artifact is None:
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_ATTACHED,
                "requested artifact is not attached to this case",
            )
        if artifact.kind is not ArtifactKind.SYSMON:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_KIND, "a Sysmon artifact is required"
            )
        return artifact


def _is_container(data: bytes) -> bool:
    head = data[:4096].lstrip()
    if head.startswith(b"<?xml"):
        head = head[head.find(b"?>") + 2 :].lstrip()
    while head.startswith(b"<!--"):
        end = head.find(b"-->")
        if end < 0:
            return False
        head = head[end + 3 :].lstrip()
    return head.startswith(b"<Events")


def typed_event(record: SysmonRecord, source: ArtifactId) -> NormalizedSysmonEvent:
    """Convert a generic ID 1/11 record using the typed normalizer's rules."""
    code = (
        DomainErrorCode.INVALID_PROCESS_CREATE
        if record.event_id == 1
        else DomainErrorCode.INVALID_FILE_CREATE
    )
    required = ("UtcTime", "ProcessGuid", "ProcessId", "Image") + (
        ("CommandLine",) if record.event_id == 1 else ("TargetFilename",)
    )
    fields = record.fields
    if (
        any(not fields.get(name, "").strip() for name in required)
        or record.record_id is None
        or re.fullmatch(r"[0-9]{1,10}", fields["ProcessId"]) is None
    ):
        raise DomainError(
            code, "required Sysmon fields are missing, ambiguous or invalid"
        )
    timestamp = parse_sysmon_time(fields["UtcTime"])
    if timestamp is None:
        raise DomainError(code, "Sysmon UtcTime is invalid")
    if record.event_id == 1:
        return ProcessCreateEvent(
            timestamp=timestamp,
            event_id=1,
            process_guid=fields["ProcessGuid"],
            process_id=int(fields["ProcessId"]),
            image=fields["Image"],
            command_line=fields["CommandLine"],
            source_artifact_id=source,
            source_record_id=record.record_id,
        )
    created = parse_sysmon_time(fields.get("CreationUtcTime")) or timestamp
    return FileCreateEvent(
        timestamp=timestamp,
        event_id=11,
        process_guid=fields["ProcessGuid"],
        process_id=int(fields["ProcessId"]),
        image=fields["Image"],
        target_filename=fields["TargetFilename"],
        creation_utc_time=created,
        source_artifact_id=source,
        source_record_id=record.record_id,
    )
