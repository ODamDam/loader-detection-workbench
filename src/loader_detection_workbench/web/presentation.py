"""Path-safe presentation models for the local web interface."""

from __future__ import annotations

from dataclasses import dataclass

from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.events import NormalizedSysmonEvent
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.evidence.domain import ManualEvidence


@dataclass(frozen=True, slots=True)
class ArtifactView:
    display_id: str
    kind: str
    classification: str
    sha256: str
    size_bytes: int
    created_at: str
    original_filename: str | None = None
    source: str | None = None
    description: str | None = None
    evidence_type: str | None = None


@dataclass(frozen=True, slots=True)
class TimelineEventView:
    timestamp: str
    event_id: int
    event_name: str
    process_id: int
    artifact_id: str
    record_id: str


def artifact_views(
    artifacts: list[Artifact], evidence: list[ManualEvidence]
) -> tuple[ArtifactView, ...]:
    provenance = {item.artifact.artifact_id.ulid: item.provenance for item in evidence}
    views: list[ArtifactView] = []
    for artifact in artifacts:
        details = provenance.get(artifact.artifact_id.ulid)
        if artifact.kind is ArtifactKind.SYSMON:
            classification = "Sysmon telemetry"
        elif artifact.kind is ArtifactKind.EVIDENCE and details is not None:
            classification = "Manual evidence"
        elif artifact.kind is ArtifactKind.EVIDENCE:
            classification = "Evidence (provenance unavailable)"
        elif artifact.kind is ArtifactKind.OTHER:
            classification = "Other artifact"
        else:
            classification = "Artifact"
        views.append(
            ArtifactView(
                display_id=artifact.artifact_id.display_id,
                kind=artifact.kind.value,
                classification=classification,
                sha256=artifact.sha256,
                size_bytes=artifact.size_bytes,
                created_at=format_utc(artifact.created_at),
                original_filename=(
                    None if details is None else details.original_filename
                ),
                source=None if details is None else details.source,
                description=None if details is None else details.description,
                evidence_type=None if details is None else details.evidence_type.value,
            )
        )
    return tuple(views)


def timeline_event_views(
    events: tuple[NormalizedSysmonEvent, ...],
) -> tuple[TimelineEventView, ...]:
    return tuple(
        TimelineEventView(
            timestamp=format_utc(event.timestamp),
            event_id=event.event_id,
            event_name="Process Create" if event.event_id == 1 else "File Create",
            process_id=event.process_id,
            artifact_id=event.source_artifact_id.display_id,
            record_id=event.source_record_id,
        )
        for event in events
    )
