"""Read-only Case projection over the existing single-Artifact Sysmon boundary."""

from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.case import Case
from loader_detection_workbench.domain.events import NormalizedSysmonEvent
from loader_detection_workbench.sysmon.service import SysmonService


@dataclass(frozen=True, slots=True)
class CaseTimeline:
    case: Case
    observations: tuple[NormalizedSysmonEvent, ...]
    sysmon_artifact_count: int


class CaseTimelineQuery:
    def __init__(self, root: Path) -> None:
        self._root = root

    def query(self, case_display_id: str) -> CaseTimeline:
        case = CaseService(self._root).show(case_display_id)
        artifacts = [
            artifact
            for artifact in ArtifactService(self._root).list_artifacts(case_display_id)
            if artifact.kind is ArtifactKind.SYSMON
        ]
        observations: list[NormalizedSysmonEvent] = []
        sysmon = SysmonService(self._root)
        for artifact in artifacts:
            # Deliberately propagate any failure; never return a partial timeline.
            observations.extend(
                sysmon.normalize(case_display_id, artifact.artifact_id.display_id)
            )
        observations.sort(
            key=lambda event: (
                event.timestamp,
                event.event_id,
                event.source_artifact_id.display_id,
                event.source_record_id,
            )
        )
        return CaseTimeline(case, tuple(observations), len(artifacts))
