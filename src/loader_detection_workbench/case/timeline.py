"""Read-only Case projection over attached Sysmon Artifacts.

Typed Event ID 1/11 observations keep the original Timeline contract. Other
Sysmon Event IDs (for example 3, 12–14, 22 from a multi-event collection) are
exposed separately as generic records so existing consumers are unchanged.
"""

from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.case import Case
from loader_detection_workbench.domain.events import NormalizedSysmonEvent
from loader_detection_workbench.sysmon.records import SysmonRecord
from loader_detection_workbench.sysmon.service import SysmonService


@dataclass(frozen=True, slots=True)
class CaseTimeline:
    case: Case
    observations: tuple[NormalizedSysmonEvent, ...]
    sysmon_artifact_count: int
    other_records: tuple[SysmonRecord, ...] = ()


def _record_key(record: SysmonRecord) -> tuple[str, int, str, int]:
    return (
        "" if record.timestamp is None else record.timestamp.isoformat(),
        record.event_id,
        ""
        if record.source_artifact_id is None
        else record.source_artifact_id.display_id,
        int(record.record_id or 0),
    )


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
        others: list[SysmonRecord] = []
        sysmon = SysmonService(self._root)
        for artifact in artifacts:
            # Deliberately propagate any failure; never return a partial timeline.
            typed, other = sysmon.normalize_all(
                case_display_id, artifact.artifact_id.display_id
            )
            observations.extend(typed)
            others.extend(other)
        observations.sort(
            key=lambda event: (
                event.timestamp,
                event.event_id,
                event.source_artifact_id.display_id,
                event.source_record_id,
            )
        )
        others.sort(key=_record_key)
        return CaseTimeline(case, tuple(observations), len(artifacts), tuple(others))
