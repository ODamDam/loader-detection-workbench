"""Read-only process/file relationship query for an already queried Case."""

from pathlib import Path

from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.sysmon.records import (
    MAX_RECORD_XML_BYTES,
    SysmonRecord,
    parse_sysmon_records,
)
from loader_detection_workbench.sysmon.relations import (
    ProcessRelations,
    build_process_relations,
)


class CaseProcessRelationsQuery:
    """Reads every attached Sysmon Artifact; any invalid document fails the query."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def query(self, timeline: CaseTimeline) -> ProcessRelations:
        store = ArtifactStore(self._root)
        records: list[SysmonRecord] = []
        for artifact in timeline.artifacts:
            if artifact.kind is not ArtifactKind.SYSMON:
                continue
            records.extend(
                parse_sysmon_records(
                    store.read_verified(
                        artifact.relative_path,
                        (artifact.sha256, artifact.size_bytes),
                        max_bytes=MAX_RECORD_XML_BYTES,
                    ),
                    artifact.artifact_id,
                )
            )
        return build_process_relations(records)
