"""Read-only process/file relationship query for an already queried Case."""

import sqlite3
from pathlib import Path

from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError
from loader_detection_workbench.project.manifest import load_manifest
from loader_detection_workbench.sample.sqlite_repository import read_sample_hashes
from loader_detection_workbench.sysmon.records import (
    MAX_RECORD_XML_BYTES,
    SysmonRecord,
    parse_sysmon_records,
)
from loader_detection_workbench.sysmon.relations import (
    ProcessRelations,
    build_process_relations,
)

_MANIFEST_NAME = "project.json"


class CaseProcessRelationsQuery:
    """Reads every attached Sysmon Artifact; any invalid document fails the query."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def known_files(self, timeline: CaseTimeline) -> dict[str, str]:
        """SHA-256 → display ID for files the Project already holds.

        The Case's own sample Artifacts win over Project samples, so a dropped
        exact copy reads as "same as ART-…" (the sample started in this Case)
        and a different registered sample reads as "same as SMP-…".
        """
        known: dict[str, str] = {}
        manifest = self._root / _MANIFEST_NAME
        try:
            if manifest.is_file():
                database = load_manifest(manifest).database_path.resolve_under(
                    self._root
                )
                known.update(read_sample_hashes(database))
        except (DomainError, OSError, sqlite3.Error):
            pass  # identity is a convenience; the relations view still works
        for artifact in timeline.artifacts:
            if artifact.kind is ArtifactKind.SAMPLE:
                known[artifact.sha256.lower()] = artifact.artifact_id.display_id
        return known

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
        return build_process_relations(records, self.known_files(timeline))
