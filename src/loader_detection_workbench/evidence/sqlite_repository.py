"""SQLite v2 persistence for manual evidence provenance."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager

from loader_detection_workbench.artifact.sqlite_repository import (
    SQLiteArtifactRepository,
)
from loader_detection_workbench.domain.artifact import Artifact
from loader_detection_workbench.domain.case import Case
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.evidence.domain import (
    ArtifactProvenance,
    EvidenceType,
    ManualEvidence,
)
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

_COLUMNS = "artifact_id, original_filename, source, description, evidence_type"


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.INVALID_ARTIFACT_PROVENANCE,
        "persisted manual evidence provenance is invalid",
    )


class SQLiteEvidenceRepository:
    def __init__(self, workspace: ProjectWorkspace, *, write: bool = False) -> None:
        if workspace.sqlite_schema_version < 2:
            raise DomainError(
                DomainErrorCode.PROJECT_MIGRATION_REQUIRED,
                "manual evidence requires an explicit Project migration to schema v2",
            )
        self._write = write
        self._connection = connect_database(
            workspace.database_path, read_only=not write
        )
        self._artifacts = SQLiteArtifactRepository(
            workspace, write=write, connection=self._connection
        )

    def close(self) -> None:
        self._connection.close()

    def transaction(self) -> AbstractContextManager[None]:
        return self._artifacts.transaction()

    def get_case(self, display_id: str) -> Case:
        return self._artifacts.get_case(display_id)

    def allocate_artifact_display_id(self) -> str:
        return self._artifacts.allocate_display_id()

    def insert_artifact(self, artifact: Artifact) -> None:
        self._artifacts.insert(artifact)

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("Evidence writes require an explicit write transaction")

    def insert_provenance(self, provenance: ArtifactProvenance) -> None:
        self._require_write()
        self._connection.execute(
            f"INSERT INTO artifact_provenance ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
            (
                provenance.artifact_id,
                provenance.original_filename,
                provenance.source,
                provenance.description,
                provenance.evidence_type.value,
            ),
        )
        row = self._connection.execute(
            f"SELECT {_COLUMNS} FROM artifact_provenance WHERE artifact_id = ?",
            (provenance.artifact_id,),
        ).fetchone()
        if row is None or self._deserialize_provenance(row) != provenance:
            raise _invalid()

    def get(self, case_id: str, artifact_display_id: str) -> ManualEvidence:
        try:
            artifact = self._artifacts.get(artifact_display_id)
        except DomainError as exc:
            if exc.code is not DomainErrorCode.ARTIFACT_NOT_FOUND:
                raise
            raise DomainError(
                DomainErrorCode.MANUAL_EVIDENCE_NOT_FOUND,
                "manual evidence was not found in the requested Case",
            ) from exc
        if artifact.case_id != case_id:
            raise DomainError(
                DomainErrorCode.MANUAL_EVIDENCE_NOT_FOUND,
                "manual evidence was not found in the requested Case",
            )
        row = self._connection.execute(
            f"SELECT {_COLUMNS} FROM artifact_provenance WHERE artifact_id = ?",
            (artifact.artifact_id.ulid,),
        ).fetchone()
        if row is None:
            raise DomainError(
                DomainErrorCode.MANUAL_EVIDENCE_NOT_FOUND,
                "Artifact is not registered manual evidence",
            )
        return ManualEvidence(artifact, self._deserialize_provenance(row))

    def list_evidence(self, case_id: str) -> list[ManualEvidence]:
        display_ids = [
            str(row[0])
            for row in self._connection.execute(
                "SELECT a.display_id FROM artifacts AS a "
                "JOIN artifact_provenance AS p ON p.artifact_id = a.internal_id "
                "WHERE a.case_id = ? ORDER BY CAST(substr(a.display_id, 5) AS INTEGER)",
                (case_id,),
            )
        ]
        return [self.get(case_id, display_id) for display_id in display_ids]

    def has_content_reference(self, relative_path: str, sha256: str) -> bool:
        return self._artifacts.has_content_reference(relative_path, sha256)

    @staticmethod
    def _deserialize_provenance(row: sqlite3.Row) -> ArtifactProvenance:
        try:
            for key in (
                "artifact_id",
                "original_filename",
                "source",
                "evidence_type",
            ):
                if not isinstance(row[key], str):
                    raise _invalid()
            if row["description"] is not None and not isinstance(
                row["description"], str
            ):
                raise _invalid()
            return ArtifactProvenance(
                row["artifact_id"],
                row["original_filename"],
                row["source"],
                row["description"],
                EvidenceType.parse(row["evidence_type"]),
            )
        except (DomainError, TypeError, ValueError) as exc:
            raise _invalid() from exc
