"""Artifact rows and counters in the Project SQLite schema."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from dataclasses import replace

from loader_detection_workbench.case.sqlite_repository import SQLiteCaseRepository
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.case import Case, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.time import format_utc, parse_utc
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

_COLUMNS = (
    "internal_id, project_id, display_id, case_id, kind, relative_path, "
    "sha256, size_bytes, created_at"
)


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.INVALID_ARTIFACT_RECORD, "persisted artifact is invalid"
    )


class SQLiteArtifactRepository:
    def __init__(
        self,
        workspace: ProjectWorkspace,
        *,
        write: bool = False,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        self._workspace = workspace
        self._write = write
        self._owns_connection = connection is None
        self._connection = (
            connection
            if connection is not None
            else connect_database(workspace.database_path, read_only=not write)
        )
        self._cases = SQLiteCaseRepository(
            workspace, write=write, connection=self._connection
        )

    def close(self) -> None:
        if self._owns_connection:
            self._connection.close()

    def transaction(self) -> AbstractContextManager[None]:
        # Case status and Artifact changes share one snapshot and writer lock.
        return self._cases.transaction()

    def get_case(self, display_id: str) -> Case:
        return self._cases.get(display_id)

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("Artifact writes require an explicit write transaction")

    def _require_open(self, case_id: str) -> None:
        row = self._connection.execute(
            "SELECT display_id FROM cases WHERE internal_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise DomainError(DomainErrorCode.CASE_NOT_FOUND, "case was not found")
        if self.get_case(row[0]).status is not CaseStatus.OPEN:
            raise DomainError(DomainErrorCode.CASE_CLOSED, "closed case is read-only")

    def allocate_display_id(self) -> str:
        self._require_write()
        row = self._connection.execute(
            "SELECT next_value FROM counters WHERE name = 'artifact'"
        ).fetchone()
        if row is None or type(row[0]) is not int or not 1 <= row[0] < 2**63 - 1:
            raise DomainError(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact counter is invalid or exhausted",
            )
        value = row[0]
        cursor = self._connection.execute(
            "UPDATE counters SET next_value = ? WHERE name = 'artifact'", (value + 1,)
        )
        advanced = self._connection.execute(
            "SELECT next_value FROM counters WHERE name = 'artifact'"
        ).fetchone()
        if cursor.rowcount != 1 or advanced is None or advanced[0] != value + 1:
            raise DomainError(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact counter could not advance",
            )
        return f"ART-{value:06d}"

    def insert(self, artifact: Artifact) -> None:
        self._require_write()
        if artifact.case_id is None:
            raise _invalid()
        self._require_open(artifact.case_id)
        self._connection.execute(
            f"INSERT INTO artifacts ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                artifact.artifact_id.ulid,
                artifact.project_id,
                artifact.artifact_id.display_id,
                artifact.case_id,
                artifact.kind.value,
                artifact.relative_path.as_posix(),
                artifact.sha256,
                artifact.size_bytes,
                format_utc(artifact.created_at),
            ),
        )
        if self.get(artifact.artifact_id.display_id) != artifact:
            raise _invalid()

    def get(self, display_id: str) -> Artifact:
        rows = self._connection.execute(
            f"SELECT {_COLUMNS} FROM artifacts WHERE display_id = ?", (display_id,)
        ).fetchall()
        if not rows:
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_FOUND, "artifact was not found"
            )
        if len(rows) != 1:
            raise _invalid()
        return self._deserialize(rows[0])

    def list_artifacts(self, case_id: str) -> list[Artifact]:
        artifacts = [
            self._deserialize(row)
            for row in self._connection.execute(
                f"SELECT {_COLUMNS} FROM artifacts WHERE case_id = ?", (case_id,)
            )
        ]
        return sorted(
            artifacts,
            key=lambda a: (int(a.artifact_id.display_id[4:]), a.artifact_id.display_id),
        )

    def detach(self, case_id: str, display_id: str) -> Artifact:
        self._require_write()
        self._require_open(case_id)
        artifact = self.get(display_id)
        if artifact.case_id != case_id:
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_ATTACHED,
                "artifact is not attached to the requested case",
            )
        result = replace(artifact, case_id=None)
        cursor = self._connection.execute(
            "UPDATE artifacts SET case_id = NULL WHERE internal_id = ? AND case_id = ?",
            (artifact.artifact_id.ulid, case_id),
        )
        if cursor.rowcount != 1 or self.get(display_id) != result:
            raise _invalid()
        return result

    def has_content_reference(self, relative_path: str, sha256: str) -> bool:
        self._require_write()
        return (
            self._connection.execute(
                "SELECT 1 FROM artifacts WHERE relative_path = ? OR sha256 = ? LIMIT 1",
                (relative_path, sha256),
            ).fetchone()
            is not None
        )

    def _deserialize(self, row: sqlite3.Row) -> Artifact:
        try:
            strings = (
                "internal_id",
                "project_id",
                "display_id",
                "kind",
                "relative_path",
                "sha256",
                "created_at",
            )
            if any(not isinstance(row[key], str) for key in strings):
                raise _invalid()
            if row["case_id"] is not None and not isinstance(row["case_id"], str):
                raise _invalid()
            if (
                row["internal_id"] != row["internal_id"].upper()
                or row["project_id"] != self._workspace.manifest.project_id.ulid
            ):
                raise _invalid()
            path = ProjectRelativePath.parse(row["relative_path"])
            if path.as_posix() != row["relative_path"]:
                raise _invalid()
            artifact = Artifact(
                ArtifactId(row["internal_id"], row["display_id"]),
                row["project_id"],
                row["case_id"],
                ArtifactKind.parse(row["kind"]),
                path,
                row["sha256"],
                row["size_bytes"],
                parse_utc(row["created_at"]),
            )
            if artifact.case_id is not None:
                parent = self._connection.execute(
                    "SELECT display_id FROM cases WHERE internal_id = ?",
                    (artifact.case_id,),
                ).fetchone()
                if (
                    parent is None
                    or self.get_case(parent[0]).case_id.ulid != artifact.case_id
                ):
                    raise _invalid()
            return artifact
        except (DomainError, TypeError, ValueError, OverflowError) as exc:
            raise _invalid() from exc
