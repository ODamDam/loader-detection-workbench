"""Explicit, transactional SQLite Project migrations."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.project.database import (
    ARTIFACT_PROVENANCE_SQL,
    connect_database,
    database_versions,
    read_database_version,
    validate_v2_migration_state,
)
from loader_detection_workbench.project.service import ProjectService


@dataclass(frozen=True, slots=True)
class MigrationResult:
    previous_version: int
    current_version: int
    status: str


def _apply_v2(connection: sqlite3.Connection) -> None:
    connection.execute(ARTIFACT_PROVENANCE_SQL)
    connection.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        (2, format_utc(utc_now())),
    )


class ProjectMigrationService:
    def migrate(self, root: Path, *, target: int = 2) -> MigrationResult:
        if target != 2:
            raise DomainError(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "unsupported migration target",
            )
        workspace = ProjectService().open(root)
        previous = workspace.sqlite_schema_version
        if previous == 2:
            return MigrationResult(2, 2, "already-current")
        if previous != 1:
            raise DomainError(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "unsupported migration source",
            )

        connection = connect_database(workspace.database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            if database_versions(connection) != [1]:
                raise DomainError(
                    DomainErrorCode.PROJECT_MIGRATION_FAILED,
                    "migration source changed during preflight",
                )
            _apply_v2(connection)
            validate_v2_migration_state(connection)
            connection.commit()
        except BaseException as exc:
            connection.rollback()
            connection.close()
            self._verify_rollback(root, previous)
            if isinstance(exc, DomainError) and exc.code in {
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                DomainErrorCode.PROJECT_MIGRATION_FAILED,
            }:
                raise
            raise DomainError(
                DomainErrorCode.PROJECT_MIGRATION_FAILED,
                "project migration failed and was rolled back",
            ) from exc
        else:
            connection.close()

        result = ProjectService().validate(root)
        if not result.is_valid or read_database_version(workspace.database_path) != 2:
            raise DomainError(
                DomainErrorCode.PROJECT_MIGRATION_FAILED,
                "committed migration could not be verified",
            )
        return MigrationResult(previous, 2, "migrated")

    @staticmethod
    def _verify_rollback(root: Path, expected_version: int) -> None:
        result = ProjectService().validate(root)
        if not result.is_valid:
            raise DomainError(
                DomainErrorCode.PROJECT_MIGRATION_FAILED,
                "migration failed and rollback could not be verified",
            )
        workspace = ProjectService().open(root)
        if workspace.sqlite_schema_version != expected_version:
            raise DomainError(
                DomainErrorCode.PROJECT_MIGRATION_FAILED,
                "migration failed and rollback version changed",
            )
