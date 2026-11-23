"""Case rows in the existing Project SQLite v1 database."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime

from loader_detection_workbench.domain.case import (
    Case,
    CaseKind,
    CaseLifecycle,
    CaseStatus,
    validate_case_name,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import CaseId
from loader_detection_workbench.domain.time import format_utc, parse_utc
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

_COLUMNS = (
    "internal_id, project_id, display_id, kind, status, name, description, "
    "created_at, updated_at, closed_at"
)


def _invalid_record() -> DomainError:
    return DomainError(DomainErrorCode.INVALID_CASE_RECORD, "persisted case is invalid")


class SQLiteCaseRepository:
    def __init__(
        self,
        workspace: ProjectWorkspace,
        *,
        write: bool = False,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        self._workspace = workspace
        self._write = write
        if not workspace.database_path.is_file():
            raise DomainError(
                DomainErrorCode.WORKSPACE_NOT_FOUND, "project database was not found"
            )
        self._owns_connection = connection is None
        self._connection = (
            connection
            if connection is not None
            else connect_database(workspace.database_path, read_only=not write)
        )

    def close(self) -> None:
        if self._owns_connection:
            self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            self._connection.execute("BEGIN IMMEDIATE" if self._write else "BEGIN")
            self._validate_project()
            self._validate_counters()
            yield
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("Case writes require an explicit write transaction")

    def _validate_project(self) -> None:
        manifest = self._workspace.manifest
        rows = self._connection.execute(
            "SELECT internal_id, display_id, name, created_at FROM projects"
        ).fetchall()
        expected = (
            manifest.project_id.ulid,
            manifest.project_id.display_id,
            manifest.name,
            format_utc(manifest.created_at),
        )
        if len(rows) != 1 or tuple(rows[0]) != expected:
            raise DomainError(
                DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH,
                "project.json and project database metadata differ",
            )

    def _validate_counters(self) -> None:
        counters = dict(
            self._connection.execute("SELECT name, next_value FROM counters")
        )
        for name in ("case", "artifact"):
            value = counters.get(name)
            if type(value) is not int or value < 1:
                raise DomainError(
                    DomainErrorCode.INVALID_SQLITE_SCHEMA,
                    f"counter is missing or invalid: {name}",
                )

    def allocate_display_id(self) -> str:
        self._require_write()
        self._validate_counters()
        value = self._connection.execute(
            "SELECT next_value FROM counters WHERE name = 'case'"
        ).fetchone()[0]
        # Fail without advancing beyond SQLite's integer range.
        if value >= 2**63 - 1:
            raise DomainError(
                DomainErrorCode.INVALID_SQLITE_SCHEMA, "case counter is exhausted"
            )
        cursor = self._connection.execute(
            "UPDATE counters SET next_value = ? WHERE name = 'case'", (value + 1,)
        )
        advanced = self._connection.execute(
            "SELECT next_value FROM counters WHERE name = 'case'"
        ).fetchone()
        if cursor.rowcount != 1 or advanced is None or advanced[0] != value + 1:
            raise DomainError(
                DomainErrorCode.INVALID_SQLITE_SCHEMA, "case counter could not advance"
            )
        return f"CASE-{value:04d}"

    def insert(self, case: Case) -> None:
        self._require_write()
        self._connection.execute(
            f"INSERT INTO cases ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                case.case_id.ulid,
                case.project_id,
                case.case_id.display_id,
                case.kind.value,
                case.status.value,
                case.name,
                case.description,
                format_utc(case.created_at),
                format_utc(case.updated_at),
                None if case.closed_at is None else format_utc(case.closed_at),
            ),
        )
        if self.get(case.case_id.display_id) != case:
            raise _invalid_record()

    def get(self, display_id: str) -> Case:
        # A workspace has exactly one authoritative Project. Load matching rows before
        # checking association so a corrupt project_id cannot look like a missing Case.
        rows = self._connection.execute(
            f"SELECT {_COLUMNS} FROM cases WHERE display_id = ?", (display_id,)
        ).fetchall()
        if not rows:
            raise DomainError(DomainErrorCode.CASE_NOT_FOUND, "case was not found")
        if len(rows) != 1:
            raise _invalid_record()
        return self._deserialize(rows[0])

    def list_cases(self) -> list[Case]:
        cases = [
            self._deserialize(row)
            for row in self._connection.execute(f"SELECT {_COLUMNS} FROM cases")
        ]
        return sorted(
            cases,
            key=lambda case: (
                int(case.case_id.display_id[5:]),
                case.case_id.display_id,
            ),
        )

    def rename(self, expected: Case, name: str, at: datetime) -> Case:
        self._require_current(expected)
        if expected.status is not CaseStatus.OPEN:
            raise DomainError(DomainErrorCode.CASE_CLOSED, "closed case is read-only")
        result = replace(
            expected, name=name, lifecycle=replace(expected.lifecycle, updated_at=at)
        )
        self._update(
            expected, result, "name = ?, updated_at = ?", (name, format_utc(at))
        )
        return result

    def set_lifecycle(self, expected: Case, lifecycle: CaseLifecycle) -> Case:
        self._require_current(expected)
        if expected.status is lifecycle.status:
            raise DomainError(
                DomainErrorCode.INVALID_CASE_TRANSITION,
                "case is already in the requested state",
            )
        result = replace(expected, lifecycle=lifecycle)
        self._update(
            expected,
            result,
            "status = ?, updated_at = ?, closed_at = ?",
            (
                lifecycle.status.value,
                format_utc(lifecycle.updated_at),
                None
                if lifecycle.closed_at is None
                else format_utc(lifecycle.closed_at),
            ),
        )
        return result

    def _require_current(self, expected: Case) -> None:
        self._require_write()
        if self.get(expected.case_id.display_id) != expected:
            raise _invalid_record()

    def _update(
        self, expected: Case, result: Case, assignments: str, values: tuple[object, ...]
    ) -> None:
        if result.updated_at < expected.updated_at:
            raise DomainError(
                DomainErrorCode.INVALID_TIMESTAMP,
                "case timestamp must not move backwards",
            )
        cursor = self._connection.execute(
            f"UPDATE cases SET {assignments} "
            "WHERE internal_id = ? AND project_id = ? "
            "AND status = ? AND updated_at = ?",
            (
                *values,
                expected.case_id.ulid,
                expected.project_id,
                expected.status.value,
                format_utc(expected.updated_at),
            ),
        )
        if cursor.rowcount != 1 or self.get(expected.case_id.display_id) != result:
            raise _invalid_record()

    def _deserialize(self, row: sqlite3.Row) -> Case:
        try:
            required = (
                "internal_id",
                "project_id",
                "display_id",
                "kind",
                "status",
                "name",
                "created_at",
                "updated_at",
            )
            if any(not isinstance(row[key], str) for key in required):
                raise _invalid_record()
            for key in ("description", "closed_at"):
                if row[key] is not None and not isinstance(row[key], str):
                    raise _invalid_record()
            if row["internal_id"] != row["internal_id"].upper():
                raise _invalid_record()
            if row["project_id"] != self._workspace.manifest.project_id.ulid:
                raise _invalid_record()
            identity = CaseId(row["internal_id"], row["display_id"])
            kind = CaseKind.parse(row["kind"])
            status = CaseStatus.parse(row["status"])
            validate_case_name(row["name"])
            parsed: dict[str, datetime | None] = {}
            for key in ("created_at", "updated_at", "closed_at"):
                value = row[key]
                timestamp = None if value is None else parse_utc(value)
                parsed[key] = timestamp
                if timestamp is not None and format_utc(timestamp) != value:
                    raise _invalid_record()
            created, updated, closed = (
                parsed["created_at"],
                parsed["updated_at"],
                parsed["closed_at"],
            )
            assert created is not None and updated is not None
            if created > updated:
                raise _invalid_record()
            if status is CaseStatus.OPEN and closed is not None:
                raise _invalid_record()
            if status is CaseStatus.CLOSED and (closed is None or closed != updated):
                raise _invalid_record()
            return Case(
                identity,
                row["project_id"],
                kind,
                row["name"],
                row["description"],
                created,
                CaseLifecycle(status, updated, closed),
            )
        except (DomainError, TypeError, ValueError, OverflowError) as exc:
            raise _invalid_record() from exc
