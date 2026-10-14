"""Version-aware SQLite bootstrap and structural verification."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from loader_detection_workbench.contracts import SQLITE_SCHEMA_VERSION
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, parse_utc
from loader_detection_workbench.domain.validation import Finding, FindingSeverity
from loader_detection_workbench.project.manifest import ProjectManifest

V1_CORE_TABLES = (
    "schema_migrations",
    "projects",
    "counters",
    "cases",
    "artifacts",
)
V2_TABLES = ("artifact_provenance",)
CORE_TABLES = V1_CORE_TABLES + V2_TABLES

_V1_SCHEMA_STATEMENTS = (
    """CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )""",
    """CREATE TABLE projects (
        internal_id TEXT PRIMARY KEY,
        display_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE counters (
        name TEXT PRIMARY KEY,
        next_value INTEGER NOT NULL CHECK (next_value >= 1)
    )""",
    """CREATE TABLE cases (
        internal_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        display_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('malware', 'simulator', 'benign')),
        status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
        name TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        closed_at TEXT,
        UNIQUE (project_id, display_id),
        FOREIGN KEY (project_id) REFERENCES projects(internal_id) ON DELETE RESTRICT
    )""",
    """CREATE TABLE artifacts (
        internal_id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        display_id TEXT NOT NULL,
        case_id TEXT,
        kind TEXT NOT NULL,
        relative_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
        created_at TEXT NOT NULL,
        UNIQUE (project_id, display_id),
        FOREIGN KEY (project_id) REFERENCES projects(internal_id) ON DELETE RESTRICT,
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT
    )""",
)

ARTIFACT_PROVENANCE_SQL = """CREATE TABLE artifact_provenance (
    artifact_id TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL
        CHECK (length(original_filename) BETWEEN 1 AND 255),
    source TEXT NOT NULL
        CHECK (length(trim(source)) BETWEEN 1 AND 512),
    description TEXT
        CHECK (description IS NULL OR length(description) BETWEEN 1 AND 2000),
    evidence_type TEXT NOT NULL
        CHECK (evidence_type IN (
            'analyst_note', 'event_export', 'configuration',
            'tool_output', 'indicator_list', 'other'
        )),
    FOREIGN KEY (artifact_id) REFERENCES artifacts(internal_id) ON DELETE RESTRICT
)"""

_SCHEMA_STATEMENTS = (*_V1_SCHEMA_STATEMENTS, ARTIFACT_PROVENANCE_SQL)

_EXPECTED_COLUMNS: dict[str, tuple[tuple[str, str, int, int], ...]] = {
    "schema_migrations": (("version", "INTEGER", 0, 1), ("applied_at", "TEXT", 1, 0)),
    "projects": (
        ("internal_id", "TEXT", 0, 1),
        ("display_id", "TEXT", 1, 0),
        ("name", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "counters": (("name", "TEXT", 0, 1), ("next_value", "INTEGER", 1, 0)),
    "cases": (
        ("internal_id", "TEXT", 0, 1),
        ("project_id", "TEXT", 1, 0),
        ("display_id", "TEXT", 1, 0),
        ("kind", "TEXT", 1, 0),
        ("status", "TEXT", 1, 0),
        ("name", "TEXT", 1, 0),
        ("description", "TEXT", 0, 0),
        ("created_at", "TEXT", 1, 0),
        ("updated_at", "TEXT", 1, 0),
        ("closed_at", "TEXT", 0, 0),
    ),
    "artifacts": (
        ("internal_id", "TEXT", 0, 1),
        ("project_id", "TEXT", 1, 0),
        ("display_id", "TEXT", 1, 0),
        ("case_id", "TEXT", 0, 0),
        ("kind", "TEXT", 1, 0),
        ("relative_path", "TEXT", 1, 0),
        ("sha256", "TEXT", 1, 0),
        ("size_bytes", "INTEGER", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "artifact_provenance": (
        ("artifact_id", "TEXT", 0, 1),
        ("original_filename", "TEXT", 1, 0),
        ("source", "TEXT", 1, 0),
        ("description", "TEXT", 0, 0),
        ("evidence_type", "TEXT", 1, 0),
    ),
}


def connect_database(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        connection = sqlite3.connect(f"{path.absolute().as_uri()}?mode=ro", uri=True)
    else:
        connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def database_versions(connection: sqlite3.Connection) -> list[int]:
    return [
        int(row[0])
        for row in connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]


def read_database_version(path: Path) -> int:
    connection = connect_database(path, read_only=True)
    try:
        versions = database_versions(connection)
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise DomainError(
            DomainErrorCode.INVALID_SQLITE_SCHEMA,
            "SQLite migration history is malformed",
        ) from exc
    finally:
        connection.close()
    if versions not in ([1], [1, 2]):
        code = (
            DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION
            if any(version > SQLITE_SCHEMA_VERSION for version in versions)
            else DomainErrorCode.INVALID_SQLITE_SCHEMA
        )
        raise DomainError(code, "SQLite migration history is unsupported")
    return versions[-1]


def bootstrap_database(
    path: Path, manifest: ProjectManifest, created_at: datetime
) -> None:
    connection = connect_database(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            timestamp = format_utc(created_at)
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (1, timestamp),
            )
            if SQLITE_SCHEMA_VERSION >= 2:
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (2, timestamp),
                )
            connection.execute(
                "INSERT INTO projects "
                "(internal_id, display_id, name, created_at) VALUES (?, ?, ?, ?)",
                (
                    manifest.project_id.ulid,
                    manifest.project_id.display_id,
                    manifest.name,
                    timestamp,
                ),
            )
            connection.executemany(
                "INSERT INTO counters (name, next_value) VALUES (?, ?)",
                (("case", 1), ("artifact", 1)),
            )
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
    finally:
        connection.close()


def _finding(code: DomainErrorCode, message: str, field: str | None = None) -> Finding:
    return Finding(code.value, FindingSeverity.ERROR, message, field)


def _table_columns(
    connection: sqlite3.Connection, table: str
) -> tuple[tuple[str, str, int, int], ...]:
    rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    return tuple(
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5])) for row in rows
    )


def _table_sql(connection: sqlite3.Connection, table: str) -> str:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return (
        "" if row is None or row[0] is None else " ".join(str(row[0]).lower().split())
    )


def _unique_column_sets(
    connection: sqlite3.Connection, table: str
) -> set[tuple[str, ...]]:
    result: set[tuple[str, ...]] = set()
    for index in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
        if int(index[2]) != 1:
            continue
        columns = connection.execute(f'PRAGMA index_info("{index[1]}")').fetchall()
        result.add(tuple(str(column[2]) for column in columns))
    return result


def _foreign_keys(
    connection: sqlite3.Connection, table: str
) -> set[tuple[str, str, str, str]]:
    return {
        (str(row[3]), str(row[2]), str(row[4]), str(row[6]).upper())
        for row in connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
    }


def validate_v2_migration_state(connection: sqlite3.Connection) -> None:
    """Validate uncommitted v2 DDL before a migration is committed."""
    try:
        if database_versions(connection) != [1, 2]:
            raise ValueError
        if (
            _table_columns(connection, "artifact_provenance")
            != _EXPECTED_COLUMNS["artifact_provenance"]
        ):
            raise ValueError
        findings: list[Finding] = []
        _validate_artifact_provenance_schema(connection, findings)
        if findings or connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise DomainError(
            DomainErrorCode.PROJECT_MIGRATION_FAILED,
            "migrated database failed v2 verification",
        ) from exc


def validate_database(path: Path, manifest: ProjectManifest) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    try:
        connection = connect_database(path, read_only=True)
    except sqlite3.Error:
        return (
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "project database cannot be opened",
            ),
        )
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        version: int | None = None
        migration_rows: list[sqlite3.Row] = []
        if "schema_migrations" in tables:
            try:
                migration_rows = connection.execute(
                    "SELECT version, applied_at FROM schema_migrations ORDER BY version"
                ).fetchall()
                versions = [int(row[0]) for row in migration_rows]
                if any(version > SQLITE_SCHEMA_VERSION for version in versions):
                    findings.append(
                        _finding(
                            DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                            "unsupported SQLite core schema version",
                        )
                    )
                elif versions not in ([1], [1, 2]):
                    findings.append(
                        _finding(
                            DomainErrorCode.INVALID_SQLITE_SCHEMA,
                            "SQLite migration history must be [1] or [1, 2]",
                        )
                    )
                else:
                    version = versions[-1]
                for row in migration_rows:
                    value = str(row[1])
                    timestamp = parse_utc(value)
                    if format_utc(timestamp) != value:
                        raise DomainError(
                            DomainErrorCode.INVALID_TIMESTAMP,
                            "migration timestamp is not canonical UTC",
                        )
            except (sqlite3.Error, DomainError, TypeError, ValueError):
                findings.append(
                    _finding(
                        DomainErrorCode.INVALID_SQLITE_SCHEMA,
                        "SQLite migration history is malformed",
                    )
                )

        required = V1_CORE_TABLES + (V2_TABLES if version == 2 else ())
        missing = [table for table in required if table not in tables]
        for table in missing:
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_SQLITE_SCHEMA,
                    f"required core table is missing: {table}",
                    table,
                )
            )
        if version == 1 and "artifact_provenance" in tables:
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_SQLITE_SCHEMA,
                    "v1 database contains a partial v2 table",
                    "artifact_provenance",
                )
            )

        for table in required:
            if table in missing:
                continue
            if _table_columns(connection, table) != _EXPECTED_COLUMNS[table]:
                findings.append(
                    _finding(
                        DomainErrorCode.INVALID_SQLITE_SCHEMA,
                        f"core table structure is incompatible: {table}",
                        table,
                    )
                )

        if "counters" not in missing:
            _validate_counters(connection, findings)
        if "projects" not in missing:
            _validate_unique_constraints(
                connection,
                "projects",
                {("internal_id",), ("display_id",)},
                findings,
            )
        if "cases" not in missing:
            _validate_cases_schema(connection, findings)
        if "artifacts" not in missing:
            _validate_artifacts_schema(connection, findings)
        if version == 2 and "artifact_provenance" not in missing:
            _validate_artifact_provenance_schema(connection, findings)
        if "projects" not in missing:
            _validate_project_row(connection, manifest, findings)
    except sqlite3.Error:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA, "project database is malformed"
            )
        )
    finally:
        connection.close()
    return tuple(findings)


def _validate_counters(connection: sqlite3.Connection, findings: list[Finding]) -> None:
    rows = {
        str(row[0]): row[1]
        for row in connection.execute("SELECT name, next_value FROM counters")
    }
    for name in ("case", "artifact"):
        value = rows.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_SQLITE_SCHEMA,
                    f"counter is missing or invalid: {name}",
                    f"counters.{name}",
                )
            )
    if "check (next_value >= 1)" not in _table_sql(connection, "counters"):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "counter constraint is incompatible",
                "counters",
            )
        )


def _validate_cases_schema(
    connection: sqlite3.Connection, findings: list[Finding]
) -> None:
    sql = _table_sql(connection, "cases")
    required_fragments = (
        "check (kind in ('malware', 'simulator', 'benign'))",
        "check (status in ('open', 'closed'))",
    )
    if not all(fragment in sql for fragment in required_fragments):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "case constraints are incompatible",
                "cases",
            )
        )
    _validate_unique_constraints(
        connection,
        "cases",
        {("internal_id",), ("project_id", "display_id")},
        findings,
    )
    expected_fk = {("project_id", "projects", "internal_id", "RESTRICT")}
    if _foreign_keys(connection, "cases") != expected_fk:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "case foreign keys are incompatible",
                "cases",
            )
        )


def _validate_artifacts_schema(
    connection: sqlite3.Connection, findings: list[Finding]
) -> None:
    sql = _table_sql(connection, "artifacts")
    if "check (size_bytes >= 0)" not in sql:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact size constraint is missing",
                "artifacts",
            )
        )
    unique_sets = _unique_column_sets(connection, "artifacts")
    _validate_unique_constraints(
        connection,
        "artifacts",
        {("internal_id",), ("project_id", "display_id")},
        findings,
    )
    if any(
        "relative_path" in columns or "sha256" in columns for columns in unique_sets
    ):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact path and hash must not be unique",
                "artifacts",
            )
        )
    expected_fk = {
        ("project_id", "projects", "internal_id", "RESTRICT"),
        ("case_id", "cases", "internal_id", "RESTRICT"),
    }
    if _foreign_keys(connection, "artifacts") != expected_fk:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact foreign keys are incompatible",
                "artifacts",
            )
        )


def _validate_artifact_provenance_schema(
    connection: sqlite3.Connection, findings: list[Finding]
) -> None:
    sql = _table_sql(connection, "artifact_provenance")
    required_fragments = (
        "check (length(original_filename) between 1 and 255)",
        "check (length(trim(source)) between 1 and 512)",
        "check (description is null or length(description) between 1 and 2000)",
        "'analyst_note'",
        "'event_export'",
        "'configuration'",
        "'tool_output'",
        "'indicator_list'",
        "'other'",
    )
    if not all(fragment in sql for fragment in required_fragments):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact provenance constraints are incompatible",
                "artifact_provenance",
            )
        )
    _validate_unique_constraints(
        connection,
        "artifact_provenance",
        {("artifact_id",)},
        findings,
    )
    expected_fk = {("artifact_id", "artifacts", "internal_id", "RESTRICT")}
    if _foreign_keys(connection, "artifact_provenance") != expected_fk:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                "artifact provenance foreign key is incompatible",
                "artifact_provenance",
            )
        )


def _validate_unique_constraints(
    connection: sqlite3.Connection,
    table: str,
    expected: set[tuple[str, ...]],
    findings: list[Finding],
) -> None:
    if _unique_column_sets(connection, table) != expected:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_SQLITE_SCHEMA,
                f"unique constraints are incompatible: {table}",
                table,
            )
        )


def _validate_project_row(
    connection: sqlite3.Connection, manifest: ProjectManifest, findings: list[Finding]
) -> None:
    rows = connection.execute(
        "SELECT internal_id, display_id, name, created_at "
        "FROM projects ORDER BY internal_id"
    ).fetchall()
    if len(rows) != 1:
        findings.append(
            _finding(
                DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH,
                "workspace must contain exactly one Project row",
                "projects",
            )
        )
        return
    row = rows[0]
    expected: Iterable[str] = (
        manifest.project_id.ulid,
        manifest.project_id.display_id,
        manifest.name,
        format_utc(manifest.created_at),
    )
    if tuple(str(value) for value in row) != tuple(expected):
        findings.append(
            _finding(
                DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH,
                "project.json and project database metadata differ",
                "projects",
            )
        )
