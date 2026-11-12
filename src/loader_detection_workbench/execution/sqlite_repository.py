"""Module-owned execution tables inside the Project ``project.db`` (ADR-024).

Versioned independently of the core schema like the detection tables
(ADR-023). Steps are append-only, finished runs are immutable, and the single
safety-lock row survives process crashes so that a failed restore blocks every
later run until a person confirms the VM state with ``vm unlock``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, parse_utc, utc_now
from loader_detection_workbench.execution.domain import (
    RUN_PREFIX,
    ExecutionProfile,
    ExecutionRun,
    RunStatus,
    SafetyLock,
    StepName,
    StepRecord,
    StepStatus,
)
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

EXECUTION_SCHEMA_VERSION = 1

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS execution_schema (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS execution_counters (
        name TEXT PRIMARY KEY CHECK (name IN ('run')),
        next_value INTEGER NOT NULL CHECK (next_value >= 1)
    )""",
    """CREATE TABLE IF NOT EXISTS execution_runs (
        display_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        profile TEXT NOT NULL CHECK (profile IN ('sample', 'benign_scenario')),
        target TEXT NOT NULL,
        target_sha256 TEXT,
        vm_name TEXT NOT NULL,
        snapshot TEXT NOT NULL,
        timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds >= 1),
        status TEXT NOT NULL
            CHECK (status IN ('running', 'succeeded', 'failed', 'abandoned')),
        started_at TEXT NOT NULL,
        finished_at TEXT,
        error_code TEXT,
        sysmon_artifact_id TEXT,
        metadata_artifact_id TEXT,
        event_count INTEGER CHECK (event_count IS NULL OR event_count >= 0),
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT,
        FOREIGN KEY (sysmon_artifact_id) REFERENCES artifacts(internal_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (metadata_artifact_id) REFERENCES artifacts(internal_id)
            ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS execution_runs_finished_immutable
        BEFORE UPDATE ON execution_runs
        WHEN OLD.status <> 'running'
        BEGIN SELECT RAISE(ABORT, 'finished execution run is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS execution_runs_no_delete
        BEFORE DELETE ON execution_runs
        BEGIN SELECT RAISE(ABORT, 'execution runs are append-only'); END""",
    """CREATE TABLE IF NOT EXISTS execution_steps (
        run_display_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence >= 1),
        step TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('ok', 'failed', 'skipped')),
        at TEXT NOT NULL,
        detail TEXT,
        PRIMARY KEY (run_display_id, sequence),
        FOREIGN KEY (run_display_id) REFERENCES execution_runs(display_id)
            ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS execution_steps_no_update
        BEFORE UPDATE ON execution_steps
        BEGIN SELECT RAISE(ABORT, 'execution steps are append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS execution_steps_no_delete
        BEFORE DELETE ON execution_steps
        BEGIN SELECT RAISE(ABORT, 'execution steps are append-only'); END""",
    """CREATE TABLE IF NOT EXISTS execution_safety_lock (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        run_display_id TEXT,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS execution_lock_releases (
        released_at TEXT NOT NULL,
        run_display_id TEXT,
        reason TEXT NOT NULL,
        note TEXT NOT NULL
    )""",
)


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.EXECUTION_PERSISTENCE_FAILED,
        "execution record is malformed",
    )


class SQLiteExecutionRepository:
    def __init__(self, workspace: ProjectWorkspace, *, write: bool = False) -> None:
        self._workspace = workspace
        self._write = write
        self._connection = connect_database(
            workspace.database_path, read_only=not write
        )
        self._available = True

    def close(self) -> None:
        self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            self._connection.execute("BEGIN IMMEDIATE" if self._write else "BEGIN")
            if self._write:
                self._bootstrap()
            else:
                self._available = self._installed()
            yield
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _installed(self) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'execution_schema'"
        ).fetchone()
        if row is None:
            return False
        versions = [
            int(item[0])
            for item in self._connection.execute(
                "SELECT version FROM execution_schema ORDER BY version"
            )
        ]
        if versions != [EXECUTION_SCHEMA_VERSION]:
            raise DomainError(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "execution schema version is unsupported",
            )
        return True

    def _bootstrap(self) -> None:
        installed = self._installed()
        for statement in _SCHEMA:
            self._connection.execute(statement)
        if not installed:
            self._connection.execute(
                "INSERT INTO execution_schema (version, applied_at) VALUES (?, ?)",
                (EXECUTION_SCHEMA_VERSION, format_utc(utc_now())),
            )
            self._connection.execute(
                "INSERT INTO execution_counters (name, next_value) VALUES ('run', 1)"
            )

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("execution writes require a write transaction")

    # -- references -----------------------------------------------------------

    def case_ulid(self, case_display_id: str) -> str:
        row = self._connection.execute(
            "SELECT internal_id FROM cases WHERE display_id = ? AND project_id = ?",
            (case_display_id, self._workspace.manifest.project_id.ulid),
        ).fetchone()
        if row is None:
            raise DomainError(DomainErrorCode.CASE_NOT_FOUND, "case was not found")
        return str(row[0])

    def artifact_ulid(self, artifact_display_id: str) -> str:
        row = self._connection.execute(
            "SELECT internal_id FROM artifacts WHERE display_id = ? AND project_id = ?",
            (artifact_display_id, self._workspace.manifest.project_id.ulid),
        ).fetchone()
        if row is None:
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_FOUND, "artifact was not found"
            )
        return str(row[0])

    # -- runs -----------------------------------------------------------------

    def allocate_run_id(self) -> str:
        self._require_write()
        row = self._connection.execute(
            "SELECT next_value FROM execution_counters WHERE name = 'run'"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 1:
            raise _invalid()
        value = int(row[0])
        self._connection.execute(
            "UPDATE execution_counters SET next_value = ? WHERE name = 'run'",
            (value + 1,),
        )
        return f"{RUN_PREFIX}-{value:04d}"

    def insert_run(self, run: ExecutionRun) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO execution_runs (display_id, case_id, profile, target, "
            "target_sha256, vm_name, snapshot, timeout_seconds, status, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.display_id,
                self.case_ulid(run.case_display_id),
                run.profile.value,
                run.target,
                run.target_sha256,
                run.vm_name,
                run.snapshot,
                run.timeout_seconds,
                run.status.value,
                format_utc(run.started_at),
            ),
        )

    def append_step(
        self,
        run_display_id: str,
        step: StepName,
        status: StepStatus,
        detail: str | None,
    ) -> None:
        self._require_write()
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM execution_steps "
            "WHERE run_display_id = ?",
            (run_display_id,),
        ).fetchone()
        self._connection.execute(
            "INSERT INTO execution_steps (run_display_id, sequence, step, status, "
            "at, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (
                run_display_id,
                int(row[0]) + 1,
                step.value,
                status.value,
                format_utc(utc_now()),
                detail,
            ),
        )

    def finish_run(
        self,
        run_display_id: str,
        status: RunStatus,
        *,
        error_code: str | None = None,
        sysmon_artifact_id: str | None = None,
        metadata_artifact_id: str | None = None,
        event_count: int | None = None,
    ) -> None:
        self._require_write()
        cursor = self._connection.execute(
            "UPDATE execution_runs SET status = ?, finished_at = ?, error_code = ?, "
            "sysmon_artifact_id = ?, metadata_artifact_id = ?, event_count = ? "
            "WHERE display_id = ? AND status = 'running'",
            (
                status.value,
                format_utc(utc_now()),
                error_code,
                None
                if sysmon_artifact_id is None
                else self.artifact_ulid(sysmon_artifact_id),
                None
                if metadata_artifact_id is None
                else self.artifact_ulid(metadata_artifact_id),
                event_count,
                run_display_id,
            ),
        )
        if cursor.rowcount != 1:
            raise _invalid()

    def running_runs(self) -> list[str]:
        if not self._available:
            return []
        return [
            str(row[0])
            for row in self._connection.execute(
                "SELECT display_id FROM execution_runs WHERE status = 'running' "
                "ORDER BY display_id"
            )
        ]

    def _steps(self, run_display_id: str) -> tuple[StepRecord, ...]:
        return tuple(
            StepRecord(
                int(row["sequence"]),
                StepName(row["step"]),
                StepStatus(row["status"]),
                parse_utc(str(row["at"])),
                row["detail"],
            )
            for row in self._connection.execute(
                "SELECT * FROM execution_steps WHERE run_display_id = ? "
                "ORDER BY sequence",
                (run_display_id,),
            )
        )

    def _artifact_display(self, internal_id: object) -> str | None:
        if internal_id is None:
            return None
        row = self._connection.execute(
            "SELECT display_id FROM artifacts WHERE internal_id = ?", (internal_id,)
        ).fetchone()
        if row is None:
            raise _invalid()
        return str(row[0])

    def get_run(self, run_display_id: str) -> ExecutionRun:
        if not self._available:
            raise DomainError(
                DomainErrorCode.EXECUTION_RUN_NOT_FOUND, "execution run was not found"
            )
        row = self._connection.execute(
            "SELECT r.*, c.display_id AS case_display_id FROM execution_runs r "
            "JOIN cases c ON c.internal_id = r.case_id WHERE r.display_id = ?",
            (run_display_id,),
        ).fetchone()
        if row is None:
            raise DomainError(
                DomainErrorCode.EXECUTION_RUN_NOT_FOUND, "execution run was not found"
            )
        try:
            return ExecutionRun(
                display_id=str(row["display_id"]),
                case_display_id=str(row["case_display_id"]),
                profile=ExecutionProfile(row["profile"]),
                target=str(row["target"]),
                target_sha256=row["target_sha256"],
                vm_name=str(row["vm_name"]),
                snapshot=str(row["snapshot"]),
                timeout_seconds=int(row["timeout_seconds"]),
                status=RunStatus(row["status"]),
                started_at=parse_utc(str(row["started_at"])),
                finished_at=None
                if row["finished_at"] is None
                else parse_utc(str(row["finished_at"])),
                error_code=row["error_code"],
                sysmon_artifact_id=self._artifact_display(row["sysmon_artifact_id"]),
                metadata_artifact_id=self._artifact_display(
                    row["metadata_artifact_id"]
                ),
                event_count=row["event_count"],
                steps=self._steps(run_display_id),
            )
        except (ValueError, TypeError, sqlite3.Error) as exc:
            raise _invalid() from exc

    def list_runs(self) -> list[ExecutionRun]:
        if not self._available:
            return []
        ids = [
            str(row[0])
            for row in self._connection.execute("SELECT display_id FROM execution_runs")
        ]
        return [
            self.get_run(item)
            for item in sorted(ids, key=lambda value: int(value.rpartition("-")[2]))
        ]

    # -- safety lock ----------------------------------------------------------

    def get_lock(self) -> SafetyLock | None:
        if not self._available:
            return None
        row = self._connection.execute(
            "SELECT run_display_id, reason, created_at FROM execution_safety_lock "
            "WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        return SafetyLock(
            row["run_display_id"], str(row["reason"]), parse_utc(str(row["created_at"]))
        )

    def set_lock(self, run_display_id: str | None, reason: str) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT OR IGNORE INTO execution_safety_lock "
            "(id, run_display_id, reason, created_at) VALUES (1, ?, ?, ?)",
            (run_display_id, reason, format_utc(utc_now())),
        )

    def release_lock(self, note: str) -> SafetyLock | None:
        self._require_write()
        lock = self.get_lock()
        if lock is not None:
            self._connection.execute(
                "INSERT INTO execution_lock_releases (released_at, run_display_id, "
                "reason, note) VALUES (?, ?, ?, ?)",
                (format_utc(utc_now()), lock.run_display_id, lock.reason, note),
            )
            self._connection.execute("DELETE FROM execution_safety_lock WHERE id = 1")
        return lock
