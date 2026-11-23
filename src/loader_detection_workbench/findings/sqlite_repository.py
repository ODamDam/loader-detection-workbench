"""Module-owned finding tables inside the Project ``project.db`` (ADR-031).

``findings`` holds the current value of each finding. ``finding_revisions`` is
an append-only log of every create, edit, confirm and withdraw, so the content
a report was built from can always be traced back.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, parse_utc, utc_now
from loader_detection_workbench.findings.domain import (
    FINDING_PREFIX,
    AnalystFinding,
    EvidenceRef,
    FindingContent,
    FindingKind,
    FindingRevision,
    FindingState,
    RevisionAction,
    Verdict,
)
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

FINDINGS_SCHEMA_VERSION = 1

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS findings_schema (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS findings_counters (
        name TEXT PRIMARY KEY CHECK (name IN ('finding')),
        next_value INTEGER NOT NULL CHECK (next_value >= 1)
    )""",
    """CREATE TABLE IF NOT EXISTS findings (
        display_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        kind TEXT NOT NULL
            CHECK (kind IN ('hypothesis', 'evidence', 'link', 'mechanism')),
        state TEXT NOT NULL CHECK (state IN ('draft', 'confirmed', 'withdrawn')),
        source TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        content_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        confirmed_at TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS findings_no_delete
        BEFORE DELETE ON findings
        BEGIN SELECT RAISE(ABORT, 'findings are withdrawn, never deleted'); END""",
    """CREATE TRIGGER IF NOT EXISTS findings_identity_immutable
        BEFORE UPDATE ON findings
        WHEN NEW.case_id IS NOT OLD.case_id OR NEW.kind IS NOT OLD.kind
            OR NEW.source IS NOT OLD.source OR NEW.created_at IS NOT OLD.created_at
            OR NEW.revision <> OLD.revision + 1
        BEGIN SELECT RAISE(ABORT, 'finding identity is immutable'); END""",
    """CREATE TABLE IF NOT EXISTS finding_revisions (
        display_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        action TEXT NOT NULL
            CHECK (action IN ('create', 'edit', 'confirm', 'withdraw')),
        state TEXT NOT NULL CHECK (state IN ('draft', 'confirmed', 'withdrawn')),
        content_json TEXT NOT NULL,
        at TEXT NOT NULL,
        note TEXT,
        PRIMARY KEY (display_id, revision),
        FOREIGN KEY (display_id) REFERENCES findings(display_id) ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS finding_revisions_immutable
        BEFORE UPDATE ON finding_revisions
        BEGIN SELECT RAISE(ABORT, 'finding revisions are immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS finding_revisions_no_delete
        BEFORE DELETE ON finding_revisions
        BEGIN SELECT RAISE(ABORT, 'finding revisions are append-only'); END""",
)


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.FINDING_PERSISTENCE_FAILED, "persisted finding is malformed"
    )


def _not_found() -> DomainError:
    return DomainError(DomainErrorCode.FINDING_NOT_FOUND, "finding was not found")


def content_json(content: FindingContent) -> str:
    return json.dumps(
        {
            "title": content.title,
            "text": content.text,
            "verdict": None if content.verdict is None else content.verdict.value,
            "evidence": [str(ref) for ref in content.evidence],
            "hypothesis": content.hypothesis_display_id,
            "findings": list(content.finding_refs),
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def parse_content(kind: str, raw: str) -> FindingContent:
    data: Any = json.loads(raw)
    return FindingContent(
        FindingKind(kind),
        str(data["text"]),
        data["title"],
        None if data["verdict"] is None else Verdict(data["verdict"]),
        tuple(EvidenceRef.parse(str(item)) for item in data["evidence"]),
        data["hypothesis"],
        tuple(str(item) for item in data["findings"]),
    )


class SQLiteFindingRepository:
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
            "AND name = 'findings_schema'"
        ).fetchone()
        if row is None:
            return False
        versions = [
            int(item[0])
            for item in self._connection.execute(
                "SELECT version FROM findings_schema ORDER BY version"
            )
        ]
        if versions != [FINDINGS_SCHEMA_VERSION]:
            raise DomainError(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "finding schema version is unsupported",
            )
        return True

    def _bootstrap(self) -> None:
        installed = self._installed()
        for statement in _SCHEMA:
            self._connection.execute(statement)
        if not installed:
            self._connection.execute(
                "INSERT INTO findings_schema (version, applied_at) VALUES (?, ?)",
                (FINDINGS_SCHEMA_VERSION, format_utc(utc_now())),
            )
            self._connection.execute(
                "INSERT INTO findings_counters (name, next_value) VALUES ('finding', 1)"
            )

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("finding writes require a write transaction")

    # -- Case and reference lookups ------------------------------------------

    def case(self, case_display_id: str) -> tuple[str, str]:
        """Return (internal ID, status) of a Case of this Project."""
        row = self._connection.execute(
            "SELECT internal_id, status FROM cases "
            "WHERE display_id = ? AND project_id = ?",
            (case_display_id, self._workspace.manifest.project_id.ulid),
        ).fetchone()
        if row is None:
            raise DomainError(DomainErrorCode.CASE_NOT_FOUND, "case was not found")
        return str(row[0]), str(row[1])

    def case_artifacts(self, case_ulid: str) -> dict[str, str]:
        """Attached Artifacts of a Case: display ID -> kind."""
        return {
            str(row[0]): str(row[1])
            for row in self._connection.execute(
                "SELECT display_id, kind FROM artifacts WHERE case_id = ?", (case_ulid,)
            )
        }

    def case_hypotheses(self, case_ulid: str) -> set[str]:
        tables = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "detection_hypotheses" not in tables:
            return set()
        return {
            str(row[0])
            for row in self._connection.execute(
                "SELECT display_id FROM detection_hypotheses WHERE case_id = ?",
                (case_ulid,),
            )
        }

    # -- writes ---------------------------------------------------------------

    def insert(
        self,
        case_ulid: str,
        content: FindingContent,
        source: str,
        at: datetime,
        note: str | None,
    ) -> str:
        self._require_write()
        row = self._connection.execute(
            "SELECT next_value FROM findings_counters WHERE name = 'finding'"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 1:
            raise _invalid()
        value = int(row[0])
        self._connection.execute(
            "UPDATE findings_counters SET next_value = ? WHERE name = 'finding'",
            (value + 1,),
        )
        display_id = f"{FINDING_PREFIX}-{value:04d}"
        serialized = content_json(content)
        stamp = format_utc(at)
        self._connection.execute(
            "INSERT INTO findings (display_id, case_id, kind, state, source, revision, "
            "content_json, created_at, updated_at, confirmed_at) "
            "VALUES (?, ?, ?, 'draft', ?, 1, ?, ?, ?, NULL)",
            (
                display_id,
                case_ulid,
                content.kind.value,
                source,
                serialized,
                stamp,
                stamp,
            ),
        )
        self._log(
            display_id,
            1,
            RevisionAction.CREATE,
            FindingState.DRAFT,
            serialized,
            stamp,
            note,
        )
        return display_id

    def update(
        self,
        finding: AnalystFinding,
        content: FindingContent,
        state: FindingState,
        action: RevisionAction,
        at: datetime,
        note: str | None,
    ) -> None:
        self._require_write()
        revision = finding.revision + 1
        serialized = content_json(content)
        stamp = format_utc(at)
        confirmed_at: str | None
        if state is FindingState.CONFIRMED:
            confirmed_at = stamp
        elif state is FindingState.WITHDRAWN and finding.confirmed_at is not None:
            confirmed_at = format_utc(finding.confirmed_at)
        else:
            confirmed_at = None
        cursor = self._connection.execute(
            "UPDATE findings SET state = ?, revision = ?, content_json = ?, "
            "updated_at = ?, confirmed_at = ? WHERE display_id = ? AND revision = ?",
            (
                state.value,
                revision,
                serialized,
                stamp,
                confirmed_at,
                finding.display_id,
                finding.revision,
            ),
        )
        if cursor.rowcount != 1:
            raise DomainError(
                DomainErrorCode.FINDING_STATE_INVALID,
                "finding changed concurrently; reload and retry",
            )
        self._log(finding.display_id, revision, action, state, serialized, stamp, note)

    def _log(
        self,
        display_id: str,
        revision: int,
        action: RevisionAction,
        state: FindingState,
        serialized: str,
        stamp: str,
        note: str | None,
    ) -> None:
        self._connection.execute(
            "INSERT INTO finding_revisions (display_id, revision, action, state, "
            "content_json, at, note) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (display_id, revision, action.value, state.value, serialized, stamp, note),
        )

    # -- reads ----------------------------------------------------------------

    def _history(self, display_id: str, kind: str) -> tuple[FindingRevision, ...]:
        items: list[FindingRevision] = []
        for row in self._connection.execute(
            "SELECT * FROM finding_revisions WHERE display_id = ? ORDER BY revision",
            (display_id,),
        ):
            items.append(
                FindingRevision(
                    int(row["revision"]),
                    RevisionAction(row["action"]),
                    FindingState(row["state"]),
                    parse_content(kind, str(row["content_json"])),
                    parse_utc(str(row["at"])),
                    row["note"],
                )
            )
        return tuple(items)

    def get(self, display_id: str) -> AnalystFinding:
        if not self._available:
            raise _not_found()
        row = self._connection.execute(
            "SELECT f.*, c.display_id AS case_display_id FROM findings f "
            "JOIN cases c ON c.internal_id = f.case_id WHERE f.display_id = ?",
            (display_id,),
        ).fetchone()
        if row is None:
            raise _not_found()
        try:
            kind = str(row["kind"])
            return AnalystFinding(
                str(row["display_id"]),
                str(row["case_display_id"]),
                parse_content(kind, str(row["content_json"])),
                FindingState(row["state"]),
                str(row["source"]),
                int(row["revision"]),
                parse_utc(str(row["created_at"])),
                parse_utc(str(row["updated_at"])),
                None
                if row["confirmed_at"] is None
                else parse_utc(str(row["confirmed_at"])),
                self._history(display_id, kind),
            )
        except (KeyError, TypeError, ValueError, DomainError, sqlite3.Error) as exc:
            raise _invalid() from exc

    def list(self, case_ulid: str | None = None) -> list[AnalystFinding]:
        if not self._available:
            return []
        query = "SELECT display_id FROM findings"
        parameters: tuple[str, ...] = ()
        if case_ulid is not None:
            query += " WHERE case_id = ?"
            parameters = (case_ulid,)
        ids = [str(row[0]) for row in self._connection.execute(query, parameters)]
        return [
            self.get(item)
            for item in sorted(ids, key=lambda value: int(value.rpartition("-")[2]))
        ]
