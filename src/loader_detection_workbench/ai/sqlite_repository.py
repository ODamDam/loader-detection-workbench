"""Module-owned AI analysis tables inside the Project ``project.db`` (ADR-026).

Versioned independently of the core schema like the detection (ADR-023) and
execution (ADR-024) tables. An analysis and the content of its suggestions are
immutable; only the review fields of a still pending suggestion can change,
exactly once.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from loader_detection_workbench.ai.domain import (
    ANALYSIS_PREFIX,
    AiAnalysis,
    ProviderSuggestion,
    ReviewState,
    Suggestion,
    SuggestionKind,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, parse_utc, utc_now
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

AI_SCHEMA_VERSION = 3
# v1 (ADR-026) is still readable; the first write migrates it, widening the
# suggestion kinds for the ADR-031 stages (v2). v3 only adds the append-only
# ``ai_translations`` table (ADR-033), so a v2 database is upgraded in place.
READABLE_AI_SCHEMA_VERSIONS = (1, 2, 3)
TRANSLATION_LANGUAGES = ("ko",)
_KINDS = ", ".join(f"'{kind.value}'" for kind in SuggestionKind)

_SUGGESTION_TABLE = f"""CREATE TABLE IF NOT EXISTS {{name}} (
        analysis_display_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence >= 1),
        kind TEXT NOT NULL CHECK (kind IN ({_KINDS})),
        content_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'rejected')),
        reviewed_at TEXT,
        review_note TEXT,
        hypothesis_display_id TEXT,
        PRIMARY KEY (analysis_display_id, sequence),
        FOREIGN KEY (analysis_display_id) REFERENCES ai_analyses(display_id)
            ON DELETE RESTRICT
    )"""
_SUGGESTION_TRIGGERS = (
    "ai_suggestions_reviewed_immutable",
    "ai_suggestions_content_immutable",
    "ai_suggestions_no_delete",
)

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS ai_schema (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS ai_counters (
        name TEXT PRIMARY KEY CHECK (name IN ('analysis')),
        next_value INTEGER NOT NULL CHECK (next_value >= 1)
    )""",
    """CREATE TABLE IF NOT EXISTS ai_analyses (
        display_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        input_scope TEXT NOT NULL,
        input_sha256 TEXT NOT NULL,
        input_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS ai_analyses_immutable
        BEFORE UPDATE ON ai_analyses
        BEGIN SELECT RAISE(ABORT, 'AI analyses are immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS ai_analyses_no_delete
        BEFORE DELETE ON ai_analyses
        BEGIN SELECT RAISE(ABORT, 'AI analyses are append-only'); END""",
    _SUGGESTION_TABLE.format(name="ai_suggestions"),
    """CREATE TRIGGER IF NOT EXISTS ai_suggestions_reviewed_immutable
        BEFORE UPDATE ON ai_suggestions
        WHEN OLD.state <> 'pending'
        BEGIN SELECT RAISE(ABORT, 'reviewed AI suggestion is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS ai_suggestions_content_immutable
        BEFORE UPDATE ON ai_suggestions
        WHEN NEW.content_json IS NOT OLD.content_json OR NEW.kind IS NOT OLD.kind
        BEGIN SELECT RAISE(ABORT, 'AI suggestion content is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS ai_suggestions_no_delete
        BEFORE DELETE ON ai_suggestions
        BEGIN SELECT RAISE(ABORT, 'AI suggestions are append-only'); END""",
    # ADR-033: machine translations of suggestion text, for reading only.
    """CREATE TABLE IF NOT EXISTS ai_translations (
        analysis_display_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence >= 1),
        language TEXT NOT NULL CHECK (language IN ('ko')),
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        title TEXT,
        text TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (analysis_display_id, sequence, language),
        FOREIGN KEY (analysis_display_id, sequence)
            REFERENCES ai_suggestions(analysis_display_id, sequence)
            ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS ai_translations_immutable
        BEFORE UPDATE ON ai_translations
        BEGIN SELECT RAISE(ABORT, 'AI translations are immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS ai_translations_no_delete
        BEFORE DELETE ON ai_translations
        BEGIN SELECT RAISE(ABORT, 'AI translations are append-only'); END""",
)


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.AI_PERSISTENCE_FAILED, "persisted AI record is malformed"
    )


def _not_found() -> DomainError:
    return DomainError(
        DomainErrorCode.AI_ANALYSIS_NOT_FOUND, "AI analysis was not found"
    )


class SQLiteAiRepository:
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

    def _version(self) -> int | None:
        row = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ai_schema'"
        ).fetchone()
        if row is None:
            return None
        versions = [
            int(item[0])
            for item in self._connection.execute(
                "SELECT version FROM ai_schema ORDER BY version"
            )
        ]
        if len(versions) != 1 or versions[0] not in READABLE_AI_SCHEMA_VERSIONS:
            raise DomainError(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "AI analysis schema version is unsupported",
            )
        return versions[0]

    def _installed(self) -> bool:
        return self._version() is not None

    def _migrate_v1(self) -> None:
        """Widen the suggestion kinds; rows and triggers are carried over."""
        self._connection.execute(_SUGGESTION_TABLE.format(name="ai_suggestions_v2"))
        self._connection.execute(
            "INSERT INTO ai_suggestions_v2 SELECT analysis_display_id, sequence, "
            "kind, content_json, state, reviewed_at, review_note, "
            "hypothesis_display_id FROM ai_suggestions"
        )
        for trigger in _SUGGESTION_TRIGGERS:
            self._connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        self._connection.execute("DROP TABLE ai_suggestions")
        self._connection.execute(
            "ALTER TABLE ai_suggestions_v2 RENAME TO ai_suggestions"
        )
        self._connection.execute("DELETE FROM ai_schema")
        self._connection.execute(
            "INSERT INTO ai_schema (version, applied_at) VALUES (?, ?)",
            (AI_SCHEMA_VERSION, format_utc(utc_now())),
        )

    def _bootstrap(self) -> None:
        version = self._version()
        installed = version is not None
        if version == 1:
            self._migrate_v1()
        elif version == 2:
            # v2 -> v3 adds a table only; the statements below create it.
            self._connection.execute(
                "UPDATE ai_schema SET version = ?, applied_at = ?",
                (AI_SCHEMA_VERSION, format_utc(utc_now())),
            )
        for statement in _SCHEMA:
            self._connection.execute(statement)
        if not installed:
            self._connection.execute(
                "INSERT INTO ai_schema (version, applied_at) VALUES (?, ?)",
                (AI_SCHEMA_VERSION, format_utc(utc_now())),
            )
            self._connection.execute(
                "INSERT INTO ai_counters (name, next_value) VALUES ('analysis', 1)"
            )

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("AI writes require a write transaction")

    def case_ulid(self, case_display_id: str) -> str:
        row = self._connection.execute(
            "SELECT internal_id FROM cases WHERE display_id = ? AND project_id = ?",
            (case_display_id, self._workspace.manifest.project_id.ulid),
        ).fetchone()
        if row is None:
            raise DomainError(DomainErrorCode.CASE_NOT_FOUND, "case was not found")
        return str(row[0])

    # -- writes ---------------------------------------------------------------

    def insert_analysis(
        self,
        case_display_id: str,
        provider: str,
        model: str,
        input_scope: str,
        input_sha256: str,
        input_json: str,
        suggestions: tuple[ProviderSuggestion, ...],
    ) -> str:
        self._require_write()
        row = self._connection.execute(
            "SELECT next_value FROM ai_counters WHERE name = 'analysis'"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 1:
            raise _invalid()
        value = int(row[0])
        self._connection.execute(
            "UPDATE ai_counters SET next_value = ? WHERE name = 'analysis'",
            (value + 1,),
        )
        display_id = f"{ANALYSIS_PREFIX}-{value:04d}"
        self._connection.execute(
            "INSERT INTO ai_analyses (display_id, case_id, provider, model, "
            "input_scope, input_sha256, input_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                display_id,
                self.case_ulid(case_display_id),
                provider,
                model,
                input_scope,
                input_sha256,
                input_json,
                format_utc(utc_now()),
            ),
        )
        for sequence, suggestion in enumerate(suggestions, start=1):
            self._connection.execute(
                "INSERT INTO ai_suggestions (analysis_display_id, sequence, kind, "
                "content_json, state) VALUES (?, ?, ?, ?, 'pending')",
                (
                    display_id,
                    sequence,
                    suggestion.kind.value,
                    json.dumps(
                        {
                            "title": suggestion.title,
                            "text": suggestion.text,
                            "evidence": list(suggestion.evidence_artifact_ids),
                            "expected_benign": suggestion.expected_benign,
                        },
                        sort_keys=True,
                        ensure_ascii=False,
                    ),
                ),
            )
        return display_id

    def review(
        self,
        analysis_display_id: str,
        sequence: int,
        state: ReviewState,
        note: str | None,
        hypothesis_display_id: str | None,
        at: datetime,
    ) -> None:
        self._require_write()
        cursor = self._connection.execute(
            "UPDATE ai_suggestions SET state = ?, reviewed_at = ?, review_note = ?, "
            "hypothesis_display_id = ? WHERE analysis_display_id = ? AND sequence = ? "
            "AND state = 'pending'",
            (
                state.value,
                format_utc(at),
                note,
                hypothesis_display_id,
                analysis_display_id,
                sequence,
            ),
        )
        if cursor.rowcount != 1:
            raise DomainError(
                DomainErrorCode.AI_SUGGESTION_ALREADY_REVIEWED,
                "suggestion is missing or was already reviewed",
            )

    def insert_translations(
        self,
        analysis_display_id: str,
        language: str,
        provider: str,
        model: str,
        request_sha256: str,
        items: tuple[tuple[int, str | None, str], ...],
    ) -> int:
        """Store (sequence, title, text) translations; existing ones are kept."""
        self._require_write()
        if language not in TRANSLATION_LANGUAGES:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "translation language is unsupported",
            )
        stored = 0
        at = format_utc(utc_now())
        for sequence, title, text in items:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO ai_translations (analysis_display_id, sequence, "
                "language, provider, model, title, text, request_sha256, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    analysis_display_id,
                    sequence,
                    language,
                    provider,
                    model,
                    title,
                    text,
                    request_sha256,
                    at,
                ),
            )
            stored += cursor.rowcount
        return stored

    # -- reads ----------------------------------------------------------------

    def translations(
        self, analysis_display_id: str, language: str = "ko"
    ) -> dict[int, tuple[str | None, str]]:
        """sequence -> (title, text); empty before v3 or without translations."""
        if not self._available:
            return {}
        exists = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'ai_translations'"
        ).fetchone()
        if exists is None:
            return {}
        return {
            int(row["sequence"]): (row["title"], str(row["text"]))
            for row in self._connection.execute(
                "SELECT sequence, title, text FROM ai_translations "
                "WHERE analysis_display_id = ? AND language = ? ORDER BY sequence",
                (analysis_display_id, language),
            )
        }

    def _suggestions(self, display_id: str) -> tuple[Suggestion, ...]:
        items: list[Suggestion] = []
        for row in self._connection.execute(
            "SELECT * FROM ai_suggestions WHERE analysis_display_id = ? "
            "ORDER BY sequence",
            (display_id,),
        ):
            try:
                content = json.loads(row["content_json"])
                items.append(
                    Suggestion(
                        int(row["sequence"]),
                        SuggestionKind(row["kind"]),
                        content["title"],
                        str(content["text"]),
                        tuple(str(item) for item in content["evidence"]),
                        content["expected_benign"],
                        ReviewState(row["state"]),
                        None
                        if row["reviewed_at"] is None
                        else parse_utc(str(row["reviewed_at"])),
                        row["review_note"],
                        row["hypothesis_display_id"],
                    )
                )
            except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
                raise _invalid() from exc
        return tuple(items)

    def get(self, display_id: str) -> AiAnalysis:
        if not self._available:
            raise _not_found()
        row = self._connection.execute(
            "SELECT a.*, c.display_id AS case_display_id FROM ai_analyses a "
            "JOIN cases c ON c.internal_id = a.case_id WHERE a.display_id = ?",
            (display_id,),
        ).fetchone()
        if row is None:
            raise _not_found()
        try:
            return AiAnalysis(
                str(row["display_id"]),
                str(row["case_display_id"]),
                str(row["provider"]),
                str(row["model"]),
                str(row["input_scope"]),
                str(row["input_sha256"]),
                str(row["input_json"]),
                parse_utc(str(row["created_at"])),
                self._suggestions(display_id),
            )
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc

    def list(self, case_display_id: str | None = None) -> list[AiAnalysis]:
        if not self._available:
            return []
        query = "SELECT display_id FROM ai_analyses"
        parameters: tuple[str, ...] = ()
        if case_display_id is not None:
            query += " WHERE case_id = ?"
            parameters = (self.case_ulid(case_display_id),)
        ids = [str(row[0]) for row in self._connection.execute(query, parameters)]
        return [
            self.get(item)
            for item in sorted(ids, key=lambda value: int(value.rpartition("-")[2]))
        ]
