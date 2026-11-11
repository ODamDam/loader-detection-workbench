"""Module-owned detection tables inside the Project ``project.db``.

Like the Sample Intake tables, these tables are versioned independently of the
core Project/Case/Artifact schema (see ADR-023). Case and Artifact references
use the core internal ULIDs with foreign keys, while the domain exposes display
IDs. Frozen Rule versions, frozen Benchmarks and recorded Validation results
are protected by SQLite triggers in addition to service checks.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from loader_detection_workbench.detection.domain import (
    Benchmark,
    BenchmarkMember,
    DetectionRule,
    Hypothesis,
    HypothesisStatus,
    MemberRole,
    Outcome,
    RuleFormat,
    RuleVersion,
    RuleVersionStatus,
    RunKind,
    ValidationResult,
    ValidationRun,
    format_display_id,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, parse_utc, utc_now
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectWorkspace

DETECTION_SCHEMA_VERSION = 1

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS detection_schema (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS detection_counters (
        name TEXT PRIMARY KEY
            CHECK (name IN ('hypothesis', 'rule', 'benchmark', 'run')),
        next_value INTEGER NOT NULL CHECK (next_value >= 1)
    )""",
    """CREATE TABLE IF NOT EXISTS detection_rules (
        display_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        format TEXT NOT NULL CHECK (format IN ('yara', 'sigma')),
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS detection_rule_versions (
        rule_display_id TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version >= 1),
        content TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('draft', 'frozen')),
        created_at TEXT NOT NULL,
        frozen_at TEXT,
        note TEXT,
        PRIMARY KEY (rule_display_id, version),
        FOREIGN KEY (rule_display_id) REFERENCES detection_rules(display_id)
            ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS detection_rule_versions_frozen_update
        BEFORE UPDATE ON detection_rule_versions
        WHEN OLD.status = 'frozen'
        BEGIN SELECT RAISE(ABORT, 'frozen rule version is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS detection_rule_versions_no_delete
        BEFORE DELETE ON detection_rule_versions
        BEGIN SELECT RAISE(ABORT, 'rule versions are append-only'); END""",
    """CREATE TABLE IF NOT EXISTS detection_hypotheses (
        display_id TEXT PRIMARY KEY,
        case_id TEXT,
        title TEXT NOT NULL,
        statement TEXT NOT NULL,
        status TEXT NOT NULL
            CHECK (status IN ('proposed', 'supported', 'weakened', 'rejected')),
        expected_benign TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS detection_hypothesis_evidence (
        hypothesis_display_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        PRIMARY KEY (hypothesis_display_id, artifact_id),
        FOREIGN KEY (hypothesis_display_id)
            REFERENCES detection_hypotheses(display_id) ON DELETE RESTRICT,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(internal_id)
            ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS detection_hypothesis_rules (
        hypothesis_display_id TEXT NOT NULL,
        rule_display_id TEXT NOT NULL,
        PRIMARY KEY (hypothesis_display_id, rule_display_id),
        FOREIGN KEY (hypothesis_display_id)
            REFERENCES detection_hypotheses(display_id) ON DELETE RESTRICT,
        FOREIGN KEY (rule_display_id) REFERENCES detection_rules(display_id)
            ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS detection_benchmarks (
        display_id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at TEXT NOT NULL,
        frozen_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS detection_benchmark_members (
        benchmark_display_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        role TEXT NOT NULL
            CHECK (role IN ('dev', 'unseen', 'benign_common', 'benign_matched')),
        added_at TEXT NOT NULL,
        PRIMARY KEY (benchmark_display_id, case_id),
        FOREIGN KEY (benchmark_display_id)
            REFERENCES detection_benchmarks(display_id) ON DELETE RESTRICT,
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS detection_benchmark_frozen_insert
        BEFORE INSERT ON detection_benchmark_members
        WHEN (SELECT frozen_at FROM detection_benchmarks
              WHERE display_id = NEW.benchmark_display_id) IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'frozen benchmark is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS detection_benchmark_frozen_member_change
        BEFORE DELETE ON detection_benchmark_members
        WHEN (SELECT frozen_at FROM detection_benchmarks
              WHERE display_id = OLD.benchmark_display_id) IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'frozen benchmark is immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS detection_benchmark_member_no_update
        BEFORE UPDATE ON detection_benchmark_members
        BEGIN SELECT RAISE(ABORT, 'benchmark members are immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS detection_benchmark_unfreeze
        BEFORE UPDATE ON detection_benchmarks
        WHEN OLD.frozen_at IS NOT NULL
        BEGIN SELECT RAISE(ABORT, 'frozen benchmark is immutable'); END""",
    """CREATE TABLE IF NOT EXISTS detection_validation_runs (
        display_id TEXT PRIMARY KEY,
        rule_display_id TEXT NOT NULL,
        rule_version INTEGER NOT NULL,
        rule_sha256 TEXT NOT NULL,
        benchmark_display_id TEXT NOT NULL,
        roles TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('development', 'evaluation', 'tuning')),
        engine TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (rule_display_id, rule_version)
            REFERENCES detection_rule_versions(rule_display_id, version)
            ON DELETE RESTRICT,
        FOREIGN KEY (benchmark_display_id)
            REFERENCES detection_benchmarks(display_id) ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS detection_validation_results (
        run_display_id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        role TEXT NOT NULL,
        matched INTEGER CHECK (matched IS NULL OR matched IN (0, 1)),
        outcome TEXT NOT NULL
            CHECK (outcome IN ('TP', 'FP', 'FN', 'TN', 'not_evaluable')),
        detail TEXT NOT NULL,
        PRIMARY KEY (run_display_id, case_id),
        FOREIGN KEY (run_display_id) REFERENCES detection_validation_runs(display_id)
            ON DELETE RESTRICT,
        FOREIGN KEY (case_id) REFERENCES cases(internal_id) ON DELETE RESTRICT
    )""",
    """CREATE TRIGGER IF NOT EXISTS detection_validation_runs_immutable
        BEFORE UPDATE ON detection_validation_runs
        BEGIN SELECT RAISE(ABORT, 'validation runs are immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS detection_validation_results_immutable
        BEFORE UPDATE ON detection_validation_results
        BEGIN SELECT RAISE(ABORT, 'validation results are immutable'); END""",
)

_COUNTERS = ("hypothesis", "rule", "benchmark", "run")


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.INVALID_DETECTION_RECORD,
        "persisted detection record is invalid",
    )


def _time(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = parse_utc(value)
    if format_utc(parsed) != value:
        raise _invalid()
    return parsed


def _required_time(value: str) -> datetime:
    parsed = _time(value)
    if parsed is None:
        raise _invalid()
    return parsed


class SQLiteDetectionRepository:
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
            "AND name = 'detection_schema'"
        ).fetchone()
        if row is None:
            return False
        versions = [
            int(item[0])
            for item in self._connection.execute(
                "SELECT version FROM detection_schema ORDER BY version"
            )
        ]
        if versions != [DETECTION_SCHEMA_VERSION]:
            raise DomainError(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "detection schema version is unsupported",
            )
        return True

    def _bootstrap(self) -> None:
        installed = self._installed()
        for statement in _SCHEMA:
            self._connection.execute(statement)
        if not installed:
            self._connection.execute(
                "INSERT INTO detection_schema (version, applied_at) VALUES (?, ?)",
                (DETECTION_SCHEMA_VERSION, format_utc(utc_now())),
            )
            self._connection.executemany(
                "INSERT INTO detection_counters (name, next_value) VALUES (?, 1)",
                ((name,) for name in _COUNTERS),
            )

    def _require_write(self) -> None:
        if not self._write or not self._connection.in_transaction:
            raise RuntimeError("detection writes require a write transaction")

    # -- identity -------------------------------------------------------------

    def allocate(self, kind: str) -> str:
        self._require_write()
        row = self._connection.execute(
            "SELECT next_value FROM detection_counters WHERE name = ?", (kind,)
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 1:
            raise _invalid()
        value = int(row[0])
        self._connection.execute(
            "UPDATE detection_counters SET next_value = ? WHERE name = ?",
            (value + 1, kind),
        )
        return format_display_id(kind, value)

    def case_ulid(self, case_display_id: str) -> str:
        row = self._connection.execute(
            "SELECT internal_id FROM cases WHERE display_id = ? AND project_id = ?",
            (case_display_id, self._workspace.manifest.project_id.ulid),
        ).fetchone()
        if row is None:
            raise DomainError(DomainErrorCode.CASE_NOT_FOUND, "case was not found")
        return str(row[0])

    def artifact_ulid(self, artifact_display_id: str, case_ulid: str | None) -> str:
        row = self._connection.execute(
            "SELECT internal_id, case_id FROM artifacts "
            "WHERE display_id = ? AND project_id = ?",
            (artifact_display_id, self._workspace.manifest.project_id.ulid),
        ).fetchone()
        if row is None or (case_ulid is not None and row[1] != case_ulid):
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_ATTACHED,
                "evidence artifact is not attached to the hypothesis case",
            )
        return str(row[0])

    # -- rules ----------------------------------------------------------------

    def insert_rule(self, rule: DetectionRule) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO detection_rules (display_id, name, format, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                rule.display_id,
                rule.name,
                rule.format.value,
                format_utc(rule.created_at),
            ),
        )
        for version in rule.versions:
            self.insert_rule_version(version)

    def insert_rule_version(self, version: RuleVersion) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO detection_rule_versions (rule_display_id, version, content, "
            "sha256, status, created_at, frozen_at, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                version.rule_display_id,
                version.version,
                version.content,
                version.sha256,
                version.status.value,
                format_utc(version.created_at),
                None if version.frozen_at is None else format_utc(version.frozen_at),
                version.note,
            ),
        )

    def freeze_rule_version(self, rule_display_id: str, version: int, at: str) -> None:
        self._require_write()
        cursor = self._connection.execute(
            "UPDATE detection_rule_versions SET status = 'frozen', frozen_at = ? "
            "WHERE rule_display_id = ? AND version = ? AND status = 'draft'",
            (at, rule_display_id, version),
        )
        if cursor.rowcount != 1:
            raise _invalid()

    def get_rule(self, display_id: str) -> DetectionRule:
        if not self._available:
            raise DomainError(
                DomainErrorCode.DETECTION_RULE_NOT_FOUND, "rule was not found"
            )
        row = self._connection.execute(
            "SELECT display_id, name, format, created_at FROM detection_rules "
            "WHERE display_id = ?",
            (display_id,),
        ).fetchone()
        if row is None:
            raise DomainError(
                DomainErrorCode.DETECTION_RULE_NOT_FOUND, "rule was not found"
            )
        versions = tuple(
            RuleVersion(
                str(item["rule_display_id"]),
                int(item["version"]),
                str(item["content"]),
                str(item["sha256"]),
                RuleVersionStatus(item["status"]),
                _required_time(item["created_at"]),
                _time(item["frozen_at"]),
                item["note"],
            )
            for item in self._connection.execute(
                "SELECT * FROM detection_rule_versions WHERE rule_display_id = ? "
                "ORDER BY version",
                (display_id,),
            )
        )
        if not versions:
            raise _invalid()
        return DetectionRule(
            str(row["display_id"]),
            str(row["name"]),
            RuleFormat(row["format"]),
            _required_time(row["created_at"]),
            versions,
        )

    def list_rules(self) -> list[DetectionRule]:
        if not self._available:
            return []
        ids = [
            str(row[0])
            for row in self._connection.execute(
                "SELECT display_id FROM detection_rules"
            )
        ]
        return [self.get_rule(item) for item in sorted(ids, key=_numeric)]

    def has_evaluation_run(self, rule_display_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM detection_validation_runs WHERE rule_display_id = ? "
            "AND kind IN ('evaluation', 'tuning') LIMIT 1",
            (rule_display_id,),
        ).fetchone()
        return row is not None

    # -- hypotheses -----------------------------------------------------------

    def insert_hypothesis(self, hypothesis: Hypothesis, case_ulid: str | None) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO detection_hypotheses (display_id, case_id, title, statement, "
            "status, expected_benign, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                hypothesis.display_id,
                case_ulid,
                hypothesis.title,
                hypothesis.statement,
                hypothesis.status.value,
                hypothesis.expected_benign,
                format_utc(hypothesis.created_at),
                format_utc(hypothesis.updated_at),
            ),
        )

    def link_evidence(self, hypothesis_display_id: str, artifact_ulid: str) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT OR IGNORE INTO detection_hypothesis_evidence "
            "(hypothesis_display_id, artifact_id) VALUES (?, ?)",
            (hypothesis_display_id, artifact_ulid),
        )

    def link_rule(self, hypothesis_display_id: str, rule_display_id: str) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT OR IGNORE INTO detection_hypothesis_rules "
            "(hypothesis_display_id, rule_display_id) VALUES (?, ?)",
            (hypothesis_display_id, rule_display_id),
        )

    def set_hypothesis_status(
        self, display_id: str, status: HypothesisStatus, at: datetime
    ) -> None:
        self._require_write()
        cursor = self._connection.execute(
            "UPDATE detection_hypotheses SET status = ?, updated_at = ? "
            "WHERE display_id = ?",
            (status.value, format_utc(at), display_id),
        )
        if cursor.rowcount != 1:
            raise DomainError(
                DomainErrorCode.HYPOTHESIS_NOT_FOUND, "hypothesis was not found"
            )

    def get_hypothesis(self, display_id: str) -> Hypothesis:
        row = (
            self._connection.execute(
                "SELECT h.*, c.display_id AS case_display_id "
                "FROM detection_hypotheses h "
                "LEFT JOIN cases c ON c.internal_id = h.case_id "
                "WHERE h.display_id = ?",
                (display_id,),
            ).fetchone()
            if self._available
            else None
        )
        if row is None:
            raise DomainError(
                DomainErrorCode.HYPOTHESIS_NOT_FOUND, "hypothesis was not found"
            )
        evidence = tuple(
            sorted(
                str(item[0])
                for item in self._connection.execute(
                    "SELECT a.display_id FROM detection_hypothesis_evidence e "
                    "JOIN artifacts a ON a.internal_id = e.artifact_id "
                    "WHERE e.hypothesis_display_id = ?",
                    (display_id,),
                )
            )
        )
        rules = tuple(
            sorted(
                (
                    str(item[0])
                    for item in self._connection.execute(
                        "SELECT rule_display_id FROM detection_hypothesis_rules "
                        "WHERE hypothesis_display_id = ?",
                        (display_id,),
                    )
                ),
                key=_numeric,
            )
        )
        return Hypothesis(
            str(row["display_id"]),
            row["case_display_id"],
            str(row["title"]),
            str(row["statement"]),
            HypothesisStatus(row["status"]),
            _required_time(row["created_at"]),
            _required_time(row["updated_at"]),
            evidence,
            rules,
            row["expected_benign"],
        )

    def list_hypotheses(self, case_ulid: str | None = None) -> list[Hypothesis]:
        if not self._available:
            return []
        query = "SELECT display_id FROM detection_hypotheses"
        parameters: tuple[str, ...] = ()
        if case_ulid is not None:
            query += " WHERE case_id = ?"
            parameters = (case_ulid,)
        ids = [str(row[0]) for row in self._connection.execute(query, parameters)]
        return [self.get_hypothesis(item) for item in sorted(ids, key=_numeric)]

    # -- benchmarks -----------------------------------------------------------

    def insert_benchmark(self, benchmark: Benchmark) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO detection_benchmarks "
            "(display_id, name, description, created_at, frozen_at) "
            "VALUES (?, ?, ?, ?, NULL)",
            (
                benchmark.display_id,
                benchmark.name,
                benchmark.description,
                format_utc(benchmark.created_at),
            ),
        )

    def add_member(
        self, benchmark_display_id: str, case_ulid: str, role: MemberRole, at: str
    ) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO detection_benchmark_members "
            "(benchmark_display_id, case_id, role, added_at) VALUES (?, ?, ?, ?)",
            (benchmark_display_id, case_ulid, role.value, at),
        )

    def freeze_benchmark(self, display_id: str, at: str) -> None:
        self._require_write()
        cursor = self._connection.execute(
            "UPDATE detection_benchmarks SET frozen_at = ? "
            "WHERE display_id = ? AND frozen_at IS NULL",
            (at, display_id),
        )
        if cursor.rowcount != 1:
            raise _invalid()

    def get_benchmark(self, display_id: str) -> Benchmark:
        row = (
            self._connection.execute(
                "SELECT * FROM detection_benchmarks WHERE display_id = ?",
                (display_id,),
            ).fetchone()
            if self._available
            else None
        )
        if row is None:
            raise DomainError(
                DomainErrorCode.BENCHMARK_NOT_FOUND, "benchmark was not found"
            )
        members = tuple(
            sorted(
                (
                    BenchmarkMember(
                        str(item["case_display_id"]),
                        MemberRole(item["role"]),
                        _required_time(item["added_at"]),
                    )
                    for item in self._connection.execute(
                        "SELECT c.display_id AS case_display_id, m.role, m.added_at "
                        "FROM detection_benchmark_members m "
                        "JOIN cases c ON c.internal_id = m.case_id "
                        "WHERE m.benchmark_display_id = ?",
                        (display_id,),
                    )
                ),
                key=lambda member: _numeric(member.case_display_id),
            )
        )
        return Benchmark(
            str(row["display_id"]),
            str(row["name"]),
            row["description"],
            _required_time(row["created_at"]),
            _time(row["frozen_at"]),
            members,
        )

    def list_benchmarks(self) -> list[Benchmark]:
        if not self._available:
            return []
        ids = [
            str(row[0])
            for row in self._connection.execute(
                "SELECT display_id FROM detection_benchmarks"
            )
        ]
        return [self.get_benchmark(item) for item in sorted(ids, key=_numeric)]

    def member_case_ids(self, case_ulid: str) -> list[str]:
        """Benchmarks that already contain this Case (used for leakage checks)."""
        return [
            str(row[0])
            for row in self._connection.execute(
                "SELECT benchmark_display_id FROM detection_benchmark_members "
                "WHERE case_id = ?",
                (case_ulid,),
            )
        ]

    # -- validation -----------------------------------------------------------

    def insert_run(self, run: ValidationRun) -> None:
        self._require_write()
        self._connection.execute(
            "INSERT INTO detection_validation_runs (display_id, rule_display_id, "
            "rule_version, rule_sha256, benchmark_display_id, roles, kind, engine, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.display_id,
                run.rule_display_id,
                run.rule_version,
                run.rule_sha256,
                run.benchmark_display_id,
                ",".join(role.value for role in run.roles),
                run.kind.value,
                run.engine,
                format_utc(run.created_at),
            ),
        )
        for result in run.results:
            self._connection.execute(
                "INSERT INTO detection_validation_results "
                "(run_display_id, case_id, role, matched, outcome, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run.display_id,
                    self.case_ulid(result.case_display_id),
                    result.role.value,
                    None if result.matched is None else int(result.matched),
                    result.outcome.value,
                    result.detail,
                ),
            )

    def get_run(self, display_id: str) -> ValidationRun:
        row = (
            self._connection.execute(
                "SELECT * FROM detection_validation_runs WHERE display_id = ?",
                (display_id,),
            ).fetchone()
            if self._available
            else None
        )
        if row is None:
            raise DomainError(
                DomainErrorCode.VALIDATION_RUN_NOT_FOUND, "validation run was not found"
            )
        results = tuple(
            sorted(
                (
                    ValidationResult(
                        str(item["case_display_id"]),
                        MemberRole(item["role"]),
                        None if item["matched"] is None else bool(item["matched"]),
                        Outcome(item["outcome"]),
                        str(item["detail"]),
                    )
                    for item in self._connection.execute(
                        "SELECT c.display_id AS case_display_id, r.role, r.matched, "
                        "r.outcome, r.detail FROM detection_validation_results r "
                        "JOIN cases c ON c.internal_id = r.case_id "
                        "WHERE r.run_display_id = ?",
                        (display_id,),
                    )
                ),
                key=lambda result: _numeric(result.case_display_id),
            )
        )
        return ValidationRun(
            str(row["display_id"]),
            str(row["rule_display_id"]),
            int(row["rule_version"]),
            str(row["rule_sha256"]),
            str(row["benchmark_display_id"]),
            tuple(MemberRole(item) for item in str(row["roles"]).split(",")),
            RunKind(row["kind"]),
            _required_time(row["created_at"]),
            str(row["engine"]),
            results,
        )

    def list_runs(self, rule_display_id: str | None = None) -> list[ValidationRun]:
        if not self._available:
            return []
        query = "SELECT display_id FROM detection_validation_runs"
        parameters: tuple[str, ...] = ()
        if rule_display_id is not None:
            query += " WHERE rule_display_id = ?"
            parameters = (rule_display_id,)
        ids = [str(row[0]) for row in self._connection.execute(query, parameters)]
        return [self.get_run(item) for item in sorted(ids, key=_numeric)]


def _numeric(display_id: str) -> tuple[int, str]:
    prefix, _, number = display_id.rpartition("-")
    return (int(number) if number.isdigit() else 0, prefix)
