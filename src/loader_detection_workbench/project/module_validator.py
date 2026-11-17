"""Read-only Tier 2 checks for the module-owned detection, execution and AI tables.

The core validator (``project.validator``) owns Project/Case/Artifact checks.
The detection (ADR-023), execution (ADR-024) and AI (ADR-026) tables live in the same
``project.db`` but are versioned by their own schema tables, so they are
checked here only when that marker table exists. A Project that never used
those modules produces no finding.

Every check reads raw rows with SQL. Nothing is repaired or written.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable

from loader_detection_workbench.ai.digest import DIGEST_SCOPE
from loader_detection_workbench.ai.sqlite_repository import AI_SCHEMA_VERSION
from loader_detection_workbench.detection.sqlite_repository import (
    DETECTION_SCHEMA_VERSION,
)
from loader_detection_workbench.domain.artifact import Artifact
from loader_detection_workbench.domain.case import Case, CaseKind
from loader_detection_workbench.domain.validation import (
    FindingSeverity,
    ValidationScope,
)
from loader_detection_workbench.execution.sqlite_repository import (
    EXECUTION_SCHEMA_VERSION,
)

MODULE_SCHEMA_UNSUPPORTED = "MODULE_SCHEMA_UNSUPPORTED"
MODULE_SCHEMA_INCOMPLETE = "MODULE_SCHEMA_INCOMPLETE"
DETECTION_COUNTER_INVALID = "DETECTION_COUNTER_INVALID"
DETECTION_RECORD_INVALID = "DETECTION_RECORD_INVALID"
DETECTION_REFERENCE_BROKEN = "DETECTION_REFERENCE_BROKEN"
DETECTION_FREEZE_VIOLATION = "DETECTION_FREEZE_VIOLATION"
DETECTION_RESULT_INCONSISTENT = "DETECTION_RESULT_INCONSISTENT"
EXECUTION_COUNTER_INVALID = "EXECUTION_COUNTER_INVALID"
EXECUTION_RECORD_INVALID = "EXECUTION_RECORD_INVALID"
EXECUTION_REFERENCE_BROKEN = "EXECUTION_REFERENCE_BROKEN"
EXECUTION_RUN_UNFINISHED = "EXECUTION_RUN_UNFINISHED"
EXECUTION_SAFETY_LOCK_SET = "EXECUTION_SAFETY_LOCK_SET"
AI_COUNTER_INVALID = "AI_COUNTER_INVALID"
AI_RECORD_INVALID = "AI_RECORD_INVALID"
AI_REFERENCE_BROKEN = "AI_REFERENCE_BROKEN"
AI_INPUT_TAMPERED = "AI_INPUT_TAMPERED"
ARTIFACT_REFERENCE_DETACHED = "ARTIFACT_REFERENCE_DETACHED"

# (tier, code, severity, scope, subject, message)
Emit = Callable[[int, str, FindingSeverity, ValidationScope, str | None, str], None]

_DETECTION_TABLES = (
    "detection_counters",
    "detection_rules",
    "detection_rule_versions",
    "detection_hypotheses",
    "detection_hypothesis_evidence",
    "detection_hypothesis_rules",
    "detection_benchmarks",
    "detection_benchmark_members",
    "detection_validation_runs",
    "detection_validation_results",
)
_DETECTION_TRIGGERS = (
    "detection_rule_versions_frozen_update",
    "detection_rule_versions_no_delete",
    "detection_benchmark_frozen_insert",
    "detection_benchmark_frozen_member_change",
    "detection_benchmark_member_no_update",
    "detection_benchmark_unfreeze",
    "detection_validation_runs_immutable",
    "detection_validation_results_immutable",
)
_EXECUTION_TABLES = (
    "execution_counters",
    "execution_runs",
    "execution_steps",
    "execution_safety_lock",
    "execution_lock_releases",
)
_EXECUTION_TRIGGERS = (
    "execution_runs_finished_immutable",
    "execution_runs_no_delete",
    "execution_steps_no_update",
    "execution_steps_no_delete",
)
_DETECTION_IDS = {
    "hypothesis": ("detection_hypotheses", "HYP"),
    "rule": ("detection_rules", "RULE"),
    "benchmark": ("detection_benchmarks", "BMK"),
    "run": ("detection_validation_runs", "RUN"),
}
_MALICIOUS_ROLES = {"dev", "unseen"}
_BENIGN_ROLES = {"benign_common", "benign_matched"}
_RUN_KINDS = {"development", "evaluation", "tuning"}
_EXECUTION_STATUSES = {"running", "succeeded", "failed", "abandoned"}
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _objects(connection: sqlite3.Connection, kind: str) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ?", (kind,)
        )
    }


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _sequence(display_id: object, prefix: str) -> int | None:
    if not isinstance(display_id, str):
        return None
    match = re.fullmatch(rf"{prefix}-([0-9]{{4,}})", display_id, re.ASCII)
    return int(match.group(1)) if match and int(match.group(1)) >= 1 else None


def _schema_ready(
    connection: sqlite3.Connection,
    emit: Emit,
    *,
    marker: str,
    version: int,
    tables: tuple[str, ...],
    triggers: tuple[str, ...],
    scope: ValidationScope,
) -> bool:
    """Return whether the module is installed and structurally inspectable."""
    existing = _objects(connection, "table")
    if marker not in existing:
        return False
    versions = [row[0] for row in connection.execute(f"SELECT version FROM {marker}")]  # noqa: S608
    if versions != [version]:
        emit(
            1,
            MODULE_SCHEMA_UNSUPPORTED,
            FindingSeverity.ERROR,
            scope,
            marker,
            "module schema version is unsupported",
        )
        return False
    ready = True
    for name in tables:
        if name not in existing:
            ready = False
            emit(
                1,
                MODULE_SCHEMA_INCOMPLETE,
                FindingSeverity.ERROR,
                scope,
                name,
                "module table is missing",
            )
    present = _objects(connection, "trigger")
    for name in triggers:
        if name not in present:
            emit(
                1,
                MODULE_SCHEMA_INCOMPLETE,
                FindingSeverity.ERROR,
                scope,
                name,
                "immutability trigger is missing",
            )
    return ready


def _check_artifact(
    emit: Emit,
    artifacts: dict[str, Artifact],
    internal_id: object,
    case_internal_id: object,
    *,
    scope: ValidationScope,
    code: str,
    subject: str | None,
    label: str,
) -> None:
    artifact = artifacts.get(internal_id) if isinstance(internal_id, str) else None
    if artifact is None:
        emit(
            2,
            code,
            FindingSeverity.ERROR,
            scope,
            subject,
            f"{label} references a missing or invalid Artifact",
        )
    elif artifact.case_id is None:
        emit(
            2,
            ARTIFACT_REFERENCE_DETACHED,
            FindingSeverity.WARNING,
            scope,
            subject,
            f"{label} references a detached Artifact",
        )
    elif case_internal_id is not None and artifact.case_id != case_internal_id:
        emit(
            2,
            code,
            FindingSeverity.ERROR,
            scope,
            subject,
            f"{label} references an Artifact of another Case",
        )


def validate_detection(
    connection: sqlite3.Connection,
    cases: dict[str, Case],
    artifacts: list[Artifact],
    emit: Emit,
) -> None:
    scope = ValidationScope.DETECTION
    if not _schema_ready(
        connection,
        emit,
        marker="detection_schema",
        version=DETECTION_SCHEMA_VERSION,
        tables=_DETECTION_TABLES,
        triggers=_DETECTION_TRIGGERS,
        scope=scope,
    ):
        return
    error = FindingSeverity.ERROR
    by_internal = {artifact.artifact_id.ulid: artifact for artifact in artifacts}

    # Counters must stay ahead of every allocated display sequence.
    counters = {
        str(row["name"]): row["next_value"]
        for row in connection.execute("SELECT name, next_value FROM detection_counters")
    }
    for kind, (table, prefix) in _DETECTION_IDS.items():
        sequences: list[int] = []
        for row in connection.execute(f"SELECT display_id FROM {table}"):  # noqa: S608
            sequence = _sequence(row[0], prefix)
            if sequence is None:
                emit(
                    2,
                    DETECTION_RECORD_INVALID,
                    error,
                    scope,
                    _text(row[0]),
                    f"{kind} display ID is invalid",
                )
            else:
                sequences.append(sequence)
        value = counters.get(kind)
        if type(value) is not int or value < 1:
            emit(
                2,
                DETECTION_COUNTER_INVALID,
                error,
                scope,
                kind,
                "counter is missing or below its minimum value",
            )
        elif sequences and value <= max(sequences):
            emit(
                2,
                DETECTION_COUNTER_INVALID,
                error,
                scope,
                kind,
                "counter is behind a persisted display sequence",
            )

    # Rules and their append-only versions.
    rule_ids = {
        str(row[0])
        for row in connection.execute("SELECT display_id FROM detection_rules")
    }
    versions: dict[tuple[str, int], sqlite3.Row] = {}
    numbers: dict[str, list[int]] = {rule: [] for rule in rule_ids}
    for row in connection.execute(
        "SELECT rule_display_id, version, content, sha256, status, frozen_at "
        "FROM detection_rule_versions"
    ):
        rule = _text(row["rule_display_id"])
        subject = f"{rule}@v{row['version']}"
        if rule not in rule_ids or type(row["version"]) is not int:
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                subject,
                "rule version references a missing Rule",
            )
            continue
        assert rule is not None
        versions[(rule, row["version"])] = row
        numbers[rule].append(row["version"])
        content = row["content"]
        if (
            not isinstance(content, str)
            or hashlib.sha256(content.encode("utf-8")).hexdigest() != row["sha256"]
        ):
            emit(
                2,
                DETECTION_RECORD_INVALID,
                error,
                scope,
                subject,
                "rule version content does not match its SHA-256",
            )
        if (row["status"] == "frozen") != (row["frozen_at"] is not None) or row[
            "status"
        ] not in {"draft", "frozen"}:
            emit(
                2,
                DETECTION_FREEZE_VIOLATION,
                error,
                scope,
                subject,
                "rule version status and freeze time disagree",
            )
    for rule, found in sorted(numbers.items()):
        if sorted(found) != list(range(1, len(found) + 1)) or not found:
            emit(
                2,
                DETECTION_RECORD_INVALID,
                error,
                scope,
                rule,
                "rule versions are not a contiguous sequence starting at 1",
            )

    # Hypotheses, their evidence Artifacts and linked Rules.
    hypothesis_cases: dict[str, object] = {}
    for row in connection.execute(
        "SELECT display_id, case_id FROM detection_hypotheses"
    ):
        display_id = _text(row["display_id"])
        if display_id is None:
            continue
        hypothesis_cases[display_id] = row["case_id"]
        if row["case_id"] is not None and row["case_id"] not in cases:
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                display_id,
                "hypothesis references a missing Case",
            )
    for row in connection.execute(
        "SELECT hypothesis_display_id, artifact_id FROM detection_hypothesis_evidence"
    ):
        hypothesis = _text(row["hypothesis_display_id"])
        if hypothesis not in hypothesis_cases:
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                hypothesis,
                "evidence link references a missing Hypothesis",
            )
            continue
        assert hypothesis is not None
        _check_artifact(
            emit,
            by_internal,
            row["artifact_id"],
            hypothesis_cases[hypothesis],
            scope=scope,
            code=DETECTION_REFERENCE_BROKEN,
            subject=hypothesis,
            label="hypothesis evidence",
        )
    for row in connection.execute(
        "SELECT hypothesis_display_id, rule_display_id FROM detection_hypothesis_rules"
    ):
        if (
            row["hypothesis_display_id"] not in hypothesis_cases
            or row["rule_display_id"] not in rule_ids
        ):
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                _text(row["hypothesis_display_id"]),
                "rule link references a missing Hypothesis or Rule",
            )

    # Benchmarks and members; a role must agree with the Case kind.
    frozen_benchmarks = {
        str(row["display_id"]): row["frozen_at"] is not None
        for row in connection.execute(
            "SELECT display_id, frozen_at FROM detection_benchmarks"
        )
    }
    members: dict[tuple[str, str], str] = {}
    for row in connection.execute(
        "SELECT benchmark_display_id, case_id, role FROM detection_benchmark_members"
    ):
        benchmark = _text(row["benchmark_display_id"])
        case = cases.get(row["case_id"]) if isinstance(row["case_id"], str) else None
        role = _text(row["role"])
        if benchmark not in frozen_benchmarks or case is None:
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                benchmark,
                "benchmark member references a missing Benchmark or Case",
            )
            continue
        assert benchmark is not None
        subject = f"{benchmark}/{case.case_id.display_id}"
        members[(benchmark, case.case_id.ulid)] = role or ""
        benign = case.kind is CaseKind.BENIGN
        if (
            (role in _MALICIOUS_ROLES and benign)
            or (role in _BENIGN_ROLES and not benign)
            or (role == "unseen" and case.kind is not CaseKind.MALWARE)
            or role not in _MALICIOUS_ROLES | _BENIGN_ROLES
        ):
            emit(
                2,
                DETECTION_RECORD_INVALID,
                error,
                scope,
                subject,
                "benchmark member role does not agree with the Case kind",
            )

    # Validation runs: frozen inputs for Unseen runs and consistent outcomes.
    runs: dict[str, sqlite3.Row] = {}
    for row in connection.execute(
        "SELECT display_id, rule_display_id, rule_version, rule_sha256, "
        "benchmark_display_id, roles, kind FROM detection_validation_runs"
    ):
        display_id = _text(row["display_id"])
        if display_id is None:
            continue
        runs[display_id] = row
        version = versions.get((row["rule_display_id"], row["rule_version"]))
        if version is None or row["benchmark_display_id"] not in frozen_benchmarks:
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                display_id,
                "validation run references a missing Rule version or Benchmark",
            )
            continue
        if version["sha256"] != row["rule_sha256"]:
            emit(
                2,
                DETECTION_RECORD_INVALID,
                error,
                scope,
                display_id,
                "validation run hash differs from its Rule version",
            )
        kind = row["kind"]
        roles = set(str(row["roles"]).split(","))
        if kind not in _RUN_KINDS or not roles <= _MALICIOUS_ROLES | _BENIGN_ROLES:
            emit(
                2,
                DETECTION_RECORD_INVALID,
                error,
                scope,
                display_id,
                "validation run kind or roles are invalid",
            )
        unseen = "unseen" in roles
        if unseen != (kind in {"evaluation", "tuning"}):
            emit(
                2,
                DETECTION_FREEZE_VIOLATION,
                error,
                scope,
                display_id,
                "run kind does not agree with its use of Unseen members",
            )
        if unseen and (
            version["status"] != "frozen"
            or not frozen_benchmarks[row["benchmark_display_id"]]
        ):
            emit(
                2,
                DETECTION_FREEZE_VIOLATION,
                error,
                scope,
                display_id,
                "Unseen run does not use a frozen Rule version and Benchmark",
            )
    for row in connection.execute(
        "SELECT run_display_id, case_id, role, matched, outcome "
        "FROM detection_validation_results"
    ):
        run_id = _text(row["run_display_id"])
        run = runs.get(run_id) if run_id is not None else None
        case = cases.get(row["case_id"]) if isinstance(row["case_id"], str) else None
        if run is None or case is None:
            emit(
                2,
                DETECTION_REFERENCE_BROKEN,
                error,
                scope,
                run_id,
                "validation result references a missing Run or Case",
            )
            continue
        subject = f"{run_id}/{case.case_id.display_id}"
        role, matched = row["role"], row["matched"]
        if matched is None:
            expected = "not_evaluable"
        elif role in _MALICIOUS_ROLES:
            expected = "TP" if matched else "FN"
        else:
            expected = "FP" if matched else "TN"
        if (
            role not in set(str(run["roles"]).split(","))
            or matched not in (None, 0, 1)
            or row["outcome"] != expected
        ):
            emit(
                2,
                DETECTION_RESULT_INCONSISTENT,
                error,
                scope,
                subject,
                "validation outcome does not follow from role and match",
            )
        benchmark = str(run["benchmark_display_id"])
        if (
            frozen_benchmarks.get(benchmark)
            and members.get((benchmark, case.case_id.ulid)) != role
        ):
            emit(
                2,
                DETECTION_RESULT_INCONSISTENT,
                error,
                scope,
                subject,
                "validation result is not a member of the frozen Benchmark",
            )


def validate_execution(
    connection: sqlite3.Connection,
    cases: dict[str, Case],
    artifacts: list[Artifact],
    emit: Emit,
) -> None:
    scope = ValidationScope.EXECUTION
    if not _schema_ready(
        connection,
        emit,
        marker="execution_schema",
        version=EXECUTION_SCHEMA_VERSION,
        tables=_EXECUTION_TABLES,
        triggers=_EXECUTION_TRIGGERS,
        scope=scope,
    ):
        return
    error = FindingSeverity.ERROR
    warning = FindingSeverity.WARNING
    by_internal = {artifact.artifact_id.ulid: artifact for artifact in artifacts}

    run_ids: set[str] = set()
    sequences: list[int] = []
    for row in connection.execute(
        "SELECT display_id, case_id, profile, status, finished_at, "
        "sysmon_artifact_id, metadata_artifact_id, event_count FROM execution_runs"
    ):
        display_id = _text(row["display_id"])
        sequence = _sequence(display_id, "VMR")
        if display_id is None or sequence is None:
            emit(
                2,
                EXECUTION_RECORD_INVALID,
                error,
                scope,
                display_id,
                "execution run display ID is invalid",
            )
            continue
        run_ids.add(display_id)
        sequences.append(sequence)
        if row["case_id"] not in cases:
            emit(
                2,
                EXECUTION_REFERENCE_BROKEN,
                error,
                scope,
                display_id,
                "execution run references a missing Case",
            )
            continue
        status = row["status"]
        if (
            status not in _EXECUTION_STATUSES
            or row["profile"] not in {"sample", "benign_scenario"}
            or (status == "running") != (row["finished_at"] is None)
            or (
                status == "succeeded"
                and (row["sysmon_artifact_id"] is None or row["event_count"] is None)
            )
        ):
            emit(
                2,
                EXECUTION_RECORD_INVALID,
                error,
                scope,
                display_id,
                "execution run status and recorded results disagree",
            )
        if status == "running":
            emit(
                2,
                EXECUTION_RUN_UNFINISHED,
                warning,
                scope,
                display_id,
                "execution run never finished; further runs are blocked",
            )
        for column, label in (
            ("sysmon_artifact_id", "execution run Sysmon collection"),
            ("metadata_artifact_id", "execution run manifest"),
        ):
            if row[column] is not None:
                _check_artifact(
                    emit,
                    by_internal,
                    row[column],
                    row["case_id"],
                    scope=scope,
                    code=EXECUTION_REFERENCE_BROKEN,
                    subject=display_id,
                    label=label,
                )

    counter = connection.execute(
        "SELECT next_value FROM execution_counters WHERE name = 'run'"
    ).fetchone()
    value = None if counter is None else counter[0]
    if type(value) is not int or value < 1:
        emit(
            2,
            EXECUTION_COUNTER_INVALID,
            error,
            scope,
            "run",
            "counter is missing or below its minimum value",
        )
    elif sequences and value <= max(sequences):
        emit(
            2,
            EXECUTION_COUNTER_INVALID,
            error,
            scope,
            "run",
            "counter is behind a persisted display sequence",
        )

    steps: dict[str, list[int]] = {}
    for row in connection.execute(
        "SELECT run_display_id, sequence FROM execution_steps"
    ):
        run_id = _text(row["run_display_id"])
        if run_id not in run_ids or type(row["sequence"]) is not int:
            emit(
                2,
                EXECUTION_REFERENCE_BROKEN,
                error,
                scope,
                run_id,
                "execution step references a missing Run",
            )
            continue
        assert run_id is not None
        steps.setdefault(run_id, []).append(row["sequence"])
    for run_id, found in sorted(steps.items()):
        if sorted(found) != list(range(1, len(found) + 1)):
            emit(
                2,
                EXECUTION_RECORD_INVALID,
                error,
                scope,
                run_id,
                "execution steps are not a contiguous sequence starting at 1",
            )

    lock = connection.execute(
        "SELECT run_display_id FROM execution_safety_lock WHERE id = 1"
    ).fetchone()
    if lock is not None:
        emit(
            2,
            EXECUTION_SAFETY_LOCK_SET,
            warning,
            scope,
            _text(lock[0]),
            "the VM safety lock is set; verify the VM before 'vm unlock'",
        )


_AI_TABLES = ("ai_counters", "ai_analyses", "ai_suggestions")
_AI_TRIGGERS = (
    "ai_analyses_immutable",
    "ai_analyses_no_delete",
    "ai_suggestions_reviewed_immutable",
    "ai_suggestions_content_immutable",
    "ai_suggestions_no_delete",
)
_AI_KINDS = {"summary", "hypothesis", "review_item"}
_AI_STATES = {"pending", "accepted", "rejected"}


def _json_object(value: object) -> dict[str, object] | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def validate_ai(
    connection: sqlite3.Connection, cases: dict[str, Case], emit: Emit
) -> None:
    """Check stored AI analyses and suggestions (ADR-026).

    The stored provider input must still hash to its recorded SHA-256, since
    that pair is how a reviewer confirms what left the evidence store. Review
    state must agree with the review fields, and an accepted hypothesis
    suggestion must point at an existing Detection Hypothesis of the same Case.
    """
    scope = ValidationScope.AI
    if not _schema_ready(
        connection,
        emit,
        marker="ai_schema",
        version=AI_SCHEMA_VERSION,
        tables=_AI_TABLES,
        triggers=_AI_TRIGGERS,
        scope=scope,
    ):
        return
    error = FindingSeverity.ERROR

    hypotheses: dict[str, object] = {}
    if "detection_hypotheses" in _objects(connection, "table"):
        hypotheses = {
            str(row[0]): row[1]
            for row in connection.execute(
                "SELECT display_id, case_id FROM detection_hypotheses"
            )
        }

    analysis_cases: dict[str, object] = {}
    sequences: list[int] = []
    for row in connection.execute(
        "SELECT display_id, case_id, input_scope, input_sha256, input_json "
        "FROM ai_analyses"
    ):
        display_id = _text(row["display_id"])
        sequence = _sequence(display_id, "AIA")
        if display_id is None or sequence is None:
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                display_id,
                "AI analysis display ID is invalid",
            )
            continue
        sequences.append(sequence)
        analysis_cases[display_id] = row["case_id"]
        if row["case_id"] not in cases:
            emit(
                2,
                AI_REFERENCE_BROKEN,
                error,
                scope,
                display_id,
                "AI analysis references a missing Case",
            )
        if row["input_scope"] != DIGEST_SCOPE:
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                display_id,
                "AI analysis input scope is not an approved scope",
            )
        payload = row["input_json"]
        recorded = row["input_sha256"]
        if (
            not isinstance(payload, str)
            or not isinstance(recorded, str)
            or _SHA256.fullmatch(recorded) is None
            or hashlib.sha256(payload.encode("utf-8")).hexdigest() != recorded
        ):
            emit(
                2,
                AI_INPUT_TAMPERED,
                error,
                scope,
                display_id,
                "stored provider input does not match its recorded SHA-256",
            )
        elif _json_object(payload) is None:
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                display_id,
                "stored provider input is not a JSON object",
            )

    counter = connection.execute(
        "SELECT next_value FROM ai_counters WHERE name = 'analysis'"
    ).fetchone()
    value = None if counter is None else counter[0]
    if analysis_cases or counter is not None:
        if type(value) is not int or value < 1:
            emit(
                2,
                AI_COUNTER_INVALID,
                error,
                scope,
                "analysis",
                "counter is missing or below its minimum value",
            )
        elif sequences and value <= max(sequences):
            emit(
                2,
                AI_COUNTER_INVALID,
                error,
                scope,
                "analysis",
                "counter is behind a persisted display sequence",
            )

    found: dict[str, list[int]] = {}
    summaries: dict[str, int] = {}
    for row in connection.execute(
        "SELECT analysis_display_id, sequence, kind, content_json, state, "
        "reviewed_at, hypothesis_display_id FROM ai_suggestions"
    ):
        analysis_id = _text(row["analysis_display_id"])
        subject = f"{analysis_id}#{row['sequence']}"
        if analysis_id not in analysis_cases or type(row["sequence"]) is not int:
            emit(
                2,
                AI_REFERENCE_BROKEN,
                error,
                scope,
                subject,
                "AI suggestion references a missing analysis",
            )
            continue
        assert analysis_id is not None
        found.setdefault(analysis_id, []).append(row["sequence"])
        kind, state = row["kind"], row["state"]
        if kind == "summary":
            summaries[analysis_id] = summaries.get(analysis_id, 0) + 1
        if kind not in _AI_KINDS or _json_object(row["content_json"]) is None:
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                subject,
                "AI suggestion kind or content is invalid",
            )
        linked = row["hypothesis_display_id"]
        if (
            state not in _AI_STATES
            or (state == "pending") != (row["reviewed_at"] is None)
            or (linked is not None and (state != "accepted" or kind != "hypothesis"))
        ):
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                subject,
                "AI suggestion review state and review fields disagree",
            )
            continue
        if linked is not None:
            if linked not in hypotheses:
                emit(
                    2,
                    AI_REFERENCE_BROKEN,
                    error,
                    scope,
                    subject,
                    "accepted AI suggestion references a missing hypothesis",
                )
            elif hypotheses[linked] != analysis_cases[analysis_id]:
                emit(
                    2,
                    AI_REFERENCE_BROKEN,
                    error,
                    scope,
                    subject,
                    "accepted AI suggestion references a hypothesis of another Case",
                )
    for analysis_id, numbers in sorted(found.items()):
        if sorted(numbers) != list(range(1, len(numbers) + 1)):
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                analysis_id,
                "AI suggestions are not a contiguous sequence starting at 1",
            )
        if summaries.get(analysis_id, 0) > 1:
            emit(
                2,
                AI_RECORD_INVALID,
                error,
                scope,
                analysis_id,
                "AI analysis has more than one summary",
            )
