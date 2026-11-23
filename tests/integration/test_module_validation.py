"""Core validator checks for module-owned detection and execution tables."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from analysis_fixture import add_execution_run, build_workspace

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.validation import (
    FindingSeverity,
    ValidationScope,
)
from loader_detection_workbench.execution.domain import RunStatus
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.project.validator import validate_workspace


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return build_workspace(tmp_path)


def mutate(root: Path, *statements: str) -> None:
    with closing(sqlite3.connect(root / "project.db")) as connection, connection:
        for statement in statements:
            connection.execute(statement)


def found(root: Path) -> set[tuple[str, str | None]]:
    return {(f.code, f.subject) for f in validate_workspace(root).findings}


def internal_id(root: Path, table: str, display_id: str) -> str:
    with closing(sqlite3.connect(root / "project.db")) as connection:
        row = connection.execute(
            f"SELECT internal_id FROM {table} WHERE display_id = ?",  # noqa: S608
            (display_id,),
        ).fetchone()
    return str(row[0])


def test_clean_workspace_with_all_modules_has_no_finding(root: Path) -> None:
    before = (root / "project.db").read_bytes()
    assert validate_workspace(root).findings == ()
    assert validate_workspace(root, full=True).findings == ()
    assert (root / "project.db").read_bytes() == before


def test_project_without_module_tables_is_unaffected(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    ProjectService().create(plain, "Plain")
    assert validate_workspace(plain).findings == ()


def test_unsupported_module_schema_stops_module_checks(root: Path) -> None:
    mutate(
        root,
        "UPDATE detection_schema SET version = 2",
        "UPDATE detection_counters SET next_value = 1",
    )
    report = validate_workspace(root)
    assert [(f.code, f.scope, f.subject) for f in report.findings] == [
        ("MODULE_SCHEMA_UNSUPPORTED", ValidationScope.DETECTION, "detection_schema")
    ]
    assert not report.is_valid


def test_missing_table_and_trigger_are_reported(root: Path) -> None:
    mutate(
        root,
        "DROP TRIGGER detection_validation_runs_immutable",
        "DROP TRIGGER execution_steps_no_delete",
    )
    assert found(root) == {
        ("MODULE_SCHEMA_INCOMPLETE", "detection_validation_runs_immutable"),
        ("MODULE_SCHEMA_INCOMPLETE", "execution_steps_no_delete"),
    }
    mutate(root, "DROP TABLE execution_lock_releases")
    assert ("MODULE_SCHEMA_INCOMPLETE", "execution_lock_releases") in found(root)


def test_counters_behind_persisted_sequences(root: Path) -> None:
    mutate(
        root,
        "UPDATE detection_counters SET next_value = 5 WHERE name = 'run'",
        "UPDATE execution_counters SET next_value = 1",
    )
    assert found(root) == {
        ("DETECTION_COUNTER_INVALID", "run"),
        ("EXECUTION_COUNTER_INVALID", "run"),
    }


def test_tampered_frozen_rule_version_is_detected(root: Path) -> None:
    mutate(
        root,
        "DROP TRIGGER detection_rule_versions_frozen_update",
        "UPDATE detection_rule_versions SET content = content || '# edited' "
        "WHERE rule_display_id = 'RULE-0002' AND version = 2",
    )
    assert ("DETECTION_RECORD_INVALID", "RULE-0002@v2") in found(root)

    mutate(
        root,
        "UPDATE detection_rule_versions SET status = 'draft' "
        "WHERE rule_display_id = 'RULE-0002' AND version = 2",
    )
    result = found(root)
    assert ("DETECTION_FREEZE_VIOLATION", "RULE-0002@v2") in result
    # The Unseen evaluation and tuning runs no longer rest on a frozen version.
    assert ("DETECTION_FREEZE_VIOLATION", "RUN-0004") in result
    assert ("DETECTION_FREEZE_VIOLATION", "RUN-0005") in result


def test_version_gap_and_run_hash_mismatch(root: Path) -> None:
    mutate(
        root,
        "DROP TRIGGER detection_validation_runs_immutable",
        "UPDATE detection_validation_runs SET rule_sha256 = 'x' "
        "WHERE display_id = 'RUN-0001'",
        "UPDATE detection_validation_runs SET kind = 'evaluation' "
        "WHERE display_id = 'RUN-0003'",
        "DROP TRIGGER detection_rule_versions_no_delete",
        "DELETE FROM detection_rule_versions "
        "WHERE rule_display_id = 'RULE-0002' AND version = 1",
    )
    result = found(root)
    assert ("DETECTION_RECORD_INVALID", "RUN-0001") in result
    assert ("DETECTION_FREEZE_VIOLATION", "RUN-0003") in result
    assert ("DETECTION_RECORD_INVALID", "RULE-0002") in result
    assert ("DETECTION_REFERENCE_BROKEN", "RUN-0002") in result


def test_inconsistent_validation_result(root: Path) -> None:
    mutate(
        root,
        "DROP TRIGGER detection_validation_results_immutable",
        "UPDATE detection_validation_results SET outcome = 'TN' "
        "WHERE run_display_id = 'RUN-0002' AND outcome = 'FP'",
    )
    assert ("DETECTION_RESULT_INCONSISTENT", "RUN-0002/CASE-0002") in found(root)


def test_result_outside_frozen_benchmark(root: Path) -> None:
    case = internal_id(root, "cases", "CASE-0004")
    mutate(
        root,
        "INSERT INTO detection_validation_results "
        "(run_display_id, case_id, role, matched, outcome, detail) "
        f"VALUES ('RUN-0004', '{case}', 'benign_common', 0, 'TN', '-')",
    )
    assert found(root) == {("DETECTION_RESULT_INCONSISTENT", "RUN-0004/CASE-0004")}


def test_hypothesis_evidence_of_another_case(root: Path) -> None:
    other = internal_id(root, "artifacts", "ART-000004")
    mutate(
        root,
        "INSERT INTO detection_hypothesis_evidence "
        f"(hypothesis_display_id, artifact_id) VALUES ('HYP-0001', '{other}')",
    )
    report = validate_workspace(root)
    assert [(f.code, f.subject) for f in report.findings] == [
        ("DETECTION_REFERENCE_BROKEN", "HYP-0001")
    ]
    assert "another Case" in report.findings[0].message


def test_detached_evidence_is_a_warning(root: Path) -> None:
    ArtifactService(root).detach("CASE-0001", "ART-000003")
    report = validate_workspace(root)
    assert [(f.code, f.severity) for f in report.findings] == [
        ("ARTIFACT_REFERENCE_DETACHED", FindingSeverity.WARNING)
    ]
    assert report.is_valid


def test_benchmark_member_role_must_match_case_kind(root: Path) -> None:
    benign = internal_id(root, "cases", "CASE-0004")
    mutate(
        root,
        "INSERT INTO detection_benchmarks (display_id, name, created_at) "
        "VALUES ('BMK-0002', 'tampered', '2026-11-17T00:00:00Z')",
        "UPDATE detection_counters SET next_value = 3 WHERE name = 'benchmark'",
        "INSERT INTO detection_benchmark_members "
        "(benchmark_display_id, case_id, role, added_at) "
        f"VALUES ('BMK-0002', '{benign}', 'unseen', '2026-11-17T00:00:00Z')",
    )
    assert found(root) == {("DETECTION_RECORD_INVALID", "BMK-0002/CASE-0004")}


def test_execution_findings(root: Path) -> None:
    # Unfinished run and safety lock are warnings: they describe VM state.
    add_execution_run(root, "CASE-0002", status=RunStatus.RUNNING)  # VMR-0002
    mutate(
        root,
        "INSERT INTO execution_safety_lock (id, run_display_id, reason, created_at) "
        "VALUES (1, 'VMR-0002', 'restore failed', '2026-11-17T00:00:00Z')",
    )
    report = validate_workspace(root)
    assert {(f.code, f.severity, f.subject) for f in report.findings} == {
        ("EXECUTION_RUN_UNFINISHED", FindingSeverity.WARNING, "VMR-0002"),
        ("EXECUTION_SAFETY_LOCK_SET", FindingSeverity.WARNING, "VMR-0002"),
    }
    assert report.is_valid

    # A collection Artifact of another Case and a step gap are errors.
    add_execution_run(root, "CASE-0003", sysmon_artifact="ART-000002")  # VMR-0003
    mutate(
        root,
        "PRAGMA foreign_keys = OFF",
        "INSERT INTO execution_steps (run_display_id, sequence, step, status, at) "
        "VALUES ('VMR-0001', 9, 'verify', 'ok', '2026-11-17T00:00:00Z')",
        "INSERT INTO execution_steps (run_display_id, sequence, step, status, at) "
        "VALUES ('VMR-9999', 1, 'verify', 'ok', '2026-11-17T00:00:00Z')",
    )
    report = validate_workspace(root)
    errors = {
        (f.code, f.subject)
        for f in report.findings
        if f.severity is FindingSeverity.ERROR
    }
    assert errors == {
        ("EXECUTION_REFERENCE_BROKEN", "VMR-0003"),
        ("EXECUTION_RECORD_INVALID", "VMR-0001"),
        ("EXECUTION_REFERENCE_BROKEN", "VMR-9999"),
    }
    assert not report.is_valid


def test_succeeded_run_requires_collection(root: Path) -> None:
    add_execution_run(root, "CASE-0002")  # succeeded without a Sysmon Artifact
    assert found(root) == {("EXECUTION_RECORD_INVALID", "VMR-0002")}


def test_cli_reports_module_findings(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["project", "validate", str(root)]) == 0
    assert capsys.readouterr().out == "valid\n"
    mutate(
        root,
        "INSERT INTO execution_safety_lock (id, run_display_id, reason, created_at) "
        "VALUES (1, NULL, 'manual', '2026-11-17T00:00:00Z')",
    )
    assert main(["project", "validate", str(root)]) == 0
    captured = capsys.readouterr()
    assert "warning EXECUTION_SAFETY_LOCK_SET [execution]" in captured.err
    mutate(root, "UPDATE detection_counters SET next_value = 1 WHERE name = 'rule'")
    before = (root / "project.db").read_bytes()
    assert main(["project", "validate", str(root), "--full"]) == 1
    captured = capsys.readouterr()
    assert "error DETECTION_COUNTER_INVALID [detection/rule]" in captured.err
    assert str(root) not in captured.err
    assert (root / "project.db").read_bytes() == before
