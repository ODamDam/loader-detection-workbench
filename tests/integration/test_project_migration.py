import sqlite3
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.bundle.service import BundleService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project import migration as migration_module
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.migration import ProjectMigrationService
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.report.service import ReportService
from loader_detection_workbench.sysmon.service import SysmonService


def _downgrade_to_v1(root: Path) -> None:
    connection = connect_database(root / "project.db")
    try:
        with connection:
            connection.execute("DROP TABLE artifact_provenance")
            connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    finally:
        connection.close()


def _versions(root: Path) -> list[int]:
    connection = connect_database(root / "project.db", read_only=True)
    try:
        return [
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
    finally:
        connection.close()


def test_explicit_v1_to_v2_migration_preserves_existing_data(tmp_path: Path) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Migration")
    case = CaseService(root).create("Existing", "benign")
    _downgrade_to_v1(root)

    before = ProjectService().open(root)
    result = ProjectMigrationService().migrate(root)

    assert before.sqlite_schema_version == 1
    assert (result.previous_version, result.current_version, result.status) == (
        1,
        2,
        "migrated",
    )
    assert _versions(root) == [1, 2]
    assert CaseService(root).show(case.case_id.display_id) == case
    assert ProjectService().validate(root).is_valid


def test_repeat_v2_migration_is_an_explicit_noop(tmp_path: Path) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Current")

    result = ProjectMigrationService().migrate(root)

    assert (result.previous_version, result.current_version, result.status) == (
        2,
        2,
        "already-current",
    )
    assert _versions(root) == [1, 2]


def test_failed_migration_rolls_back_schema_and_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Rollback")
    case = CaseService(root).create("Existing", "benign")
    _downgrade_to_v1(root)

    def fail_after_ddl(connection: sqlite3.Connection) -> None:
        migration_module._apply_v2(connection)
        raise sqlite3.OperationalError("injected migration failure")

    monkeypatch.setattr(migration_module, "_apply_v2", fail_after_ddl)
    with pytest.raises(DomainError) as caught:
        ProjectMigrationService().migrate(root)

    assert caught.value.code is DomainErrorCode.PROJECT_MIGRATION_FAILED
    assert _versions(root) == [1]
    connection = connect_database(root / "project.db", read_only=True)
    try:
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'artifact_provenance'"
            ).fetchone()
            is None
        )
    finally:
        connection.close()
    assert ProjectService().open(root).sqlite_schema_version == 1
    assert CaseService(root).show(case.case_id.display_id) == case


def test_partial_v2_state_is_rejected_instead_of_implicitly_migrated(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Partial")
    connection = connect_database(root / "project.db")
    try:
        with connection:
            connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    finally:
        connection.close()

    with pytest.raises(DomainError) as caught:
        ProjectMigrationService().migrate(root)

    assert caught.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA


def test_v1_project_keeps_existing_case_artifact_bundle_sysmon_and_report(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Legacy")
    CaseService(root).create("Legacy Case", "benign")
    _downgrade_to_v1(root)
    fixture = Path("tests/fixtures/public/sysmon/process-create.xml")

    artifact = ArtifactService(root).add("CASE-0001", fixture, "sysmon")
    events = SysmonService(root).normalize("CASE-0001", artifact.artifact_id.display_id)
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    report = tmp_path / "legacy.md"
    ReportService(root).build("CASE-0001", report)
    bundle = tmp_path / "legacy.zip"
    BundleService(root).export("CASE-0001", bundle)

    assert ProjectService().open(root).sqlite_schema_version == 1
    assert len(events) == 1
    assert timeline.observations == tuple(events)
    assert report.is_file()
    assert BundleService(root).validate(bundle).is_valid
    assert ProjectService().validate_report(root, full=True).is_valid
