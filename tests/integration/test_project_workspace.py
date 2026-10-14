import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ProjectId
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.project import database as database_module
from loader_detection_workbench.project import service as service_module
from loader_detection_workbench.project.database import CORE_TABLES, connect_database
from loader_detection_workbench.project.manifest import ProjectManifest, write_manifest
from loader_detection_workbench.project.service import ProjectService, ProjectWorkspace


def create(root: Path) -> ProjectWorkspace:
    return ProjectService().create(root, "Workspace")


def mutate_db(root: Path, sql: str, parameters: tuple[object, ...] = ()) -> None:
    connection = sqlite3.connect(root / "project.db")
    try:
        with connection:
            connection.execute(sql, parameters)
    finally:
        connection.close()


def test_create_nonexistent_and_existing_empty_roots(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    first = create(missing)
    empty = tmp_path / "empty"
    empty.mkdir()
    second = create(empty)

    assert first.manifest.name == "Workspace"
    assert second.manifest.name == "Workspace"
    assert set(path.name for path in missing.iterdir()) == {
        "project.json",
        "project.db",
    }
    assert set(path.name for path in empty.iterdir()) == {"project.json", "project.db"}


def test_create_rejects_nonempty_root_and_second_create(tmp_path: Path) -> None:
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    marker = nonempty / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(DomainError) as first_error:
        create(nonempty)
    assert first_error.value.code is DomainErrorCode.WORKSPACE_ALREADY_EXISTS
    assert marker.read_text(encoding="utf-8") == "keep"

    root = tmp_path / "project"
    create(root)
    with pytest.raises(DomainError) as second_error:
        create(root)
    assert second_error.value.code is DomainErrorCode.WORKSPACE_ALREADY_EXISTS


def test_manifest_and_database_bootstrap_are_exact(tmp_path: Path) -> None:
    root = tmp_path / "project"
    workspace = create(root)
    manifest = json.loads((root / "project.json").read_text(encoding="utf-8"))

    assert manifest == {
        "schema_version": "1",
        "project": {
            "internal_id": workspace.manifest.project_id.ulid,
            "display_id": "PRJ-0001",
            "name": "Workspace",
        },
        "created_at": manifest["created_at"],
        "database": {"path": "project.db"},
    }
    connection = connect_database(root / "project.db")
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert set(CORE_TABLES) <= tables
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        ] == [(1,), (2,)]
        project_rows = connection.execute(
            "SELECT internal_id, display_id, name, created_at FROM projects"
        ).fetchall()
        assert len(project_rows) == 1
        assert tuple(project_rows[0]) == (
            manifest["project"]["internal_id"],
            "PRJ-0001",
            "Workspace",
            manifest["created_at"],
        )
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT name, next_value FROM counters ORDER BY name"
            ).fetchall()
        ] == [("artifact", 1), ("case", 1)]
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        connection.close()


def test_case_schema_uses_final_lifecycle_and_foreign_keys(tmp_path: Path) -> None:
    root = tmp_path / "project"
    workspace = create(root)
    connection = connect_database(root / "project.db")
    try:
        project_id = workspace.manifest.project_id.ulid
        with connection:
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "01ARZ3NDEKTSV4RRFFQ69G5FAW",
                    project_id,
                    "CASE-0001",
                    "simulator",
                    "open",
                    "reserved",
                    None,
                    "2026-09-03T00:00:00Z",
                    "2026-09-03T00:00:00Z",
                    None,
                ),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "01ARZ3NDEKTSV4RRFFQ69G5FAX",
                    project_id,
                    "CASE-0002",
                    "simulator",
                    "ready",
                    "invalid",
                    None,
                    "2026-09-03T00:00:00Z",
                    "2026-09-03T00:00:00Z",
                    None,
                ),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "01ARZ3NDEKTSV4RRFFQ69G5FAY",
                    "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
                    "CASE-0002",
                    "simulator",
                    "closed",
                    "orphan",
                    None,
                    "2026-09-03T00:00:00Z",
                    "2026-09-03T00:00:00Z",
                    "2026-09-03T00:00:00Z",
                ),
            )
    finally:
        connection.close()


def test_artifact_path_and_hash_are_not_unique(tmp_path: Path) -> None:
    root = tmp_path / "project"
    workspace = create(root)
    connection = connect_database(root / "project.db")
    try:
        values = (
            workspace.manifest.project_id.ulid,
            None,
            "log",
            "same/path",
            "a" * 64,
            1,
            "2026-09-03T00:00:00Z",
        )
        with connection:
            connection.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("01ARZ3NDEKTSV4RRFFQ69G5FAW", values[0], "ART-000001", *values[1:]),
            )
            connection.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("01ARZ3NDEKTSV4RRFFQ69G5FAX", values[0], "ART-000002", *values[1:]),
            )
    finally:
        connection.close()


def test_workspace_reopens_after_relocation(tmp_path: Path) -> None:
    source = tmp_path / "source" / "project"
    destination = tmp_path / "archive" / "project"
    create(source)
    destination.parent.mkdir()
    shutil.move(source, destination)

    reopened = ProjectService().open(destination)

    assert reopened.root == destination.absolute()
    assert reopened.database_path == (destination / "project.db").absolute()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("future", DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION),
        ("drop_migrations", DomainErrorCode.INVALID_SQLITE_SCHEMA),
        ("drop_artifacts", DomainErrorCode.INVALID_SQLITE_SCHEMA),
        ("zero_projects", DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH),
        ("multiple_projects", DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH),
        ("metadata_mismatch", DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH),
        ("missing_counter", DomainErrorCode.INVALID_SQLITE_SCHEMA),
    ],
)
def test_structural_database_failures_are_rejected(
    tmp_path: Path, mutation: str, expected: DomainErrorCode
) -> None:
    root = tmp_path / mutation
    create(root)
    if mutation == "future":
        mutate_db(
            root,
            "INSERT INTO schema_migrations VALUES (3, '2026-09-03T00:00:00Z')",
        )
    elif mutation == "drop_migrations":
        mutate_db(root, "DROP TABLE schema_migrations")
    elif mutation == "drop_artifacts":
        mutate_db(root, "DROP TABLE artifacts")
    elif mutation == "zero_projects":
        mutate_db(root, "DELETE FROM projects")
    elif mutation == "multiple_projects":
        mutate_db(
            root,
            "INSERT INTO projects VALUES (?, ?, ?, ?)",
            ("01ARZ3NDEKTSV4RRFFQ69G5FAW", "PRJ-0002", "other", "2026-09-03T00:00:00Z"),
        )
    elif mutation == "metadata_mismatch":
        mutate_db(root, "UPDATE projects SET name = 'different'")
    elif mutation == "missing_counter":
        mutate_db(root, "DELETE FROM counters WHERE name = 'case'")

    result = ProjectService().validate(root)

    assert not result.is_valid
    assert expected.value in {finding.code for finding in result.findings}


def test_missing_malformed_and_corrupt_workspace_inputs(tmp_path: Path) -> None:
    missing = ProjectService().validate(tmp_path / "missing")
    assert missing.findings[0].code == DomainErrorCode.WORKSPACE_NOT_FOUND.value

    no_manifest = tmp_path / "no-manifest"
    no_manifest.mkdir()
    assert (
        ProjectService().validate(no_manifest).findings[0].code
        == DomainErrorCode.WORKSPACE_NOT_FOUND.value
    )

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "project.json").write_text("{", encoding="utf-8")
    assert (
        ProjectService().validate(malformed).findings[0].code
        == DomainErrorCode.INVALID_PROJECT_MANIFEST.value
    )

    missing_db = tmp_path / "missing-db"
    create(missing_db)
    (missing_db / "project.db").unlink()
    assert (
        ProjectService().validate(missing_db).findings[0].code
        == DomainErrorCode.WORKSPACE_NOT_FOUND.value
    )

    corrupt = tmp_path / "corrupt"
    create(corrupt)
    (corrupt / "project.db").write_bytes(b"not sqlite")
    assert (
        ProjectService().validate(corrupt).findings[0].code
        == DomainErrorCode.INVALID_SQLITE_SCHEMA.value
    )


def test_malformed_non_integer_counter_returns_finding_and_cli_exit_one(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "malformed-counter"
    create(root)
    connection = sqlite3.connect(root / "project.db")
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        with connection:
            connection.execute(
                "UPDATE counters SET next_value = 'invalid' WHERE name = 'case'"
            )
    finally:
        connection.close()

    result = ProjectService().validate(root)

    assert not result.is_valid
    assert DomainErrorCode.INVALID_SQLITE_SCHEMA.value in {
        finding.code for finding in result.findings
    }
    from loader_detection_workbench.cli import main

    assert main(["project", "validate", str(root)]) == 1
    assert "COUNTER_INVALID" in capsys.readouterr().err


def test_bootstrap_failure_rolls_back_all_core_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bootstrap.db"
    manifest = ProjectManifest(
        schema_version="1",
        project_id=ProjectId("01ARZ3NDEKTSV4RRFFQ69G5FAV", "PRJ-0001"),
        name="Transaction Test",
        created_at=datetime(2026, 9, 3, tzinfo=UTC),
        database_path=ProjectRelativePath.parse("project.db"),
    )
    monkeypatch.setattr(
        database_module,
        "_SCHEMA_STATEMENTS",
        (database_module._SCHEMA_STATEMENTS[0], "CREATE TABLE invalid ("),
    )

    with pytest.raises(sqlite3.OperationalError):
        database_module.bootstrap_database(path, manifest, manifest.created_at)

    connection = sqlite3.connect(path)
    try:
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            == []
        )
    finally:
        connection.close()


def test_create_rollback_preserves_external_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "race"
    root.mkdir()

    def create_external_manifest(path: Path, manifest: ProjectManifest) -> None:
        path.write_text("external actor", encoding="utf-8")
        write_manifest(path, manifest)

    monkeypatch.setattr(service_module, "write_manifest", create_external_manifest)

    with pytest.raises(FileExistsError):
        create(root)

    assert (root / "project.json").read_text(encoding="utf-8") == "external actor"
    assert not (root / "project.db").exists()
