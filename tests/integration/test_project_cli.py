import sqlite3
from pathlib import Path

import pytest

from loader_detection_workbench.cli import main


def test_project_create_show_and_validate_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "workspace"

    assert main(["project", "create", str(root), "--name", "CLI Project"]) == 0
    create_output = capsys.readouterr().out
    assert "schema_version: 1" in create_output
    assert "display_id: PRJ-0001" in create_output
    assert "database.path: project.db" in create_output
    assert str(root) not in create_output

    assert main(["project", "show", str(root)]) == 0
    assert "name: CLI Project" in capsys.readouterr().out

    monkeypatch.chdir(root)
    assert main(["project", "show"]) == 0
    capsys.readouterr()
    assert main(["project", "validate"]) == 0
    assert capsys.readouterr().out.strip() == "valid"


def test_project_validate_and_runtime_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid = tmp_path / "invalid"
    invalid.mkdir()

    assert main(["project", "validate", str(invalid)]) == 1
    assert "WORKSPACE_NOT_FOUND" in capsys.readouterr().err

    occupied = tmp_path / "occupied"
    occupied.write_text("not a directory", encoding="utf-8")
    assert main(["project", "create", str(occupied), "--name", "No"]) == 2
    assert "project root must not exist" in capsys.readouterr().err


def test_sample_default_uses_project_database_without_legacy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "workspace"
    assert main(["project", "create", str(root), "--name", "Samples"]) == 0
    capsys.readouterr()
    fixture = root / "benign.txt"
    fixture.write_text("benign", encoding="utf-8")
    legacy = root / ".workbench" / "sample-intake.db"
    legacy.parent.mkdir()
    legacy_connection = sqlite3.connect(legacy)
    try:
        with legacy_connection:
            legacy_connection.execute("CREATE TABLE legacy_marker (value TEXT)")
            legacy_connection.execute("INSERT INTO legacy_marker VALUES ('preserve')")
    finally:
        legacy_connection.close()
    monkeypatch.chdir(root)

    assert (
        main(
            [
                "sample",
                "add",
                str(fixture),
                "--source",
                "test",
                "--source-reference",
                "benign.txt",
            ]
        )
        == 0
    )
    assert "SMP-000001" in capsys.readouterr().out
    legacy_connection = sqlite3.connect(legacy)
    try:
        assert (
            legacy_connection.execute("SELECT value FROM legacy_marker").fetchone()[0]
            == "preserve"
        )
        assert (
            legacy_connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'candidate_samples'"
            ).fetchone()
            is None
        )
    finally:
        legacy_connection.close()

    connection = sqlite3.connect(root / "project.db")
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {
            "schema_migrations",
            "projects",
            "counters",
            "cases",
            "artifacts",
            "candidate_samples",
        } <= tables
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            connection.execute("SELECT version FROM schema_migrations").fetchone()[0]
            == 1
        )
    finally:
        connection.close()
    assert main(["project", "validate"]) == 0


def test_sample_without_project_does_not_create_legacy_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = tmp_path / "benign.txt"
    fixture.write_text("benign", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "sample",
            "add",
            str(fixture),
            "--source",
            "test",
            "--source-reference",
            "benign.txt",
        ]
    )

    assert result == 2
    assert "project.json was not found" in capsys.readouterr().err
    assert not (tmp_path / ".workbench" / "sample-intake.db").exists()
