import sqlite3
from pathlib import Path

import pytest

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectService


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "CLI Evidence")
    CaseService(root).create("Case", "benign")
    monkeypatch.chdir(root)
    return root


def test_evidence_add_list_show_cli(
    root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("benign notes", encoding="utf-8")

    assert (
        main(
            [
                "case",
                "evidence",
                "add",
                "CASE-0001",
                str(source),
                "--origin",
                "analyst",
                "--type",
                "analyst_note",
                "--description",
                "review notes",
            ]
        )
        == 0
    )
    added = capsys.readouterr().out
    assert "artifact_id: ART-000001" in added
    assert "original_filename: notes.txt" in added
    assert "origin: analyst" in added
    assert str(tmp_path) not in added

    assert main(["case", "evidence", "list", "CASE-0001"]) == 0
    assert capsys.readouterr().out.startswith("ART-000001\tanalyst_note\tnotes.txt\t")

    assert main(["case", "evidence", "show", "CASE-0001", "ART-000001"]) == 0
    shown = capsys.readouterr().out
    assert "description: review notes" in shown
    assert "relative_path: artifacts/sha256/" in shown


def test_evidence_cli_reports_stable_error_code(
    root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "blocked.exe"
    source.write_bytes(b"harmless")

    assert (
        main(
            [
                "case",
                "evidence",
                "add",
                "CASE-0001",
                str(source),
                "--origin",
                "analyst",
                "--type",
                "other",
            ]
        )
        == 2
    )
    assert "EVIDENCE_EXTENSION_NOT_ALLOWED" in capsys.readouterr().err


def test_project_migrate_cli_is_explicit_and_repeatable(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    connection = connect_database(root / "project.db")
    try:
        with connection:
            connection.execute("DROP TABLE artifact_provenance")
            connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    finally:
        connection.close()

    assert main(["project", "migrate"]) == 0
    assert "migration: migrated 1 -> 2" in capsys.readouterr().out
    assert main(["project", "migrate"]) == 0
    assert "migration: already-current 2 -> 2" in capsys.readouterr().out

    with sqlite3.connect(root / "project.db") as query:
        assert query.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,)]
