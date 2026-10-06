import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.service import ProjectService


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    ProjectService().create(tmp_path, "CLI Project")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_cli_full_case_flow(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["case", "list"]) == 0
    assert capsys.readouterr().out == ""
    assert main(["case", "create", "--name", " Name ", "--kind", "benign"]) == 0
    output = capsys.readouterr().out
    assert "display_id: CASE-0001" in output
    assert "status: open" in output and "description: NULL" in output
    assert "closed_at: NULL" in output and "name:  Name \n" in output
    assert str(workspace) not in output
    assert main(["case", "rename", "CASE-0001", "--name", "Renamed"]) == 0
    assert "name: Renamed" in capsys.readouterr().out
    assert main(["case", "close", "CASE-0001"]) == 0
    assert "status: closed" in capsys.readouterr().out
    assert main(["case", "show", "CASE-0001"]) == 0
    assert "status: closed" in capsys.readouterr().out
    assert main(["case", "rename", "CASE-0001", "--name", "No"]) == 2
    assert "CASE_CLOSED" in capsys.readouterr().err
    assert main(["case", "close", "CASE-0001"]) == 2
    assert "INVALID_CASE_TRANSITION" in capsys.readouterr().err
    assert main(["case", "reopen", "CASE-0001"]) == 0
    assert "closed_at: NULL" in capsys.readouterr().out
    assert main(["case", "reopen", "CASE-0001"]) == 2
    assert "INVALID_CASE_TRANSITION" in capsys.readouterr().err
    assert main(["case", "rename", "CASE-0001", "--name", "Allowed"]) == 0
    capsys.readouterr()
    assert main(["case", "list"]) == 0
    assert capsys.readouterr().out == "CASE-0001\tbenign\topen\tAllowed\n"
    assert main(["project", "show"]) == 0
    assert main(["project", "validate"]) == 0


@pytest.mark.parametrize(
    "args,code",
    [
        (["create", "--name", "Name", "--kind", "bad"], "INVALID_CASE_KIND"),
        (["create", "--name", " ", "--kind", "benign"], "INVALID_CASE_NAME"),
        (["rename", "CASE-0001", "--name", ""], "INVALID_CASE_NAME"),
        (["show", "CASE-0001"], "CASE_NOT_FOUND"),
        (["show", "00000000000000000000000000"], "INVALID_DISPLAY_ID"),
    ],
)
def test_cli_errors_use_existing_domain_exit_convention(
    workspace: Path,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    code: str,
) -> None:
    assert main(["case", *args]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"error: {code}:")
    assert str(workspace) not in captured.err


def test_cli_numeric_order(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    service = CaseService(workspace)
    service.create("First", "benign")
    with closing(sqlite3.connect(workspace / "project.db")) as connection, connection:
        connection.execute("UPDATE counters SET next_value = 9999 WHERE name = 'case'")
    service.create("Boundary", "simulator")
    service.create("Next", "malware")
    assert main(["case", "list"]) == 0
    assert [line.split("\t")[0] for line in capsys.readouterr().out.splitlines()] == [
        "CASE-0001",
        "CASE-9999",
        "CASE-10000",
    ]


def test_cli_project_scope_and_no_parent_search(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = CaseService(workspace).create("Parent", "benign")
    child = workspace / "child"
    child.mkdir()
    monkeypatch.chdir(child)
    assert main(["case", "show", case.case_id.display_id]) == 2
    assert "WORKSPACE_NOT_FOUND" in capsys.readouterr().err
    ProjectService().create(child, "Child")
    assert main(["case", "show", case.case_id.display_id]) == 2
    assert "CASE_NOT_FOUND" in capsys.readouterr().err


def test_case_preserves_sample_routing_and_legacy_database(
    workspace: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    legacy = workspace / ".workbench" / "sample-intake.db"
    legacy.parent.mkdir()
    with closing(sqlite3.connect(legacy)) as connection, connection:
        connection.execute("CREATE TABLE marker (value TEXT)")
        connection.execute("INSERT INTO marker VALUES ('preserve')")
    legacy_bytes = legacy.read_bytes()
    fixture = workspace / "harmless.txt"
    fixture.write_text("harmless test text", encoding="utf-8")
    assert (
        main(
            [
                "sample",
                "add",
                str(fixture),
                "--source",
                "test",
                "--source-reference",
                "harmless.txt",
            ]
        )
        == 0
    )
    assert main(["case", "create", "--name", "Case", "--kind", "benign"]) == 0
    assert main(["sample", "list", "--format", "json"]) == 0
    assert "SMP-000001" in capsys.readouterr().out
    assert main(["project", "validate"]) == 0
    assert legacy.read_bytes() == legacy_bytes
    with closing(sqlite3.connect(workspace / "project.db")) as connection:
        assert connection.execute("SELECT count(*) FROM cases").fetchone()[0] == 1
        assert (
            connection.execute("SELECT count(*) FROM candidate_samples").fetchone()[0]
            == 1
        )
        assert (
            connection.execute("SELECT version FROM schema_migrations").fetchone()[0]
            == 1
        )


def test_cli_hides_sqlite_failure_details(
    workspace: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with closing(sqlite3.connect(workspace / "project.db")) as connection, connection:
        connection.execute(
            "CREATE TRIGGER fail_insert AFTER INSERT ON cases "
            "BEGIN SELECT RAISE(ABORT, 'private details'); END"
        )
    assert main(["case", "create", "--name", "Case", "--kind", "benign"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "INVALID_SQLITE_SCHEMA" in captured.err
    assert "private details" not in captured.err


@pytest.mark.parametrize("command", ["delete", "attach", "import-bundle"])
def test_no_later_case_commands(command: str) -> None:
    with pytest.raises(SystemExit) as error:
        main(["case", command])
    assert error.value.code == 2
