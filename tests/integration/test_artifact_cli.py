from pathlib import Path

import pytest

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.service import ProjectService


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    ProjectService().create(tmp_path, "Artifact CLI")
    CaseService(tmp_path).create("Example", "benign")
    (tmp_path / "benign.txt").write_bytes(b"benign fixture")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_add_list_detach_cli(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prefix = ["case", "artifact"]
    assert main([*prefix, "list", "CASE-0001"]) == 0
    assert capsys.readouterr().out == ""
    assert main([*prefix, "add", "CASE-0001", "benign.txt", "--kind", "evidence"]) == 0
    output = capsys.readouterr().out
    columns = output.strip().split("\t")
    assert columns[:2] == ["ART-000001", "evidence"]
    assert columns[3] == "14"
    assert columns[4] == f"artifacts/sha256/{columns[2][:2]}/{columns[2]}"
    assert str(workspace) not in output
    assert main([*prefix, "list", "CASE-0001"]) == 0
    assert capsys.readouterr().out == output
    assert main([*prefix, "detach", "CASE-0001", "ART-000001"]) == 0
    assert capsys.readouterr().out == output
    assert main([*prefix, "list", "CASE-0001"]) == 0
    assert capsys.readouterr().out == ""
    assert main(["project", "validate"]) == 0


@pytest.mark.parametrize(
    "args,code",
    [
        (
            ["add", "CASE-0001", "benign.txt", "--kind", "OTHER"],
            "INVALID_ARTIFACT_KIND",
        ),
        (
            ["add", "CASE-0001", "missing.txt", "--kind", "other"],
            "ARTIFACT_SOURCE_INVALID",
        ),
        (["list", "CASE-9999"], "CASE_NOT_FOUND"),
        (["list", "bad"], "INVALID_DISPLAY_ID"),
        (["detach", "CASE-0001", "ART-999999"], "ARTIFACT_NOT_FOUND"),
        (["detach", "CASE-0001", "ART-0001"], "INVALID_DISPLAY_ID"),
    ],
)
def test_safe_cli_errors(
    workspace: Path, capsys: pytest.CaptureFixture[str], args: list[str], code: str
) -> None:
    assert main(["case", "artifact", *args]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"error: {code}:")
    assert str(workspace) not in captured.err
    assert "Traceback" not in captured.err


def test_closed_cli_and_current_project_only(
    workspace: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    CaseService(workspace).close("CASE-0001")
    assert (
        main(["case", "artifact", "add", "CASE-0001", "benign.txt", "--kind", "other"])
        == 2
    )
    assert "CASE_CLOSED" in capsys.readouterr().err
    assert main(["case", "artifact", "list", "CASE-0001"]) == 0
    assert (
        main(["--database", "ignored.db", "case", "artifact", "list", "CASE-0001"]) == 0
    )
    assert not (workspace / "ignored.db").exists()
    child = workspace / "child"
    child.mkdir()
    monkeypatch.chdir(child)
    assert main(["case", "artifact", "list", "CASE-0001"]) == 2
    assert "WORKSPACE_NOT_FOUND" in capsys.readouterr().err
