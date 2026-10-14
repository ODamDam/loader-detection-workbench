import shutil
from pathlib import Path

import pytest

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.service import ProjectService

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Collection CLI")
    CaseService(root).create("Open", "benign")
    monkeypatch.chdir(root)
    return root


def test_collection_import_cli_is_safe_and_repeatable(
    root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    collection = tmp_path / "private-looking-collection"
    shutil.copytree(FIXTURES, collection)

    assert main(["case", "collection", "import", "CASE-0001", str(collection)]) == 0
    first = capsys.readouterr()
    assert not first.err
    assert "status: imported" in first.out
    assert "process_artifact: ART-000001" in first.out
    assert "file_artifact: ART-000002" in first.out
    assert "metadata_artifact: ART-000003" in first.out
    assert "created: 3\nreused: 0" in first.out
    assert str(tmp_path) not in first.out
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in first.out
    assert "11111111-2222-4333-8444-555555555555" not in first.out

    assert main(["case", "collection", "import", "CASE-0001", str(collection)]) == 0
    second = capsys.readouterr()
    assert not second.err
    assert "status: already-present" in second.out
    assert "created: 0\nreused: 3" in second.out


def test_collection_import_cli_reports_stable_error(
    root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "case",
                "collection",
                "import",
                "CASE-0001",
                str(tmp_path / "missing"),
            ]
        )
        == 2
    )
    output = capsys.readouterr()
    assert not output.out
    assert "INVALID_SYSMON_COLLECTION_FILE" in output.err
    assert str(tmp_path) not in output.err
