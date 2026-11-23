from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.paths import ProjectRelativePath


def test_nested_relative_path_is_accepted_and_resolved(tmp_path: Path) -> None:
    path = ProjectRelativePath.parse("cases/CASE-0001/static/result.json")

    assert path.as_posix() == "cases/CASE-0001/static/result.json"
    assert path.resolve_under(tmp_path) == (
        tmp_path / "cases" / "CASE-0001" / "static" / "result.json"
    )


def test_windows_separators_are_canonicalized() -> None:
    path = ProjectRelativePath.parse(r"cases\CASE-0001\sample\input.exe")

    assert path.as_posix() == "cases/CASE-0001/sample/input.exe"


@pytest.mark.parametrize(
    "value", ["/etc/passwd", r"C:\Windows\system.ini", r"\\host\share\file"]
)
def test_absolute_paths_are_rejected(value: str) -> None:
    with pytest.raises(DomainError) as error:
        ProjectRelativePath.parse(value)

    assert error.value.code is DomainErrorCode.INVALID_RELATIVE_PATH


@pytest.mark.parametrize(
    "value", ["../secret", "cases/../../secret", r"cases\..\secret"]
)
def test_parent_traversal_is_rejected(value: str) -> None:
    with pytest.raises(DomainError) as error:
        ProjectRelativePath.parse(value)

    assert error.value.code is DomainErrorCode.PATH_ESCAPE


@pytest.mark.parametrize("value", ["", ".", "./"])
def test_empty_or_current_directory_path_is_rejected(value: str) -> None:
    with pytest.raises(DomainError) as error:
        ProjectRelativePath.parse(value)

    assert error.value.code is DomainErrorCode.INVALID_RELATIVE_PATH


def test_project_relative_path_is_immutable() -> None:
    path = ProjectRelativePath.parse("cases/CASE-0001")

    with pytest.raises(FrozenInstanceError):
        path._value = "other"  # type: ignore[misc]
