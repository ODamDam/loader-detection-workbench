import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.case import (
    Case,
    CaseKind,
    CaseLifecycle,
    CaseStatus,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import CaseId
from loader_detection_workbench.project.service import ProjectService


@pytest.mark.parametrize("name", ["", " ", "\t\n"])
def test_invalid_names_before_workspace_access(name: str, tmp_path: Path) -> None:
    service = CaseService(tmp_path / "absent")
    operations: tuple[Callable[[], Case], ...] = (
        lambda: service.create(name, "benign"),
        lambda: service.rename("CASE-0001", name),
    )
    for operation in operations:
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code is DomainErrorCode.INVALID_CASE_NAME
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("kind", ["", "unknown", "Benign", " benign "])
def test_invalid_kind_before_workspace_access(kind: str, tmp_path: Path) -> None:
    with pytest.raises(DomainError) as error:
        CaseService(tmp_path).create("Name", kind)
    assert error.value.code is DomainErrorCode.INVALID_CASE_KIND


@pytest.mark.parametrize(
    "selector",
    ["CASE-001", "CASE-0000", "case-0001", "00000000000000000000000000", " CASE-0001"],
)
def test_selector_validation(selector: str, tmp_path: Path) -> None:
    service = CaseService(tmp_path)
    for operation in (service.show, service.close, service.reopen):
        with pytest.raises(DomainError) as error:
            operation(selector)
        assert error.value.code is DomainErrorCode.INVALID_DISPLAY_ID


@pytest.mark.parametrize(
    "failure,code",
    [
        (
            sqlite3.OperationalError("private database details"),
            DomainErrorCode.INVALID_SQLITE_SCHEMA,
        ),
        (OSError("private filesystem details"), DomainErrorCode.WORKSPACE_NOT_FOUND),
    ],
)
def test_errors_are_translated_without_private_details(
    failure: Exception,
    code: DomainErrorCode,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(self: ProjectService, root: Path) -> None:
        raise failure

    monkeypatch.setattr(ProjectService, "open", fail)
    with pytest.raises(DomainError) as error:
        CaseService(tmp_path).list_cases()
    assert error.value.code is code
    assert "private" not in str(error.value)


def test_operation_timestamp_accepts_equal_and_rejects_backwards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timestamp = datetime(2026, 9, 8, tzinfo=UTC)
    case = Case(
        CaseId("00000000000000000000000000", "CASE-0001"),
        "00000000000000000000000001",
        CaseKind.BENIGN,
        "Name",
        None,
        timestamp,
        CaseLifecycle(CaseStatus.OPEN, timestamp),
    )
    monkeypatch.setattr(
        "loader_detection_workbench.case.service.utc_now", lambda: timestamp
    )
    assert CaseService._timestamp(case) == timestamp
    monkeypatch.setattr(
        "loader_detection_workbench.case.service.utc_now",
        lambda: timestamp - timedelta(seconds=1),
    )
    with pytest.raises(DomainError) as error:
        CaseService._timestamp(case)
    assert error.value.code is DomainErrorCode.INVALID_TIMESTAMP
