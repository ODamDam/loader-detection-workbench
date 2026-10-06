from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from loader_detection_workbench.domain.case import (
    CaseKind,
    CaseLifecycle,
    CaseStatus,
    validate_case_name,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

OPENED_AT = datetime(2026, 9, 1, 12, tzinfo=UTC)
CLOSED_AT = datetime(2026, 9, 2, 12, tzinfo=UTC)
REOPENED_AT = datetime(2026, 9, 3, 12, tzinfo=UTC)


def test_open_case_can_be_closed() -> None:
    lifecycle = CaseLifecycle(CaseStatus.OPEN, OPENED_AT)

    closed = lifecycle.close(CLOSED_AT)

    assert closed.status is CaseStatus.CLOSED
    assert closed.updated_at == CLOSED_AT
    assert closed.closed_at == CLOSED_AT
    assert lifecycle.status is CaseStatus.OPEN
    assert lifecycle.updated_at == OPENED_AT
    assert lifecycle.closed_at is None


def test_closed_case_can_be_reopened() -> None:
    lifecycle = CaseLifecycle(CaseStatus.OPEN, OPENED_AT).close(CLOSED_AT)

    reopened = lifecycle.reopen(REOPENED_AT)

    assert reopened.status is CaseStatus.OPEN
    assert reopened.updated_at == REOPENED_AT
    assert reopened.closed_at is None


def test_same_state_transitions_are_rejected_without_mutation() -> None:
    opened = CaseLifecycle(CaseStatus.OPEN, OPENED_AT)
    with pytest.raises(DomainError) as close_error:
        opened.reopen(REOPENED_AT)
    assert close_error.value.code is DomainErrorCode.INVALID_CASE_TRANSITION
    assert opened.updated_at == OPENED_AT
    assert opened.closed_at is None

    closed = opened.close(CLOSED_AT)
    with pytest.raises(DomainError) as reopen_error:
        closed.close(REOPENED_AT)
    assert reopen_error.value.code is DomainErrorCode.INVALID_CASE_TRANSITION
    assert closed.updated_at == CLOSED_AT
    assert closed.closed_at == CLOSED_AT


def test_case_status_parse_rejects_unknown_state() -> None:
    with pytest.raises(DomainError) as error:
        CaseStatus.parse("completed")

    assert error.value.code is DomainErrorCode.INVALID_CASE_STATUS


def test_case_lifecycle_rejects_untyped_status() -> None:
    with pytest.raises(DomainError) as error:
        CaseLifecycle("open", OPENED_AT)  # type: ignore[arg-type]

    assert error.value.code is DomainErrorCode.INVALID_CASE_STATUS


def test_case_lifecycle_is_immutable() -> None:
    lifecycle = CaseLifecycle(CaseStatus.OPEN, OPENED_AT)

    with pytest.raises(FrozenInstanceError):
        lifecycle.status = CaseStatus.CLOSED  # type: ignore[misc]


@pytest.mark.parametrize("kind", ["malware", "simulator", "benign"])
def test_case_kind_parse(kind: str) -> None:
    assert CaseKind.parse(kind).value == kind


def test_case_name_and_kind_validation() -> None:
    validate_case_name(" Name ")
    with pytest.raises(DomainError) as name_error:
        validate_case_name("  ")
    assert name_error.value.code is DomainErrorCode.INVALID_CASE_NAME
    with pytest.raises(DomainError) as kind_error:
        CaseKind.parse("unknown")
    assert kind_error.value.code is DomainErrorCode.INVALID_CASE_KIND
