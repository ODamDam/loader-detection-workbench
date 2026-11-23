"""Minimal case lifecycle contract."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import CaseId
from loader_detection_workbench.domain.time import require_utc


class CaseKind(StrEnum):
    MALWARE = "malware"
    SIMULATOR = "simulator"
    BENIGN = "benign"

    @classmethod
    def parse(cls, value: str) -> CaseKind:
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_CASE_KIND, "unsupported case kind"
            ) from exc


def validate_case_name(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(
            DomainErrorCode.INVALID_CASE_NAME, "case name must be a non-empty string"
        )


class CaseStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"

    @classmethod
    def parse(cls, value: str) -> CaseStatus:
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_CASE_STATUS,
                f"unsupported case status: {value}",
            ) from exc


@dataclass(frozen=True, slots=True)
class CaseLifecycle:
    status: CaseStatus
    updated_at: datetime
    closed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, CaseStatus):
            raise DomainError(
                DomainErrorCode.INVALID_CASE_STATUS,
                f"unsupported case status: {self.status}",
            )
        object.__setattr__(self, "updated_at", require_utc(self.updated_at))
        if self.closed_at is not None:
            object.__setattr__(self, "closed_at", require_utc(self.closed_at))

    def close(self, at: datetime) -> CaseLifecycle:
        if self.status is not CaseStatus.OPEN:
            raise DomainError(
                DomainErrorCode.INVALID_CASE_TRANSITION,
                "only an open case can be closed",
            )
        timestamp = require_utc(at)
        return replace(
            self, status=CaseStatus.CLOSED, updated_at=timestamp, closed_at=timestamp
        )

    def reopen(self, at: datetime) -> CaseLifecycle:
        if self.status is not CaseStatus.CLOSED:
            raise DomainError(
                DomainErrorCode.INVALID_CASE_TRANSITION,
                "only a closed case can be reopened",
            )
        return replace(
            self,
            status=CaseStatus.OPEN,
            updated_at=require_utc(at),
            closed_at=None,
        )


@dataclass(frozen=True, slots=True)
class Case:
    case_id: CaseId
    project_id: str
    kind: CaseKind
    name: str
    description: str | None
    created_at: datetime
    lifecycle: CaseLifecycle

    @property
    def status(self) -> CaseStatus:
        return self.lifecycle.status

    @property
    def updated_at(self) -> datetime:
        return self.lifecycle.updated_at

    @property
    def closed_at(self) -> datetime | None:
        return self.lifecycle.closed_at
