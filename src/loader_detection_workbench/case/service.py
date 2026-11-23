"""Application orchestration for the six Case operations."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loader_detection_workbench.case.repository import CaseRepository
from loader_detection_workbench.case.sqlite_repository import SQLiteCaseRepository
from loader_detection_workbench.domain.case import (
    Case,
    CaseKind,
    CaseLifecycle,
    CaseStatus,
    validate_case_name,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import CaseId, generate_ulid
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.project.service import ProjectService


class CaseService:
    def __init__(self, root: Path) -> None:
        self._root = root

    @contextmanager
    def _repository(
        self, *, write: bool = False
    ) -> Iterator[tuple[CaseRepository, str]]:
        repository: SQLiteCaseRepository | None = None
        try:
            workspace = ProjectService().open(self._root)
            repository = SQLiteCaseRepository(workspace, write=write)
            with repository.transaction():
                yield repository, workspace.manifest.project_id.ulid
        except sqlite3.Error as exc:
            raise DomainError(
                DomainErrorCode.INVALID_SQLITE_SCHEMA, "case database operation failed"
            ) from exc
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.WORKSPACE_NOT_FOUND,
                "project workspace cannot be accessed",
            ) from exc
        finally:
            if repository is not None:
                repository.close()

    @staticmethod
    def _validate_selector(display_id: str) -> None:
        # Reuse Issue #7's display-ID validation without exposing an ULID selector.
        CaseId("00000000000000000000000000", display_id)

    def create(self, name: str, kind: str, description: str | None = None) -> Case:
        validate_case_name(name)
        parsed_kind = CaseKind.parse(kind)
        with self._repository(write=True) as (repository, project_id):
            timestamp = utc_now()
            case = Case(
                CaseId(generate_ulid(), repository.allocate_display_id()),
                project_id,
                parsed_kind,
                name,
                description,
                timestamp,
                CaseLifecycle(CaseStatus.OPEN, timestamp),
            )
            repository.insert(case)
            return case

    def list_cases(self) -> list[Case]:
        with self._repository() as (repository, _):
            return repository.list_cases()

    def show(self, display_id: str) -> Case:
        self._validate_selector(display_id)
        with self._repository() as (repository, _):
            return repository.get(display_id)

    def rename(self, display_id: str, name: str) -> Case:
        self._validate_selector(display_id)
        validate_case_name(name)
        with self._repository(write=True) as (repository, _):
            case = repository.get(display_id)
            if case.status is not CaseStatus.OPEN:
                raise DomainError(
                    DomainErrorCode.CASE_CLOSED, "closed case is read-only"
                )
            return repository.rename(case, name, self._timestamp(case))

    def close(self, display_id: str) -> Case:
        return self._transition(display_id, CaseStatus.CLOSED)

    def reopen(self, display_id: str) -> Case:
        return self._transition(display_id, CaseStatus.OPEN)

    def _transition(self, display_id: str, target: CaseStatus) -> Case:
        self._validate_selector(display_id)
        with self._repository(write=True) as (repository, _):
            case = repository.get(display_id)
            if case.status is target:
                raise DomainError(
                    DomainErrorCode.INVALID_CASE_TRANSITION,
                    "case is already in the requested state",
                )
            timestamp = self._timestamp(case)
            lifecycle = (
                case.lifecycle.close(timestamp)
                if target is CaseStatus.CLOSED
                else case.lifecycle.reopen(timestamp)
            )
            return repository.set_lifecycle(case, lifecycle)

    @staticmethod
    def _timestamp(case: Case) -> datetime:
        timestamp = utc_now()
        if timestamp < case.updated_at:
            raise DomainError(
                DomainErrorCode.INVALID_TIMESTAMP,
                "case timestamp must not move backwards",
            )
        return timestamp
