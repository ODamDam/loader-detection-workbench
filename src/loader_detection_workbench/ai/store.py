"""Read-only access to stored AI analyses.

Kept apart from ``ai.service`` so that ``report.analysis`` can include stored
analyses in a Case report without importing the service that itself builds its
input from ``report.analysis``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from loader_detection_workbench.ai.domain import AiAnalysis, require_analysis_id
from loader_detection_workbench.ai.sqlite_repository import SQLiteAiRepository
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import CaseId
from loader_detection_workbench.project.service import ProjectService


@contextmanager
def ai_repository(root: Path, *, write: bool = False) -> Iterator[SQLiteAiRepository]:
    repository: SQLiteAiRepository | None = None
    try:
        repository = SQLiteAiRepository(ProjectService().open(root), write=write)
        with repository.transaction():
            yield repository
    except sqlite3.Error as exc:
        raise DomainError(
            DomainErrorCode.AI_PERSISTENCE_FAILED, "AI database operation failed"
        ) from exc
    finally:
        if repository is not None:
            repository.close()


class AiAnalysisReader:
    def __init__(self, root: Path) -> None:
        self._root = root

    def list(self, case_display_id: str | None = None) -> list[AiAnalysis]:
        if case_display_id is not None:
            CaseId("00000000000000000000000000", case_display_id)
        with ai_repository(self._root) as repository:
            return repository.list(case_display_id)

    def show(self, analysis_display_id: str) -> AiAnalysis:
        require_analysis_id(analysis_display_id)
        with ai_repository(self._root) as repository:
            return repository.get(analysis_display_id)
