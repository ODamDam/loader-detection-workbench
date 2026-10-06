"""Case-aware Artifact orchestration and compensating content cleanup."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from loader_detection_workbench.artifact.repository import ArtifactRepository
from loader_detection_workbench.artifact.sqlite_repository import (
    SQLiteArtifactRepository,
)
from loader_detection_workbench.artifact.store import ArtifactStore, PublishedContent
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.case import Case, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, CaseId, generate_ulid
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.project.service import ProjectService


class ArtifactService:
    def __init__(self, root: Path) -> None:
        self._root = root

    @contextmanager
    def _repository(self, *, write: bool = False) -> Iterator[ArtifactRepository]:
        repository: SQLiteArtifactRepository | None = None
        try:
            workspace = ProjectService().open(self._root)
            repository = SQLiteArtifactRepository(workspace, write=write)
            with repository.transaction():
                yield repository
        except sqlite3.Error as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED,
                "artifact database operation failed",
            ) from exc
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_STORE_FAILED,
                "artifact workspace cannot be accessed",
            ) from exc
        finally:
            if repository is not None:
                repository.close()

    @staticmethod
    def _validate_case_selector(display_id: str) -> None:
        CaseId("00000000000000000000000000", display_id)

    @staticmethod
    def _require_open(case: Case) -> None:
        if case.status is not CaseStatus.OPEN:
            raise DomainError(DomainErrorCode.CASE_CLOSED, "closed case is read-only")

    def add(self, case_display_id: str, source: Path, kind: str) -> Artifact:
        self._validate_case_selector(case_display_id)
        parsed_kind = ArtifactKind.parse(kind)
        content: PublishedContent | None = None
        store = ArtifactStore(self._root)
        try:
            # Serialize publishers and Case close/detach with the existing SQLite
            # writer lock. Rows/counter are committed only after verified publication.
            with self._repository(write=True) as repository:
                case = repository.get_case(case_display_id)
                self._require_open(case)
                content = store.publish(source)
                artifact = Artifact(
                    ArtifactId(generate_ulid(), repository.allocate_display_id()),
                    case.project_id,
                    case.case_id.ulid,
                    parsed_kind,
                    content.relative_path,
                    content.sha256,
                    content.size_bytes,
                    utc_now(),
                )
                repository.insert(artifact)
            return artifact
        except BaseException:
            content = content or store.published
            if content is not None and content.owned_identity is not None:
                self._compensate(store, content)
            raise

    def _compensate(self, store: ArtifactStore, content: PublishedContent) -> None:
        try:
            # The failed transaction has rolled back. Reacquire a writer lock before
            # checking committed references: a racing add may now own a reference.
            with self._repository(write=True) as repository:
                if not repository.has_content_reference(
                    content.relative_path.as_posix(), content.sha256
                ):
                    store.cleanup(content)
        except (DomainError, OSError, sqlite3.Error) as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_CLEANUP_FAILED,
                "artifact operation failed; content cleanup could not complete",
            ) from exc

    def list_artifacts(self, case_display_id: str) -> list[Artifact]:
        self._validate_case_selector(case_display_id)
        with self._repository() as repository:
            case = repository.get_case(case_display_id)
            return repository.list_artifacts(case.case_id.ulid)

    def detach(self, case_display_id: str, artifact_display_id: str) -> Artifact:
        self._validate_case_selector(case_display_id)
        ArtifactId("00000000000000000000000000", artifact_display_id)
        with self._repository(write=True) as repository:
            case = repository.get_case(case_display_id)
            self._require_open(case)
            return repository.detach(case.case_id.ulid, artifact_display_id)
