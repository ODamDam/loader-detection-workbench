"""Atomic ingestion of a validated Collection into an existing open Case."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from loader_detection_workbench.artifact.cleanup import compensate_publications
from loader_detection_workbench.artifact.repository import ArtifactRepository
from loader_detection_workbench.artifact.sqlite_repository import (
    SQLiteArtifactRepository,
)
from loader_detection_workbench.artifact.store import ArtifactStore, PublishedContent
from loader_detection_workbench.collection.domain import (
    CollectionArtifactRole,
    CollectionIngestionResult,
    ValidatedCollectionFile,
)
from loader_detection_workbench.collection.validator import CollectionValidator
from loader_detection_workbench.domain.artifact import Artifact
from loader_detection_workbench.domain.case import Case, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import FileCreateEvent, ProcessCreateEvent
from loader_detection_workbench.domain.ids import ArtifactId, CaseId, generate_ulid
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.sysmon.normalizer import (
    MAX_XML_BYTES,
    normalize_sysmon_event,
)


class CollectionIngestionService:
    def __init__(
        self, root: Path, *, validator: CollectionValidator | None = None
    ) -> None:
        self._root = root
        self._validator = validator or CollectionValidator()

    @contextmanager
    def _repository(self) -> Iterator[ArtifactRepository]:
        repository: SQLiteArtifactRepository | None = None
        try:
            workspace = ProjectService().open(self._root)
            repository = SQLiteArtifactRepository(workspace, write=True)
            with repository.transaction():
                yield repository
        except sqlite3.Error as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED,
                "Collection ingestion database operation failed",
            ) from exc
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_STORE_FAILED,
                "Collection ingestion workspace cannot be accessed",
            ) from exc
        finally:
            if repository is not None:
                repository.close()

    @staticmethod
    def _require_open(case: Case) -> None:
        if case.status is not CaseStatus.OPEN:
            raise DomainError(DomainErrorCode.CASE_CLOSED, "closed case is read-only")

    def import_collection(
        self, case_display_id: str, collection_directory: Path
    ) -> CollectionIngestionResult:
        CaseId("00000000000000000000000000", case_display_id)
        publications: list[tuple[ArtifactStore, PublishedContent]] = []
        current_store: ArtifactStore | None = None
        try:
            with self._repository() as repository:
                case = repository.get_case(case_display_id)
                self._require_open(case)
                collection = self._validator.validate(collection_directory)
                artifacts: dict[CollectionArtifactRole, Artifact] = {}
                created = 0
                reused = 0
                for item in collection.files_in_registration_order():
                    existing = repository.find_by_content(
                        case.case_id.ulid, item.kind, item.sha256
                    )
                    if existing is not None:
                        self._verify_reusable(existing, item)
                        artifacts[item.role] = existing
                        reused += 1
                        continue

                    current_store = ArtifactStore(self._root)
                    content = current_store.publish_bytes(item.data)
                    if content.owned_identity is not None:
                        publications.append((current_store, content))
                    artifact = Artifact(
                        ArtifactId(generate_ulid(), repository.allocate_display_id()),
                        case.project_id,
                        case.case_id.ulid,
                        item.kind,
                        content.relative_path,
                        content.sha256,
                        content.size_bytes,
                        utc_now(),
                    )
                    repository.insert(artifact)
                    artifacts[item.role] = artifact
                    created += 1
                    current_store = None

            status = (
                "already-present"
                if created == 0
                else "imported"
                if reused == 0
                else "imported-with-reuse"
            )
            return CollectionIngestionResult(
                status,
                case_display_id,
                artifacts[CollectionArtifactRole.PROCESS_CREATE],
                artifacts[CollectionArtifactRole.FILE_CREATE],
                artifacts[CollectionArtifactRole.METADATA],
                created,
                reused,
            )
        except BaseException:
            if (
                current_store is not None
                and current_store.published is not None
                and current_store.published.owned_identity is not None
                and all(store is not current_store for store, _ in publications)
            ):
                publications.append((current_store, current_store.published))
            if publications:
                compensate_publications(self._root, publications)
            raise

    def _verify_reusable(
        self, artifact: Artifact, item: ValidatedCollectionFile
    ) -> None:
        if artifact.size_bytes != item.size_bytes:
            raise DomainError(
                DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH,
                "reusable Artifact size does not match validated content",
            )
        store = ArtifactStore(self._root)
        store.verify(
            store.resolve(artifact.relative_path),
            (artifact.sha256, artifact.size_bytes),
        )
        if item.role is CollectionArtifactRole.METADATA:
            return
        data = store.read_verified(
            artifact.relative_path,
            (artifact.sha256, artifact.size_bytes),
            max_bytes=MAX_XML_BYTES,
        )
        event = normalize_sysmon_event(data, artifact.artifact_id)[0]
        valid_role = (
            item.role is CollectionArtifactRole.PROCESS_CREATE
            and isinstance(event, ProcessCreateEvent)
        ) or (
            item.role is CollectionArtifactRole.FILE_CREATE
            and isinstance(event, FileCreateEvent)
        )
        if not valid_role:
            raise DomainError(
                DomainErrorCode.SYSMON_COLLECTION_EVENT_MISMATCH,
                "reusable Artifact does not match the Collection role",
            )
