"""Compensation shared by Artifact-producing application services."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

from loader_detection_workbench.artifact.sqlite_repository import (
    SQLiteArtifactRepository,
)
from loader_detection_workbench.artifact.store import ArtifactStore, PublishedContent
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService


def compensate_publication(
    root: Path, store: ArtifactStore, content: PublishedContent
) -> None:
    repository: SQLiteArtifactRepository | None = None
    try:
        workspace = ProjectService().open(root)
        repository = SQLiteArtifactRepository(workspace, write=True)
        with repository.transaction():
            if not repository.has_content_reference(
                content.relative_path.as_posix(), content.sha256
            ):
                store.cleanup(content)
    except (DomainError, OSError, sqlite3.Error) as exc:
        raise DomainError(
            DomainErrorCode.ARTIFACT_CLEANUP_FAILED,
            "artifact operation failed; content cleanup could not complete",
        ) from exc
    finally:
        if repository is not None:
            repository.close()


def compensate_publications(
    root: Path,
    publications: Iterable[tuple[ArtifactStore, PublishedContent]],
) -> None:
    """Remove every newly owned, still-unreferenced publication after rollback."""
    owned = [item for item in publications if item[1].owned_identity is not None]
    if not owned:
        return
    repository: SQLiteArtifactRepository | None = None
    failures: list[BaseException] = []
    try:
        workspace = ProjectService().open(root)
        repository = SQLiteArtifactRepository(workspace, write=True)
        with repository.transaction():
            for store, content in reversed(owned):
                try:
                    if not repository.has_content_reference(
                        content.relative_path.as_posix(), content.sha256
                    ):
                        store.cleanup(content)
                except (DomainError, OSError) as exc:
                    failures.append(exc)
    except (DomainError, OSError, sqlite3.Error) as exc:
        raise DomainError(
            DomainErrorCode.ARTIFACT_CLEANUP_FAILED,
            "Collection ingestion failed; published content cleanup could not complete",
        ) from exc
    finally:
        if repository is not None:
            repository.close()
    if failures:
        raise DomainError(
            DomainErrorCode.ARTIFACT_CLEANUP_FAILED,
            "Collection ingestion failed; some published content could not be cleaned",
        ) from failures[0]
