"""Compensation shared by Artifact-producing application services."""

from __future__ import annotations

import sqlite3
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
