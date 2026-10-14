"""Case-aware registration and query service for analyst-supplied evidence."""

from __future__ import annotations

import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from loader_detection_workbench.artifact.cleanup import compensate_publication
from loader_detection_workbench.artifact.store import ArtifactStore, PublishedContent
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.case import Case, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, CaseId, generate_ulid
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.evidence.domain import (
    MANUAL_EVIDENCE_EXTENSIONS,
    MANUAL_EVIDENCE_MAX_BYTES,
    ArtifactProvenance,
    EvidenceType,
    ManualEvidence,
    validate_description,
    validate_original_filename,
    validate_source,
)
from loader_detection_workbench.evidence.repository import EvidenceRepository
from loader_detection_workbench.evidence.sqlite_repository import (
    SQLiteEvidenceRepository,
)
from loader_detection_workbench.project.service import ProjectService


class ManualEvidenceService:
    def __init__(self, root: Path) -> None:
        self._root = root

    @contextmanager
    def _repository(self, *, write: bool = False) -> Iterator[EvidenceRepository]:
        repository: SQLiteEvidenceRepository | None = None
        try:
            workspace = ProjectService().open(self._root)
            repository = SQLiteEvidenceRepository(workspace, write=write)
            with repository.transaction():
                yield repository
        except sqlite3.Error as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED,
                "manual evidence database operation failed",
            ) from exc
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_STORE_FAILED,
                "manual evidence workspace cannot be accessed",
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

    @staticmethod
    def _validate_extension(filename: str) -> None:
        if Path(filename).suffix.lower() not in MANUAL_EVIDENCE_EXTENSIONS:
            raise DomainError(
                DomainErrorCode.EVIDENCE_EXTENSION_NOT_ALLOWED,
                "manual evidence file extension is not allowed",
            )

    @staticmethod
    def _reject_source_link(source: Path) -> None:
        try:
            info = source.lstat()
        except (OSError, ValueError) as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_SOURCE_INVALID,
                "source must be a readable regular file",
            ) from exc
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise DomainError(
                DomainErrorCode.ARTIFACT_SOURCE_INVALID,
                "manual evidence source must not be a filesystem link",
            )

    def register(
        self,
        case_display_id: str,
        source_path: Path,
        *,
        source: str,
        evidence_type: str,
        description: str | None = None,
        original_filename: str | None = None,
    ) -> ManualEvidence:
        self._validate_case_selector(case_display_id)
        filename = source_path.name if original_filename is None else original_filename
        validate_original_filename(filename)
        validate_source(source)
        normalized_description = None if description == "" else description
        validate_description(normalized_description)
        parsed_type = EvidenceType.parse(evidence_type)

        content: PublishedContent | None = None
        store = ArtifactStore(self._root)
        try:
            with self._repository(write=True) as repository:
                case = repository.get_case(case_display_id)
                self._require_open(case)
                self._validate_extension(filename)
                self._reject_source_link(source_path)
                content = store.publish(
                    source_path, max_bytes=MANUAL_EVIDENCE_MAX_BYTES
                )
                artifact = Artifact(
                    ArtifactId(
                        generate_ulid(), repository.allocate_artifact_display_id()
                    ),
                    case.project_id,
                    case.case_id.ulid,
                    ArtifactKind.EVIDENCE,
                    content.relative_path,
                    content.sha256,
                    content.size_bytes,
                    utc_now(),
                )
                provenance = ArtifactProvenance(
                    artifact.artifact_id.ulid,
                    filename,
                    source,
                    normalized_description,
                    parsed_type,
                )
                repository.insert_artifact(artifact)
                repository.insert_provenance(provenance)
            return ManualEvidence(artifact, provenance)
        except BaseException:
            content = content or store.published
            if content is not None and content.owned_identity is not None:
                compensate_publication(self._root, store, content)
            raise

    def list_evidence(self, case_display_id: str) -> list[ManualEvidence]:
        self._validate_case_selector(case_display_id)
        with self._repository() as repository:
            case = repository.get_case(case_display_id)
            return repository.list_evidence(case.case_id.ulid)

    def show(self, case_display_id: str, artifact_display_id: str) -> ManualEvidence:
        self._validate_case_selector(case_display_id)
        ArtifactId("00000000000000000000000000", artifact_display_id)
        with self._repository() as repository:
            case = repository.get_case(case_display_id)
            return repository.get(case.case_id.ulid, artifact_display_id)
