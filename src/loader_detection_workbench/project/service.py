"""Application service for creating and validating Project workspaces."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.contracts import (
    PROJECT_JSON_SCHEMA_VERSION,
    SQLITE_SCHEMA_VERSION,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ProjectId, generate_ulid
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.domain.validation import (
    Finding,
    FindingSeverity,
    ValidationReport,
    ValidationResult,
)
from loader_detection_workbench.project.database import (
    bootstrap_database,
    validate_database,
)
from loader_detection_workbench.project.manifest import (
    ProjectManifest,
    load_manifest,
    parse_manifest_data,
    read_manifest_data,
    validate_manifest_data,
    write_manifest,
)

_MANIFEST_NAME = "project.json"
_DATABASE_NAME = "project.db"


@dataclass(frozen=True, slots=True)
class ProjectWorkspace:
    root: Path
    manifest: ProjectManifest
    database_path: Path
    sqlite_schema_version: int


class ProjectService:
    def create(self, root: Path, name: str) -> ProjectWorkspace:
        if not isinstance(name, str) or not name.strip():
            raise DomainError(
                DomainErrorCode.INVALID_PROJECT_MANIFEST,
                "project name must be a non-empty string",
            )
        root_existed = root.exists()
        if root_existed:
            if not root.is_dir() or any(root.iterdir()):
                raise DomainError(
                    DomainErrorCode.WORKSPACE_ALREADY_EXISTS,
                    "project root must not exist or must be an empty directory",
                )
        else:
            root.mkdir(parents=True)

        manifest_path = root / _MANIFEST_NAME
        database_path = root / _DATABASE_NAME
        created_paths: list[Path] = []
        try:
            created_at = utc_now()
            manifest = ProjectManifest(
                schema_version=PROJECT_JSON_SCHEMA_VERSION,
                project_id=ProjectId(generate_ulid(), "PRJ-0001"),
                name=name,
                created_at=created_at,
                database_path=ProjectRelativePath.parse(_DATABASE_NAME),
            )
            database_path.open("xb").close()
            created_paths.append(database_path)
            bootstrap_database(database_path, manifest, created_at)
            write_manifest(manifest_path, manifest)
            created_paths.append(manifest_path)
            return ProjectWorkspace(
                root.absolute(),
                manifest,
                database_path.absolute(),
                SQLITE_SCHEMA_VERSION,
            )
        except Exception:
            self._rollback_create(root, root_existed, created_paths)
            raise

    def open(self, root: Path) -> ProjectWorkspace:
        result = self.validate(root)
        if not result.is_valid:
            first = result.findings[0]
            raise DomainError(DomainErrorCode(first.code), first.message)
        manifest = load_manifest(root / _MANIFEST_NAME)
        database_path = manifest.database_path.resolve_under(root)
        return ProjectWorkspace(
            root.absolute(), manifest, database_path, SQLITE_SCHEMA_VERSION
        )

    def show(self, root: Path) -> ProjectWorkspace:
        return self.open(root)

    def validate_report(self, root: Path, *, full: bool = False) -> ValidationReport:
        """Run the read-only cross-contract validator for a workspace."""
        from loader_detection_workbench.project.validator import validate_workspace

        return validate_workspace(root, full=full)

    def validate(self, root: Path) -> ValidationResult:
        findings: list[Finding] = []
        if not root.exists() or not root.is_dir():
            return ValidationResult(
                (
                    Finding(
                        DomainErrorCode.WORKSPACE_NOT_FOUND.value,
                        FindingSeverity.ERROR,
                        "project workspace root was not found",
                    ),
                )
            )
        manifest_path = root / _MANIFEST_NAME
        if not manifest_path.is_file():
            return ValidationResult(
                (
                    Finding(
                        DomainErrorCode.WORKSPACE_NOT_FOUND.value,
                        FindingSeverity.ERROR,
                        "project.json was not found",
                    ),
                )
            )
        try:
            data = read_manifest_data(manifest_path)
        except DomainError as exc:
            return ValidationResult(
                (Finding(exc.code.value, FindingSeverity.ERROR, str(exc)),)
            )
        manifest_result = validate_manifest_data(data)
        findings.extend(manifest_result.findings)
        if not manifest_result.is_valid:
            return ValidationResult(tuple(findings))
        manifest = parse_manifest_data(data)
        database_path = manifest.database_path.resolve_under(root)
        if not database_path.is_file():
            findings.append(
                Finding(
                    DomainErrorCode.WORKSPACE_NOT_FOUND.value,
                    FindingSeverity.ERROR,
                    "referenced project database was not found",
                    "database.path",
                )
            )
            return ValidationResult(tuple(findings))
        findings.extend(validate_database(database_path, manifest))
        return ValidationResult(tuple(findings))

    @staticmethod
    def _rollback_create(
        root: Path,
        root_existed: bool,
        created_paths: list[Path],
    ) -> None:
        cleanup = [*created_paths]
        for path in created_paths:
            if path.name == _DATABASE_NAME:
                cleanup.extend(
                    (
                        Path(f"{path}-journal"),
                        Path(f"{path}-wal"),
                        Path(f"{path}-shm"),
                    )
                )
        for path in reversed(cleanup):
            with suppress(OSError):
                path.unlink(missing_ok=True)
        if not root_existed:
            with suppress(OSError):
                root.rmdir()
