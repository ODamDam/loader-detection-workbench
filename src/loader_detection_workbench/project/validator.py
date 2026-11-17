"""Read-only Tier 1/2/3 validation of a Project workspace."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.artifact.sqlite_repository import (
    SQLiteArtifactRepository,
)
from loader_detection_workbench.artifact.store import ArtifactStore, open_content
from loader_detection_workbench.case.sqlite_repository import SQLiteCaseRepository
from loader_detection_workbench.domain.artifact import Artifact, canonical_path
from loader_detection_workbench.domain.case import Case
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.validation import (
    Finding,
    FindingSeverity,
    ValidationFinding,
    ValidationReport,
    ValidationScope,
)
from loader_detection_workbench.evidence.domain import (
    ArtifactProvenance,
    EvidenceType,
)
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.module_validator import (
    validate_ai,
    validate_detection,
    validate_execution,
)
from loader_detection_workbench.project.service import ProjectService, ProjectWorkspace

DATABASE_MISSING = "DATABASE_MISSING"
COUNTER_INVALID = "COUNTER_INVALID"
BROKEN_CASE_REFERENCE = "BROKEN_CASE_REFERENCE"
ARTIFACT_PATH_INVALID = "ARTIFACT_PATH_INVALID"
ARTIFACT_MISSING = "ARTIFACT_MISSING"
ARTIFACT_SIZE_MISMATCH = "ARTIFACT_SIZE_MISMATCH"
ARTIFACT_SHA256_MISMATCH = "ARTIFACT_SHA256_MISMATCH"
ORPHAN_ARTIFACT_CONTENT = "ORPHAN_ARTIFACT_CONTENT"
STALE_STAGING_CONTENT = "STALE_STAGING_CONTENT"

_CASE_COLUMNS = (
    "internal_id, project_id, display_id, kind, status, name, description, "
    "created_at, updated_at, closed_at"
)
_ARTIFACT_COLUMNS = (
    "internal_id, project_id, display_id, case_id, kind, relative_path, "
    "sha256, size_bytes, created_at"
)
_HEX_2 = re.compile(r"[0-9a-f]{2}", re.ASCII)
_HEX_64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_STAGING = re.compile(r"\.artifact-.+\.tmp", re.ASCII)


@dataclass(frozen=True, slots=True)
class _Collected:
    tier: int
    finding: ValidationFinding


def _finding(
    tier: int,
    code: str,
    severity: FindingSeverity,
    scope: ValidationScope,
    subject: str | None,
    message: str,
) -> _Collected:
    return _Collected(tier, ValidationFinding(code, severity, scope, subject, message))


def _from_existing(
    finding: Finding, *, scope: ValidationScope, tier: int = 1
) -> _Collected:
    code = finding.code
    if (
        code == DomainErrorCode.WORKSPACE_NOT_FOUND.value
        and finding.field == "database.path"
    ):
        code = DATABASE_MISSING
    elif (
        code == DomainErrorCode.INVALID_SQLITE_SCHEMA.value
        and finding.field is not None
        and finding.field.startswith("counters")
    ):
        code = COUNTER_INVALID
    return _finding(
        tier,
        code,
        finding.severity,
        scope,
        finding.field,
        finding.message,
    )


def _scope_for_field(field: str | None) -> ValidationScope:
    if field is None:
        return ValidationScope.PROJECT
    if field.startswith("database") or field.startswith("counters"):
        return ValidationScope.DATABASE
    return ValidationScope.PROJECT


def _sorted(findings: Iterable[_Collected]) -> ValidationReport:
    ordered = sorted(
        findings,
        key=lambda item: (
            item.tier,
            item.finding.scope.value,
            item.finding.subject or "",
            item.finding.code,
            item.finding.message,
        ),
    )
    return ValidationReport(tuple(item.finding for item in ordered))


def validate_workspace(root: Path, *, full: bool = False) -> ValidationReport:
    """Validate a workspace without changing its database or filesystem."""
    service = ProjectService()
    baseline = service.validate(root)
    collected = [
        _from_existing(
            finding,
            scope=_scope_for_field(finding.field),
        )
        for finding in baseline.findings
    ]
    if not baseline.is_valid:
        # A manifest, database, schema, or Project identity failure means later
        # tiers cannot be interpreted safely. Preserve all structural findings.
        return _sorted(collected)

    try:
        workspace = service.open(root)
    except DomainError as exc:
        return _sorted(
            [
                *collected,
                _finding(
                    1,
                    exc.code.value,
                    FindingSeverity.ERROR,
                    ValidationScope.PROJECT,
                    None,
                    str(exc),
                ),
            ]
        )

    connection: sqlite3.Connection | None = None
    try:
        connection = connect_database(workspace.database_path, read_only=True)
        cases, case_subjects = _validate_cases(connection, workspace, collected)
        artifacts = _validate_artifacts(
            connection, workspace, cases, case_subjects, collected
        )
        if workspace.sqlite_schema_version >= 2:
            _validate_provenance(connection, artifacts, collected)
        _validate_counters(connection, cases, artifacts, collected)

        def emit(
            tier: int,
            code: str,
            severity: FindingSeverity,
            scope: ValidationScope,
            subject: str | None,
            message: str,
        ) -> None:
            collected.append(_finding(tier, code, severity, scope, subject, message))

        # Module-owned tables (ADR-023, ADR-024, ADR-026); skipped when never
        # installed.
        validate_detection(connection, cases, artifacts, emit)
        validate_execution(connection, cases, artifacts, emit)
        validate_ai(connection, cases, emit)
        if full:
            _validate_content(workspace, artifacts, collected)
    except sqlite3.Error:
        collected.append(
            _finding(
                1,
                DomainErrorCode.INVALID_SQLITE_SCHEMA.value,
                FindingSeverity.ERROR,
                ValidationScope.DATABASE,
                None,
                "project database could not be inspected",
            )
        )
    finally:
        if connection is not None:
            connection.close()
    return _sorted(collected)


def _validate_cases(
    connection: sqlite3.Connection,
    workspace: ProjectWorkspace,
    collected: list[_Collected],
) -> tuple[dict[str, Case], set[str]]:
    repository = SQLiteCaseRepository(workspace, connection=connection)
    cases: dict[str, Case] = {}
    subjects: set[str] = set()
    rows = connection.execute(f"SELECT {_CASE_COLUMNS} FROM cases").fetchall()
    for row in rows:
        display_id = row["display_id"] if isinstance(row["display_id"], str) else None
        subject = display_id
        if isinstance(display_id, str):
            subjects.add(display_id)
        if row["project_id"] != workspace.manifest.project_id.ulid:
            collected.append(
                _finding(
                    2,
                    BROKEN_CASE_REFERENCE,
                    FindingSeverity.ERROR,
                    ValidationScope.CASE,
                    subject,
                    "case references an unexpected Project",
                )
            )
            continue
        try:
            case = repository._deserialize(row)
        except DomainError:
            collected.append(
                _finding(
                    2,
                    DomainErrorCode.INVALID_CASE_RECORD.value,
                    FindingSeverity.ERROR,
                    ValidationScope.CASE,
                    subject,
                    "persisted Case record is invalid",
                )
            )
            continue
        cases[case.case_id.ulid] = case
    repository.close()
    return cases, subjects


def _validate_artifacts(
    connection: sqlite3.Connection,
    workspace: ProjectWorkspace,
    cases: dict[str, Case],
    case_subjects: set[str],
    collected: list[_Collected],
) -> list[Artifact]:
    repository = SQLiteArtifactRepository(workspace, write=False, connection=connection)
    artifacts: list[Artifact] = []
    rows = connection.execute(f"SELECT {_ARTIFACT_COLUMNS} FROM artifacts").fetchall()
    for row in rows:
        display_id = row["display_id"] if isinstance(row["display_id"], str) else None
        subject = display_id
        if row["project_id"] != workspace.manifest.project_id.ulid:
            collected.append(
                _finding(
                    2,
                    BROKEN_CASE_REFERENCE,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    subject,
                    "artifact references an unexpected Project",
                )
            )
            continue
        case_id = row["case_id"]
        if case_id is not None and case_id not in cases:
            collected.append(
                _finding(
                    2,
                    BROKEN_CASE_REFERENCE,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    subject,
                    "artifact references a missing Case",
                )
            )
            continue
        raw_hash = row["sha256"]
        raw_path = row["relative_path"]
        parsed_path: ProjectRelativePath | None = None
        if isinstance(raw_path, str):
            try:
                parsed_path = ProjectRelativePath.parse(raw_path)
            except DomainError as exc:
                collected.append(
                    _finding(
                        2,
                        exc.code.value,
                        FindingSeverity.ERROR,
                        ValidationScope.ARTIFACT,
                        subject,
                        "artifact relative path is invalid",
                    )
                )
                continue
            if parsed_path.as_posix() != raw_path:
                collected.append(
                    _finding(
                        2,
                        DomainErrorCode.INVALID_RELATIVE_PATH.value,
                        FindingSeverity.ERROR,
                        ValidationScope.ARTIFACT,
                        subject,
                        "artifact relative path is not canonical POSIX form",
                    )
                )
                continue
        if isinstance(raw_hash, str) and isinstance(raw_path, str):
            try:
                expected_path = canonical_path(raw_hash).as_posix()
            except DomainError:
                expected_path = None
            if expected_path is not None and raw_path != expected_path:
                collected.append(
                    _finding(
                        2,
                        ARTIFACT_PATH_INVALID,
                        FindingSeverity.ERROR,
                        ValidationScope.ARTIFACT,
                        subject,
                        "artifact relative path does not match its SHA-256",
                    )
                )
                continue
        try:
            artifact = repository._deserialize(row)
        except DomainError:
            collected.append(
                _finding(
                    2,
                    DomainErrorCode.INVALID_ARTIFACT_RECORD.value,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    subject,
                    "persisted Artifact record is invalid",
                )
            )
            continue
        artifacts.append(artifact)
    repository.close()
    return artifacts


def _validate_provenance(
    connection: sqlite3.Connection,
    artifacts: list[Artifact],
    collected: list[_Collected],
) -> None:
    by_internal_id = {artifact.artifact_id.ulid: artifact for artifact in artifacts}
    rows = connection.execute(
        "SELECT artifact_id, original_filename, source, description, evidence_type "
        "FROM artifact_provenance"
    ).fetchall()
    for row in rows:
        artifact_id = row["artifact_id"]
        artifact = (
            by_internal_id.get(artifact_id) if isinstance(artifact_id, str) else None
        )
        subject = None if artifact is None else artifact.artifact_id.display_id
        try:
            if artifact is None:
                raise DomainError(
                    DomainErrorCode.INVALID_ARTIFACT_PROVENANCE,
                    "provenance references an invalid Artifact",
                )
            provenance = ArtifactProvenance(
                artifact_id,
                row["original_filename"],
                row["source"],
                row["description"],
                EvidenceType.parse(row["evidence_type"]),
            )
            if provenance.artifact_id != artifact.artifact_id.ulid:
                raise DomainError(
                    DomainErrorCode.INVALID_ARTIFACT_PROVENANCE,
                    "provenance and Artifact identities differ",
                )
            if artifact.kind.value != "evidence":
                raise DomainError(
                    DomainErrorCode.INVALID_ARTIFACT_PROVENANCE,
                    "provenance requires ArtifactKind.EVIDENCE",
                )
        except (DomainError, TypeError, ValueError):
            collected.append(
                _finding(
                    2,
                    DomainErrorCode.INVALID_ARTIFACT_PROVENANCE.value,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    subject,
                    "persisted manual evidence provenance is invalid",
                )
            )


def _validate_counters(
    connection: sqlite3.Connection,
    cases: dict[str, Case],
    artifacts: list[Artifact],
    collected: list[_Collected],
) -> None:
    rows = {
        str(row["name"]): row["next_value"]
        for row in connection.execute("SELECT name, next_value FROM counters")
    }
    sequences = {
        "case": [int(case.case_id.display_id[5:]) for case in cases.values()],
        "artifact": [
            int(artifact.artifact_id.display_id[4:]) for artifact in artifacts
        ],
    }
    for name, values in sequences.items():
        value = rows.get(name)
        if type(value) is not int or value < 1:
            collected.append(
                _finding(
                    2,
                    COUNTER_INVALID,
                    FindingSeverity.ERROR,
                    ValidationScope.DATABASE,
                    name,
                    "counter is missing or below its minimum value",
                )
            )
        elif values and value <= max(values):
            collected.append(
                _finding(
                    2,
                    COUNTER_INVALID,
                    FindingSeverity.ERROR,
                    ValidationScope.DATABASE,
                    name,
                    "counter is behind a persisted display sequence",
                )
            )


def _validate_content(
    workspace: ProjectWorkspace,
    artifacts: list[Artifact],
    collected: list[_Collected],
) -> None:
    store = ArtifactStore(workspace.root)
    cache: dict[str, tuple[int, str]] = {}
    referenced: set[Path] = set()
    for artifact in artifacts:
        try:
            path = store.resolve(artifact.relative_path)
        except DomainError as exc:
            collected.append(
                _finding(
                    3,
                    exc.code.value,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    artifact.artifact_id.display_id,
                    "artifact path is outside the workspace or traverses a link",
                )
            )
            continue
        referenced.add(path)
        if not path.exists():
            collected.append(
                _finding(
                    3,
                    ARTIFACT_MISSING,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    artifact.artifact_id.display_id,
                    "canonical artifact content is missing",
                )
            )
            continue
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise OSError("not a regular file")
            if artifact.sha256 in cache:
                size, digest = cache[artifact.sha256]
            else:
                with open_content(path) as stream:
                    digest_obj = hashlib.sha256()
                    size = 0
                    while chunk := stream.read(1024 * 1024):
                        digest_obj.update(chunk)
                        size += len(chunk)
                    digest = digest_obj.hexdigest()
                cache[artifact.sha256] = (size, digest)
        except OSError:
            collected.append(
                _finding(
                    3,
                    ARTIFACT_MISSING,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    artifact.artifact_id.display_id,
                    "canonical artifact content is not a regular readable file",
                )
            )
            continue
        if size != artifact.size_bytes:
            collected.append(
                _finding(
                    3,
                    ARTIFACT_SIZE_MISMATCH,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    artifact.artifact_id.display_id,
                    "canonical artifact size does not match metadata",
                )
            )
        if digest != artifact.sha256:
            collected.append(
                _finding(
                    3,
                    ARTIFACT_SHA256_MISMATCH,
                    FindingSeverity.ERROR,
                    ValidationScope.ARTIFACT,
                    artifact.artifact_id.display_id,
                    "canonical artifact SHA-256 does not match metadata",
                )
            )
    _scan_residue(workspace.root, referenced, collected)


def _scan_residue(
    root: Path, referenced: set[Path], collected: list[_Collected]
) -> None:
    content_root = root / "artifacts" / "sha256"
    if not content_root.is_dir():
        return
    for shard in sorted(content_root.iterdir(), key=lambda path: path.name):
        if not shard.is_dir() or _HEX_2.fullmatch(shard.name) is None:
            continue
        for entry in sorted(shard.iterdir(), key=lambda path: path.name):
            if _STAGING.fullmatch(entry.name):
                collected.append(
                    _finding(
                        3,
                        STALE_STAGING_CONTENT,
                        FindingSeverity.WARNING,
                        ValidationScope.FILESYSTEM,
                        f"{shard.name}/{entry.name}",
                        "artifact staging residue remains",
                    )
                )
            elif _HEX_64.fullmatch(entry.name) and entry not in referenced:
                collected.append(
                    _finding(
                        3,
                        ORPHAN_ARTIFACT_CONTENT,
                        FindingSeverity.WARNING,
                        ValidationScope.FILESYSTEM,
                        f"{shard.name}/{entry.name}",
                        "canonical-looking content is not referenced by metadata",
                    )
                )
