"""Strict project.json v1 parsing and deterministic serialization."""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from loader_detection_workbench.contracts import PROJECT_JSON_SCHEMA_VERSION
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ProjectId
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.time import format_utc, parse_utc
from loader_detection_workbench.domain.validation import (
    Finding,
    FindingSeverity,
    ValidationResult,
)

_TOP_LEVEL_KEYS = {"schema_version", "project", "created_at", "database"}
_PROJECT_KEYS = {"internal_id", "display_id", "name"}
_DATABASE_KEYS = {"path"}


@dataclass(frozen=True, slots=True)
class ProjectManifest:
    schema_version: str
    project_id: ProjectId
    name: str
    created_at: datetime
    database_path: ProjectRelativePath

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "project": {
                "internal_id": self.project_id.ulid,
                "display_id": self.project_id.display_id,
                "name": self.name,
            },
            "created_at": format_utc(self.created_at),
            "database": {"path": self.database_path.as_posix()},
        }


def _finding(code: DomainErrorCode, message: str, field: str | None = None) -> Finding:
    return Finding(code.value, FindingSeverity.ERROR, message, field)


def validate_manifest_data(data: object) -> ValidationResult:
    findings: list[Finding] = []
    if not isinstance(data, dict):
        return ValidationResult(
            (
                _finding(
                    DomainErrorCode.INVALID_PROJECT_MANIFEST,
                    "manifest must be an object",
                ),
            )
        )

    if set(data) != _TOP_LEVEL_KEYS:
        findings.append(
            _finding(
                DomainErrorCode.INVALID_PROJECT_MANIFEST,
                "manifest top-level fields do not match schema v1",
            )
        )

    schema_version = data.get("schema_version")
    if not isinstance(schema_version, str):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_PROJECT_MANIFEST,
                "schema_version must be a string",
                "schema_version",
            )
        )
    elif schema_version != PROJECT_JSON_SCHEMA_VERSION:
        findings.append(
            _finding(
                DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
                "unsupported project manifest schema version",
                "schema_version",
            )
        )

    project = data.get("project")
    if not isinstance(project, dict):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_PROJECT_MANIFEST,
                "project must be an object",
                "project",
            )
        )
    else:
        if set(project) != _PROJECT_KEYS:
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_PROJECT_MANIFEST,
                    "project fields do not match schema v1",
                    "project",
                )
            )
        internal_id = project.get("internal_id")
        display_id = project.get("display_id")
        if not isinstance(internal_id, str):
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_ULID,
                    "internal_id must be a string",
                    "project.internal_id",
                )
            )
        elif internal_id != internal_id.upper():
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_ULID,
                    "persisted ULID must be canonical uppercase",
                    "project.internal_id",
                )
            )
        if not isinstance(display_id, str):
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_DISPLAY_ID,
                    "display_id must be a string",
                    "project.display_id",
                )
            )
        if isinstance(internal_id, str) and isinstance(display_id, str):
            try:
                ProjectId(internal_id, display_id)
            except DomainError as exc:
                if not any(item.code == exc.code.value for item in findings):
                    findings.append(_finding(exc.code, str(exc), "project"))
            if display_id != "PRJ-0001" and not any(
                item.code == DomainErrorCode.INVALID_DISPLAY_ID.value
                for item in findings
            ):
                findings.append(
                    _finding(
                        DomainErrorCode.INVALID_DISPLAY_ID,
                        "display_id must be PRJ-0001",
                        "project.display_id",
                    )
                )
        name = project.get("name")
        if not isinstance(name, str) or not name.strip():
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_PROJECT_MANIFEST,
                    "project name must be a non-empty string",
                    "project.name",
                )
            )

    created_at = data.get("created_at")
    if not isinstance(created_at, str):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_TIMESTAMP,
                "created_at must be a string",
                "created_at",
            )
        )
    else:
        try:
            parse_utc(created_at)
        except DomainError as exc:
            findings.append(_finding(exc.code, str(exc), "created_at"))

    database = data.get("database")
    if not isinstance(database, dict):
        findings.append(
            _finding(
                DomainErrorCode.INVALID_PROJECT_MANIFEST,
                "database must be an object",
                "database",
            )
        )
    else:
        if set(database) != _DATABASE_KEYS:
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_PROJECT_MANIFEST,
                    "database fields do not match schema v1",
                    "database",
                )
            )
        database_path = database.get("path")
        if not isinstance(database_path, str):
            findings.append(
                _finding(
                    DomainErrorCode.INVALID_RELATIVE_PATH,
                    "database.path must be a string",
                    "database.path",
                )
            )
        else:
            try:
                parsed_path = ProjectRelativePath.parse(database_path)
                if parsed_path.as_posix() != database_path:
                    findings.append(
                        _finding(
                            DomainErrorCode.INVALID_RELATIVE_PATH,
                            "database.path must be canonical POSIX form",
                            "database.path",
                        )
                    )
            except DomainError as exc:
                findings.append(_finding(exc.code, str(exc), "database.path"))

    return ValidationResult(tuple(findings))


def parse_manifest_data(data: object) -> ProjectManifest:
    result = validate_manifest_data(data)
    if not result.is_valid:
        first = result.findings[0]
        raise DomainError(DomainErrorCode(first.code), first.message)
    typed = data
    assert isinstance(typed, dict)
    project = typed["project"]
    database = typed["database"]
    assert isinstance(project, dict) and isinstance(database, dict)
    return ProjectManifest(
        schema_version=typed["schema_version"],
        project_id=ProjectId(project["internal_id"], project["display_id"]),
        name=project["name"],
        created_at=parse_utc(typed["created_at"]),
        database_path=ProjectRelativePath.parse(database["path"]),
    )


def read_manifest_data(path: Path) -> object:
    try:
        with path.open("r", encoding="utf-8") as stream:
            data: Any = json.load(stream)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DomainError(
            DomainErrorCode.INVALID_PROJECT_MANIFEST,
            "project.json is not valid UTF-8 JSON",
        ) from exc
    return data


def load_manifest(path: Path) -> ProjectManifest:
    return parse_manifest_data(read_manifest_data(path))


def write_manifest(path: Path, manifest: ProjectManifest) -> None:
    serialized = json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2)
    created = False
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(f"{serialized}\n")
    except Exception:
        if created:
            with suppress(OSError):
                path.unlink()
        raise
