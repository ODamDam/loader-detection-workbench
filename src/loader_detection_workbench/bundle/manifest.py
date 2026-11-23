"""Strict Bundle v1 manifest parsing and deterministic serialization."""

from __future__ import annotations

from typing import Any

from loader_detection_workbench.bundle.domain import ARTIFACT_SENSITIVITY, Sensitivity
from loader_detection_workbench.contracts import CASE_BUNDLE_SCHEMA_VERSION
from loader_detection_workbench.domain.artifact import ArtifactKind, canonical_path
from loader_detection_workbench.domain.case import CaseKind, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, CaseId, ProjectId
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.time import parse_utc

_ROOT = {
    "schema_version",
    "bundle_kind",
    "classification",
    "source_project",
    "case",
    "artifacts",
    "contents",
}
_PROJECT = {"internal_id", "display_id", "name", "created_at"}
_CASE = {
    "internal_id",
    "display_id",
    "project_id",
    "kind",
    "status",
    "name",
    "description",
    "created_at",
    "updated_at",
    "closed_at",
}
_ARTIFACT = {
    "internal_id",
    "display_id",
    "project_id",
    "case_id",
    "kind",
    "relative_path",
    "sha256",
    "size_bytes",
    "created_at",
    "sensitivity",
}
_CONTENT = {"relative_path", "sha256", "size_bytes"}


def _bad(message: str) -> DomainError:
    return DomainError(DomainErrorCode.INVALID_BUNDLE_MANIFEST, message)


def _object(value: object, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _bad(f"{name} has an invalid shape")
    return value


def validate_manifest(data: object) -> dict[str, Any]:
    root = _object(data, _ROOT, "manifest")
    if (
        root["schema_version"] != CASE_BUNDLE_SCHEMA_VERSION
        or root["bundle_kind"] != "case"
    ):
        raise DomainError(
            DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION, "unsupported Bundle contract"
        )
    if not isinstance(root["classification"], str) or root["classification"] not in {
        x.value for x in Sensitivity
    }:
        raise _bad("classification is invalid")
    project = _object(root["source_project"], _PROJECT, "source_project")
    if not all(isinstance(project[key], str) for key in _PROJECT):
        raise _bad("source_project fields are invalid")
    ProjectId(project["internal_id"], project["display_id"])
    parse_utc(project["created_at"])
    case = _object(root["case"], _CASE, "case")
    if (
        not isinstance(case["internal_id"], str)
        or not isinstance(case["display_id"], str)
        or not isinstance(case["project_id"], str)
    ):
        raise _bad("case identity fields are invalid")
    CaseId(case["internal_id"], case["display_id"])
    ProjectId(case["project_id"], "PRJ-0001")
    if case["project_id"] != project["internal_id"]:
        raise _bad("case does not belong to source Project")
    if not isinstance(case["kind"], str) or not isinstance(case["status"], str):
        raise _bad("case kind or status is invalid")
    if case["kind"] not in {x.value for x in CaseKind} or case["status"] not in {
        x.value for x in CaseStatus
    }:
        raise _bad("case kind or status is invalid")
    if not isinstance(case["name"], str) or not case["name"].strip():
        raise _bad("case name is invalid")
    if case["description"] is not None and not isinstance(case["description"], str):
        raise _bad("case description is invalid")
    for key in ("created_at", "updated_at"):
        parse_utc(case[key])
    if case["closed_at"] is not None:
        parse_utc(case["closed_at"])
    if (case["status"] == "closed") != (case["closed_at"] is not None):
        raise _bad("case lifecycle is inconsistent")
    artifacts = root["artifacts"]
    contents = root["contents"]
    if not isinstance(artifacts, list) or not isinstance(contents, list):
        raise _bad("artifacts and contents must be arrays")
    seen_art: set[str] = set()
    seen_art_display: set[str] = set()
    seen_content: set[str] = set()
    for item in artifacts:
        artifact = _object(item, _ARTIFACT, "artifact")
        if not isinstance(artifact["internal_id"], str) or not isinstance(
            artifact["display_id"], str
        ):
            raise _bad("artifact identity fields are invalid")
        if not all(
            isinstance(artifact[key], str)
            for key in (
                "project_id",
                "case_id",
                "kind",
                "relative_path",
                "sha256",
                "created_at",
            )
        ):
            raise _bad("artifact fields are invalid")
        aid = ArtifactId(artifact["internal_id"], artifact["display_id"])
        del aid
        if (
            artifact["project_id"] != case["project_id"]
            or artifact["case_id"] != case["internal_id"]
        ):
            raise _bad("artifact source relationship is invalid")
        ArtifactKind.parse(artifact["kind"])
        if artifact["sensitivity"] != ARTIFACT_SENSITIVITY[artifact["kind"]].value:
            raise DomainError(
                DomainErrorCode.BUNDLE_CLASSIFICATION_MISMATCH,
                "artifact sensitivity is inconsistent",
            )
        parse_utc(artifact["created_at"])
        path = ProjectRelativePath.parse(artifact["relative_path"])
        if path.as_posix() != artifact["relative_path"] or path != canonical_path(
            artifact["sha256"]
        ):
            raise _bad("artifact canonical path is invalid")
        if type(artifact["size_bytes"]) is not int or artifact["size_bytes"] < 0:
            raise _bad("artifact size is invalid")
        if artifact["internal_id"] in seen_art:
            raise _bad("duplicate Artifact identity")
        if artifact["display_id"] in seen_art_display:
            raise _bad("duplicate Artifact display ID")
        seen_art.add(artifact["internal_id"])
        seen_art_display.add(artifact["display_id"])
    for item in contents:
        content = _object(item, _CONTENT, "content")
        if not isinstance(content["sha256"], str) or not isinstance(
            content["relative_path"], str
        ):
            raise _bad("content identity fields are invalid")
        path = ProjectRelativePath.parse(content["relative_path"])
        if path.as_posix() != content["relative_path"] or path != canonical_path(
            content["sha256"]
        ):
            raise _bad("content canonical path is invalid")
        if type(content["size_bytes"]) is not int or content["size_bytes"] < 0:
            raise _bad("content size is invalid")
        if content["sha256"] in seen_content:
            raise _bad("duplicate content identity")
        seen_content.add(content["sha256"])
    by_hash = {item["sha256"]: item for item in contents}
    for artifact in artifacts:
        matching_content = by_hash.get(artifact["sha256"])
        if (
            matching_content is None
            or matching_content["relative_path"] != artifact["relative_path"]
            or matching_content["size_bytes"] != artifact["size_bytes"]
        ):
            raise DomainError(
                DomainErrorCode.MISSING_BUNDLE_CONTENT,
                "Artifact content reference is missing or inconsistent",
            )
    expected = max(
        [
            Sensitivity.INTERNAL,
            *(Sensitivity(item["sensitivity"]) for item in artifacts),
        ],
        key=lambda x: x.rank,
    ).value
    if root["classification"] != expected:
        raise DomainError(
            DomainErrorCode.BUNDLE_CLASSIFICATION_MISMATCH,
            "Bundle classification is inconsistent",
        )
    return root
