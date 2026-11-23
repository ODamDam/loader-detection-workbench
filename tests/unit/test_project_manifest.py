from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from loader_detection_workbench.domain.errors import DomainErrorCode
from loader_detection_workbench.domain.ids import ProjectId
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.project.manifest import (
    ProjectManifest,
    parse_manifest_data,
    validate_manifest_data,
)

ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def valid_data() -> dict[str, Any]:
    return {
        "schema_version": "1",
        "project": {
            "internal_id": ULID,
            "display_id": "PRJ-0001",
            "name": "Review Project",
        },
        "created_at": "2026-09-03T12:30:45Z",
        "database": {"path": "project.db"},
    }


def codes(data: object) -> list[str]:
    return [finding.code for finding in validate_manifest_data(data).findings]


def test_valid_manifest_round_trip() -> None:
    manifest = ProjectManifest(
        "1",
        ProjectId(ULID, "PRJ-0001"),
        "Review Project",
        datetime(2026, 9, 3, 12, 30, 45, tzinfo=UTC),
        ProjectRelativePath.parse("project.db"),
    )

    assert parse_manifest_data(manifest.to_dict()) == manifest


def test_integer_schema_version_is_rejected() -> None:
    data = valid_data()
    data["schema_version"] = 1

    assert codes(data) == [DomainErrorCode.INVALID_PROJECT_MANIFEST.value]


def test_unsupported_schema_version_is_rejected() -> None:
    data = valid_data()
    data["schema_version"] = "2"

    assert codes(data) == [DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION.value]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.__setitem__("unknown", True),
        lambda data: data["project"].__setitem__("unknown", True),
        lambda data: data["database"].__setitem__("unknown", True),
    ],
)
def test_unknown_fields_are_rejected(mutation: Any) -> None:
    data = deepcopy(valid_data())
    mutation(data)

    assert DomainErrorCode.INVALID_PROJECT_MANIFEST.value in codes(data)


def test_lowercase_persisted_ulid_is_rejected() -> None:
    data = valid_data()
    data["project"]["internal_id"] = ULID.lower()

    assert DomainErrorCode.INVALID_ULID.value in codes(data)


@pytest.mark.parametrize("name", ["", "   ", 1, None])
def test_invalid_project_name_is_rejected(name: object) -> None:
    data = valid_data()
    data["project"]["name"] = name

    assert DomainErrorCode.INVALID_PROJECT_MANIFEST.value in codes(data)


def test_invalid_timestamp_is_rejected() -> None:
    data = valid_data()
    data["created_at"] = "2026-09-03T12:30:45+00:00"

    assert codes(data) == [DomainErrorCode.INVALID_TIMESTAMP.value]


@pytest.mark.parametrize(
    "path",
    [
        "/project.db",
        r"C:\workspace\project.db",
        r"\\server\share\project.db",
        "../project.db",
        r"nested\project.db",
    ],
)
def test_unsafe_or_noncanonical_database_path_is_rejected(path: str) -> None:
    data = valid_data()
    data["database"]["path"] = path

    assert not validate_manifest_data(data).is_valid
