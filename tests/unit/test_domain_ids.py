from dataclasses import FrozenInstanceError

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import (
    ArtifactId,
    CaseId,
    ProjectId,
    generate_ulid,
)

VALID_ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


@pytest.mark.parametrize(
    ("identifier_type", "display_id"),
    [
        (ProjectId, "PRJ-0001"),
        (CaseId, "CASE-0001"),
        (ArtifactId, "ART-000001"),
    ],
)
def test_ids_accept_canonical_contract_formats(
    identifier_type: type[ProjectId] | type[CaseId] | type[ArtifactId],
    display_id: str,
) -> None:
    identifier = identifier_type(VALID_ULID.lower(), display_id)

    assert identifier.ulid == VALID_ULID
    assert identifier.display_id == display_id


@pytest.mark.parametrize(
    "value",
    [
        "01ARZ3NDEKTSV4RRFFQ69G5FA",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV0",
        "01ARZ3NDEKTSV4RRFFQ69G5FAI",
        "01ARZ3NDEKTSV4RRFFQ69G5FA-",
        "81ARZ3NDEKTSV4RRFFQ69G5FAV",
        f" {VALID_ULID}",
        f"{VALID_ULID} ",
    ],
)
def test_invalid_ulids_are_rejected(value: str) -> None:
    with pytest.raises(DomainError) as error:
        ProjectId(value, "PRJ-0001")

    assert error.value.code is DomainErrorCode.INVALID_ULID


@pytest.mark.parametrize(
    ("identifier_type", "display_id"),
    [
        (ProjectId, "PRJ-001"),
        (ProjectId, "PRJ-0000"),
        (ProjectId, "prj-0001"),
        (CaseId, "CASE-001"),
        (CaseId, "CASE-0001 "),
        (ArtifactId, "ART-00001"),
        (ArtifactId, "CASE-000001"),
    ],
)
def test_invalid_display_ids_are_rejected(
    identifier_type: type[ProjectId] | type[CaseId] | type[ArtifactId],
    display_id: str,
) -> None:
    with pytest.raises(DomainError) as error:
        identifier_type(VALID_ULID, display_id)

    assert error.value.code is DomainErrorCode.INVALID_DISPLAY_ID


def test_identity_is_immutable() -> None:
    identifier = ProjectId(VALID_ULID, "PRJ-0001")

    with pytest.raises(FrozenInstanceError):
        identifier.display_id = "PRJ-0002"  # type: ignore[misc]


def test_generated_ulid_satisfies_existing_identity_contract() -> None:
    generated = generate_ulid()

    assert len(generated) == 26
    assert generated == generated.upper()
    assert ProjectId(generated, "PRJ-0001").ulid == generated
