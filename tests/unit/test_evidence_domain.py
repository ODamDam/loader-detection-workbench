from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.evidence.domain import (
    MANUAL_EVIDENCE_EXTENSIONS,
    ArtifactProvenance,
    EvidenceType,
    validate_description,
    validate_original_filename,
    validate_source,
)

ARTIFACT_ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


def test_provenance_accepts_complete_metadata() -> None:
    value = ArtifactProvenance(
        ARTIFACT_ULID,
        "events.json",
        "analyst workstation export",
        "Sanitized export",
        EvidenceType.EVENT_EXPORT,
    )
    assert value.original_filename == "events.json"
    assert value.evidence_type is EvidenceType.EVENT_EXPORT


@pytest.mark.parametrize("value", ["", ".", "..", "a/b.txt", "a\\b.txt", "x. "])
def test_original_filename_rejects_unsafe_or_empty_values(value: str) -> None:
    with pytest.raises(DomainError) as caught:
        validate_original_filename(value)
    assert caught.value.code is DomainErrorCode.INVALID_ARTIFACT_PROVENANCE


@pytest.mark.parametrize("value", ["", "   ", "x" * 513])
def test_source_rejects_empty_or_oversized_values(value: str) -> None:
    with pytest.raises(DomainError) as caught:
        validate_source(value)
    assert caught.value.code is DomainErrorCode.INVALID_ARTIFACT_PROVENANCE


@pytest.mark.parametrize("value", ["", "x" * 2001])
def test_description_rejects_empty_or_oversized_values(value: str) -> None:
    with pytest.raises(DomainError) as caught:
        validate_description(value)
    assert caught.value.code is DomainErrorCode.INVALID_ARTIFACT_PROVENANCE


def test_evidence_type_has_stable_values() -> None:
    assert {item.value for item in EvidenceType} == {
        "analyst_note",
        "event_export",
        "configuration",
        "tool_output",
        "indicator_list",
        "other",
    }
    assert all(
        Path(f"file{suffix}").suffix in MANUAL_EVIDENCE_EXTENSIONS
        for suffix in MANUAL_EVIDENCE_EXTENSIONS
    )
