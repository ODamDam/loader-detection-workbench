from dataclasses import FrozenInstanceError

import pytest

from loader_detection_workbench.contracts import (
    CASE_BUNDLE_SCHEMA_VERSION,
    PROJECT_JSON_SCHEMA_VERSION,
    SQLITE_SCHEMA_VERSION,
    SUPPORTED_SQLITE_SCHEMA_VERSIONS,
)
from loader_detection_workbench.domain.errors import (
    DomainError,
    DomainErrorCategory,
    DomainErrorCode,
)
from loader_detection_workbench.domain.validation import (
    Finding,
    FindingSeverity,
    ValidationResult,
)


def test_warning_only_validation_result_is_valid_and_ordered() -> None:
    first = Finding("FIRST", FindingSeverity.WARNING, "first warning")
    second = Finding("SECOND", FindingSeverity.WARNING, "second warning", "field")
    result = ValidationResult((first, second))

    assert result.is_valid
    assert result.findings == (first, second)


def test_error_finding_makes_validation_result_invalid() -> None:
    result = ValidationResult(
        (Finding("BROKEN", FindingSeverity.ERROR, "validation failed"),)
    )

    assert not result.is_valid


def test_findings_and_results_are_immutable() -> None:
    finding = Finding("CODE", FindingSeverity.WARNING, "message")
    result = ValidationResult((finding,))

    with pytest.raises(FrozenInstanceError):
        finding.code = "OTHER"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.findings = ()  # type: ignore[misc]


@pytest.mark.parametrize(
    ("code", "category"),
    [
        (DomainErrorCode.INVALID_ULID, DomainErrorCategory.IDENTITY),
        (DomainErrorCode.INVALID_DISPLAY_ID, DomainErrorCategory.IDENTITY),
        (DomainErrorCode.INVALID_CASE_STATUS, DomainErrorCategory.STATE),
        (DomainErrorCode.INVALID_CASE_TRANSITION, DomainErrorCategory.STATE),
        (DomainErrorCode.INVALID_TIMESTAMP, DomainErrorCategory.VALIDATION),
        (DomainErrorCode.INVALID_RELATIVE_PATH, DomainErrorCategory.PATH),
        (DomainErrorCode.PATH_ESCAPE, DomainErrorCategory.PATH),
        (
            DomainErrorCode.UNSUPPORTED_CONTRACT_VERSION,
            DomainErrorCategory.CONTRACT,
        ),
        (
            DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH,
            DomainErrorCategory.WORKSPACE,
        ),
        (DomainErrorCode.WORKSPACE_NOT_FOUND, DomainErrorCategory.WORKSPACE),
        (DomainErrorCode.WORKSPACE_ALREADY_EXISTS, DomainErrorCategory.WORKSPACE),
        (
            DomainErrorCode.INVALID_PROJECT_MANIFEST,
            DomainErrorCategory.VALIDATION,
        ),
        (DomainErrorCode.INVALID_SQLITE_SCHEMA, DomainErrorCategory.CONTRACT),
    ],
)
def test_domain_error_preserves_stable_identity(
    code: DomainErrorCode, category: DomainErrorCategory
) -> None:
    error = DomainError(code, "presentation text")

    assert error.code is code
    assert error.category is category
    assert str(error) == "presentation text"


def test_contract_version_constants_match_current_contracts() -> None:
    assert PROJECT_JSON_SCHEMA_VERSION == "1"
    assert SQLITE_SCHEMA_VERSION == 2
    assert SUPPORTED_SQLITE_SCHEMA_VERSIONS == (1, 2)
    assert CASE_BUNDLE_SCHEMA_VERSION == "1"
