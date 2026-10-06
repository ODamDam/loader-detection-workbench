from loader_detection_workbench.domain.validation import (
    FindingSeverity,
    ValidationFinding,
    ValidationReport,
    ValidationScope,
)


def test_validator_report_warning_only_is_valid() -> None:
    report = ValidationReport(
        (
            ValidationFinding(
                "STALE_STAGING_CONTENT",
                FindingSeverity.WARNING,
                ValidationScope.FILESYSTEM,
                "ab/.artifact-x.tmp",
                "staging residue remains",
            ),
        )
    )
    assert report.is_valid
