"""Bundle classification and stable validation reporting."""

from dataclasses import dataclass
from enum import StrEnum

from loader_detection_workbench.domain.validation import (
    FindingSeverity,
    ValidationFinding,
    ValidationReport,
    ValidationScope,
)


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return {self.PUBLIC: 0, self.INTERNAL: 1, self.RESTRICTED: 2}[self]


ARTIFACT_SENSITIVITY = {
    "sample": Sensitivity.RESTRICTED,
    "sysmon": Sensitivity.RESTRICTED,
    "procmon": Sensitivity.RESTRICTED,
    "network": Sensitivity.RESTRICTED,
    "evidence": Sensitivity.RESTRICTED,
    "static": Sensitivity.INTERNAL,
    "normalized": Sensitivity.INTERNAL,
    "rule": Sensitivity.INTERNAL,
    "report": Sensitivity.INTERNAL,
    "other": Sensitivity.INTERNAL,
}


@dataclass(frozen=True, slots=True)
class BundleReport:
    findings: tuple[ValidationFinding, ...]

    @property
    def is_valid(self) -> bool:
        return all(item.severity is not FindingSeverity.ERROR for item in self.findings)

    def as_validation_report(self) -> ValidationReport:
        return ValidationReport(self.findings)


def finding(code: str, message: str, subject: str | None = None) -> ValidationFinding:
    return ValidationFinding(
        code, FindingSeverity.ERROR, ValidationScope.ARTIFACT, subject, message
    )
