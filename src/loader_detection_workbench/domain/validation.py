"""Shared validation finding and result primitives."""

from dataclasses import dataclass
from enum import StrEnum


class FindingSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


class ValidationScope(StrEnum):
    PROJECT = "project"
    DATABASE = "database"
    CASE = "case"
    ARTIFACT = "artifact"
    FILESYSTEM = "filesystem"


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: FindingSeverity
    message: str
    field: str | None = None


@dataclass(frozen=True, slots=True)
class ValidationResult:
    findings: tuple[Finding, ...]

    @property
    def is_valid(self) -> bool:
        return all(
            finding.severity is not FindingSeverity.ERROR for finding in self.findings
        )


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """Stable, safe finding emitted by the cross-contract validator."""

    code: str
    severity: FindingSeverity
    scope: ValidationScope
    subject: str | None
    message: str


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Deterministic report for a read-only workspace validation run."""

    findings: tuple[ValidationFinding, ...]

    @property
    def is_valid(self) -> bool:
        return all(
            finding.severity is not FindingSeverity.ERROR for finding in self.findings
        )
