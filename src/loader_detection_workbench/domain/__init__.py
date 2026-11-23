"""Pure domain primitives shared by workbench application services."""

from loader_detection_workbench.domain.case import CaseLifecycle, CaseStatus
from loader_detection_workbench.domain.errors import (
    DomainError,
    DomainErrorCategory,
    DomainErrorCode,
)
from loader_detection_workbench.domain.ids import (
    ArtifactId,
    CaseId,
    ProjectId,
    generate_ulid,
)
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.domain.time import (
    format_utc,
    parse_utc,
    require_utc,
    utc_now,
)
from loader_detection_workbench.domain.validation import (
    Finding,
    FindingSeverity,
    ValidationResult,
)

__all__ = [
    "ArtifactId",
    "CaseId",
    "CaseLifecycle",
    "CaseStatus",
    "DomainError",
    "DomainErrorCategory",
    "DomainErrorCode",
    "Finding",
    "FindingSeverity",
    "ProjectId",
    "ProjectRelativePath",
    "ValidationResult",
    "format_utc",
    "parse_utc",
    "require_utc",
    "utc_now",
    "generate_ulid",
]
