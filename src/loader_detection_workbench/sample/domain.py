"""Pure domain model and contract rules for candidate samples."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from random import Random


class SampleError(Exception):
    """Safe, user-facing sample workflow error."""


class ContractViolation(SampleError):
    """A requested state transition violates the workflow contract."""


class NotFoundError(SampleError):
    """A candidate sample does not exist."""


class DuplicateSampleError(SampleError):
    """A candidate with the same binary identity already exists."""


class ManifestStatus(StrEnum):
    CANDIDATE = "candidate"
    ELIGIBLE = "eligible"
    EXCLUDED = "excluded"
    FROZEN = "frozen"


class EligibilityStatus(StrEnum):
    PENDING = "pending"
    ELIGIBLE = "eligible"
    EXCLUDED = "excluded"


class CriterionStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_CHECKED = "not_checked"


class DuplicateStatus(StrEnum):
    UNIQUE = "unique"
    DUPLICATE = "duplicate"
    UNRESOLVED = "unresolved"


class DatasetRole(StrEnum):
    UNASSIGNED = "unassigned"
    MALWARE_DEV = "malware_dev"
    MALWARE_EVAL = "malware_eval"


class AssignmentReason(StrEnum):
    CONSTRAINED_RANDOM_SPLIT = "constrained_random_split"
    MANUAL_BALANCE_ADJUSTMENT = "manual_balance_adjustment"
    REPLACEMENT_BEFORE_FREEZE = "replacement_before_freeze"
    OTHER = "other"


class ExposureState(StrEnum):
    METADATA_ONLY = "metadata_only"
    BEHAVIOR_EXPOSED = "behavior_exposed"
    EVALUATION_EXPOSED = "evaluation_exposed"


class EvaluationIntegrity(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    VALID_UNSEEN = "valid_unseen"
    CONTAMINATED = "contaminated"
    UNKNOWN = "unknown"


class ExclusionReason(StrEnum):
    SCREENING_FAILED = "screening_failed"
    DUPLICATE = "duplicate"
    INVALID_BINARY = "invalid_binary"
    INSUFFICIENT_PROVENANCE = "insufficient_provenance"
    UNSUPPORTED_ANALYSIS = "unsupported_analysis"
    OTHER = "other"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ReportedRole(StrEnum):
    LOADER = "loader"
    DOWNLOADER = "downloader"
    LOADER_DOWNLOADER = "loader_downloader"
    OTHER = "other"
    UNKNOWN = "unknown"


SCREENING_FIELDS = (
    "real_world",
    "windows_target",
    "loader_downloader",
    "provenance",
    "binary_valid",
    "supported_analysis",
    "duplicate_clear",
)


def utc_now() -> str:
    """Return a canonical, second-precision UTC timestamp."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CandidateSample:
    sample_id: str
    sha256: str
    source: str
    source_reference: str
    created_at: str
    source_record_id: str | None = None
    reported_role: ReportedRole = ReportedRole.UNKNOWN
    role_label_source: str | None = None
    role_label_confidence: Confidence = Confidence.UNKNOWN
    reported_family: str | None = None
    family_label_source: str | None = None
    family_label_confidence: Confidence = Confidence.UNKNOWN
    manifest_status: ManifestStatus = ManifestStatus.CANDIDATE
    eligibility_status: EligibilityStatus = EligibilityStatus.PENDING
    duplicate_status: DuplicateStatus = DuplicateStatus.UNIQUE
    screening: dict[str, CriterionStatus] = field(
        default_factory=lambda: {
            key: CriterionStatus.NOT_CHECKED for key in SCREENING_FIELDS
        }
    )
    assigned_dataset_role: DatasetRole = DatasetRole.UNASSIGNED
    assignment_reason: AssignmentReason | None = None
    assignment_detail: str | None = None
    assigned_at: str | None = None
    split_id: str | None = None
    split_seed: int | None = None
    exclusion_reason: ExclusionReason | None = None
    exclusion_detail: str | None = None
    exposure_state: ExposureState = ExposureState.METADATA_ONLY
    detailed_behavior_inspected: bool = False
    first_detailed_access_at: str | None = None
    first_execution_at: str | None = None
    first_validation_at: str | None = None
    benchmark_id: str | None = None
    benchmark_version: int | None = None
    benchmark_frozen_at: str | None = None

    def __post_init__(self) -> None:
        if not self.sample_id.startswith("SMP-") or not self.sample_id[4:].isdigit():
            raise ValueError("sample_id must use SMP-000001 format")
        if len(self.sha256) != 64 or any(
            c not in "0123456789abcdef" for c in self.sha256
        ):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        if set(self.screening) != set(SCREENING_FIELDS):
            raise ValueError("all seven screening criteria are required")

    @property
    def evaluation_integrity(self) -> EvaluationIntegrity:
        """Derive eval integrity; no stored boolean is authoritative."""
        if self.assigned_dataset_role is not DatasetRole.MALWARE_EVAL:
            return EvaluationIntegrity.NOT_APPLICABLE
        if self.benchmark_frozen_at is None:
            return EvaluationIntegrity.UNKNOWN
        contaminated = (
            self.detailed_behavior_inspected
            or self.first_detailed_access_at is not None
            or self.first_execution_at is not None
            or self.first_validation_at is not None
            or self.exposure_state is ExposureState.BEHAVIOR_EXPOSED
        )
        return (
            EvaluationIntegrity.CONTAMINATED
            if contaminated
            else EvaluationIntegrity.VALID_UNSEEN
        )

    def require_mutable_assignment(self) -> None:
        if (
            self.benchmark_frozen_at is not None
            or self.manifest_status is ManifestStatus.FROZEN
        ):
            raise ContractViolation("frozen sample assignment cannot be changed")

    def mark_eligible(self) -> CandidateSample:
        if any(value is not CriterionStatus.PASS for value in self.screening.values()):
            raise ContractViolation("all seven screening criteria must pass")
        if self.duplicate_status is not DuplicateStatus.UNIQUE:
            raise ContractViolation("duplicate status must be unique")
        if (
            not self.sha256
            or not self.source.strip()
            or not self.source_reference.strip()
        ):
            raise ContractViolation("SHA-256 and provenance are required")
        return replace(
            self,
            eligibility_status=EligibilityStatus.ELIGIBLE,
            manifest_status=ManifestStatus.ELIGIBLE,
        )

    def exclude(self, reason: ExclusionReason, detail: str | None) -> CandidateSample:
        self.require_mutable_assignment()
        if reason is ExclusionReason.OTHER and not (detail and detail.strip()):
            raise ContractViolation("exclusion detail is required when reason is other")
        return replace(
            self,
            eligibility_status=EligibilityStatus.EXCLUDED,
            manifest_status=ManifestStatus.EXCLUDED,
            exclusion_reason=reason,
            exclusion_detail=detail,
        )

    def assign(
        self,
        role: DatasetRole,
        reason: AssignmentReason,
        detail: str | None,
        at: str,
        split_id: str | None = None,
        split_seed: int | None = None,
    ) -> CandidateSample:
        self.require_mutable_assignment()
        if self.eligibility_status is not EligibilityStatus.ELIGIBLE:
            raise ContractViolation("only eligible samples can be assigned")
        if self.duplicate_status is not DuplicateStatus.UNIQUE:
            raise ContractViolation("only unique samples can be assigned")
        if role is DatasetRole.UNASSIGNED:
            raise ContractViolation(
                "assignment role must be malware_dev or malware_eval"
            )
        if reason is AssignmentReason.OTHER and not (detail and detail.strip()):
            raise ContractViolation(
                "assignment detail is required when reason is other"
            )
        return replace(
            self,
            assigned_dataset_role=role,
            assignment_reason=reason,
            assignment_detail=detail,
            assigned_at=at,
            split_id=split_id,
            split_seed=split_seed,
        )

    def freeze(self, benchmark_id: str, version: int, at: str) -> CandidateSample:
        if self.assigned_dataset_role is DatasetRole.UNASSIGNED:
            raise ContractViolation("only assigned split members can be frozen")
        if self.eligibility_status is not EligibilityStatus.ELIGIBLE:
            raise ContractViolation("all frozen members must be eligible")
        if self.duplicate_status is not DuplicateStatus.UNIQUE:
            raise ContractViolation("all frozen members must be unique")
        if (
            not self.sha256
            or not self.source.strip()
            or not self.source_reference.strip()
        ):
            raise ContractViolation(
                "all frozen members require identity and provenance"
            )
        if self.assigned_dataset_role is DatasetRole.MALWARE_EVAL and (
            self.detailed_behavior_inspected
            or self.first_detailed_access_at
            or self.first_execution_at
            or self.first_validation_at
        ):
            raise ContractViolation("evaluation member is contaminated before freeze")
        return replace(
            self,
            benchmark_id=benchmark_id,
            benchmark_version=version,
            benchmark_frozen_at=at,
            manifest_status=ManifestStatus.FROZEN,
        )

    def eval_open(self, at: str) -> CandidateSample:
        if self.assigned_dataset_role is not DatasetRole.MALWARE_EVAL:
            raise ContractViolation("eval-open requires malware_eval role")
        if self.benchmark_frozen_at is None:
            raise ContractViolation("eval-open requires a frozen benchmark")
        if self.evaluation_integrity is not EvaluationIntegrity.VALID_UNSEEN:
            raise ContractViolation("evaluation integrity must be valid_unseen")
        return replace(
            self,
            first_detailed_access_at=self.first_detailed_access_at or at,
            exposure_state=ExposureState.EVALUATION_EXPOSED,
        )


def deterministic_split[T](
    items: list[T], dev_count: int, eval_count: int, seed: int
) -> tuple[list[T], list[T]]:
    """Split a stable input pool without consulting behavior metadata."""
    if dev_count < 0 or eval_count < 0:
        raise ContractViolation("split counts cannot be negative")
    if dev_count + eval_count > len(items):
        raise ContractViolation("eligible candidate pool is too small")
    shuffled = list(items)
    Random(seed).shuffle(shuffled)
    return shuffled[:dev_count], shuffled[dev_count : dev_count + eval_count]
