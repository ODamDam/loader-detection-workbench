"""Detection Hypothesis, Detection Rule, Benchmark and Validation records.

Validation is evaluated per Case: each Benchmark member Case carries the
expected label implied by its role, and each Rule version is applied to the
Case's Artifacts (YARA) or Sysmon records (Sigma).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

MAX_RULE_BYTES = 256 * 1024
MAX_TEXT = 4000
_DISPLAY = {
    "hypothesis": ("HYP", 4),
    "rule": ("RULE", 4),
    "benchmark": ("BMK", 4),
    "run": ("RUN", 4),
}


def format_display_id(kind: str, value: int) -> str:
    prefix, width = _DISPLAY[kind]
    return f"{prefix}-{value:0{width}d}"


def require_display_id(kind: str, value: str) -> str:
    prefix, width = _DISPLAY[kind]
    if (
        not isinstance(value, str)
        or re.fullmatch(rf"{prefix}-[0-9]{{{width},}}", value, re.ASCII) is None
        or int(value.rpartition("-")[2]) < 1
    ):
        raise DomainError(
            DomainErrorCode.INVALID_DISPLAY_ID,
            f"display ID must use {prefix}-{'0' * (width - 1)}1 format",
        )
    return value


def require_text(
    value: str | None,
    field: str,
    *,
    code: DomainErrorCode,
    optional: bool = False,
    maximum: int = MAX_TEXT,
) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum:
        raise DomainError(code, f"{field} must contain 1 to {maximum} characters")
    return value.strip()


class RuleFormat(StrEnum):
    YARA = "yara"
    SIGMA = "sigma"

    @classmethod
    def parse(cls, value: str) -> RuleFormat:
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_DETECTION_RULE, "rule format must be yara|sigma"
            ) from exc


class RuleVersionStatus(StrEnum):
    DRAFT = "draft"
    FROZEN = "frozen"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    REJECTED = "rejected"

    @classmethod
    def parse(cls, value: str) -> HypothesisStatus:
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_HYPOTHESIS,
                "hypothesis status must be proposed|supported|weakened|rejected",
            ) from exc


class MemberRole(StrEnum):
    DEV = "dev"
    UNSEEN = "unseen"
    BENIGN_COMMON = "benign_common"
    BENIGN_MATCHED = "benign_matched"

    @classmethod
    def parse(cls, value: str) -> MemberRole:
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_BENCHMARK,
                "member role must be dev|unseen|benign_common|benign_matched",
            ) from exc

    @property
    def expected_malicious(self) -> bool:
        return self in (MemberRole.DEV, MemberRole.UNSEEN)


class RunKind(StrEnum):
    """Development runs may be repeated; evaluation runs touch Unseen members."""

    DEVELOPMENT = "development"
    EVALUATION = "evaluation"
    TUNING = "tuning"


class Outcome(StrEnum):
    TP = "TP"
    FP = "FP"
    FN = "FN"
    TN = "TN"
    NOT_EVALUABLE = "not_evaluable"


def classify(expected_malicious: bool, matched: bool | None) -> Outcome:
    if matched is None:
        return Outcome.NOT_EVALUABLE
    if expected_malicious:
        return Outcome.TP if matched else Outcome.FN
    return Outcome.FP if matched else Outcome.TN


def content_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def require_rule_content(content: str) -> str:
    if not isinstance(content, str) or not content.strip():
        raise DomainError(DomainErrorCode.INVALID_DETECTION_RULE, "rule is empty")
    if len(content.encode("utf-8")) > MAX_RULE_BYTES:
        raise DomainError(
            DomainErrorCode.INVALID_DETECTION_RULE, "rule exceeds the 256 KiB limit"
        )
    return content


@dataclass(frozen=True, slots=True)
class RuleVersion:
    rule_display_id: str
    version: int
    content: str
    sha256: str
    status: RuleVersionStatus
    created_at: datetime
    frozen_at: datetime | None
    note: str | None


@dataclass(frozen=True, slots=True)
class DetectionRule:
    display_id: str
    name: str
    format: RuleFormat
    created_at: datetime
    versions: tuple[RuleVersion, ...]

    @property
    def latest(self) -> RuleVersion:
        return self.versions[-1]

    def version(self, number: int | None) -> RuleVersion:
        if number is None:
            return self.latest
        for item in self.versions:
            if item.version == number:
                return item
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_NOT_FOUND, "rule version was not found"
        )


@dataclass(frozen=True, slots=True)
class Hypothesis:
    display_id: str
    case_display_id: str | None
    title: str
    statement: str
    status: HypothesisStatus
    created_at: datetime
    updated_at: datetime
    evidence_artifact_ids: tuple[str, ...]
    rule_display_ids: tuple[str, ...]
    expected_benign: str | None


@dataclass(frozen=True, slots=True)
class BenchmarkMember:
    case_display_id: str
    role: MemberRole
    added_at: datetime


@dataclass(frozen=True, slots=True)
class Benchmark:
    display_id: str
    name: str
    description: str | None
    created_at: datetime
    frozen_at: datetime | None
    members: tuple[BenchmarkMember, ...]

    @property
    def is_frozen(self) -> bool:
        return self.frozen_at is not None


@dataclass(frozen=True, slots=True)
class ValidationResult:
    case_display_id: str
    role: MemberRole
    matched: bool | None
    outcome: Outcome
    detail: str


@dataclass(frozen=True, slots=True)
class ValidationMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    not_evaluable: int

    @classmethod
    def from_results(cls, results: tuple[ValidationResult, ...]) -> ValidationMetrics:
        counts = {outcome: 0 for outcome in Outcome}
        for result in results:
            counts[result.outcome] += 1
        return cls(
            counts[Outcome.TP],
            counts[Outcome.FP],
            counts[Outcome.FN],
            counts[Outcome.TN],
            counts[Outcome.NOT_EVALUABLE],
        )

    @property
    def malicious_total(self) -> int:
        return self.tp + self.fn

    @property
    def benign_total(self) -> int:
        return self.fp + self.tn

    @property
    def recall(self) -> float | None:
        return None if not self.malicious_total else self.tp / self.malicious_total

    @property
    def precision(self) -> float | None:
        flagged = self.tp + self.fp
        return None if not flagged else self.tp / flagged

    @property
    def false_positive_rate(self) -> float | None:
        return None if not self.benign_total else self.fp / self.benign_total


@dataclass(frozen=True, slots=True)
class ValidationRun:
    display_id: str
    rule_display_id: str
    rule_version: int
    rule_sha256: str
    benchmark_display_id: str
    roles: tuple[MemberRole, ...]
    kind: RunKind
    created_at: datetime
    engine: str
    results: tuple[ValidationResult, ...]

    @property
    def metrics(self) -> ValidationMetrics:
        return ValidationMetrics.from_results(self.results)
