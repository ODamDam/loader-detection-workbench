"""Application service for the sample intake use cases."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any

from loader_detection_workbench.sample.domain import (
    SCREENING_FIELDS,
    AssignmentReason,
    CandidateSample,
    Confidence,
    ContractViolation,
    CriterionStatus,
    DatasetRole,
    DuplicateSampleError,
    DuplicateStatus,
    EligibilityStatus,
    EvaluationIntegrity,
    ExclusionReason,
    ManifestStatus,
    ReportedRole,
    deterministic_split,
    utc_now,
)
from loader_detection_workbench.sample.repository import SampleRepository


class SampleService:
    def __init__(self, repository: SampleRepository) -> None:
        self.repository = repository

    def add(self, path: Path, **labels: Any) -> CandidateSample:
        """Register a candidate from a file on disk (hash only; not stored)."""
        if not path.is_file():
            raise ContractViolation("input must be an existing regular file")
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise ContractViolation("input file could not be read") from exc
        return self.register(digest.hexdigest(), **labels)

    def register(
        self,
        sha256: str,
        *,
        source: str,
        source_reference: str,
        source_record_id: str | None = None,
        reported_role: ReportedRole = ReportedRole.UNKNOWN,
        role_label_source: str | None = None,
        role_label_confidence: Confidence = Confidence.UNKNOWN,
        reported_family: str | None = None,
        family_label_source: str | None = None,
        family_label_confidence: Confidence = Confidence.UNKNOWN,
    ) -> CandidateSample:
        """Register a candidate by the SHA-256 of its content."""
        if re.fullmatch(r"[0-9a-f]{64}", sha256, re.ASCII) is None:
            raise ContractViolation("sha256 must be lowercase hexadecimal")
        with self.repository.transaction():
            duplicate = self.repository.find_by_sha256(sha256)
            if duplicate is not None:
                raise DuplicateSampleError(
                    f"exact SHA-256 duplicate of {duplicate.sample_id}"
                )
            sample = CandidateSample(
                sample_id=self.repository.allocate_sample_id(),
                sha256=sha256,
                source=source,
                source_reference=source_reference,
                source_record_id=source_record_id,
                reported_role=reported_role,
                role_label_source=role_label_source,
                role_label_confidence=role_label_confidence,
                reported_family=reported_family,
                family_label_source=family_label_source,
                family_label_confidence=family_label_confidence,
                created_at=utc_now(),
            )
            self.repository.add(sample)
        return sample

    def show(self, sample_id: str) -> CandidateSample:
        return self.repository.get(sample_id)

    def list_samples(
        self, status: ManifestStatus | None = None, role: DatasetRole | None = None
    ) -> list[CandidateSample]:
        return self.repository.list_samples(status, role)

    def screen(
        self, sample_id: str, screening: dict[str, CriterionStatus]
    ) -> CandidateSample:
        if set(screening) != set(SCREENING_FIELDS):
            raise ContractViolation("all seven screening criteria must be supplied")
        with self.repository.transaction():
            sample = self.repository.get(sample_id)
            sample.require_mutable_assignment()
            updated = replace(sample, screening=dict(screening))
            self.repository.save(updated)
        return updated

    def eligible(self, sample_id: str) -> CandidateSample:
        with self.repository.transaction():
            updated = self.repository.get(sample_id).mark_eligible()
            self.repository.save(updated)
        return updated

    def exclude(
        self, sample_id: str, reason: ExclusionReason, detail: str | None
    ) -> CandidateSample:
        with self.repository.transaction():
            updated = self.repository.get(sample_id).exclude(reason, detail)
            self.repository.save(updated)
        return updated

    def assign(
        self,
        sample_id: str,
        role: DatasetRole,
        reason: AssignmentReason,
        detail: str | None = None,
    ) -> CandidateSample:
        with self.repository.transaction():
            updated = self.repository.get(sample_id).assign(
                role, reason, detail, utc_now()
            )
            self.repository.save(updated)
        return updated

    def split(
        self, dev_count: int, eval_count: int, seed: int, split_id: str
    ) -> tuple[list[CandidateSample], list[str]]:
        with self.repository.transaction():
            pool = [
                s
                for s in self.repository.list_samples()
                if s.eligibility_status is EligibilityStatus.ELIGIBLE
                and s.duplicate_status is DuplicateStatus.UNIQUE
                and s.assigned_dataset_role is DatasetRole.UNASSIGNED
            ]
            dev, evaluation = deterministic_split(pool, dev_count, eval_count, seed)
            now = utc_now()
            assigned = [
                s.assign(
                    DatasetRole.MALWARE_DEV,
                    AssignmentReason.CONSTRAINED_RANDOM_SPLIT,
                    None,
                    now,
                    split_id,
                    seed,
                )
                for s in dev
            ]
            assigned += [
                s.assign(
                    DatasetRole.MALWARE_EVAL,
                    AssignmentReason.CONSTRAINED_RANDOM_SPLIT,
                    None,
                    now,
                    split_id,
                    seed,
                )
                for s in evaluation
            ]
            for sample in assigned:
                self.repository.save(sample)
        warnings = self._concentration_warnings(assigned)
        return assigned, warnings

    @staticmethod
    def _concentration_warnings(samples: list[CandidateSample]) -> list[str]:
        warnings: list[str] = []
        for label, values in (
            ("source", [s.source for s in samples]),
            ("family", [s.reported_family for s in samples if s.reported_family]),
        ):
            counts = Counter(values)
            if samples and counts and counts.most_common(1)[0][1] > len(samples) / 2:
                warnings.append(f"{label} concentration exceeds 50%")
        return warnings

    def freeze(
        self, benchmark_id: str, benchmark_version: int
    ) -> list[CandidateSample]:
        if benchmark_version < 1:
            raise ContractViolation("benchmark version must be positive")
        with self.repository.transaction():
            members = [
                s
                for s in self.repository.list_samples()
                if s.assigned_dataset_role is not DatasetRole.UNASSIGNED
            ]
            if not members:
                raise ContractViolation("no assigned split members to freeze")
            now = utc_now()
            frozen = [s.freeze(benchmark_id, benchmark_version, now) for s in members]
            for sample in frozen:
                self.repository.save(sample)
        return frozen

    def eval_open(self, sample_id: str) -> CandidateSample:
        with self.repository.transaction():
            updated = self.repository.get(sample_id).eval_open(utc_now())
            self.repository.save(updated)
        return updated

    def validate(
        self, sample_id: str | None = None, gate: str | None = None
    ) -> list[str]:
        samples = (
            [self.repository.get(sample_id)]
            if sample_id
            else self.repository.list_samples()
        )
        errors: list[str] = []
        for sample in samples:
            prefix = sample.sample_id
            if (
                sample.assigned_dataset_role is not DatasetRole.UNASSIGNED
                and sample.eligibility_status is not EligibilityStatus.ELIGIBLE
            ):
                errors.append(f"{prefix}: ASSIGNED_BEFORE_ELIGIBLE")
            if (
                sample.assigned_dataset_role is not DatasetRole.UNASSIGNED
                and sample.duplicate_status is not DuplicateStatus.UNIQUE
            ):
                errors.append(f"{prefix}: ASSIGNED_WITH_DUPLICATE_UNRESOLVED")
            if sample.assigned_dataset_role is DatasetRole.MALWARE_EVAL:
                if sample.evaluation_integrity is EvaluationIntegrity.CONTAMINATED:
                    errors.append(f"{prefix}: EVAL_CONTAMINATED")
                elif sample.evaluation_integrity is EvaluationIntegrity.UNKNOWN:
                    errors.append(f"{prefix}: EVAL_INTEGRITY_UNKNOWN")
            if sample.eligibility_status is EligibilityStatus.ELIGIBLE and any(
                v is not CriterionStatus.PASS for v in sample.screening.values()
            ):
                errors.append(f"{prefix}: ELIGIBLE_WITH_INCOMPLETE_CRITERIA")
            if gate == "eligibility":
                try:
                    sample.mark_eligible()
                except ContractViolation as exc:
                    errors.append(f"{prefix}: {exc}")
            elif (
                gate == "freeze"
                and sample.assigned_dataset_role is not DatasetRole.UNASSIGNED
            ):
                try:
                    sample.freeze("validation", 1, utc_now())
                except ContractViolation as exc:
                    errors.append(f"{prefix}: {exc}")
            elif (
                gate == "eval-open"
                and sample.assigned_dataset_role is DatasetRole.MALWARE_EVAL
            ):
                try:
                    sample.eval_open(utc_now())
                except ContractViolation as exc:
                    errors.append(f"{prefix}: {exc}")
        return errors
