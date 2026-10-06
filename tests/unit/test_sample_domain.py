from dataclasses import replace
from typing import Any, cast

import pytest

from loader_detection_workbench.sample.domain import (
    SCREENING_FIELDS,
    AssignmentReason,
    CandidateSample,
    ContractViolation,
    CriterionStatus,
    DatasetRole,
    EvaluationIntegrity,
    ExclusionReason,
    deterministic_split,
)


def sample(**changes: object) -> CandidateSample:
    base = CandidateSample(
        sample_id="SMP-000001",
        sha256="a" * 64,
        source="repo",
        source_reference="record",
        created_at="2026-01-01T00:00:00Z",
    )
    return replace(base, **cast(Any, changes))


def test_domain_validation_and_eligibility_gate() -> None:
    with pytest.raises(ValueError):
        sample(sha256="bad")
    with pytest.raises(ContractViolation):
        sample().mark_eligible()
    passed = sample(
        screening={key: CriterionStatus.PASS for key in SCREENING_FIELDS}
    ).mark_eligible()
    assert passed.eligibility_status.value == "eligible"


def test_other_exclusion_requires_detail() -> None:
    with pytest.raises(ContractViolation):
        sample().exclude(ExclusionReason.OTHER, None)


def test_integrity_is_derived_and_eval_open_gate() -> None:
    eligible = sample(
        screening={key: CriterionStatus.PASS for key in SCREENING_FIELDS}
    ).mark_eligible()
    evaluation = eligible.assign(
        DatasetRole.MALWARE_EVAL, AssignmentReason.CONSTRAINED_RANDOM_SPLIT, None, "now"
    ).freeze("BMK-1", 1, "frozen")
    assert evaluation.evaluation_integrity is EvaluationIntegrity.VALID_UNSEEN
    opened = evaluation.eval_open("opened")
    assert opened.first_detailed_access_at == "opened"
    assert opened.evaluation_integrity is EvaluationIntegrity.CONTAMINATED


def test_frozen_assignment_rejected() -> None:
    eligible = sample(
        screening={key: CriterionStatus.PASS for key in SCREENING_FIELDS}
    ).mark_eligible()
    frozen = eligible.assign(
        DatasetRole.MALWARE_DEV, AssignmentReason.MANUAL_BALANCE_ADJUSTMENT, None, "now"
    ).freeze("BMK", 1, "now")
    with pytest.raises(ContractViolation):
        frozen.assign(
            DatasetRole.MALWARE_EVAL, AssignmentReason.OTHER, "change", "later"
        )


def test_deterministic_split() -> None:
    first = deterministic_split(list(range(10)), 3, 2, 42)
    assert first == deterministic_split(list(range(10)), 3, 2, 42)
