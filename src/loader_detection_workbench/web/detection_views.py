"""Read-only presentation models for hypotheses, rules and validation runs.

Counts are always paired with their denominators and Unseen evaluation runs
are never merged with development or tuning runs.
"""

from __future__ import annotations

from dataclasses import dataclass

from loader_detection_workbench.detection.domain import (
    Benchmark,
    DetectionRule,
    RunKind,
    ValidationRun,
)
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.report.render import match_evidence, ratio

KIND_ORDER = (RunKind.DEVELOPMENT, RunKind.EVALUATION, RunKind.TUNING)
KIND_TITLES = {
    RunKind.DEVELOPMENT: "Development",
    RunKind.EVALUATION: "Evaluation (Unseen)",
    RunKind.TUNING: "Tuning (after Unseen)",
}


@dataclass(frozen=True, slots=True)
class RunView:
    display_id: str
    rule_display_id: str
    rule_version: int
    benchmark_display_id: str
    kind: str
    kind_title: str
    roles: str
    engine: str
    created_at: str
    detected: str
    false_positives: str
    not_evaluable: int
    missed: int
    case_outcome: str | None = None


@dataclass(frozen=True, slots=True)
class ResultView:
    case_display_id: str
    role: str
    outcome: str
    evidence: str


@dataclass(frozen=True, slots=True)
class VersionView:
    version: int
    status: str
    sha256: str
    created_at: str
    frozen_at: str
    note: str


@dataclass(frozen=True, slots=True)
class ComparisonCell:
    run_display_id: str | None
    detected: str
    false_positives: str
    not_evaluable: str


@dataclass(frozen=True, slots=True)
class ComparisonRow:
    version: int
    status: str
    cells: tuple[ComparisonCell, ...]  # one per KIND_ORDER entry


@dataclass(frozen=True, slots=True)
class OutcomeRow:
    case_display_id: str
    role: str
    outcomes: tuple[str, ...]  # one per version column
    changed: bool


@dataclass(frozen=True, slots=True)
class BenchmarkComparison:
    benchmark_display_id: str
    benchmark_name: str
    frozen: bool
    rows: tuple[ComparisonRow, ...]
    versions: tuple[int, ...]
    outcome_rows: tuple[OutcomeRow, ...]


def run_view(run: ValidationRun, case_display_id: str | None = None) -> RunView:
    metrics = run.metrics
    outcome: str | None = None
    if case_display_id is not None:
        result = next(
            (r for r in run.results if r.case_display_id == case_display_id), None
        )
        outcome = (
            "not a member"
            if result is None
            else f"{result.role.value}: {result.outcome.value}"
        )
    return RunView(
        display_id=run.display_id,
        rule_display_id=run.rule_display_id,
        rule_version=run.rule_version,
        benchmark_display_id=run.benchmark_display_id,
        kind=run.kind.value,
        kind_title=KIND_TITLES[run.kind],
        roles=", ".join(role.value for role in run.roles),
        engine=run.engine,
        created_at=format_utc(run.created_at),
        detected=ratio(metrics.tp, metrics.malicious_total),
        false_positives=ratio(metrics.fp, metrics.benign_total),
        not_evaluable=metrics.not_evaluable,
        missed=metrics.fn,
        case_outcome=outcome,
    )


def result_views(run: ValidationRun) -> tuple[ResultView, ...]:
    return tuple(
        ResultView(
            result.case_display_id,
            result.role.value,
            result.outcome.value,
            match_evidence(result),
        )
        for result in run.results
    )


def version_views(rule: DetectionRule) -> tuple[VersionView, ...]:
    return tuple(
        VersionView(
            version.version,
            version.status.value,
            version.sha256,
            format_utc(version.created_at),
            "—" if version.frozen_at is None else format_utc(version.frozen_at),
            version.note or "—",
        )
        for version in rule.versions
    )


_EMPTY = ComparisonCell(None, "—", "—", "—")


def _cell(run: ValidationRun | None) -> ComparisonCell:
    if run is None:
        return _EMPTY
    view = run_view(run)
    return ComparisonCell(
        run.display_id, view.detected, view.false_positives, str(view.not_evaluable)
    )


def compare_versions(
    rule: DetectionRule, runs: list[ValidationRun], benchmarks: list[Benchmark]
) -> tuple[BenchmarkComparison, ...]:
    """Per Benchmark: latest run of each kind for every rule version.

    The per-Case matrix uses the latest *development* run of each version, so
    it never mixes Unseen members into the comparison used while iterating.
    """
    names = {benchmark.display_id: benchmark for benchmark in benchmarks}
    comparisons: list[BenchmarkComparison] = []
    for benchmark_id in sorted({run.benchmark_display_id for run in runs}):
        scoped = [run for run in runs if run.benchmark_display_id == benchmark_id]
        latest: dict[tuple[int, RunKind], ValidationRun] = {}
        for run in scoped:  # runs arrive in display-ID order; later wins
            latest[(run.rule_version, run.kind)] = run
        rows = tuple(
            ComparisonRow(
                version.version,
                version.status.value,
                tuple(
                    _cell(latest.get((version.version, kind))) for kind in KIND_ORDER
                ),
            )
            for version in rule.versions
        )
        development = {
            version: run
            for (version, kind), run in latest.items()
            if kind is RunKind.DEVELOPMENT
        }
        versions = tuple(sorted(development))
        cases: dict[str, str] = {}
        for version in versions:
            for result in development[version].results:
                cases.setdefault(result.case_display_id, result.role.value)
        outcome_rows: list[OutcomeRow] = []
        for case_id, role in sorted(cases.items()):
            outcomes = tuple(
                next(
                    (
                        result.outcome.value
                        for result in development[version].results
                        if result.case_display_id == case_id
                    ),
                    "—",
                )
                for version in versions
            )
            outcome_rows.append(
                OutcomeRow(case_id, role, outcomes, len(set(outcomes)) > 1)
            )
        benchmark = names.get(benchmark_id)
        comparisons.append(
            BenchmarkComparison(
                benchmark_id,
                benchmark_id if benchmark is None else benchmark.name,
                benchmark is not None and benchmark.is_frozen,
                rows,
                versions,
                tuple(outcome_rows),
            )
        )
    return tuple(comparisons)
