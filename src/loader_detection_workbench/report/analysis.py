"""Read-only Case projection over static, detection and execution records.

``CaseAnalysisQuery`` extends an already queried ``CaseTimeline`` with every
other recorded fact about the same Case: static PE results, Detection
Hypotheses, the Rules they link, Validation Runs and VM Execution Runs. Reports
and the web UI consume this single immutable result. Any unreadable record
fails the whole query; a partial analysis is never returned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.ai.domain import AiAnalysis
from loader_detection_workbench.ai.store import AiAnalysisReader
from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.detection.domain import (
    Benchmark,
    BenchmarkMember,
    DetectionRule,
    Hypothesis,
    RunKind,
    ValidationResult,
    ValidationRun,
)
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.execution.domain import ExecutionRun
from loader_detection_workbench.execution.service import ExecutionService
from loader_detection_workbench.findings.domain import AnalystFinding
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.static_analysis.domain import StaticAnalysis
from loader_detection_workbench.static_analysis.service import StaticAnalysisService


@dataclass(frozen=True, slots=True)
class BenchmarkMembership:
    benchmark: Benchmark
    member: BenchmarkMember


@dataclass(frozen=True, slots=True)
class CaseAnalysis:
    case_display_id: str
    artifacts: tuple[Artifact, ...]
    static_results: tuple[StaticAnalysis, ...]
    hypotheses: tuple[Hypothesis, ...]
    rules: tuple[DetectionRule, ...]
    validation_runs: tuple[ValidationRun, ...]
    memberships: tuple[BenchmarkMembership, ...]
    execution_runs: tuple[ExecutionRun, ...]
    # Inferences, kept apart from every observed record above (ADR-026).
    ai_analyses: tuple[AiAnalysis, ...] = ()
    # Confirmed analyst findings: the only content of a report body (ADR-031).
    findings: tuple[AnalystFinding, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.static_results
            or self.hypotheses
            or self.rules
            or self.validation_runs
            or self.memberships
            or self.execution_runs
            or self.ai_analyses
            or self.findings
        )

    def rule(self, display_id: str) -> DetectionRule | None:
        return next((r for r in self.rules if r.display_id == display_id), None)

    def case_result(self, run: ValidationRun) -> ValidationResult | None:
        return next(
            (
                result
                for result in run.results
                if result.case_display_id == self.case_display_id
            ),
            None,
        )

    def runs_of_kind(self, kind: RunKind) -> tuple[ValidationRun, ...]:
        return tuple(run for run in self.validation_runs if run.kind is kind)


def _numeric(display_id: str) -> int:
    number = display_id.rpartition("-")[2]
    return int(number) if number.isdigit() else 0


class CaseAnalysisQuery:
    def __init__(self, root: Path) -> None:
        self._root = root

    def query(self, timeline: CaseTimeline) -> CaseAnalysis:
        case_id = timeline.case.case_id.display_id
        static = StaticAnalysisService(self._root)
        static_results = tuple(
            static.show(case_id, artifact.artifact_id.display_id)
            for artifact in timeline.artifacts
            if artifact.kind is ArtifactKind.STATIC
        )
        detection = DetectionService(self._root)
        hypotheses = tuple(detection.list_hypotheses(case_id))
        linked = {rule for item in hypotheses for rule in item.rule_display_ids}
        runs = tuple(
            run
            for run in detection.list_runs()
            if run.rule_display_id in linked
            or any(result.case_display_id == case_id for result in run.results)
        )
        rule_ids = sorted(linked | {run.rule_display_id for run in runs}, key=_numeric)
        rules = tuple(detection.show_rule(item) for item in rule_ids)
        memberships = tuple(
            BenchmarkMembership(benchmark, member)
            for benchmark in detection.list_benchmarks()
            for member in benchmark.members
            if member.case_display_id == case_id
        )
        execution_runs = tuple(
            run
            for run in ExecutionService(self._root).list_runs()
            if run.case_display_id == case_id
        )
        return CaseAnalysis(
            case_id,
            timeline.artifacts,
            static_results,
            hypotheses,
            rules,
            runs,
            memberships,
            execution_runs,
            tuple(AiAnalysisReader(self._root).list(case_id)),
            tuple(FindingService(self._root).confirmed(case_id)),
        )
