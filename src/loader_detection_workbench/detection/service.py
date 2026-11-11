"""Application service for Hypotheses, Rules, Benchmarks and Validation Runs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.detection import sigma_engine, yara_engine
from loader_detection_workbench.detection.domain import (
    Benchmark,
    DetectionRule,
    Hypothesis,
    HypothesisStatus,
    MemberRole,
    RuleFormat,
    RuleVersion,
    RuleVersionStatus,
    RunKind,
    ValidationResult,
    ValidationRun,
    classify,
    content_sha256,
    require_display_id,
    require_rule_content,
    require_text,
)
from loader_detection_workbench.detection.sqlite_repository import (
    SQLiteDetectionRepository,
)
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.case import CaseKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, CaseId
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.sysmon.records import (
    MAX_RECORD_XML_BYTES,
    SysmonRecord,
    parse_sysmon_records,
)

MAX_SAMPLE_BYTES = 64 * 1024 * 1024
DEFAULT_DEVELOPMENT_ROLES = (
    MemberRole.DEV,
    MemberRole.BENIGN_COMMON,
    MemberRole.BENIGN_MATCHED,
)


@dataclass(frozen=True, slots=True)
class RuleCheck:
    format: RuleFormat
    summary: str


def _case_selector(display_id: str) -> str:
    CaseId("00000000000000000000000000", display_id)
    return display_id


def _artifact_selector(display_id: str) -> str:
    ArtifactId("00000000000000000000000000", display_id)
    return display_id


def check_rule(rule_format: RuleFormat, content: str) -> RuleCheck:
    require_rule_content(content)
    if rule_format is RuleFormat.YARA:
        names = yara_engine.check_rule(content)
        return RuleCheck(rule_format, f"yara rules: {', '.join(names)}")
    compiled = sigma_engine.compile_rule(content)
    scope = (
        "sysmon:any"
        if compiled.event_ids is None
        else "sysmon:" + ",".join(str(item) for item in sorted(compiled.event_ids))
    )
    return RuleCheck(rule_format, f"sigma rule: {compiled.title} [{scope}]")


class DetectionService:
    def __init__(self, root: Path) -> None:
        self._root = root

    @contextmanager
    def _repository(
        self, *, write: bool = False
    ) -> Iterator[SQLiteDetectionRepository]:
        repository: SQLiteDetectionRepository | None = None
        try:
            workspace = ProjectService().open(self._root)
            repository = SQLiteDetectionRepository(workspace, write=write)
            with repository.transaction():
                yield repository
        except sqlite3.IntegrityError as exc:
            raise DomainError(
                DomainErrorCode.DETECTION_PERSISTENCE_FAILED,
                f"detection record violates an integrity rule: {exc}",
            ) from exc
        except sqlite3.Error as exc:
            raise DomainError(
                DomainErrorCode.DETECTION_PERSISTENCE_FAILED,
                "detection database operation failed",
            ) from exc
        finally:
            if repository is not None:
                repository.close()

    # -- rules ----------------------------------------------------------------

    def add_rule(
        self, name: str, rule_format: str, content: str, note: str | None = None
    ) -> DetectionRule:
        parsed = RuleFormat.parse(rule_format)
        title = require_text(
            name, "rule name", code=DomainErrorCode.INVALID_DETECTION_RULE, maximum=200
        )
        assert title is not None
        note = require_text(
            note, "note", code=DomainErrorCode.INVALID_DETECTION_RULE, optional=True
        )
        check_rule(parsed, content)
        now = utc_now()
        with self._repository(write=True) as repository:
            display_id = repository.allocate("rule")
            rule = DetectionRule(
                display_id,
                title,
                parsed,
                now,
                (
                    RuleVersion(
                        display_id,
                        1,
                        content,
                        content_sha256(content),
                        RuleVersionStatus.DRAFT,
                        now,
                        None,
                        note,
                    ),
                ),
            )
            repository.insert_rule(rule)
            return repository.get_rule(display_id)

    def revise_rule(
        self, rule_display_id: str, content: str, note: str | None = None
    ) -> DetectionRule:
        require_display_id("rule", rule_display_id)
        note = require_text(
            note, "note", code=DomainErrorCode.INVALID_DETECTION_RULE, optional=True
        )
        with self._repository(write=True) as repository:
            rule = repository.get_rule(rule_display_id)
            check_rule(rule.format, content)
            digest = content_sha256(content)
            if digest == rule.latest.sha256:
                raise DomainError(
                    DomainErrorCode.INVALID_DETECTION_RULE,
                    "revision is identical to the latest version",
                )
            repository.insert_rule_version(
                RuleVersion(
                    rule_display_id,
                    rule.latest.version + 1,
                    content,
                    digest,
                    RuleVersionStatus.DRAFT,
                    utc_now(),
                    None,
                    note,
                )
            )
            return repository.get_rule(rule_display_id)

    def freeze_rule(
        self, rule_display_id: str, version: int | None = None
    ) -> DetectionRule:
        require_display_id("rule", rule_display_id)
        with self._repository(write=True) as repository:
            rule = repository.get_rule(rule_display_id)
            target = rule.version(version)
            if target.status is RuleVersionStatus.FROZEN:
                raise DomainError(
                    DomainErrorCode.INVALID_DETECTION_RULE,
                    "rule version is already frozen",
                )
            repository.freeze_rule_version(
                rule_display_id, target.version, format_utc(utc_now())
            )
            return repository.get_rule(rule_display_id)

    def show_rule(self, rule_display_id: str) -> DetectionRule:
        require_display_id("rule", rule_display_id)
        with self._repository() as repository:
            return repository.get_rule(rule_display_id)

    def list_rules(self) -> list[DetectionRule]:
        with self._repository() as repository:
            return repository.list_rules()

    # -- hypotheses -----------------------------------------------------------

    def add_hypothesis(
        self,
        case_display_id: str,
        title: str,
        statement: str,
        *,
        evidence: Sequence[str] = (),
        expected_benign: str | None = None,
    ) -> Hypothesis:
        _case_selector(case_display_id)
        code = DomainErrorCode.INVALID_HYPOTHESIS
        clean_title = require_text(title, "title", code=code, maximum=200)
        clean_statement = require_text(statement, "statement", code=code)
        benign = require_text(
            expected_benign, "expected benign counterpart", code=code, optional=True
        )
        assert clean_title is not None and clean_statement is not None
        for item in evidence:
            _artifact_selector(item)
        now = utc_now()
        with self._repository(write=True) as repository:
            case_ulid = repository.case_ulid(case_display_id)
            display_id = repository.allocate("hypothesis")
            repository.insert_hypothesis(
                Hypothesis(
                    display_id,
                    case_display_id,
                    clean_title,
                    clean_statement,
                    HypothesisStatus.PROPOSED,
                    now,
                    now,
                    (),
                    (),
                    benign,
                ),
                case_ulid,
            )
            for item in evidence:
                repository.link_evidence(
                    display_id, repository.artifact_ulid(item, case_ulid)
                )
            return repository.get_hypothesis(display_id)

    def link_evidence(
        self, hypothesis_display_id: str, artifact_display_ids: Sequence[str]
    ) -> Hypothesis:
        require_display_id("hypothesis", hypothesis_display_id)
        for item in artifact_display_ids:
            _artifact_selector(item)
        with self._repository(write=True) as repository:
            hypothesis = repository.get_hypothesis(hypothesis_display_id)
            case_ulid = (
                None
                if hypothesis.case_display_id is None
                else repository.case_ulid(hypothesis.case_display_id)
            )
            for item in artifact_display_ids:
                repository.link_evidence(
                    hypothesis_display_id, repository.artifact_ulid(item, case_ulid)
                )
            return repository.get_hypothesis(hypothesis_display_id)

    def link_rule(self, hypothesis_display_id: str, rule_display_id: str) -> Hypothesis:
        require_display_id("hypothesis", hypothesis_display_id)
        require_display_id("rule", rule_display_id)
        with self._repository(write=True) as repository:
            repository.get_hypothesis(hypothesis_display_id)
            repository.get_rule(rule_display_id)
            repository.link_rule(hypothesis_display_id, rule_display_id)
            return repository.get_hypothesis(hypothesis_display_id)

    def set_hypothesis_status(
        self, hypothesis_display_id: str, status: str
    ) -> Hypothesis:
        require_display_id("hypothesis", hypothesis_display_id)
        parsed = HypothesisStatus.parse(status)
        with self._repository(write=True) as repository:
            repository.set_hypothesis_status(hypothesis_display_id, parsed, utc_now())
            return repository.get_hypothesis(hypothesis_display_id)

    def show_hypothesis(self, hypothesis_display_id: str) -> Hypothesis:
        require_display_id("hypothesis", hypothesis_display_id)
        with self._repository() as repository:
            return repository.get_hypothesis(hypothesis_display_id)

    def list_hypotheses(self, case_display_id: str | None = None) -> list[Hypothesis]:
        with self._repository() as repository:
            case_ulid = (
                None
                if case_display_id is None
                else repository.case_ulid(_case_selector(case_display_id))
            )
            return repository.list_hypotheses(case_ulid)

    # -- benchmarks -----------------------------------------------------------

    def create_benchmark(self, name: str, description: str | None = None) -> Benchmark:
        code = DomainErrorCode.INVALID_BENCHMARK
        clean_name = require_text(name, "benchmark name", code=code, maximum=200)
        clean_description = require_text(
            description, "description", code=code, optional=True
        )
        assert clean_name is not None
        with self._repository(write=True) as repository:
            if any(item.name == clean_name for item in repository.list_benchmarks()):
                raise DomainError(code, "benchmark name already exists")
            display_id = repository.allocate("benchmark")
            repository.insert_benchmark(
                Benchmark(
                    display_id, clean_name, clean_description, utc_now(), None, ()
                )
            )
            return repository.get_benchmark(display_id)

    def add_member(
        self, benchmark_display_id: str, case_display_id: str, role: str
    ) -> Benchmark:
        require_display_id("benchmark", benchmark_display_id)
        _case_selector(case_display_id)
        parsed = MemberRole.parse(role)
        case = CaseService(self._root).show(case_display_id)
        if parsed.expected_malicious and case.kind is CaseKind.BENIGN:
            raise DomainError(
                DomainErrorCode.INVALID_BENCHMARK,
                "a benign Case cannot be a dev or unseen malware member",
            )
        if not parsed.expected_malicious and case.kind is not CaseKind.BENIGN:
            raise DomainError(
                DomainErrorCode.INVALID_BENCHMARK,
                "benign roles require a benign Case",
            )
        if parsed is MemberRole.UNSEEN and case.kind is not CaseKind.MALWARE:
            raise DomainError(
                DomainErrorCode.INVALID_BENCHMARK,
                "unseen members must be real-world malware Cases",
            )
        with self._repository(write=True) as repository:
            benchmark = repository.get_benchmark(benchmark_display_id)
            if benchmark.is_frozen:
                raise DomainError(
                    DomainErrorCode.BENCHMARK_FROZEN, "benchmark is frozen"
                )
            if any(m.case_display_id == case_display_id for m in benchmark.members):
                raise DomainError(
                    DomainErrorCode.INVALID_BENCHMARK,
                    "case is already a member of this benchmark",
                )
            repository.add_member(
                benchmark_display_id,
                repository.case_ulid(case_display_id),
                parsed,
                format_utc(utc_now()),
            )
            return repository.get_benchmark(benchmark_display_id)

    def freeze_benchmark(self, benchmark_display_id: str) -> Benchmark:
        require_display_id("benchmark", benchmark_display_id)
        with self._repository(write=True) as repository:
            benchmark = repository.get_benchmark(benchmark_display_id)
            if benchmark.is_frozen:
                raise DomainError(
                    DomainErrorCode.BENCHMARK_FROZEN, "benchmark is already frozen"
                )
            if not benchmark.members:
                raise DomainError(
                    DomainErrorCode.INVALID_BENCHMARK,
                    "an empty benchmark cannot freeze",
                )
            repository.freeze_benchmark(benchmark_display_id, format_utc(utc_now()))
            return repository.get_benchmark(benchmark_display_id)

    def show_benchmark(self, benchmark_display_id: str) -> Benchmark:
        require_display_id("benchmark", benchmark_display_id)
        with self._repository() as repository:
            return repository.get_benchmark(benchmark_display_id)

    def list_benchmarks(self) -> list[Benchmark]:
        with self._repository() as repository:
            return repository.list_benchmarks()

    # -- validation -----------------------------------------------------------

    def run_validation(
        self,
        rule_display_id: str,
        benchmark_display_id: str,
        *,
        version: int | None = None,
        roles: Sequence[str] | None = None,
    ) -> ValidationRun:
        require_display_id("rule", rule_display_id)
        require_display_id("benchmark", benchmark_display_id)
        selected = (
            DEFAULT_DEVELOPMENT_ROLES
            if not roles
            else tuple(dict.fromkeys(MemberRole.parse(item) for item in roles))
        )
        with self._repository() as repository:
            rule = repository.get_rule(rule_display_id)
            target = rule.version(version)
            benchmark = repository.get_benchmark(benchmark_display_id)
            prior_evaluation = repository.has_evaluation_run(rule_display_id)
        kind = RunKind.DEVELOPMENT
        if MemberRole.UNSEEN in selected:
            if target.status is not RuleVersionStatus.FROZEN:
                raise DomainError(
                    DomainErrorCode.DETECTION_RULE_NOT_FROZEN,
                    "unseen evaluation requires a frozen rule version",
                )
            if not benchmark.is_frozen:
                raise DomainError(
                    DomainErrorCode.BENCHMARK_NOT_FROZEN,
                    "unseen evaluation requires a frozen benchmark",
                )
            kind = RunKind.TUNING if prior_evaluation else RunKind.EVALUATION
        members = [m for m in benchmark.members if m.role in selected]
        if not members:
            raise DomainError(
                DomainErrorCode.INVALID_VALIDATION_REQUEST,
                "benchmark has no members with the selected roles",
            )
        evaluator = _Evaluator(self._root, rule.format, target)
        results = tuple(
            evaluator.evaluate(member.case_display_id, member.role)
            for member in members
        )
        with self._repository(write=True) as repository:
            current = repository.get_benchmark(benchmark_display_id)
            if current.members != benchmark.members:
                raise DomainError(
                    DomainErrorCode.INVALID_VALIDATION_REQUEST,
                    "benchmark membership changed during validation",
                )
            if repository.get_rule(rule_display_id).version(target.version) != target:
                raise DomainError(
                    DomainErrorCode.INVALID_VALIDATION_REQUEST,
                    "rule version changed during validation",
                )
            run = ValidationRun(
                repository.allocate("run"),
                rule_display_id,
                target.version,
                target.sha256,
                benchmark_display_id,
                selected,
                kind,
                utc_now(),
                evaluator.engine,
                results,
            )
            repository.insert_run(run)
            return repository.get_run(run.display_id)

    def show_run(self, run_display_id: str) -> ValidationRun:
        require_display_id("run", run_display_id)
        with self._repository() as repository:
            return repository.get_run(run_display_id)

    def list_runs(self, rule_display_id: str | None = None) -> list[ValidationRun]:
        with self._repository() as repository:
            return repository.list_runs(rule_display_id)


class _Evaluator:
    """Applies one Rule version to the Artifacts of a Benchmark member Case."""

    def __init__(self, root: Path, rule_format: RuleFormat, version: RuleVersion):
        self._root = root
        self._format = rule_format
        self._store = ArtifactStore(root)
        self._artifacts = ArtifactService(root)
        if rule_format is RuleFormat.YARA:
            self._yara = yara_engine.compile_rule(version.content)
            self.engine = yara_engine.engine_label()
        else:
            self._sigma = sigma_engine.compile_rule(version.content)
            self.engine = sigma_engine.engine_label()

    def _read(self, artifact: Artifact, limit: int) -> bytes:
        return self._store.read_verified(
            artifact.relative_path,
            (artifact.sha256, artifact.size_bytes),
            max_bytes=limit,
        )

    def evaluate(self, case_display_id: str, role: MemberRole) -> ValidationResult:
        artifacts = self._artifacts.list_artifacts(case_display_id)
        if self._format is RuleFormat.YARA:
            matched, detail = self._evaluate_yara(artifacts)
        else:
            matched, detail = self._evaluate_sigma(artifacts)
        return ValidationResult(
            case_display_id,
            role,
            matched,
            classify(role.expected_malicious, matched),
            json.dumps(detail, sort_keys=True, ensure_ascii=False),
        )

    def _evaluate_yara(
        self, artifacts: list[Artifact]
    ) -> tuple[bool | None, dict[str, Any]]:
        targets = [a for a in artifacts if a.kind is ArtifactKind.SAMPLE]
        if not targets:
            return None, {"reason": "no sample artifact attached"}
        hits: list[dict[str, Any]] = []
        for artifact in targets:
            for match in yara_engine.scan(
                self._yara, self._read(artifact, MAX_SAMPLE_BYTES)
            ):
                hits.append(
                    {
                        "artifact": artifact.artifact_id.display_id,
                        "rule": match.rule,
                        "strings": [
                            {
                                "id": hit.identifier,
                                "offset": hit.offset,
                                "length": hit.length,
                            }
                            for hit in match.strings
                        ],
                    }
                )
        return bool(hits), {
            "scanned": [a.artifact_id.display_id for a in targets],
            "matches": hits,
        }

    def _evaluate_sigma(
        self, artifacts: list[Artifact]
    ) -> tuple[bool | None, dict[str, Any]]:
        targets = [a for a in artifacts if a.kind is ArtifactKind.SYSMON]
        if not targets:
            return None, {"reason": "no sysmon artifact attached"}
        records: list[SysmonRecord] = []
        for artifact in targets:
            records.extend(
                parse_sysmon_records(
                    self._read(artifact, MAX_RECORD_XML_BYTES), artifact.artifact_id
                )
            )
        matched = sigma_engine.evaluate(self._sigma, records)
        return bool(matched), {
            "records": len(records),
            "matched_records": [
                {
                    "artifact": (
                        None
                        if record.source_artifact_id is None
                        else record.source_artifact_id.display_id
                    ),
                    "record_id": record.record_id,
                    "event_id": record.event_id,
                }
                for record in matched[: sigma_engine.MAX_MATCHED_RECORDS]
            ],
            "matched_total": len(matched),
        }
