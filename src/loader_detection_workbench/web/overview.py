"""Read-only view models for the overview pages (dashboard, samples, rules,
validation, outputs, environment).

Every number here is computed from the existing Application Services at request
time; nothing is cached or stored. Display text is Korean (UI only).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from loader_detection_workbench.ai.external import KEY_ENV, api_key
from loader_detection_workbench.ai.store import AiAnalysisReader
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.config import DEFAULT_AI_MODELS
from loader_detection_workbench.detection.domain import (
    DetectionRule,
    MemberRole,
    Outcome,
    RuleVersionStatus,
    ValidationRun,
)
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.case import CaseKind
from loader_detection_workbench.domain.errors import DomainError
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.execution.domain import (
    ExecutionRun,
    RunStatus,
    VmSettings,
)
from loader_detection_workbench.execution.service import (
    GUEST_RUN_OVERHEAD_SECONDS,
    ExecutionService,
)
from loader_detection_workbench.findings.domain import AnalystFinding, FindingState
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.project.manifest import load_manifest
from loader_detection_workbench.report.render import attack_summary
from loader_detection_workbench.sample.sqlite_repository import read_sample_registry

ROLE_LABELS = {
    "dev": "dev",
    "extra": "추가 dev",
    "eval": "eval",
    "benign": "정상",
    "other": "기타",
}
_REGISTRY_ROLES = {
    "malware_dev": "dev",
    "malware_eval": "eval",
    "unassigned": "extra",
}
STAGE_NAMES = ("정적", "동적", "AI", "소견 확정", "보고서")
_MALICIOUS = {MemberRole.DEV, MemberRole.UNSEEN}


def _database(root: Path) -> Path | None:
    manifest = root / "project.json"
    if not manifest.is_file():
        return None
    try:
        return load_manifest(manifest).database_path.resolve_under(root)
    except (DomainError, OSError, ValueError):
        return None


def sample_registry(root: Path) -> list[dict[str, str | None]]:
    database = _database(root)
    return [] if database is None else read_sample_registry(database)


@dataclass(slots=True)
class CaseRow:
    case_id: str
    name: str
    kind: str
    role: str
    family: str | None
    sample_id: str | None
    sample_count: int
    static_count: int
    sysmon_count: int
    last_vm: str | None
    ai_count: int
    findings_total: int
    confirmed: int
    stages: list[str] = field(default_factory=list)  # "done" | "part" | ""

    @property
    def role_label(self) -> str:
        return ROLE_LABELS.get(self.role, self.role)

    @property
    def dropped(self) -> int:
        """Collected files (ADR-032): sample Artifacts beyond the original."""
        return max(0, self.sample_count - 1) if self.kind == "malware" else 0

    @property
    def report_ready(self) -> bool:
        return self.confirmed > 0


def _family(name: str, registry_family: str | None) -> str | None:
    if registry_family:
        return registry_family
    first = name.split(" ", 1)[0]
    return first if first and first[0].isupper() else None


def case_rows(root: Path) -> list[CaseRow]:
    registry = {item["sha256"]: item for item in sample_registry(root)}
    artifacts = ArtifactService(root)
    findings = FindingService(root)
    ai = AiAnalysisReader(root)
    runs = ExecutionService(root).list_runs()
    rows: list[CaseRow] = []
    for case in CaseService(root).list_cases():
        cid = case.case_id.display_id
        items = artifacts.list_artifacts(cid)
        samples = [a for a in items if a.kind is ArtifactKind.SAMPLE]
        # The first stored sample is the analysed one; later ones are collected.
        entry = registry.get(samples[0].sha256.lower()) if samples else None
        if case.kind is CaseKind.BENIGN:
            role = "benign"
        elif entry is not None:
            role = _REGISTRY_ROLES.get(str(entry["role"]), "other")
        else:
            role = "other"
        case_findings = _findings(findings, cid)
        succeeded = [
            r
            for r in runs
            if r.case_display_id == cid and r.status is RunStatus.SUCCEEDED
        ]
        row = CaseRow(
            cid,
            case.name,
            case.kind.value,
            role,
            None
            if case.kind is CaseKind.BENIGN
            else _family(case.name, None if entry is None else entry["family"]),
            None if entry is None else str(entry["sample_id"]),
            len(samples),
            sum(1 for a in items if a.kind is ArtifactKind.STATIC),
            sum(1 for a in items if a.kind is ArtifactKind.SYSMON),
            succeeded[-1].display_id if succeeded else None,
            len(ai.list(cid)),
            sum(1 for f in case_findings if f.state is not FindingState.WITHDRAWN),
            sum(1 for f in case_findings if f.state is FindingState.CONFIRMED),
        )
        if case.kind is not CaseKind.BENIGN:
            row.stages = [
                "done" if row.static_count else "",
                "done" if row.sysmon_count else "",
                "done" if row.ai_count else "",
                "done"
                if row.findings_total and row.confirmed == row.findings_total
                else ("part" if row.findings_total else ""),
                "done" if row.report_ready else "",
            ]
        rows.append(row)
    return rows


def _findings(service: FindingService, case_id: str) -> list[AnalystFinding]:
    try:
        return service.list_findings(case_id)
    except DomainError:
        return []


# -- dashboard ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Activity:
    at: datetime
    text: str
    refs: tuple[str, ...]

    @property
    def when(self) -> str:
        return format_utc(self.at)[5:16].replace("T", " ")


def recent_activity(
    root: Path, rows: list[CaseRow], rules: list[DetectionRule], limit: int = 8
) -> list[Activity]:
    items: list[Activity] = []
    for run in ExecutionService(root).list_runs():
        if run.finished_at is not None:
            state = "성공" if run.status is RunStatus.SUCCEEDED else "실패"
            items.append(
                Activity(
                    run.finished_at,
                    f"VM 실행 {state}",
                    (run.display_id, run.case_display_id),
                )
            )
    for rule in rules:
        for version in rule.versions:
            if version.frozen_at is not None:
                items.append(
                    Activity(
                        version.frozen_at,
                        f"룰 v{version.version} 동결",
                        (rule.display_id,),
                    )
                )
    findings = FindingService(root)
    for row in rows:
        for finding in _findings(findings, row.case_id):
            for revision in finding.history:
                label = {
                    "create": "소견 초안 작성",
                    "edit": "소견 수정",
                    "confirm": "소견 확정",
                    "withdraw": "소견 취소",
                }.get(revision.action.value, "소견 변경")
                items.append(Activity(revision.at, label, (finding.display_id,)))
    for analysis in AiAnalysisReader(root).list():
        items.append(
            Activity(
                analysis.created_at,
                f"AI 의견 ({analysis.provider})",
                (analysis.display_id, analysis.case_display_id),
            )
        )
    items.sort(key=lambda item: item.at, reverse=True)
    return items[:limit]


def dashboard(root: Path) -> dict[str, object]:
    rows = case_rows(root)
    registry = sample_registry(root)
    roles = Counter(_REGISTRY_ROLES.get(str(i["role"]), "other") for i in registry)
    malicious = [r for r in rows if r.kind == "malware" and r.role != "eval"]
    dev = [r for r in rows if r.role == "dev"]
    runs = ExecutionService(root).list_runs()
    rules = DetectionService(root).list_rules()
    frozen = Counter(
        rule.format.value
        for rule in rules
        if any(v.status is RuleVersionStatus.FROZEN for v in rule.versions)
    )
    findings_total = sum(r.findings_total for r in dev)
    confirmed = sum(r.confirmed for r in dev)
    return {
        "samples_total": len(registry),
        "sample_roles": roles,
        "analysed": sum(1 for r in malicious if r.static_count and r.sysmon_count),
        "malicious_total": len(malicious),
        "vm_ok": sum(1 for r in runs if r.status is RunStatus.SUCCEEDED),
        "vm_total": len(runs),
        "findings_total": findings_total,
        "findings_confirmed": confirmed,
        "frozen_yara": frozen.get("yara", 0),
        "frozen_sigma": frozen.get("sigma", 0),
        "reports_ready": sum(1 for r in dev if r.report_ready),
        "dev_total": len(dev),
        "dev_rows": dev,
        "activity": recent_activity(root, rows, rules),
        "todo": _todo(rows, findings_total - confirmed),
    }


def _todo(rows: list[CaseRow], drafts: int) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if drafts:
        items.append(("확정", f"소견 초안 {drafts}개 검토·확정 (확정해야 보고서 생성)"))
    missing_ai = [r.case_id for r in rows if r.role == "dev" and not r.ai_count]
    if missing_ai:
        items.append(("AI", f"AI 의견 없음: {', '.join(missing_ai)}"))
    if any(r.role == "dev" and r.confirmed for r in rows):
        items.append(("AI", "확정 소견이 있는 Case의 synthesis 단계 의견"))
    items.append(("평가", "eval 샘플은 룰 동결 후 평가 런으로만 엽니다"))
    return items


# -- rules and validation -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleRow:
    rule: DetectionRule
    shown_version: int
    frozen: bool
    attack: str | None
    tp_cases: tuple[str, ...]
    malicious_cases: tuple[str, ...]
    fp_cases: tuple[str, ...]
    benign_cases: tuple[str, ...]


def _latest_runs(runs: Iterable[ValidationRun]) -> dict[tuple[str, str], ValidationRun]:
    latest: dict[tuple[str, str], ValidationRun] = {}
    for run in sorted(runs, key=lambda r: int(r.display_id.rpartition("-")[2])):
        latest[(run.rule_display_id, run.benchmark_display_id)] = run
    return latest


def rule_rows(root: Path) -> list[RuleRow]:
    detection = DetectionService(root)
    latest = _latest_runs(detection.list_runs())
    rows: list[RuleRow] = []
    for rule in detection.list_rules():
        frozen = [v for v in rule.versions if v.status is RuleVersionStatus.FROZEN]
        shown = frozen[-1] if frozen else rule.latest
        tp: set[str] = set()
        malicious: set[str] = set()
        fp: set[str] = set()
        benign: set[str] = set()
        for (rule_id, _), run in latest.items():
            if rule_id != rule.display_id:
                continue
            for result in run.results:
                if result.outcome is Outcome.NOT_EVALUABLE:
                    continue
                if result.role in _MALICIOUS:
                    malicious.add(result.case_display_id)
                    if result.outcome is Outcome.TP:
                        tp.add(result.case_display_id)
                else:
                    benign.add(result.case_display_id)
                    if result.outcome is Outcome.FP:
                        fp.add(result.case_display_id)
        rows.append(
            RuleRow(
                rule,
                shown.version,
                bool(frozen),
                attack_summary(rule, shown),
                tuple(sorted(tp)),
                tuple(sorted(malicious)),
                tuple(sorted(fp)),
                tuple(sorted(benign)),
            )
        )
    return rows


def validation_view(root: Path, benchmark_id: str | None) -> dict[str, object]:
    detection = DetectionService(root)
    benchmarks = detection.list_benchmarks()
    runs = detection.list_runs()
    chosen = next(
        (b for b in benchmarks if b.display_id == benchmark_id),
        benchmarks[-1] if benchmarks else None,
    )
    matrix: list[tuple[str, str, dict[str, str]]] = []
    if chosen is not None:
        latest = _latest_runs(
            r for r in runs if r.benchmark_display_id == chosen.display_id
        )
        for (rule_id, _), run in sorted(latest.items()):
            cells = {r.case_display_id: r.outcome.value for r in run.results}
            matrix.append((rule_id, run.display_id, cells))
    counts = Counter(r.benchmark_display_id for r in runs)
    return {
        "benchmarks": benchmarks,
        "run_counts": counts,
        "chosen": chosen,
        "matrix": matrix,
        "run_total": len(runs),
    }


# -- outputs and environment ------------------------------------------------------


def frozen_rules(root: Path) -> list[tuple[DetectionRule, int, str, str]]:
    """(rule, version, sha256, content) of each rule's newest frozen version."""
    items = []
    for rule in DetectionService(root).list_rules():
        frozen = [v for v in rule.versions if v.status is RuleVersionStatus.FROZEN]
        if frozen:
            version = frozen[-1]
            items.append((rule, version.version, version.sha256, version.content))
    return items


def environment(root: Path) -> dict[str, object]:
    service = ExecutionService(root)
    settings = VmSettings()
    lock = service.lock_status()
    runs: list[ExecutionRun] = service.list_runs()
    return {
        "settings": settings,
        "locked": lock.locked,
        "credentials": service.credentials_configured(),
        "overhead": GUEST_RUN_OVERHEAD_SECONDS,
        "last_run": runs[-1] if runs else None,
        "providers": [
            (name, DEFAULT_AI_MODELS[name], api_key(name) is not None)
            for name in KEY_ENV
        ],
    }
