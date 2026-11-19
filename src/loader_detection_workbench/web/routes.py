"""Thin HTTP routes over existing Application Services."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue

from loader_detection_workbench.ai.compare import latest_per_provider
from loader_detection_workbench.ai.domain import AnalysisStage, SuggestionKind
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.relations import CaseProcessRelationsQuery
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.detection.domain import (
    RunKind,
    ValidationRun,
    require_display_id,
)
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.case import CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.evidence.domain import (
    MANUAL_EVIDENCE_EXTENSIONS,
    EvidenceType,
)
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.execution.domain import ExecutionRun
from loader_detection_workbench.findings.domain import (
    AnalystFinding,
    FindingKind,
    FindingState,
    Verdict,
)
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.report.analysis import CaseAnalysisQuery
from loader_detection_workbench.report.render import render_html, render_markdown
from loader_detection_workbench.static_analysis.service import StaticAnalysisService
from loader_detection_workbench.sysmon.records import record_summary
from loader_detection_workbench.web.detection_views import (
    KIND_ORDER,
    KIND_TITLES,
    RunView,
    compare_versions,
    result_views,
    run_view,
    version_views,
)
from loader_detection_workbench.web.graph import evidence_graph, process_graph
from loader_detection_workbench.web.presentation import (
    artifact_views,
    timeline_event_views,
)

web = Blueprint("web", __name__)


def _root() -> Path:
    return cast(Path, current_app.config["WORKBENCH_PROJECT_ROOT"])


@web.get("/health")
def health() -> tuple[dict[str, str], int]:
    return {"status": "ready"}, 200


@web.get("/cases")
def cases() -> str:
    return render_template("cases.html", cases=CaseService(_root()).list_cases())


def _case_context(case_display_id: str) -> dict[str, object]:
    case = CaseService(_root()).show(case_display_id)
    artifacts = ArtifactService(_root()).list_artifacts(case_display_id)
    timeline = CaseTimelineQuery(_root()).query(case_display_id)
    migration_required = False
    try:
        evidence = ManualEvidenceService(_root()).list_evidence(case_display_id)
    except DomainError as error:
        if error.code is not DomainErrorCode.PROJECT_MIGRATION_REQUIRED:
            raise
        evidence = []
        migration_required = True
    return {
        "case": case,
        "case_created_at": format_utc(case.created_at),
        "case_updated_at": format_utc(case.updated_at),
        "artifacts": artifact_views(artifacts, evidence, timeline.observations),
        "artifact_count": len(artifacts),
        "evidence_count": len(evidence),
        "observation_count": len(timeline.observations),
        "migration_required": migration_required,
        "upload_available": (not migration_required and case.status is CaseStatus.OPEN),
    }


@web.get("/cases/<case_display_id>")
def case_detail(case_display_id: str) -> str:
    return render_template(
        "case_detail.html",
        **_case_context(case_display_id),
        uploaded=request.args.get("uploaded"),
    )


@web.get("/cases/<case_display_id>/artifacts/<artifact_display_id>")
def artifact_detail(case_display_id: str, artifact_display_id: str) -> str:
    context = _case_context(case_display_id)
    ArtifactService(_root()).show(case_display_id, artifact_display_id)
    artifact = next(
        (
            item
            for item in cast(tuple[object, ...], context["artifacts"])
            if getattr(item, "display_id", None) == artifact_display_id
        ),
        None,
    )
    if artifact is None:
        raise DomainError(
            DomainErrorCode.ARTIFACT_NOT_FOUND,
            "artifact was not found in the requested case",
        )
    observations = tuple(
        event
        for event in CaseTimelineQuery(_root()).query(case_display_id).observations
        if event.source_artifact_id.display_id == artifact_display_id
    )
    static_result = None
    if getattr(artifact, "kind", None) == "static":
        static_result = StaticAnalysisService(_root()).show(
            case_display_id, artifact_display_id
        )
    return render_template(
        "artifact_detail.html",
        case=context["case"],
        artifact=artifact,
        events=timeline_event_views(observations),
        migration_required=context["migration_required"],
        static_result=static_result,
    )


@web.get("/cases/<case_display_id>/evidence/new")
def evidence_form(case_display_id: str) -> str:
    context = _case_context(case_display_id)
    return render_template(
        "evidence_form.html",
        **context,
        evidence_types=tuple(EvidenceType),
        allowed_extensions=", ".join(sorted(MANUAL_EVIDENCE_EXTENSIONS)),
    )


@web.post("/cases/<case_display_id>/evidence")
def evidence_add(case_display_id: str) -> ResponseReturnValue:
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return (
            render_template(
                "error.html",
                status=400,
                code="EVIDENCE_FILE_REQUIRED",
                message="Select an evidence file to upload.",
            ),
            400,
        )
    temp_root = current_app.config.get("UPLOAD_TEMP_ROOT")
    with TemporaryDirectory(
        prefix="workbench-evidence-",
        dir=None if temp_root is None else str(temp_root),
    ) as directory:
        staged = Path(directory) / "upload"
        upload.save(staged)
        result = ManualEvidenceService(_root()).register(
            case_display_id,
            staged,
            source=request.form.get("source", ""),
            evidence_type=request.form.get("evidence_type", ""),
            description=request.form.get("description") or None,
            original_filename=upload.filename,
        )
    return redirect(
        url_for(
            "web.case_detail",
            case_display_id=case_display_id,
            uploaded=result.artifact.artifact_id.display_id,
        ),
        code=303,
    )


@web.get("/cases/<case_display_id>/timeline")
def timeline(case_display_id: str) -> str:
    result = CaseTimelineQuery(_root()).query(case_display_id)
    other_events = [
        {
            "timestamp": "—"
            if record.timestamp is None
            else format_utc(record.timestamp),
            "event_id": record.event_id,
            "summary": record_summary(record, include_paths=False),
            "artifact_id": (
                "—"
                if record.source_artifact_id is None
                else record.source_artifact_id.display_id
            ),
            "record_id": record.record_id or "—",
        }
        for record in result.other_records
    ]
    return render_template(
        "timeline.html",
        case=result.case,
        events=timeline_event_views(result.observations),
        artifact_count=result.sysmon_artifact_count,
        other_events=other_events,
    )


@web.get("/cases/<case_display_id>/report")
def report_preview(case_display_id: str) -> str:
    result = CaseTimelineQuery(_root()).query(case_display_id)
    return render_template(
        "report_preview.html",
        case=result.case,
        generated_at=format_utc(utc_now()),
        events=timeline_event_views(result.observations),
        artifact_count=result.sysmon_artifact_count,
    )


def _runs_by_kind(
    runs: list[ValidationRun] | tuple[ValidationRun, ...],
    case_display_id: str | None = None,
) -> list[tuple[str, list[RunView]]]:
    grouped: dict[RunKind, list[RunView]] = {}
    for run in runs:
        grouped.setdefault(run.kind, []).append(run_view(run, case_display_id))
    return [
        (KIND_TITLES[kind], grouped[kind]) for kind in KIND_ORDER if kind in grouped
    ]


@web.get("/cases/<case_display_id>/analysis")
def case_analysis(case_display_id: str) -> str:
    result = CaseTimelineQuery(_root()).query(case_display_id)
    analysis = CaseAnalysisQuery(_root()).query(result)
    relations = CaseProcessRelationsQuery(_root()).query(result)
    graph = evidence_graph(
        analysis,
        artifact_href={
            artifact.artifact_id.display_id: url_for(
                "web.artifact_detail",
                case_display_id=case_display_id,
                artifact_display_id=artifact.artifact_id.display_id,
            )
            for artifact in analysis.artifacts
        },
        rule_href={
            rule.display_id: url_for("web.rule_detail", rule_display_id=rule.display_id)
            for rule in analysis.rules
        },
        run_href={
            run.display_id: url_for("web.validation_run", run_display_id=run.display_id)
            for run in analysis.validation_runs
        },
    )
    execution_runs = [
        {
            "display_id": run.display_id,
            "profile": run.profile.value,
            "target": run.target,
            "status": run.status.value,
            "error_code": run.error_code,
            "started_at": format_utc(run.started_at),
            "event_count": "—" if run.event_count is None else run.event_count,
            "sysmon_artifact_id": run.sysmon_artifact_id or "—",
            # Step names and results only; recorded step detail is never shown.
            "steps": ", ".join(f"{s.step.value} {s.status.value}" for s in run.steps),
        }
        for run in analysis.execution_runs
    ]
    return render_template(
        "case_analysis.html",
        case=result.case,
        analysis=analysis,
        evidence_graph=graph,
        process_graph=process_graph(relations),
        relations=relations,
        runs_by_kind=_runs_by_kind(analysis.validation_runs, case_display_id),
        execution_runs=execution_runs,
    )


@web.get("/detection")
def detection_overview() -> str:
    service = DetectionService(_root())
    return render_template(
        "detection.html",
        rules=service.list_rules(),
        benchmarks=service.list_benchmarks(),
        runs_by_kind=_runs_by_kind(service.list_runs()),
    )


@web.get("/rules/<rule_display_id>")
def rule_detail(rule_display_id: str) -> str:
    service = DetectionService(_root())
    rule = service.show_rule(rule_display_id)
    runs = service.list_runs(rule_display_id)
    return render_template(
        "rule_detail.html",
        rule=rule,
        created_at=format_utc(rule.created_at),
        versions=version_views(rule),
        hypotheses=[
            hypothesis
            for hypothesis in service.list_hypotheses()
            if rule_display_id in hypothesis.rule_display_ids
        ],
        comparisons=compare_versions(rule, runs, service.list_benchmarks()),
        kind_titles=[KIND_TITLES[kind] for kind in KIND_ORDER],
        runs_by_kind=_runs_by_kind(runs),
    )


@web.get("/validation/<run_display_id>")
def validation_run(run_display_id: str) -> str:
    require_display_id("run", run_display_id)
    run = DetectionService(_root()).show_run(run_display_id)
    return render_template(
        "validation_run.html",
        run=run_view(run),
        rule_sha256=run.rule_sha256,
        results=result_views(run),
    )


# -- Case workspace (ADR-031) ---------------------------------------------------

WORKSPACE_TABS = ("overview", "evidence", "process", "ai", "findings", "report")
_ADOPTABLE = frozenset(
    {
        SuggestionKind.HYPOTHESIS,
        SuggestionKind.HYPOTHESIS_CANDIDATE,
        SuggestionKind.KEY_HYPOTHESIS,
        SuggestionKind.MECHANISM,
    }
)


def _form(name: str) -> str | None:
    value = request.form.get(name, "").strip()
    return value or None


def _form_list(name: str) -> list[str]:
    return [
        item for item in request.form.get(name, "").replace(",", " ").split() if item
    ]


def _form_refs(name: str) -> list[str] | None:
    """References from an edit form; a field that was not sent keeps its value."""
    return _form_list(name) if name in request.form else None


def _workspace_ai(case_display_id: str, stage: AnalysisStage) -> dict[str, object]:
    """Opinions of the newest analysis per provider, shared groups first.

    Each item carries the Korean reading translation (ADR-033) when stored; the
    English text stays the record and is one toggle away.
    """
    service = AiAnalysisService(_root())
    staged = [a for a in service.list_analyses(case_display_id) if a.stage is stage]
    columns = latest_per_provider(staged) if staged else []
    korean = {a.display_id: service.translations(a.display_id) for a in columns}
    suggestions = {
        (a.display_id, s.sequence): (a, s) for a in columns for s in a.suggestions
    }

    def item(
        analysis_id: str, sequence: int, providers: tuple[str, ...]
    ) -> dict[str, object]:
        analysis, suggestion = suggestions[(analysis_id, sequence)]
        ko = korean.get(analysis_id, {}).get(sequence)
        return {
            "analysis": analysis,
            "s": suggestion,
            "providers": providers,
            "ko_title": None if ko is None else ko[0],
            "ko_text": None if ko is None else ko[1],
            "adoptable": suggestion.kind in _ADOPTABLE,
        }

    groups: list[tuple[str, list[dict[str, object]]]] = []
    comparison = None
    if len(columns) >= 2:
        try:
            comparison = service.compare(
                case_display_id, [analysis.display_id for analysis in columns]
            )
        except DomainError:
            comparison = None  # e.g. providers answered different inputs
    if comparison is not None:
        shared = [
            item(g.opinions[0].analysis_display_id, g.opinions[0].sequence, g.providers)
            for g in comparison.common
        ]
        single = [
            item(o.analysis_display_id, o.sequence, (o.provider,))
            for g in comparison.individual
            for o in g.opinions
        ]
        groups = [("공통 의견", shared), ("개별 의견", single)]
    else:
        groups = [
            (
                f"{a.provider} 의견",
                [item(a.display_id, s.sequence, (a.provider,)) for s in a.suggestions],
            )
            for a in columns
        ]
    return {
        "columns": columns,
        "ai_groups": [(label, items) for label, items in groups if items],
        "has_korean": any(korean.values()),
    }


_KIND_ORDER = (
    FindingKind.EVIDENCE,
    FindingKind.HYPOTHESIS,
    FindingKind.LINK,
    FindingKind.MECHANISM,
)
KIND_LABELS = {
    FindingKind.EVIDENCE: "증거",
    FindingKind.HYPOTHESIS: "가설",
    FindingKind.LINK: "연결",
    FindingKind.MECHANISM: "작동 원리",
}


def _review_queue(
    findings: list[AnalystFinding],
) -> list[tuple[str, list[dict[str, object]]]]:
    """Findings by kind in confirmation order; drafts first inside each kind.

    A link or mechanism waits while a finding it cites is not confirmed yet.
    """
    state = {f.display_id: f.state for f in findings}
    queue = []
    for kind in _KIND_ORDER:
        items = [f for f in findings if f.kind is kind]
        items.sort(key=lambda f: (f.state is not FindingState.DRAFT, f.display_id))
        queue.append(
            (
                KIND_LABELS[kind],
                [
                    {
                        "f": f,
                        "waiting": [
                            ref
                            for ref in f.content.finding_refs
                            if state.get(ref) is not FindingState.CONFIRMED
                        ],
                    }
                    for f in items
                ],
            )
        )
    return queue


def _evidence_groups(
    artifacts: tuple[Artifact, ...], runs: list[ExecutionRun]
) -> list[tuple[str, list[tuple[Artifact, str]]]]:
    by_sysmon = {
        r.sysmon_artifact_id: r.display_id for r in runs if r.sysmon_artifact_id
    }
    samples = [a for a in artifacts if a.kind is ArtifactKind.SAMPLE]
    groups: dict[str, list[tuple[Artifact, str]]] = {
        "샘플": [],
        "정적 분석": [],
        "VM 실행 (Sysmon)": [],
        "회수한 파일": [],
        "기타": [],
    }
    for artifact in artifacts:
        aid = artifact.artifact_id.display_id
        if artifact.kind is ArtifactKind.SAMPLE:
            key = "샘플" if artifact is samples[0] else "회수한 파일"
            groups[key].append((artifact, ""))
        elif artifact.kind is ArtifactKind.STATIC:
            groups["정적 분석"].append((artifact, ""))
        elif artifact.kind is ArtifactKind.SYSMON:
            groups["VM 실행 (Sysmon)"].append((artifact, by_sysmon.get(aid, "")))
        else:
            groups["기타"].append((artifact, ""))
    return [(label, items) for label, items in groups.items() if items]


@web.get("/cases/<case_display_id>/workspace")
def workspace(case_display_id: str) -> str:
    tab = request.args.get("tab", "overview")
    tab = {"hypotheses": "findings"}.get(tab, tab)
    if tab not in WORKSPACE_TABS:
        tab = "overview"
    stage_value = request.args.get("stage", AnalysisStage.COLLECTION.value)
    stage = AnalysisStage.parse(stage_value)
    timeline = CaseTimelineQuery(_root()).query(case_display_id)
    analysis = CaseAnalysisQuery(_root()).query(timeline)
    findings = FindingService(_root()).list_findings(case_display_id)
    live = [f for f in findings if f.state is not FindingState.WITHDRAWN]
    ai_count = len(AiAnalysisService(_root()).list_analyses(case_display_id))
    context: dict[str, object] = {
        "case": timeline.case,
        "tab": tab,
        "tabs": WORKSPACE_TABS,
        "stage": stage.value,
        "analysis": analysis,
        "artifacts": analysis.artifacts,
        "observation_count": len(timeline.observations),
        "record_count": len(timeline.other_records),
        "findings": findings,
        "live_count": len(live),
        "confirmed_count": sum(
            1 for f in findings if f.state is FindingState.CONFIRMED
        ),
        "draft_count": sum(1 for f in findings if f.state is FindingState.DRAFT),
        "ai_count": ai_count,
        "kind_labels": {k.value: v for k, v in KIND_LABELS.items()},
        "verdicts": tuple(Verdict),
        "editable": timeline.case.status is CaseStatus.OPEN,
        "format_utc": format_utc,
        "execution_runs": analysis.execution_runs,
    }
    if tab == "overview":
        context["stages"] = [
            (
                "정적 분석",
                any(a.kind is ArtifactKind.STATIC for a in analysis.artifacts),
            ),
            (
                "동적 분석",
                any(a.kind is ArtifactKind.SYSMON for a in analysis.artifacts),
            ),
            ("AI 의견", ai_count > 0),
            (
                "소견 확정",
                bool(live) and all(f.state is FindingState.CONFIRMED for f in live),
            ),
            ("보고서", any(f.state is FindingState.CONFIRMED for f in live)),
        ]
    elif tab == "evidence":
        context["evidence_groups"] = _evidence_groups(
            analysis.artifacts, list(analysis.execution_runs)
        )
    elif tab == "process":
        relations = CaseProcessRelationsQuery(_root()).query(timeline)
        context["process_graph"] = process_graph(relations)
        context["relations"] = relations
    elif tab == "findings":
        context["queue"] = _review_queue(findings)
    elif tab == "ai":
        context.update(_workspace_ai(case_display_id, stage))
    return render_template("workspace.html", **context)


def _back(case_display_id: str, tab: str = "findings") -> ResponseReturnValue:
    return redirect(
        url_for("web.workspace", case_display_id=case_display_id, tab=tab), code=303
    )


@web.post("/cases/<case_display_id>/findings")
def finding_create(case_display_id: str) -> ResponseReturnValue:
    FindingService(_root()).create(
        case_display_id,
        request.form.get("kind", ""),
        request.form.get("text", ""),
        title=_form("title"),
        verdict=_form("verdict"),
        evidence=_form_list("evidence"),
        hypothesis=_form("hypothesis"),
        findings=_form_list("findings"),
        note=_form("note"),
    )
    return _back(case_display_id)


@web.post("/cases/<case_display_id>/findings/<finding_display_id>/edit")
def finding_edit(case_display_id: str, finding_display_id: str) -> ResponseReturnValue:
    finding = FindingService(_root()).show(finding_display_id)
    if finding.case_display_id != case_display_id:
        raise DomainError(DomainErrorCode.FINDING_NOT_FOUND, "finding was not found")
    kind = finding.kind
    FindingService(_root()).edit(
        finding_display_id,
        text=_form("text"),
        title=_form("title"),
        verdict=_form("verdict") if kind is FindingKind.HYPOTHESIS else None,
        evidence=_form_refs("evidence") if kind is FindingKind.EVIDENCE else None,
        findings=(
            _form_refs("findings")
            if kind in (FindingKind.LINK, FindingKind.MECHANISM)
            else None
        ),
        note=_form("note"),
    )
    return _back(case_display_id)


@web.post("/cases/<case_display_id>/findings/<finding_display_id>/<action>")
def finding_transition(
    case_display_id: str, finding_display_id: str, action: str
) -> ResponseReturnValue:
    service = FindingService(_root())
    if service.show(finding_display_id).case_display_id != case_display_id:
        raise DomainError(DomainErrorCode.FINDING_NOT_FOUND, "finding was not found")
    if action == "confirm":
        service.confirm(finding_display_id, _form("note"))
    elif action == "withdraw":
        service.withdraw(finding_display_id, request.form.get("note", ""))
    else:
        raise DomainError(DomainErrorCode.INVALID_FINDING, "unknown finding action")
    return _back(case_display_id)


@web.post("/cases/<case_display_id>/ai/<analysis_display_id>/<int:sequence>/adopt")
def ai_adopt(
    case_display_id: str, analysis_display_id: str, sequence: int
) -> ResponseReturnValue:
    analysis = AiAnalysisService(_root()).show(analysis_display_id)
    if analysis.case_display_id != case_display_id:
        raise DomainError(
            DomainErrorCode.AI_ANALYSIS_NOT_FOUND, "AI analysis was not found"
        )
    FindingService(_root()).adopt(analysis_display_id, sequence, _form("note"))
    return _back(case_display_id)


@web.get("/cases/<case_display_id>/workspace/report.<fmt>")
def workspace_report(case_display_id: str, fmt: str) -> ResponseReturnValue:
    if fmt not in ("html", "md"):
        abort(404)
    timeline = CaseTimelineQuery(_root()).query(case_display_id)
    analysis = CaseAnalysisQuery(_root()).query(timeline)
    if fmt == "html":
        body = render_html(timeline, utc_now(), analysis)
        return body, 200, {"Content-Type": "text/html; charset=utf-8"}
    body = render_markdown(timeline, utc_now(), analysis)
    return (
        body,
        200,
        {
            "Content-Type": "text/markdown; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{case_display_id}.md"',
        },
    )
