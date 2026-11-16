"""Thin HTTP routes over existing Application Services."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from flask import Blueprint, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

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
from loader_detection_workbench.domain.case import CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.evidence.domain import (
    MANUAL_EVIDENCE_EXTENSIONS,
    EvidenceType,
)
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.report.analysis import CaseAnalysisQuery
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


@web.get("/")
def index() -> ResponseReturnValue:
    return redirect(url_for("web.cases"))


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
