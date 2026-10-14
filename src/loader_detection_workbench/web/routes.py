"""Thin HTTP routes over existing Application Services."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from flask import Blueprint, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.case import CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.evidence.domain import (
    MANUAL_EVIDENCE_EXTENSIONS,
    EvidenceType,
)
from loader_detection_workbench.evidence.service import ManualEvidenceService
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
        "artifacts": artifact_views(artifacts, evidence),
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
    return render_template(
        "timeline.html",
        case=result.case,
        events=timeline_event_views(result.observations),
        artifact_count=result.sysmon_artifact_count,
    )
