"""Overview pages of the redesigned UI: dashboard, samples, rules, validation,
outputs, environment, ID search and the workspace detail panel.

Read-only except the ruleset download, which only packages frozen rule
versions that are already stored.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import cast

from flask import abort, current_app, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue

from loader_detection_workbench.ai.store import AiAnalysisReader
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.execution.service import ExecutionService
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.web import overview
from loader_detection_workbench.web.detail import ID_PATTERN, detail_context
from loader_detection_workbench.web.routes import web

_SAMPLE_FILTERS = {
    "all": "전체",
    "dev": "dev",
    "extra": "추가 dev",
    "eval": "eval",
    "benign": "정상",
}


def _root() -> Path:
    return cast(Path, current_app.config["WORKBENCH_PROJECT_ROOT"])


@web.get("/")
def dashboard() -> str:
    return render_template("dashboard.html", **overview.dashboard(_root()))


@web.get("/samples")
def samples() -> str:
    selected = request.args.get("filter", "all")
    if selected not in _SAMPLE_FILTERS:
        selected = "all"
    rows = overview.case_rows(_root())
    registry = overview.sample_registry(_root())
    shown = [r for r in rows if selected == "all" or r.role == selected]
    malicious = [r for r in rows if r.kind == "malware" and r.role != "eval"]
    dev = [r for r in rows if r.role == "dev"]
    eval_samples = [
        str(item["sample_id"]) for item in registry if item["role"] == "malware_eval"
    ]
    counts = {key: sum(1 for r in rows if r.role == key) for key in _SAMPLE_FILTERS}
    counts["all"] = len(rows)
    return render_template(
        "samples.html",
        rows=shown,
        filters=_SAMPLE_FILTERS,
        selected=selected,
        counts=counts,
        malicious=malicious,
        dev=dev,
        benign=[r for r in rows if r.role == "benign"],
        eval_samples=eval_samples,
        eval_cases=[r for r in rows if r.role == "eval"],
    )


@web.get("/rules")
def rules() -> str:
    selected = request.args.get("format", "all")
    rows = overview.rule_rows(_root())
    shown = [r for r in rows if selected == "all" or r.rule.format.value == selected]
    malicious = sorted({c for r in rows for c in r.malicious_cases})
    detected = sorted({c for r in rows for c in r.tp_cases})
    benign = sorted({c for r in rows for c in r.benign_cases})
    false_positives = sorted({c for r in rows for c in r.fp_cases})
    return render_template(
        "rules.html",
        rows=shown,
        selected=selected,
        totals={
            fmt: (
                sum(1 for r in rows if r.rule.format.value == fmt and r.frozen),
                sum(1 for r in rows if r.rule.format.value == fmt and not r.frozen),
            )
            for fmt in ("yara", "sigma")
        },
        malicious=malicious,
        detected=detected,
        benign=benign,
        false_positives=false_positives,
    )


@web.get("/validation")
def validation() -> str:
    return render_template(
        "validation.html",
        **overview.validation_view(_root(), request.args.get("benchmark")),
    )


@web.get("/outputs")
def outputs() -> str:
    rows = [r for r in overview.case_rows(_root()) if r.kind == "malware"]
    return render_template(
        "outputs.html",
        rows=[r for r in rows if r.role != "eval"],
        frozen=overview.frozen_rules(_root()),
        ai_cases=sorted({a.case_display_id for a in AiAnalysisReader(_root()).list()}),
    )


@web.get("/outputs/frozen-rules.zip")
def frozen_rules_zip() -> ResponseReturnValue:
    frozen = overview.frozen_rules(_root())
    buffer = io.BytesIO()
    manifest = []
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for rule, version, sha256, content in frozen:
            suffix = "yar" if rule.format.value == "yara" else "yml"
            name = f"{rule.format.value}/{rule.display_id}-v{version}.{suffix}"
            archive.writestr(name, content)
            manifest.append(
                {
                    "rule": rule.display_id,
                    "name": rule.name,
                    "format": rule.format.value,
                    "version": version,
                    "sha256": sha256,
                    "file": name,
                }
            )
        archive.writestr(
            "manifest.json",
            json.dumps(
                {"exported_at": format_utc(utc_now()), "rules": manifest},
                indent=2,
                ensure_ascii=False,
            ),
        )
    return (
        buffer.getvalue(),
        200,
        {
            "Content-Type": "application/zip",
            "Content-Disposition": 'attachment; filename="frozen-rules.zip"',
        },
    )


@web.get("/environment")
def environment() -> str:
    return render_template("environment.html", **overview.environment(_root()))


@web.get("/go")
def go() -> ResponseReturnValue:
    """Jump to the page of one Workbench ID typed into the header search."""
    query = request.args.get("q", "").strip().upper().replace(":", "#")
    match = ID_PATTERN.fullmatch(query)
    target = _resolve(match.group("id")) if match else None
    if target is None:
        return render_template("not_found.html", query=query[:40]), 404
    return redirect(target)


def _resolve(ref: str) -> str | None:
    root = _root()
    base = ref.split("#")[0]
    try:
        if base.startswith("CASE-"):
            CaseService(root).show(base)
            return url_for("web.workspace", case_display_id=base)
        if base.startswith("RULE-"):
            DetectionService(root).show_rule(base)
            return url_for("web.rule_detail", rule_display_id=base)
        if base.startswith("RUN-"):
            return url_for("web.validation_run", run_display_id=base)
        if base.startswith("BMK-"):
            return url_for("web.validation", benchmark=base)
        if base.startswith("FND-"):
            finding = FindingService(root).show(base)
            return url_for(
                "web.workspace", case_display_id=finding.case_display_id, tab="findings"
            )
        if base.startswith("AIA-"):
            analysis = AiAnalysisReader(root).show(base)
            return url_for(
                "web.workspace", case_display_id=analysis.case_display_id, tab="ai"
            )
        if base.startswith("VMR-"):
            run = ExecutionService(root).show_run(base)
            return url_for("web.workspace", case_display_id=run.case_display_id)
        if base.startswith("ART-"):
            artifacts = ArtifactService(root)
            for case in CaseService(root).list_cases():
                cid = case.case_id.display_id
                if any(
                    a.artifact_id.display_id == base
                    for a in artifacts.list_artifacts(cid)
                ):
                    return url_for(
                        "web.artifact_detail",
                        case_display_id=cid,
                        artifact_display_id=base,
                    )
        if base.startswith("SMP-"):
            for row in overview.case_rows(root):
                if row.sample_id == base:
                    return url_for("web.workspace", case_display_id=row.case_id)
            return url_for("web.samples")
    except DomainError:
        return None
    return None


@web.get("/cases/<case_display_id>/detail")
def case_detail_panel(case_display_id: str) -> str:
    ref = request.args.get("ref", "")
    if ID_PATTERN.fullmatch(ref.replace(":", "#")) is None:
        abort(404)
    detail = detail_context(_root(), case_display_id, ref)
    return render_template("_detail.html", detail=detail, cid=case_display_id)
