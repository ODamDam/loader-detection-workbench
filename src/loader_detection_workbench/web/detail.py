"""Detail panel content and ID links for the Case workspace.

``link_ids`` turns Workbench display IDs in already escaped text into links.
Every link has a normal ``href`` (works without JavaScript) and, inside a Case,
a ``data-detail`` URL that ``workbench.js`` loads into the side panel.
``detail_context`` resolves one reference for that panel, read-only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from flask import url_for
from markupsafe import Markup, escape

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.execution.service import ExecutionService
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.static_analysis.service import StaticAnalysisService
from loader_detection_workbench.sysmon.records import (
    MAX_RECORD_XML_BYTES,
    SysmonRecord,
    parse_sysmon_records,
)
from loader_detection_workbench.sysmon.relations import image_sha256, leaf_name

ID_PATTERN = re.compile(
    r"\b(?P<id>(?:ART-[0-9]{6,})(?:[#:][0-9]{1,12})?|CASE-[0-9]{4,}|FND-[0-9]{4,}"
    r"|RULE-[0-9]{4,}|VMR-[0-9]{4,}|SMP-[0-9]{6,}|BMK-[0-9]{4,}|RUN-[0-9]{4,}"
    r"|AIA-[0-9]{4,}|HYP-[0-9]{4,})\b",
    re.ASCII,
)
# Sysmon fields shown in the panel, in this order, when present. The local UI
# contract (docs/local-platform-ui-contract.md) never shows command lines or
# full paths: path fields are reduced to their last element (``leaf_name``).
_FIELDS = (
    ("UtcTime", "시각 (UTC)", False),
    ("Image", "프로세스", True),
    ("ProcessId", "PID", False),
    ("ParentImage", "부모 프로세스", True),
    ("TargetFilename", "파일", True),
    ("TargetObject", "레지스트리 값", True),
    ("ImageLoaded", "로드한 이미지", True),
    ("QueryName", "DNS 이름", False),
    ("DestinationPort", "목적지 포트", False),
)
_EVENT_NAMES = {
    1: "Process Create",
    3: "Network",
    5: "Process Terminated",
    7: "Image Load",
    11: "File Create",
    12: "Registry Create/Delete",
    13: "Registry Value Set",
    22: "DNS Query",
    23: "File Delete",
    26: "File Delete Logged",
}


def _href(ref: str, case_id: str | None) -> str:
    base = ref.split("#")[0].split(":")[0]
    if base.startswith("CASE-"):
        return url_for("web.workspace", case_display_id=base)
    if base.startswith("RULE-"):
        return url_for("web.rule_detail", rule_display_id=base)
    if base.startswith("RUN-"):
        return url_for("web.validation_run", run_display_id=base)
    if base.startswith("ART-") and case_id is not None:
        return url_for(
            "web.artifact_detail", case_display_id=case_id, artifact_display_id=base
        )
    return url_for("web.go", q=base)


def link_ids(text: object, case_id: str | None = None) -> Markup:
    """Escape ``text`` and link every Workbench ID in it."""
    escaped = str(escape(text))

    def replace(match: re.Match[str]) -> str:
        ref = match.group("id")
        href = escape(_href(ref, case_id))
        data = ""
        if case_id is not None:
            detail = url_for("web.case_detail_panel", case_display_id=case_id, ref=ref)
            data = f' data-detail="{escape(detail)}"'
        return f'<a class="id" href="{href}"{data}>{ref}</a>'

    return Markup(ID_PATTERN.sub(replace, escaped))


@dataclass(frozen=True, slots=True)
class Detail:
    title: str
    subtitle: str
    rows: tuple[tuple[str, str], ...]
    cited_by: tuple[str, ...] = ()
    link: str | None = None
    link_label: str | None = None
    text: str | None = None


@lru_cache(maxsize=8)
def _records(
    root: str, relative: ProjectRelativePath, sha256: str, size: int
) -> dict[str, SysmonRecord]:
    data = ArtifactStore(Path(root)).read_verified(
        relative, (sha256, size), max_bytes=MAX_RECORD_XML_BYTES
    )
    return {r.record_id or "": r for r in parse_sysmon_records(data)}


def _artifact(root: Path, case_id: str, artifact_id: str) -> Artifact:
    return ArtifactService(root).show(case_id, artifact_id)


def _cited_by(root: Path, case_id: str, ref: str) -> tuple[str, ...]:
    base = ref.split("#")[0]
    hits: list[str] = []
    for finding in FindingService(root).list_findings(case_id):
        refs = {str(item).replace(":", "#") for item in finding.content.evidence}
        if ref in refs or base in refs or ref in finding.content.finding_refs:
            hits.append(finding.display_id)
    return tuple(hits)


def detail_context(root: Path, case_id: str, ref: str) -> Detail:
    ref = ref.replace(":", "#")
    if ID_PATTERN.fullmatch(ref) is None:
        raise DomainError(DomainErrorCode.ARTIFACT_NOT_FOUND, "unknown reference")
    base, _, record = ref.partition("#")
    if base.startswith("ART-"):
        artifact = _artifact(root, case_id, base)
        if record:
            return _event_detail(root, case_id, artifact, record, ref)
        return _artifact_detail(root, case_id, artifact)
    if base.startswith("FND-"):
        finding = FindingService(root).show(base)
        content = finding.content
        rows = [
            ("종류", content.kind.value),
            ("상태", f"{finding.state.value} · r{finding.revision}"),
        ]
        if content.verdict is not None:
            rows.append(("판정", content.verdict.value))
        if content.evidence:
            rows.append(("근거", " ".join(str(e) for e in content.evidence)))
        if content.finding_refs:
            rows.append(("참조 소견", " ".join(content.finding_refs)))
        return Detail(
            base,
            content.title or "소견",
            tuple(rows),
            _cited_by(root, case_id, base),
            text=content.text,
        )
    if base.startswith("RULE-"):
        rule = DetectionService(root).show_rule(base)
        version = rule.latest
        rule_rows = (
            ("형식", rule.format.value),
            ("버전", f"v{version.version} · {version.status.value}"),
            ("SHA-256", version.sha256[:16] + "…"),
        )
        return Detail(
            base,
            rule.name,
            rule_rows,
            link=url_for("web.rule_detail", rule_display_id=base),
            link_label="룰 상세 열기",
        )
    if base.startswith("VMR-"):
        run = ExecutionService(root).show_run(base)
        run_rows = (
            ("Case", run.case_display_id),
            ("대상", run.target),
            ("상태", run.status.value),
            ("이벤트", "—" if run.event_count is None else str(run.event_count)),
            ("Sysmon", run.sysmon_artifact_id or "—"),
        )
        return Detail(base, "VM 실행", run_rows)
    return Detail(base, "", (), link=url_for("web.go", q=base), link_label="이동")


def _artifact_detail(root: Path, case_id: str, artifact: Artifact) -> Detail:
    aid = artifact.artifact_id.display_id
    rows: list[tuple[str, str]] = [
        ("종류", artifact.kind.value),
        ("크기", f"{artifact.size_bytes:,} B"),
        ("SHA-256", artifact.sha256[:16] + "…"),
    ]
    if artifact.kind in (ArtifactKind.SAMPLE, ArtifactKind.STATIC):
        static = _static_for(root, case_id, artifact)
        if static is not None:
            rows += [
                ("PE", "예" if static.is_pe else "아니오"),
                ("아키텍처", str(static.architecture or "—")),
                (
                    "엔트로피",
                    "—"
                    if static.file_entropy is None
                    else f"{static.file_entropy:.2f}",
                ),
                ("서명", str(static.signature or "—")),
            ]
    return Detail(
        aid,
        "Artifact",
        tuple(rows),
        _cited_by(root, case_id, aid),
        link=url_for(
            "web.artifact_detail", case_display_id=case_id, artifact_display_id=aid
        ),
        link_label="Artifact 상세 열기",
    )


def _static_for(root: Path, case_id: str, artifact: Artifact):  # type: ignore[no-untyped-def]
    service = StaticAnalysisService(root)
    aid = artifact.artifact_id.display_id
    for item in ArtifactService(root).list_artifacts(case_id):
        if item.kind is not ArtifactKind.STATIC:
            continue
        try:
            result = service.show(case_id, item.artifact_id.display_id)
        except DomainError:
            continue
        if item.artifact_id.display_id == aid or result.source_artifact_id == aid:
            return result
    return None


def _event_detail(
    root: Path, case_id: str, artifact: Artifact, record_id: str, ref: str
) -> Detail:
    if artifact.kind is not ArtifactKind.SYSMON:
        return _artifact_detail(root, case_id, artifact)
    records = _records(
        str(root),
        artifact.relative_path,
        artifact.sha256,
        artifact.size_bytes,
    )
    record = records.get(record_id)
    if record is None:
        return Detail(ref, "이 기록에 해당 이벤트가 없습니다", ())
    rows = tuple(
        (label, leaf_name(record.fields[name]) if leaf else str(record.fields[name]))
        for name, label, leaf in _FIELDS
        if record.fields.get(name)
    )
    sha256 = image_sha256(record.fields.get("Hashes"))
    if sha256 is not None:
        rows += (("이미지 SHA-256", sha256[:16] + "…"),)
    name = _EVENT_NAMES.get(record.event_id, f"Event {record.event_id}")
    return Detail(
        ref,
        f"Sysmon {record.event_id} · {name}",
        rows,
        _cited_by(root, case_id, ref),
        link=url_for("web.timeline", case_display_id=case_id),
        link_label="타임라인 열기",
    )
