"""Bounded, structural evidence digest: the only input a provider receives.

Scope ``structural`` (ADR-026) is an allowlist. It carries counts, categories,
API and file *names*, and display IDs (including which recorded sample a
process image is identical to, by display ID). It never carries sample bytes, raw
Sysmon XML, extracted strings, indicator values, command lines, directories,
hashes, ProcessGuids, host or user names, or analyst free text.

Widening this scope, and sending any digest to a provider outside this
machine, are separate decisions that need the project owner's approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.report.analysis import CaseAnalysis
from loader_detection_workbench.sysmon.relations import (
    ProcessRelations,
    prioritized_processes,
)

# 2 adds ``same_file_as``: the display ID a process image is identical to.
DIGEST_VERSION = 2
DIGEST_SCOPE = "structural"
# Synthesis (ADR-031) adds the analyst's confirmed findings to the same digest.
SYNTHESIS_SCOPE = "structural+findings"
APPROVED_SCOPES = frozenset({DIGEST_SCOPE, SYNTHESIS_SCOPE})
MAX_FINDINGS = 60
MAX_IMPORT_DLLS = 32
MAX_IMPORT_FUNCTIONS = 40
MAX_SECTIONS = 32
MAX_PROCESSES = 40
MAX_FLAGS = 32
_NAME = re.compile(r"[A-Za-z0-9_.@?$+\- ]{1,64}", re.ASCII)
_PLACEHOLDER = "(non-standard name)"
_DISPLAY_ID = re.compile(r"(?:ART|SMP)-[0-9]{6}", re.ASCII)
# Analyzer leads look like ``notable_imports:LoadLibraryA,VirtualAlloc``.
_LEAD = re.compile(r"[A-Za-z0-9_.:,\-]{1,160}", re.ASCII)


def safe_lead(value: object) -> str:
    if isinstance(value, str) and _LEAD.fullmatch(value) is not None:
        return value
    return _PLACEHOLDER


def safe_name(value: object) -> str:
    """Keep only short plain names; anything else becomes a fixed placeholder."""
    if isinstance(value, str) and _NAME.fullmatch(value) is not None:
        return value
    return _PLACEHOLDER


def _extension(name: str) -> str:
    suffix = name.rpartition(".")[2] if "." in name else ""
    return f".{suffix.lower()}" if re.fullmatch(r"[A-Za-z0-9]{1,8}", suffix) else ""


def _number(value: object) -> float | int | None:
    return (
        value
        if isinstance(value, int | float) and not isinstance(value, bool)
        else None
    )


def _findings(analysis: CaseAnalysis) -> list[dict[str, Any]]:
    """Confirmed findings in the analyst's own words (synthesis input)."""
    items: list[dict[str, Any]] = []
    for finding in analysis.findings[:MAX_FINDINGS]:
        content = finding.content
        items.append(
            {
                "id": finding.display_id,
                "kind": content.kind.value,
                "title": content.title,
                "text": content.text,
                "verdict": None if content.verdict is None else content.verdict.value,
                "evidence": [str(ref) for ref in content.evidence],
                "findings": list(content.finding_refs),
            }
        )
    return items


def build_digest(
    timeline: CaseTimeline,
    analysis: CaseAnalysis,
    relations: ProcessRelations,
    stage: str | None = None,
) -> dict[str, Any]:
    """Build the provider input; ``stage`` is ``collection`` or ``synthesis``.

    Without a stage the ADR-026 digest is produced unchanged. The synthesis
    digest additionally carries the Case's confirmed findings.
    """
    event_counts: dict[str, int] = {}
    for event in timeline.observations:
        key = str(event.event_id)
        event_counts[key] = event_counts.get(key, 0) + 1
    for record in timeline.other_records:
        key = str(record.event_id)
        event_counts[key] = event_counts.get(key, 0) + 1

    static: list[dict[str, Any]] = []
    for result in analysis.static_results:
        static.append(
            {
                "artifact": result.artifact.artifact_id.display_id,
                "source_artifact": safe_name(result.source_artifact_id),
                "status": safe_name(result.status),
                "is_pe": bool(result.is_pe),
                "architecture": safe_name(result.architecture),
                "file_entropy": _number(result.file_entropy),
                "is_dll": result.is_dll if isinstance(result.is_dll, bool) else None,
                "signature": safe_name(result.signature),
                "overlay_size": result.overlay_size,
                "export_count": result.export_count,
                "import_function_count": result.import_function_count,
                "strings_total": result.strings_total,
                "sections": [
                    {
                        "name": safe_name(section.name),
                        "entropy": _number(section.entropy),
                        "executable": section.executable,
                        "writable": section.writable,
                    }
                    for section in result.sections[:MAX_SECTIONS]
                ],
                "imports": [
                    {
                        "dll": safe_name(entry.dll),
                        "functions": [
                            safe_name(name)
                            for name in entry.functions[:MAX_IMPORT_FUNCTIONS]
                        ],
                    }
                    for entry in result.imports[:MAX_IMPORT_DLLS]
                ],
                "leads": [safe_lead(flag) for flag in result.flags[:MAX_FLAGS]],
                # Counts only: indicator values stay in the Project.
                "indicator_counts": {
                    safe_name(kind): len(values)
                    for kind, values in sorted(result.indicators.items())
                },
            }
        )

    # Workbench's own guest processes (runner, event export) are not evidence
    # about the sample; models mistook them for sample behavior (ADR-031).
    candidates = prioritized_processes(relations.processes)
    excluded = relations.workbench_total
    selected = [p for p in candidates if not p.workbench][:MAX_PROCESSES]
    keys = [process.key for process in selected]
    processes: list[dict[str, Any]] = []
    for index, process in enumerate(selected):
        parent = keys.index(process.parent_key) if process.parent_key in keys else None
        processes.append(
            {
                "index": index,
                "parent_index": parent,
                "image_name": safe_name(process.image_name),
                "captured": process.captured,
                "source_artifact": (
                    None if process.source is None else process.source.partition("#")[0]
                ),
                "activity": dict(sorted(process.activity.items())),
                # A display ID, never the hash itself.
                "same_file_as": (
                    process.same_as
                    if process.same_as is not None
                    and _DISPLAY_ID.fullmatch(process.same_as) is not None
                    else None
                ),
                "files_written": process.file_total,
                "file_extensions": sorted(
                    {ext for f in process.files if (ext := _extension(f.name))}
                ),
            }
        )

    digest: dict[str, Any] = {
        "digest_version": DIGEST_VERSION,
        "scope": DIGEST_SCOPE,
        "case": {
            "display_id": timeline.case.case_id.display_id,
            "kind": timeline.case.kind.value,
        },
        "artifacts": [
            {"id": artifact.artifact_id.display_id, "kind": artifact.kind.value}
            for artifact in analysis.artifacts
        ],
        "static": static,
        "sysmon": {
            "artifact_count": timeline.sysmon_artifact_count,
            "record_total": relations.record_total,
            "event_id_counts": dict(
                sorted(event_counts.items(), key=lambda i: int(i[0]))
            ),
            "process_total": relations.process_total,
            "workbench_processes_excluded": excluded,
            "processes": processes,
        },
        "vm_runs": [
            {
                "id": run.display_id,
                "profile": run.profile.value,
                "status": run.status.value,
                "event_count": run.event_count,
            }
            for run in analysis.execution_runs
        ],
        "recorded": {
            "hypotheses": len(analysis.hypotheses),
            "rules": len(analysis.rules),
            "validation_runs": len(analysis.validation_runs),
        },
    }
    if stage is not None:
        digest["stage"] = stage
    if stage == "synthesis":
        digest["scope"] = SYNTHESIS_SCOPE
        digest["findings"] = _findings(analysis)
    return digest


def serialize_digest(digest: dict[str, Any]) -> str:
    """Canonical JSON so the stored input and its SHA-256 are reproducible."""
    return json.dumps(digest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_sha256(serialized: str) -> str:
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
