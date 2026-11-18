"""Pure rendering of a Case report from the shared query results.

The report body is built from analyst-confirmed findings only (ADR-031).
Everything the Workbench recorded or computed (evidence summary, static PE
evidence, timeline, VM runs, working hypotheses, rules and validation) follows
in "Appendix A", and AI suggestions in "Appendix B"; neither is a conclusion.
Sections without recorded data are omitted.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from loader_detection_workbench.ai.compare import compare_analyses, latest_per_provider
from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.detection.domain import (
    DetectionRule,
    RuleVersion,
    RuleVersionStatus,
    RunKind,
    ValidationResult,
    ValidationRun,
)
from loader_detection_workbench.domain.events import ProcessCreateEvent
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.execution.domain import ExecutionRun
from loader_detection_workbench.findings.domain import AnalystFinding, FindingKind
from loader_detection_workbench.report import document as doc
from loader_detection_workbench.report.analysis import CaseAnalysis
from loader_detection_workbench.report.document import (
    Block,
    Bullets,
    Code,
    Document,
    Heading,
    Item,
    Paragraph,
    Table,
    item,
    trusted,
    untrusted,
)
from loader_detection_workbench.static_analysis.domain import StaticAnalysis
from loader_detection_workbench.sysmon.records import record_summary

MAX_INDICATOR_VALUES = 10
MAX_IMPORT_NAMES = 12
MAX_MATCH_REFERENCES = 10
_KIND_TITLES = {
    RunKind.DEVELOPMENT: "Development Runs",
    RunKind.EVALUATION: "Evaluation Runs (Unseen, frozen rule and benchmark)",
    RunKind.TUNING: "Tuning Runs (after the first Unseen evaluation)",
}


def _optional(value: object | None) -> str:
    return "—" if value is None or value == "" else str(value)


def ratio(numerator: int, denominator: int) -> str:
    """Always report a count together with its denominator."""
    return f"{numerator}/{denominator}"


def reported_version(rule: DetectionRule) -> RuleVersion:
    """The latest frozen version if any, otherwise the latest draft."""
    frozen = [v for v in rule.versions if v.status is RuleVersionStatus.FROZEN]
    return frozen[-1] if frozen else rule.latest


def match_evidence(result: ValidationResult) -> str:
    """Compact, path-free description of why a rule matched one Case."""
    try:
        detail: Any = json.loads(result.detail)
    except json.JSONDecodeError:
        return "(unreadable match detail)"
    if not isinstance(detail, dict):
        return "(unreadable match detail)"
    if "reason" in detail:
        return str(detail["reason"])
    parts: list[str] = []
    matches = detail.get("matches")
    if isinstance(matches, list):
        for match in matches[:MAX_MATCH_REFERENCES]:
            if not isinstance(match, dict):
                continue
            strings = match.get("strings")
            hits = (
                ", ".join(
                    f"{hit.get('id')}@{hit.get('offset')}+{hit.get('length')}"
                    for hit in strings[:MAX_MATCH_REFERENCES]
                    if isinstance(hit, dict)
                )
                if isinstance(strings, list)
                else ""
            )
            parts.append(
                f"{match.get('artifact')} rule {match.get('rule')}"
                + (f" [{hits}]" if hits else "")
            )
        scanned = detail.get("scanned")
        if not parts and isinstance(scanned, list):
            return f"no match in {len(scanned)} scanned sample Artifact(s)"
    records = detail.get("matched_records")
    if isinstance(records, list):
        total = detail.get("matched_total", len(records))
        if not records:
            return f"no match in {detail.get('records', 0)} Sysmon record(s)"
        references = ", ".join(
            f"{record.get('artifact')}#{record.get('record_id')} "
            f"(EventID {record.get('event_id')})"
            for record in records[:MAX_MATCH_REFERENCES]
            if isinstance(record, dict)
        )
        parts.append(
            f"{total} of {detail.get('records', 0)} Sysmon record(s) matched: "
            f"{references}"
        )
    return "; ".join(parts) if parts else "(no match detail)"


def _overview(timeline: CaseTimeline, generated_at: datetime) -> list[Block]:
    case = timeline.case
    return [
        Heading(2, trusted("Case Overview")),
        Bullets(
            (
                item("Case ID", case.case_id.display_id, is_trusted=True),
                item("Name", case.name),
                item("Kind", case.kind.value, is_trusted=True),
                item("Status", case.status.value, is_trusted=True),
                item("Description", case.description or ""),
                item("Generated At", format_utc(generated_at), is_trusted=True),
            )
        ),
    ]


def _summary(timeline: CaseTimeline, analysis: CaseAnalysis | None) -> list[Block]:
    items = [
        item("Sysmon Artifacts", timeline.sysmon_artifact_count, is_trusted=True),
        item("Normalized Observations", len(timeline.observations), is_trusted=True),
        item("Supported Event IDs", "1, 11", is_trusted=True),
    ]
    if analysis is not None and not analysis.is_empty:
        counts: dict[str, int] = {}
        for artifact in analysis.artifacts:
            counts[artifact.kind.value] = counts.get(artifact.kind.value, 0) + 1
        items.extend(
            [
                item(
                    "Attached Artifacts",
                    f"{len(analysis.artifacts)} ("
                    + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
                    + ")",
                    is_trusted=True,
                ),
                item(
                    "Static Analysis Results",
                    len(analysis.static_results),
                    is_trusted=True,
                ),
                item(
                    "VM Execution Runs", len(analysis.execution_runs), is_trusted=True
                ),
                item("Detection Hypotheses", len(analysis.hypotheses), is_trusted=True),
                item("Detection Rules", len(analysis.rules), is_trusted=True),
                item("Validation Runs", len(analysis.validation_runs), is_trusted=True),
            ]
        )
        if analysis.ai_analyses:
            items.append(
                item(
                    "AI-Assisted Analyses (inference)",
                    len(analysis.ai_analyses),
                    is_trusted=True,
                )
            )
        for membership in analysis.memberships:
            state = "frozen" if membership.benchmark.is_frozen else "not frozen"
            items.append(
                item(
                    "Benchmark Membership",
                    f"{membership.benchmark.display_id} as "
                    f"{membership.member.role.value} ({state})",
                    is_trusted=True,
                )
            )
    return [Heading(2, trusted("Evidence Summary")), Bullets(tuple(items))]


def _static(result: StaticAnalysis) -> list[Block]:
    blocks: list[Block] = [
        Heading(
            3,
            trusted(
                f"{result.artifact.artifact_id.display_id} — static result for "
                f"{result.source_artifact_id}"
            ),
        )
    ]
    items = [
        item("Source Artifact", result.source_artifact_id, is_trusted=True),
        item("Source SHA-256", result.source_sha256, is_trusted=True),
        item("Source Size", f"{result.source_size_bytes} bytes", is_trusted=True),
        item("Analyzer", f"{result.tool_name} {result.tool_version}"),
        item("Analyzed At", result.analyzed_at),
        item("Status", result.status),
    ]
    if result.error:
        items.append(item("Parse Error", result.error))
    if result.is_pe:
        items.append(
            item(
                "Architecture",
                f"{_optional(result.architecture)} "
                f"({_optional(result.optional_header)})",
            )
        )
    if result.schema_version >= 2:
        items.append(item("File Entropy", _optional(result.file_entropy)))
        if result.is_pe:
            items.extend(
                [
                    item("Imphash", _optional(result.imphash)),
                    item("Compile Timestamp", _optional(result.compile_timestamp)),
                    item("Entry Point", _optional(result.entry_point)),
                    item("Subsystem", _optional(result.subsystem)),
                    item("DLL", _optional(result.is_dll)),
                    item(
                        "Signature",
                        f"{_optional(result.signature)} (presence only; not verified)",
                    ),
                    item(
                        "Overlay Size",
                        f"{result.overlay_size} bytes",
                        is_trusted=True,
                    ),
                    item(
                        "Imports",
                        f"{len(result.imports)} DLLs / "
                        f"{result.import_function_count} functions"
                        + (" (truncated)" if result.imports_truncated else ""),
                        is_trusted=True,
                    ),
                    item("Exports", result.export_count, is_trusted=True),
                ]
            )
        items.append(
            item(
                "Strings",
                f"{len(result.strings)} kept / {result.strings_total} found"
                + (" (truncated)" if result.strings_truncated else ""),
                is_trusted=True,
            )
        )
        items.append(
            item(
                "Analysis Leads (not a verdict)",
                ", ".join(result.flags) if result.flags else "none",
            )
        )
        if result.parser_warning:
            items.append(item("Parser Warning", result.parser_warning))
    blocks.append(Bullets(tuple(items)))
    if result.sections:
        blocks.append(
            Table(
                ("Section", "Raw Size", "Virtual Size", "Entropy", "Exec", "Write"),
                tuple(
                    (
                        untrusted(section.name),
                        trusted(section.raw_size),
                        trusted(section.virtual_size),
                        trusted(_optional(section.entropy)),
                        trusted(_optional(section.executable)),
                        trusted(_optional(section.writable)),
                    )
                    for section in result.sections
                ),
                frozenset({1, 2, 3}),
            )
        )
    if result.imports:
        blocks.append(
            Table(
                ("Imported DLL", "Functions", "First Names"),
                tuple(
                    (
                        untrusted(entry.dll),
                        trusted(len(entry.functions)),
                        untrusted(", ".join(entry.functions[:MAX_IMPORT_NAMES])),
                    )
                    for entry in result.imports
                ),
                frozenset({1}),
            )
        )
    indicators = {k: v for k, v in sorted(result.indicators.items()) if v}
    if indicators:
        blocks.append(
            Table(
                ("String Indicator", "Count", f"First {MAX_INDICATOR_VALUES} Values"),
                tuple(
                    (
                        untrusted(kind),
                        trusted(len(values)),
                        untrusted(" ; ".join(values[:MAX_INDICATOR_VALUES])),
                    )
                    for kind, values in indicators.items()
                ),
                frozenset({1}),
            )
        )
    return blocks


def _timeline(timeline: CaseTimeline) -> list[Block]:
    blocks: list[Block] = [Heading(2, trusted("Timeline"))]
    for event in timeline.observations:
        kind = (
            "Process Create" if isinstance(event, ProcessCreateEvent) else "File Create"
        )
        items = [
            item("Event ID", event.event_id, is_trusted=True),
            item("Image", event.image),
            item("Process ID", event.process_id, is_trusted=True),
        ]
        if isinstance(event, ProcessCreateEvent):
            items.append(item("Command Line", event.command_line))
        else:
            items.extend(
                [
                    item("Target Filename", event.target_filename),
                    item(
                        "Creation UTC Time",
                        format_utc(event.creation_utc_time),
                        is_trusted=True,
                    ),
                ]
            )
        items.extend(
            [
                item(
                    "Source Artifact",
                    event.source_artifact_id.display_id,
                    is_trusted=True,
                ),
                item("Source Record", event.source_record_id, is_trusted=True),
            ]
        )
        blocks.extend(
            [
                Heading(3, trusted(f"{format_utc(event.timestamp)} — {kind}")),
                Bullets(tuple(items)),
            ]
        )
    if not timeline.observations:
        blocks.append(Paragraph(trusted("No normalized Sysmon observations.")))
    if timeline.other_records:
        blocks.append(Heading(2, trusted("Other Sysmon Events")))
        blocks.append(
            Table(
                ("Time (UTC)", "Event ID", "Summary", "Source"),
                tuple(
                    (
                        trusted(
                            "unknown"
                            if record.timestamp is None
                            else format_utc(record.timestamp)
                        ),
                        trusted(record.event_id),
                        untrusted(record_summary(record)),
                        trusted(
                            (
                                "?"
                                if record.source_artifact_id is None
                                else record.source_artifact_id.display_id
                            )
                            + f"#{record.record_id or '?'}"
                        ),
                    )
                    for record in timeline.other_records
                ),
                frozenset({1}),
            )
        )
    return blocks


def _execution(runs: tuple[ExecutionRun, ...]) -> list[Block]:
    blocks: list[Block] = [
        Heading(2, trusted("VM Execution Runs")),
        Table(
            (
                "Run",
                "Profile",
                "Target",
                "VM / Clean Snapshot",
                "Status",
                "Started",
                "Finished",
                "Events",
                "Sysmon Artifact",
                "Error",
            ),
            tuple(
                (
                    trusted(run.display_id),
                    trusted(run.profile.value),
                    untrusted(run.target),
                    untrusted(f"{run.vm_name} / {run.snapshot}"),
                    trusted(run.status.value),
                    trusted(format_utc(run.started_at)),
                    trusted(
                        "—" if run.finished_at is None else format_utc(run.finished_at)
                    ),
                    trusted(_optional(run.event_count)),
                    trusted(_optional(run.sysmon_artifact_id)),
                    untrusted(_optional(run.error_code)),
                )
                for run in runs
            ),
            frozenset({7}),
        ),
    ]
    step_items = tuple(
        item(
            run.display_id,
            f"timeout {run.timeout_seconds}s; steps: "
            + (
                " → ".join(f"{s.step.value} {s.status.value}" for s in run.steps)
                or "none recorded"
            ),
            is_trusted=True,
        )
        for run in runs
    )
    blocks.append(Bullets(step_items))
    return blocks


def _hypotheses(analysis: CaseAnalysis) -> list[Block]:
    kinds = {a.artifact_id.display_id: a.kind.value for a in analysis.artifacts}
    blocks: list[Block] = [Heading(2, trusted("Detection Hypotheses"))]
    for hypothesis in analysis.hypotheses:
        evidence = (
            ", ".join(
                f"{value} ({kinds.get(value, 'unknown')})"
                for value in hypothesis.evidence_artifact_ids
            )
            or "none linked"
        )
        blocks.extend(
            [
                Heading(3, untrusted(hypothesis.title), f"{hypothesis.display_id} — "),
                Bullets(
                    (
                        item("Status", hypothesis.status.value, is_trusted=True),
                        item("Statement", hypothesis.statement),
                        item(
                            "Expected Benign Counterpart",
                            _optional(hypothesis.expected_benign),
                        ),
                        item("Evidence Artifacts", evidence, is_trusted=True),
                        item(
                            "Linked Rules",
                            ", ".join(hypothesis.rule_display_ids) or "none linked",
                            is_trusted=True,
                        ),
                        item(
                            "Created At",
                            format_utc(hypothesis.created_at),
                            is_trusted=True,
                        ),
                        item(
                            "Updated At",
                            format_utc(hypothesis.updated_at),
                            is_trusted=True,
                        ),
                    )
                ),
            ]
        )
    return blocks


def _rules(analysis: CaseAnalysis) -> list[Block]:
    blocks: list[Block] = [Heading(2, trusted("Detection Rules"))]
    for rule in analysis.rules:
        shown = reported_version(rule)
        blocks.extend(
            [
                Heading(3, untrusted(rule.name), f"{rule.display_id} — "),
                Bullets(
                    (
                        item("Format", rule.format.value, is_trusted=True),
                        item(
                            "Created At", format_utc(rule.created_at), is_trusted=True
                        ),
                        item(
                            "Linked Hypotheses",
                            ", ".join(
                                h.display_id
                                for h in analysis.hypotheses
                                if rule.display_id in h.rule_display_ids
                            )
                            or "none in this Case",
                            is_trusted=True,
                        ),
                    )
                ),
                Table(
                    ("Version", "Status", "SHA-256", "Created", "Frozen", "Note"),
                    tuple(
                        (
                            trusted(version.version),
                            trusted(version.status.value),
                            trusted(version.sha256),
                            trusted(format_utc(version.created_at)),
                            trusted(
                                "—"
                                if version.frozen_at is None
                                else format_utc(version.frozen_at)
                            ),
                            untrusted(_optional(version.note)),
                        )
                        for version in rule.versions
                    ),
                    frozenset({0}),
                ),
                Paragraph(
                    trusted(
                        f"Content of version {shown.version} ({shown.status.value}):"
                    )
                ),
                Code(shown.content),
            ]
        )
    return blocks


def _run_row(analysis: CaseAnalysis, run: ValidationRun) -> tuple[doc.Text, ...]:
    metrics = run.metrics
    result = analysis.case_result(run)
    return (
        trusted(run.display_id),
        trusted(f"{run.rule_display_id} v{run.rule_version}"),
        trusted(run.benchmark_display_id),
        trusted(", ".join(role.value for role in run.roles)),
        trusted(ratio(metrics.tp, metrics.malicious_total)),
        trusted(ratio(metrics.fp, metrics.benign_total)),
        trusted(metrics.not_evaluable),
        trusted(
            "not a member"
            if result is None
            else f"{result.role.value}: {result.outcome.value}"
        ),
        trusted(format_utc(run.created_at)),
    )


def _validation(analysis: CaseAnalysis) -> list[Block]:
    blocks: list[Block] = [
        Heading(2, trusted("Validation Results")),
        Paragraph(
            trusted(
                "Detected = true positives / malicious members evaluated. "
                "False Positives = false positives / benign members evaluated. "
                "Members without a target Artifact are counted as Not Evaluable "
                "and excluded from both denominators."
            )
        ),
    ]
    for kind in (RunKind.DEVELOPMENT, RunKind.EVALUATION, RunKind.TUNING):
        runs = analysis.runs_of_kind(kind)
        if not runs:
            continue
        blocks.extend(
            [
                Heading(3, trusted(_KIND_TITLES[kind])),
                Table(
                    (
                        "Run",
                        "Rule",
                        "Benchmark",
                        "Roles",
                        "Detected",
                        "False Positives",
                        "Not Evaluable",
                        "This Case",
                        "Created",
                    ),
                    tuple(_run_row(analysis, run) for run in runs),
                    frozenset({6}),
                ),
            ]
        )
    evidence = tuple(
        item(
            f"{run.display_id} ({run.rule_display_id} v{run.rule_version}, "
            f"{run.kind.value}, {result.outcome.value})",
            match_evidence(result),
        )
        for run in analysis.validation_runs
        if (result := analysis.case_result(run)) is not None
    )
    if evidence:
        blocks.extend(
            [Heading(3, trusted("Match Evidence for This Case")), Bullets(evidence)]
        )
    return blocks


def _ai_comparison(analysis: CaseAnalysis) -> list[Block]:
    selected = latest_per_provider(analysis.ai_analyses)
    if len(selected) < 2:
        return []
    comparison = compare_analyses(selected)
    rows = tuple(
        (
            trusted("shared" if group.shared else "single provider"),
            untrusted(", ".join(group.providers)),
            trusted(group.kind.value),
            untrusted(
                "; ".join(
                    f"{o.analysis_display_id}#{o.sequence} "
                    + (o.text if o.title is None else f"{o.title}: {o.text}")
                    for o in group.opinions
                )
            ),
            untrusted(", ".join(group.evidence_artifact_ids) or "—"),
        )
        for group in (*comparison.common, *comparison.individual)
    )
    return [
        Heading(3, trusted("Provider Comparison")),
        Paragraph(
            trusted(
                f"{len(comparison.analyses)} providers analyzed the same input "
                f"(SHA-256 {comparison.input_sha256}). {len(comparison.common)} "
                f"opinion(s) are shared by two or more providers and "
                f"{len(comparison.individual)} come from a single provider. "
                "Grouping compares cited evidence and behavior themes; it is a "
                "heuristic, not a judgment of meaning."
            )
        ),
        Table(
            ("Agreement", "Providers", "Kind", "Opinions", "Cited Evidence"),
            rows,
            frozenset(),
        ),
    ]


def _ai(analysis: CaseAnalysis) -> list[Block]:
    blocks: list[Block] = [
        Heading(2, trusted("AI-Assisted Analysis (inference, not observed evidence)")),
        Paragraph(
            trusted(
                "The suggestions below were generated from a bounded structural "
                "digest of this Case. They are not observations. A suggestion "
                "affects the analysis only after a person accepts it; an accepted "
                "hypothesis candidate is then listed under Detection Hypotheses."
            )
        ),
    ]
    for record in analysis.ai_analyses:
        blocks.extend(
            [
                Heading(
                    3,
                    untrusted(f"{record.provider} / {record.model}"),
                    f"{record.display_id} — ",
                ),
                Bullets(
                    (
                        item(
                            "Created At", format_utc(record.created_at), is_trusted=True
                        ),
                        item("Stage", record.stage.value, is_trusted=True),
                        item("Input Scope", record.input_scope),
                        item("Input SHA-256", record.input_sha256, is_trusted=True),
                    )
                ),
                Table(
                    ("No.", "Kind", "Review", "Suggestion", "Cited Evidence", "Result"),
                    tuple(
                        (
                            trusted(suggestion.sequence),
                            trusted(suggestion.kind.value),
                            trusted(suggestion.state.value),
                            untrusted(
                                suggestion.text
                                if suggestion.title is None
                                else f"{suggestion.title}: {suggestion.text}"
                            ),
                            untrusted(
                                ", ".join(suggestion.evidence_artifact_ids) or "—"
                            ),
                            untrusted(
                                _optional(suggestion.hypothesis_display_id)
                                + (
                                    f" ({suggestion.review_note})"
                                    if suggestion.review_note
                                    else ""
                                )
                            ),
                        )
                        for suggestion in record.suggestions
                    ),
                    frozenset({0}),
                ),
            ]
        )
    blocks.extend(_ai_comparison(analysis))
    return blocks


def _lines(text: str) -> list[Block]:
    return [Paragraph(untrusted(line)) for line in text.splitlines() if line.strip()]


def _cites(finding: AnalystFinding) -> str:
    content = finding.content
    cited = [str(ref) for ref in content.evidence] + list(content.finding_refs)
    return ", ".join(cited) or "none"


def _findings(analysis: CaseAnalysis | None) -> list[Block]:
    """Report body: confirmed analyst findings only (ADR-031)."""
    blocks: list[Block] = [
        Heading(2, trusted("Confirmed Findings")),
        Paragraph(
            trusted(
                "This section contains only statements an analyst confirmed in the "
                "Workbench. Recorded data and AI suggestions are in the appendices "
                "and are not conclusions."
            )
        ),
    ]
    findings = () if analysis is None else analysis.findings
    if not findings:
        blocks.append(
            Paragraph(trusted("No finding has been confirmed for this Case."))
        )
        return blocks
    by_id = {item.display_id: item for item in findings}
    hypotheses = [f for f in findings if f.kind is FindingKind.HYPOTHESIS]
    evidence = [f for f in findings if f.kind is FindingKind.EVIDENCE]
    links = [f for f in findings if f.kind is FindingKind.LINK]
    mechanism = [f for f in findings if f.kind is FindingKind.MECHANISM]

    def header(finding: AnalystFinding) -> Bullets:
        content = finding.content
        items = []
        if content.verdict is not None:
            items.append(item("Verdict", content.verdict.value, is_trusted=True))
        if content.hypothesis_display_id is not None:
            items.append(
                item(
                    "Detection Hypothesis",
                    content.hypothesis_display_id,
                    is_trusted=True,
                )
            )
        items.append(item("Cites", _cites(finding), is_trusted=True))
        items.append(item("Source", finding.source, is_trusted=True))
        confirmed = finding.confirmed_at
        if confirmed is not None:
            items.append(
                item(
                    "Confirmed At",
                    f"{format_utc(confirmed)} (r{finding.revision})",
                    is_trusted=True,
                )
            )
        return Bullets(tuple(items))

    if hypotheses:
        blocks.append(Heading(3, trusted("Hypotheses and Verdicts")))
    for hypothesis in hypotheses:
        blocks.append(
            Heading(
                4,
                untrusted(hypothesis.content.title or ""),
                f"{hypothesis.display_id} — ",
            )
        )
        blocks.append(header(hypothesis))
        blocks.extend(_lines(hypothesis.content.text))
        support = [
            link for link in links if hypothesis.display_id in link.content.finding_refs
        ]
        if support:
            blocks.append(Paragraph(trusted("Supporting reasoning:")))
            blocks.append(
                Bullets(
                    tuple(
                        Item(
                            f"{link.display_id} (cites "
                            + ", ".join(
                                ref
                                for ref in link.content.finding_refs
                                if ref in by_id
                                and by_id[ref].kind is FindingKind.EVIDENCE
                            )
                            + ")",
                            untrusted(" ".join(link.content.text.split())),
                        )
                        for link in support
                    )
                )
            )
    if evidence:
        blocks.append(Heading(3, trusted("Confirmed Evidence")))
        blocks.append(
            Table(
                ("Finding", "Cites", "What It Shows"),
                tuple(
                    (
                        trusted(finding.display_id),
                        trusted(_cites(finding)),
                        untrusted(" ".join(finding.content.text.split())),
                    )
                    for finding in evidence
                ),
            )
        )
    if mechanism:
        blocks.append(Heading(3, trusted("How It Works")))
        for step in mechanism:
            title = step.content.title or "Step"
            blocks.append(Heading(4, untrusted(title), f"{step.display_id} — "))
            blocks.append(header(step))
            blocks.extend(_lines(step.content.text))
    return blocks


def _appendix(title: str, note: str) -> list[Block]:
    return [Heading(2, trusted(title)), Paragraph(trusted(note))]


def _limits(analysis: CaseAnalysis | None) -> list[Block]:
    lines = [
        "Only attached Sysmon XML Artifacts are queried.",
        "Supported events are Event ID 1 and Event ID 11.",
        "Results are normalized in memory; timestamps use second-precision UTC.",
        "The report body contains analyst-confirmed findings only; the "
        "Workbench itself produces no maliciousness verdict.",
        "The report does not independently attest how the source telemetry "
        "was collected.",
        "This demo report is a subset of the full analysis report template.",
    ]
    if analysis is not None and not analysis.is_empty:
        lines.extend(
            [
                "Static analysis leads and string indicators are analyst cues, "
                "not findings.",
                "Hypotheses are analyst statements; their status is set by a "
                "person, not derived automatically.",
                "Validation outcomes describe one rule version on one recorded "
                "benchmark and do not generalize beyond its members.",
                "Tuning runs are recorded separately and are not Unseen "
                "evaluation results.",
            ]
        )
        if analysis.ai_analyses:
            lines.append(
                "AI-assisted suggestions are unverified inferences; only "
                "suggestions accepted by a person become Hypotheses."
            )
    return [
        Heading(2, trusted("Collection / Analysis Limits")),
        Bullets(tuple(item(None, line, is_trusted=True) for line in lines)),
    ]


def build_document(
    timeline: CaseTimeline,
    generated_at: datetime,
    analysis: CaseAnalysis | None = None,
) -> Document:
    blocks: list[Block] = [
        *_overview(timeline, generated_at),
        *_findings(analysis),
        *_appendix(
            "Appendix A — Recorded Data",
            "Collected and computed records, shown for traceability. They are not "
            "analyst conclusions unless cited by a confirmed finding above.",
        ),
        *_summary(timeline, analysis),
    ]
    if analysis is not None and analysis.static_results:
        blocks.append(Heading(2, trusted("Static Evidence")))
        for result in analysis.static_results:
            blocks.extend(_static(result))
    blocks.extend(_timeline(timeline))
    if analysis is not None:
        if analysis.execution_runs:
            blocks.extend(_execution(analysis.execution_runs))
        if analysis.hypotheses:
            blocks.extend(_hypotheses(analysis))
        if analysis.rules:
            blocks.extend(_rules(analysis))
        if analysis.validation_runs:
            blocks.extend(_validation(analysis))
        if analysis.ai_analyses:
            blocks.extend(
                _appendix(
                    "Appendix B — AI-Assisted Analysis (inference, not confirmed)",
                    "Suggestions from language-model providers. Nothing here is "
                    "confirmed; adopted suggestions appear above only as findings an "
                    "analyst confirmed.",
                )
            )
            blocks.extend(_ai(analysis))
    blocks.extend(_limits(analysis))
    return Document(f"Case Report — {timeline.case.case_id.display_id}", tuple(blocks))


def render_markdown(
    timeline: CaseTimeline,
    generated_at: datetime,
    analysis: CaseAnalysis | None = None,
) -> str:
    return doc.render_markdown(build_document(timeline, generated_at, analysis))


def render_html(
    timeline: CaseTimeline,
    generated_at: datetime,
    analysis: CaseAnalysis | None = None,
) -> str:
    return doc.render_html(build_document(timeline, generated_at, analysis))
