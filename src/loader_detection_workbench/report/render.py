"""Pure Markdown rendering of the same CaseTimeline used by the CLI."""

from datetime import datetime

from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.domain.events import ProcessCreateEvent
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.presentation import markdown_text
from loader_detection_workbench.sysmon.records import record_summary


def render_markdown(timeline: CaseTimeline, generated_at: datetime) -> str:
    case = timeline.case
    lines = [
        f"# Case Report — {case.case_id.display_id}",
        "",
        "## Case Overview",
        "",
        f"- Case ID: {case.case_id.display_id}",
        f"- Name: {markdown_text(case.name)}",
        f"- Kind: {case.kind.value}",
        f"- Status: {case.status.value}",
        f"- Description: {markdown_text(case.description or '')}",
        f"- Generated At: {format_utc(generated_at)}",
        "",
        "## Evidence Summary",
        "",
        f"- Sysmon Artifacts: {timeline.sysmon_artifact_count}",
        f"- Normalized Observations: {len(timeline.observations)}",
        "- Supported Event IDs: 1, 11",
        "",
        "## Timeline",
        "",
    ]
    for event in timeline.observations:
        kind = (
            "Process Create" if isinstance(event, ProcessCreateEvent) else "File Create"
        )
        lines.extend(
            [
                f"### {format_utc(event.timestamp)} — {kind}",
                "",
                f"- Event ID: {event.event_id}",
                f"- Image: {markdown_text(event.image)}",
                f"- Process ID: {event.process_id}",
            ]
        )
        if isinstance(event, ProcessCreateEvent):
            lines.append(f"- Command Line: {markdown_text(event.command_line)}")
        else:
            lines.extend(
                [
                    f"- Target Filename: {markdown_text(event.target_filename)}",
                    f"- Creation UTC Time: {format_utc(event.creation_utc_time)}",
                ]
            )
        lines.extend(
            [
                f"- Source Artifact: {event.source_artifact_id.display_id}",
                f"- Source Record: {event.source_record_id}",
                "",
            ]
        )
    if not timeline.observations:
        lines.extend(["No normalized Sysmon observations.", ""])
    if timeline.other_records:
        lines.extend(
            [
                "## Other Sysmon Events",
                "",
                "| Time (UTC) | Event ID | Summary | Source |",
                "|---|---:|---|---|",
            ]
        )
        for record in timeline.other_records:
            when = (
                "unknown" if record.timestamp is None else format_utc(record.timestamp)
            )
            source = (
                "?"
                if record.source_artifact_id is None
                else record.source_artifact_id.display_id
            )
            summary = markdown_text(record_summary(record)).replace("|", "\\|")
            lines.append(
                f"| {when} | {record.event_id} | {summary} | "
                f"{source}#{record.record_id or '?'} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Collection / Analysis Limits",
            "",
            "- Only attached Sysmon XML Artifacts are queried.",
            "- Supported events are Event ID 1 and Event ID 11.",
            "- Results are normalized in memory; timestamps use second-precision UTC.",
            "- No maliciousness verdict is produced.",
            "- The report does not independently attest how the source telemetry "
            "was collected.",
            "- This demo report is a subset of the full analysis report template.",
            "",
        ]
    )
    return "\n".join(lines)
