"""Pure CLI timeline rendering from the shared query result."""

from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.domain.events import ProcessCreateEvent
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.presentation import single_line
from loader_detection_workbench.sysmon.records import record_summary


def render_timeline(timeline: CaseTimeline) -> str:
    lines = [
        f"case: {timeline.case.case_id.display_id}",
        f"sysmon_artifacts: {timeline.sysmon_artifact_count}",
        f"observations: {len(timeline.observations)}",
    ]
    for event in timeline.observations:
        kind = (
            "process_create" if isinstance(event, ProcessCreateEvent) else "file_create"
        )
        lines.extend(
            [
                f"{format_utc(event.timestamp)}  EventID={event.event_id}  {kind}",
                f"  image: {single_line(event.image)}",
                f"  pid: {event.process_id}",
            ]
        )
        if isinstance(event, ProcessCreateEvent):
            lines.append(f"  command_line: {single_line(event.command_line)}")
        else:
            lines.append(f"  target: {single_line(event.target_filename)}")
        lines.append(
            f"  source: {event.source_artifact_id.display_id}#{event.source_record_id}"
        )
    if not timeline.observations:
        lines.append("No normalized Sysmon observations.")
    if timeline.other_records:
        lines.append(f"other_sysmon_events: {len(timeline.other_records)}")
        for record in timeline.other_records:
            when = (
                "unknown-time"
                if record.timestamp is None
                else format_utc(record.timestamp)
            )
            source = (
                "?"
                if record.source_artifact_id is None
                else record.source_artifact_id.display_id
            )
            lines.append(
                f"{when}  EventID={record.event_id}  "
                f"{single_line(record_summary(record))}  "
                f"source: {source}#{record.record_id or '?'}"
            )
    return "\n".join(lines) + "\n"
