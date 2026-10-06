from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from loader_detection_workbench.case.render import render_timeline
from loader_detection_workbench.case.timeline import CaseTimeline
from loader_detection_workbench.domain.case import (
    Case,
    CaseKind,
    CaseLifecycle,
    CaseStatus,
)
from loader_detection_workbench.domain.events import FileCreateEvent, ProcessCreateEvent
from loader_detection_workbench.domain.ids import ArtifactId, CaseId
from loader_detection_workbench.report.render import render_markdown
from loader_detection_workbench.sysmon.normalizer import normalize_sysmon_event

NOW = datetime(2026, 10, 6, tzinfo=UTC)


def test_markdown_and_terminal_untrusted_values_are_inert() -> None:
    payload = (
        "<script>alert(1)</script>\n## FAKE\r\n[click](javascript:bad) "
        "`x` &lt;b&gt;\x1b[31m\u2028# END\u202e"
    )
    case = Case(
        CaseId("0" * 26, "CASE-0001"),
        "0" * 26,
        CaseKind.BENIGN,
        payload,
        payload,
        NOW,
        CaseLifecycle(CaseStatus.OPEN, NOW),
    )
    fixtures = Path(__file__).parents[1] / "fixtures/public/sysmon"
    source = ArtifactId("0" * 26, "ART-000001")
    process = normalize_sysmon_event(
        (fixtures / "process-create.xml").read_bytes(), source
    )[0]
    file = normalize_sysmon_event((fixtures / "file-create.xml").read_bytes(), source)[
        0
    ]
    assert isinstance(process, ProcessCreateEvent)
    process = replace(process, image=payload, command_line=payload)
    assert isinstance(file, FileCreateEvent)
    file = replace(file, image=payload, target_filename=payload)
    timeline = CaseTimeline(case, (process, file), 2)
    markdown = render_markdown(timeline, NOW)
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown and "&amp;lt\\;" in markdown
    assert "[click](javascript:bad)" not in markdown
    assert "\\[click\\]\\(javascript\\:bad\\)" in markdown
    assert "`x`" not in markdown and "\\`x\\`" in markdown
    assert [line for line in markdown.splitlines() if line.startswith("## ")] == [
        "## Case Overview",
        "## Evidence Summary",
        "## Timeline",
        "## Collection / Analysis Limits",
    ]
    assert "Generated At: 2026-10-06T00:00:00Z" in markdown
    text = render_timeline(timeline)
    assert "\n## FAKE" not in text
    for control in ("\r", "\x1b", "\u2028", "\u202e"):
        assert control not in markdown and control not in text
