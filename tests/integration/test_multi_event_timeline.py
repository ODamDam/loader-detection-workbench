"""Multi-event Sysmon exports in Timeline, CLI, report and UI (synthetic data)."""

from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.render import render_timeline
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import ProcessCreateEvent
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.report.render import render_markdown
from loader_detection_workbench.web import create_app

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "public" / "sysmon"


def _event(event_id: int, record: int, **fields: str) -> str:
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return (
        f'<Event xmlns="{_NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>"
        f"</System><EventData>{data}</EventData></Event>"
    )


GUID = "{11111111-2222-4333-8444-555555555555}"
PROCESS = _event(
    1,
    100,
    UtcTime="2026-11-11 01:00:00.000",
    ProcessGuid=GUID,
    ProcessId="42",
    Image="C:\\synthetic\\demo.exe",
    CommandLine="demo.exe --run",
)
NETWORK = _event(
    3,
    101,
    UtcTime="2026-11-11 01:00:01.000",
    Image="C:\\synthetic\\demo.exe",
    Protocol="tcp",
    DestinationIp="192.0.2.10",
    DestinationPort="443",
)
DNS = _event(
    22,
    102,
    UtcTime="2026-11-11 01:00:02.000",
    Image="C:\\synthetic\\demo.exe",
    QueryName="update.example.invalid",
)
REGISTRY = _event(
    13,
    103,
    UtcTime="2026-11-11 01:00:03.000",
    EventType="SetValue",
    Image="C:\\synthetic\\demo.exe",
    TargetObject="HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\demo",
    Details="demo.exe",
)


def _workspace(tmp_path: Path, *documents: str) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Multi")
    CaseService(root).create("synthetic", "simulator")
    for index, document in enumerate(documents):
        path = tmp_path / f"collection-{index}.xml"
        path.write_text(document, encoding="utf-8")
        ArtifactService(root).add("CASE-0001", path, "sysmon")
    return root


def test_container_splits_typed_and_other_events(tmp_path: Path) -> None:
    container = "<Events>" + REGISTRY + DNS + PROCESS + NETWORK + "</Events>"
    root = _workspace(tmp_path, container, (FIXTURE / "file-create.xml").read_text())

    timeline = CaseTimelineQuery(root).query("CASE-0001")

    assert len(timeline.observations) == 2
    assert any(isinstance(e, ProcessCreateEvent) for e in timeline.observations)
    assert [r.event_id for r in timeline.other_records] == [3, 22, 13]

    text = render_timeline(timeline)
    assert "other_sysmon_events: 3" in text
    assert "DestinationIp=192.0.2.10" in text
    assert "QueryName=update.example.invalid" in text

    report = render_markdown(timeline, utc_now())
    assert "## Other Sysmon Events" in report
    assert "| 13 |" in report

    page = (
        create_app(root)
        .test_client()
        .get("/cases/CASE-0001/timeline", headers={"Host": "127.0.0.1:8080"})
        .get_data(as_text=True)
    )
    assert "Other Sysmon events (3)" in page
    assert "update.example.invalid" in page
    assert "C:\\synthetic" not in page


def test_single_event_documents_keep_original_contract(tmp_path: Path) -> None:
    root = _workspace(tmp_path, (FIXTURE / "process-create.xml").read_text())

    timeline = CaseTimelineQuery(root).query("CASE-0001")

    assert len(timeline.observations) == 1
    assert timeline.other_records == ()
    assert "other_sysmon_events" not in render_timeline(timeline)


def test_invalid_typed_event_inside_container_fails_whole_timeline(
    tmp_path: Path,
) -> None:
    broken = PROCESS.replace('<Data Name="CommandLine">demo.exe --run</Data>', "")
    root = _workspace(tmp_path, "<Events>" + NETWORK + broken + "</Events>")

    with pytest.raises(DomainError) as error:
        CaseTimelineQuery(root).query("CASE-0001")
    assert error.value.code is DomainErrorCode.INVALID_PROCESS_CREATE


def test_single_non_typed_event_is_listed_as_other(tmp_path: Path) -> None:
    root = _workspace(tmp_path, DNS)

    timeline = CaseTimelineQuery(root).query("CASE-0001")

    assert timeline.observations == ()
    assert [r.event_id for r in timeline.other_records] == [22]
