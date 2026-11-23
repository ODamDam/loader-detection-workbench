from datetime import UTC, datetime
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimeline, CaseTimelineQuery
from loader_detection_workbench.cli import main
from loader_detection_workbench.presentation import markdown_text
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.report.render import render_markdown
from loader_detection_workbench.report.service import ReportService

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"
GENERATED = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Demo")
    CaseService(root).create("Synthetic Demo", "benign", "Invented telemetry only")
    monkeypatch.chdir(root)
    return root


def attach(root: Path) -> None:
    for name in ("file-create.xml", "process-create.xml"):
        ArtifactService(root).add("CASE-0001", FIXTURES / name, "sysmon")


def test_unmocked_demo_commands(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    attach(root)
    assert main(["case", "timeline", "CASE-0001"]) == 0
    output = capsys.readouterr().out
    assert "observations: 2" in output
    assert output.index("process_create") < output.index("file_create")
    assert "ART-000002#42" in output and "ART-000001#43" in output
    assert main(["report", "build", "CASE-0001", "demo.md"]) == 0
    report = (root / "demo.md").read_text(encoding="utf-8")
    assert "Normalized Observations: 2" in report
    assert report.index("— Process Create") < report.index("— File Create")
    assert "- Source Artifact: ART-000002\n- Source Record: 42" in report
    assert "- Source Artifact: ART-000001\n- Source Record: 43" in report


def test_demo_e2e_shared_query_cli_and_markdown(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    attach(root)
    query_result = CaseTimelineQuery(root).query("CASE-0001")
    before = (root / "project.db").read_bytes()
    # Both application entry points must consume exactly this query result;
    # rendering must not query the Case/Artifact/Sysmon layers independently.
    calls: list[str] = []

    def query(self: CaseTimelineQuery, selector: str) -> CaseTimeline:
        calls.append(selector)
        return query_result

    monkeypatch.setattr(CaseTimelineQuery, "query", query)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("presentation bypassed the shared query result")

    monkeypatch.setattr(CaseService, "show", forbidden)
    monkeypatch.setattr(ArtifactService, "list_artifacts", forbidden)
    assert main(["case", "timeline", "CASE-0001"]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert "sysmon_artifacts: 2\nobservations: 2\n" in output.out
    assert output.out.index("EventID=1 ") < output.out.index("EventID=11 ")
    assert "process_create" in output.out and "file_create" in output.out
    assert "source: ART-000002#42" in output.out
    assert "source: ART-000001#43" in output.out
    assert (
        "command_line:" in output.out
        and "target: synthetic-demo/output.txt" in output.out
    )
    assert query_result.case.case_id.ulid not in output.out
    assert main(["report", "build", "CASE-0001", "reports/demo.md"]) == 0
    assert capsys.readouterr().out == "report: created\n"
    content = (root / "reports/demo.md").read_text(encoding="utf-8")
    for value in (
        "# Case Report — CASE-0001",
        "## Case Overview",
        "## Evidence Summary",
        "## Timeline",
        "Process Create",
        "File Create",
        "## Collection / Analysis Limits",
        "Source Artifact: ART-000002",
        "Source Record: 42",
        "Source Record: 43",
        markdown_text("benign-demo.exe"),
        markdown_text("synthetic-demo/output.txt"),
        "Workbench itself produces no maliciousness verdict.",
    ):
        assert value in content
    assert content.index("— Process Create") < content.index("— File Create")
    assert calls == ["CASE-0001", "CASE-0001"]
    deterministic = ReportService(root, clock=lambda: GENERATED).build(
        "CASE-0001", Path("fixed.md")
    )
    assert deterministic.read_text(encoding="utf-8") == render_markdown(
        query_result, GENERATED
    )
    assert (root / "project.db").read_bytes() == before


def test_empty_closed_case_cli_and_report(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    CaseService(root).close("CASE-0001")
    assert main(["case", "timeline", "CASE-0001"]) == 0
    output = capsys.readouterr().out
    assert "sysmon_artifacts: 0\nobservations: 0" in output
    assert "No normalized Sysmon observations." in output
    assert main(["report", "build", "CASE-0001", "empty.md"]) == 0
    content = (root / "empty.md").read_text(encoding="utf-8")
    assert "- Status: closed" in content
    assert "Sysmon Artifacts: 0" in content and "Normalized Observations: 0" in content
    assert "No normalized Sysmon observations." in content


@pytest.mark.parametrize("mode", ["missing_case", "corrupt", "invalid"])
def test_cli_fail_closed_no_partial_output(
    root: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    selector = "CASE-0001"
    expected = "CASE_NOT_FOUND"
    if mode == "missing_case":
        selector = "CASE-9999"
    else:
        attach(root)
        bad = root.parent / "bad.xml"
        bad.write_bytes(b"<Event>")
        artifact = ArtifactService(root).add(selector, bad, "sysmon")
        expected = "INVALID_SYSMON_XML"
        if mode == "corrupt":
            artifact.relative_path.resolve_under(root).write_bytes(b"tamper")
            expected = "ARTIFACT_INTEGRITY_MISMATCH"
    before = (root / "project.db").read_bytes()
    for args in (
        ["case", "timeline", selector],
        ["report", "build", selector, "reports/bad.md"],
    ):
        assert main(args) == 2
        output = capsys.readouterr()
        assert output.out == ""
        assert expected in output.err
        assert str(root) not in output.err
    assert not (root / "reports").exists()
    assert (root / "project.db").read_bytes() == before


def test_existing_report_refused(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = root / "report.md"
    output.write_bytes(b"keep")
    assert main(["report", "build", "CASE-0001", "report.md"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "REPORT_OUTPUT_EXISTS" in captured.err
    assert output.read_bytes() == b"keep"
    assert not list(root.glob(".report-*.tmp"))
