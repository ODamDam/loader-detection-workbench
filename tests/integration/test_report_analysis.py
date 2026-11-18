"""Case report with static, detection, validation and VM run sections (W5)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from analysis_fixture import UNTRUSTED, add_execution_run, build_workspace

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.cli import main
from loader_detection_workbench.detection.domain import RunKind
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.execution.domain import RunStatus
from loader_detection_workbench.report.analysis import CaseAnalysisQuery
from loader_detection_workbench.report.render import render_html, render_markdown
from loader_detection_workbench.report.service import ReportFormat, ReportService

GENERATED = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    return path


def _headings(markdown: str) -> list[str]:
    return [line for line in markdown.splitlines() if line.startswith("## ")]


def test_analysis_query_collects_every_record_kind(root: Path) -> None:
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    before = (root / "project.db").read_bytes()
    analysis = CaseAnalysisQuery(root).query(timeline)

    assert [a.artifact_id.display_id for a in analysis.artifacts] == [
        "ART-000001",
        "ART-000002",
        "ART-000003",
    ]
    assert [s.source_artifact_id for s in analysis.static_results] == ["ART-000001"]
    assert [h.display_id for h in analysis.hypotheses] == ["HYP-0001"]
    assert [r.display_id for r in analysis.rules] == ["RULE-0001", "RULE-0002"]
    assert [r.display_id for r in analysis.validation_runs] == [
        f"RUN-000{n}" for n in range(1, 6)
    ]
    assert [r.kind for r in analysis.validation_runs] == [
        RunKind.DEVELOPMENT,
        RunKind.DEVELOPMENT,
        RunKind.DEVELOPMENT,
        RunKind.EVALUATION,
        RunKind.TUNING,
    ]
    assert [m.member.role.value for m in analysis.memberships] == ["dev"]
    assert [r.display_id for r in analysis.execution_runs] == ["VMR-0001"]
    assert not analysis.is_empty
    assert (root / "project.db").read_bytes() == before

    empty = CaseAnalysisQuery(root).query(CaseTimelineQuery(root).query("CASE-0004"))
    assert empty.is_empty


def test_markdown_report_contains_all_sections_with_denominators(root: Path) -> None:
    report = ReportService(root, clock=lambda: GENERATED).build(
        "CASE-0001", Path("reports/full.md")
    )
    content = report.read_text(encoding="utf-8")

    assert _headings(content) == [
        "## Case Overview",
        "## Confirmed Findings",
        "## Appendix A — Recorded Data",
        "## Evidence Summary",
        "## Static Evidence",
        "## Timeline",
        "## Other Sysmon Events",
        "## VM Execution Runs",
        "## Detection Hypotheses",
        "## Detection Rules",
        "## Validation Results",
        "## Collection / Analysis Limits",
    ]
    # Evidence summary and static evidence.
    assert "- Attached Artifacts: 3 (sample: 1, static: 1, sysmon: 1)" in content
    assert "- Benchmark Membership: BMK-0001 as dev (frozen)" in content
    assert "### ART-000003 — static result for ART-000001" in content
    assert "- Imports: 1 DLLs / 2 functions" in content
    assert "KERNEL32" in content and "LoadLibraryA" in content
    assert r"presence only\; not verified" in content
    assert "Analysis Leads (not a verdict)" in content
    # VM run: step names only, never the recorded step detail.
    assert "| VMR-0001 | benign\\_scenario |" not in content  # trusted cells unescaped
    assert (
        r"| VMR-0001 | benign_scenario | file\-write | "
        r"WIN11\-ANALYSIS \/ SYSMON\-V2\-CLEAN | succeeded |" in content
    )
    assert "approval ok → preflight ok → restore_before ok" in content
    assert "secret" not in content
    # Hypothesis, rule versions and rule body.
    assert "- Status: supported" in content
    assert "- Evidence Artifacts: ART-000002 (sysmon), ART-000003 (static)" in content
    assert "- Linked Rules: RULE-0001, RULE-0002" in content
    assert "Content of version 2 (frozen):" in content
    assert "CommandLine|contains|all: ['-enc', 'hidden']" in content
    assert '$marker = "SYNTHETIC-LOADER-MARKER"' in content
    # Validation: kinds are separated and counts carry denominators.
    development = content.index("### Development Runs")
    evaluation = content.index("### Evaluation Runs (Unseen")
    tuning = content.index("### Tuning Runs")
    assert development < evaluation < tuning
    rows = {
        line.split(" | ")[0].lstrip("| "): line
        for line in content.splitlines()
        if line.startswith("| RUN-")
    }
    assert "| RULE-0002 v1 | BMK-0001 |" in rows["RUN-0002"]
    assert " | 1/1 | 1/1 | 0 | dev: TP | " in rows["RUN-0002"]  # v1: FP on benign
    assert " | 1/1 | 0/1 | 0 | dev: TP | " in rows["RUN-0003"]  # v2 removes the FP
    assert " | 2/2 | 0/1 | 0 | dev: TP | " in rows["RUN-0004"]
    assert content.index("RUN-0004") > evaluation
    assert content.index("| RUN-0005 ") > tuning
    assert "RUN-0001 (RULE-0001 v1, development, TP)" in content
    assert "ART\\-000001 rule synthetic\\_loader\\_marker" in content
    assert "ART\\-000002\\#11 \\(EventID 1\\)" in content
    assert "Tuning runs are recorded separately" in content
    assert "Workbench itself produces no maliciousness verdict." in content


def test_untrusted_text_is_inert_in_markdown_and_html(root: Path) -> None:
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    analysis = CaseAnalysisQuery(root).query(timeline)
    markdown = render_markdown(timeline, GENERATED, analysis)
    page = render_html(timeline, GENERATED, analysis)

    assert UNTRUSTED not in markdown and UNTRUSTED not in page
    assert "<script>" not in markdown and "<script>" not in page
    assert "&lt;script&gt;" in markdown and "&lt;script&gt;" in page
    assert "\\[x\\]\\(javascript\\:bad\\)" in markdown
    assert "\\`tick\\`" in markdown
    # Untrusted pipes cannot add table cells.
    for line in markdown.splitlines():
        if line.startswith("| RUN-"):
            assert len(re.findall(r"(?<!\\)\|", line)) == 10
    # No element or attribute other than the fixed report skeleton.
    tags = set(re.findall(r"<([a-z0-9]+)", page))
    assert tags <= {
        "html",
        "head",
        "meta",
        "title",
        "style",
        "body",
        "h1",
        "h2",
        "h3",
        "ul",
        "li",
        "span",
        "p",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "pre",
    }
    assert "javascript:bad" in page and "href" not in page
    assert "default-src 'none'" in page
    assert str(root) not in markdown and str(root) not in page


def test_rule_body_cannot_close_its_code_fence(root: Path) -> None:
    detection = DetectionService(root)
    body = (
        'rule fenced {\n  strings:\n    $a = "```` ``` </pre><script>"\n'
        "  condition:\n    $a\n}\n"
    )
    rule = detection.add_rule("fence", "yara", body)
    hypothesis = detection.add_hypothesis("CASE-0002", "fence", "fence test")
    detection.link_rule(hypothesis.display_id, rule.display_id)
    timeline = CaseTimelineQuery(root).query("CASE-0002")
    analysis = CaseAnalysisQuery(root).query(timeline)

    markdown = render_markdown(timeline, GENERATED, analysis)
    fences = [line for line in markdown.splitlines() if line.startswith("`````")]
    assert fences == ["`````text", "`````"]
    page = render_html(timeline, GENERATED, analysis)
    assert "</pre><script>" not in page
    assert "&lt;/pre&gt;&lt;script&gt;" in page


def test_html_report_by_extension_and_flag(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["report", "build", "CASE-0001", "reports/case.html"]) == 0
    assert capsys.readouterr().out == "report: created\n"
    page = (root / "reports/case.html").read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>")
    assert "<h1>Case Report — CASE-0001</h1>" in page
    for section in (
        "Static Evidence",
        "VM Execution Runs",
        "Detection Hypotheses",
        "Detection Rules",
        "Validation Results",
        "Collection / Analysis Limits",
    ):
        assert f"<h2>{section}</h2>" in page
    assert '<td class="num">' in page
    assert "<script" not in page and "http://" not in page.replace(
        "http://example.invalid", ""
    )

    assert (
        main(["report", "build", "CASE-0001", "as-html.txt", "--format", "html"]) == 0
    )
    assert (root / "as-html.txt").read_text(encoding="utf-8").startswith("<!doctype")
    assert main(["report", "build", "CASE-0001", "x.html", "--format", "markdown"]) == 0
    assert (root / "x.html").read_text(encoding="utf-8").startswith("# Case Report")
    capsys.readouterr()

    assert main(["report", "build", "CASE-0001", "reports/case.html"]) == 2
    assert "REPORT_OUTPUT_EXISTS" in capsys.readouterr().err
    assert ReportFormat.for_output(Path("a.HTM")) is ReportFormat.HTML
    assert ReportFormat.for_output(Path("a.md")) is ReportFormat.MARKDOWN


def test_sysmon_only_case_keeps_the_original_report_shape(root: Path) -> None:
    timeline = CaseTimelineQuery(root).query("CASE-0004")
    analysis = CaseAnalysisQuery(root).query(timeline)
    assert render_markdown(timeline, GENERATED, analysis) == render_markdown(
        timeline, GENERATED
    )
    assert _headings(render_markdown(timeline, GENERATED, analysis)) == [
        "## Case Overview",
        "## Confirmed Findings",
        "## Appendix A — Recorded Data",
        "## Evidence Summary",
        "## Timeline",
        "## Collection / Analysis Limits",
    ]


def test_failed_run_and_non_member_case_are_reported(root: Path) -> None:
    add_execution_run(
        root, "CASE-0002", status=RunStatus.FAILED, error_code="GUEST_NOT_READY"
    )
    timeline = CaseTimelineQuery(root).query("CASE-0002")
    markdown = render_markdown(
        timeline, GENERATED, CaseAnalysisQuery(root).query(timeline)
    )
    assert (
        r"| VMR-0002 | benign_scenario | file\-write | "
        r"WIN11\-ANALYSIS \/ SYSMON\-V2\-CLEAN | failed |" in markdown
    )
    assert "GUEST\\_NOT\\_READY" in markdown
    assert "benign_common: FP" in markdown  # RUN-0002, Sigma v1
    assert "benign_common: TN" in markdown
    assert "## Detection Hypotheses" not in markdown


def test_report_fails_closed_on_invalid_static_result(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from loader_detection_workbench.artifact.service import ArtifactService

    bad = root.parent / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    ArtifactService(root).add("CASE-0004", bad, "static")
    with pytest.raises(DomainError) as error:
        CaseAnalysisQuery(root).query(CaseTimelineQuery(root).query("CASE-0004"))
    assert error.value.code is DomainErrorCode.INVALID_ARTIFACT_RECORD
    for name in ("bad.md", "bad.html"):
        assert main(["report", "build", "CASE-0004", name]) == 2
        captured = capsys.readouterr()
        assert captured.out == "" and "INVALID_ARTIFACT_RECORD" in captured.err
        assert not (root / name).exists()
    assert CaseService(root).show("CASE-0004").name == "empty"
