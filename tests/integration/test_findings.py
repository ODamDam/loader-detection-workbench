"""Analyst findings and the confirmed-only report body (ADR-031)."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from analysis_fixture import build_workspace

from loader_detection_workbench.ai.domain import SuggestionKind
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.findings.domain import FindingState, RevisionAction
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.project.validator import validate_workspace
from loader_detection_workbench.report.service import ReportService

GENERATED = datetime(2026, 11, 18, 9, 0, tzinfo=UTC)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    return path


def _code(error: pytest.ExceptionInfo[DomainError]) -> DomainErrorCode:
    return error.value.code


def _chain(service: FindingService) -> tuple[str, str, str, str]:
    """hypothesis, evidence, link and mechanism findings, all confirmed."""
    hypothesis = service.create(
        "CASE-0001",
        "hypothesis",
        "The sample starts hidden PowerShell that stages a file.",
        title="Hidden PowerShell stager",
        verdict="supported",
        hypothesis="HYP-0001",
    ).display_id
    evidence = service.create(
        "CASE-0001",
        "evidence",
        "dev.exe starts powershell -w hidden -enc; PowerShell writes out.bin.",
        evidence=["ART-000002:11", "ART-000002:12"],
    ).display_id
    service.confirm(hypothesis)
    service.confirm(evidence)
    link = service.create(
        "CASE-0001",
        "link",
        "The hidden encoded command and the staged file show the stager behavior.",
        findings=[hypothesis, evidence],
    ).display_id
    mechanism = service.create(
        "CASE-0001",
        "mechanism",
        "Step 1: the loader starts PowerShell.\nStep 2: PowerShell writes out.bin.",
        title="Staging",
        findings=[evidence],
    ).display_id
    service.confirm(link)
    service.confirm(mechanism)
    return hypothesis, evidence, link, mechanism


def test_lifecycle_keeps_every_revision(root: Path) -> None:
    service = FindingService(root)
    hypothesis, evidence, link, mechanism = _chain(service)
    assert [f.display_id for f in service.confirmed("CASE-0001")] == [
        hypothesis,
        evidence,
        link,
        mechanism,
    ]
    edited = service.edit(mechanism, text="Corrected step list.", note="typo")
    assert edited.state is FindingState.DRAFT and edited.revision == 3
    assert edited.confirmed_at is None
    again = service.confirm(mechanism, note="re-checked")
    withdrawn = service.withdraw(mechanism, "superseded")
    assert again.revision == 4 and withdrawn.revision == 5
    assert [r.action for r in withdrawn.history] == [
        RevisionAction.CREATE,
        RevisionAction.CONFIRM,
        RevisionAction.EDIT,
        RevisionAction.CONFIRM,
        RevisionAction.WITHDRAW,
    ]
    assert withdrawn.history[1].content.text.startswith("Step 1")
    assert withdrawn.history[2].content.text == "Corrected step list."
    with pytest.raises(DomainError) as error:
        service.edit(mechanism, text="x")
    assert _code(error) is DomainErrorCode.FINDING_STATE_INVALID
    assert validate_workspace(root, full=True).findings == ()


def test_content_rules_per_kind(root: Path) -> None:
    service = FindingService(root)
    cases: list[tuple[dict[str, Any], DomainErrorCode]] = [
        (dict(kind="hypothesis", text="no title"), DomainErrorCode.INVALID_FINDING),
        (
            dict(kind="evidence", text="no artifact"),
            DomainErrorCode.INVALID_FINDING,
        ),
        (
            dict(kind="evidence", text="x", evidence=["ART-000004"]),
            DomainErrorCode.FINDING_REFERENCE_INVALID,
        ),
        (
            dict(kind="evidence", text="x", evidence=["ART-000001:5"]),
            DomainErrorCode.FINDING_REFERENCE_INVALID,
        ),
        (
            dict(kind="link", text="x", findings=["FND-0099"]),
            DomainErrorCode.FINDING_REFERENCE_INVALID,
        ),
        (
            dict(kind="mechanism", text="x", evidence=["ART-000002"]),
            DomainErrorCode.INVALID_FINDING,
        ),
        (
            dict(kind="hypothesis", text="x", title="t", hypothesis="HYP-0099"),
            DomainErrorCode.FINDING_REFERENCE_INVALID,
        ),
    ]
    for arguments, code in cases:
        kind = arguments.pop("kind")
        text = arguments.pop("text")
        with pytest.raises(DomainError) as error:
            service.create("CASE-0001", kind, text, **arguments)
        assert _code(error) is code, (kind, arguments)

    no_verdict = service.create("CASE-0001", "hypothesis", "t", title="t")
    with pytest.raises(DomainError) as error:
        service.confirm(no_verdict.display_id)
    assert _code(error) is DomainErrorCode.INVALID_FINDING

    missing_event = service.create(
        "CASE-0001", "evidence", "x", evidence=["ART-000002:999"]
    )
    with pytest.raises(DomainError) as error:
        service.confirm(missing_event.display_id)
    assert _code(error) is DomainErrorCode.FINDING_REFERENCE_INVALID

    draft_evidence = service.create(
        "CASE-0001", "evidence", "x", evidence=["ART-000002:10"]
    )
    mechanism = service.create(
        "CASE-0001", "mechanism", "x", findings=[draft_evidence.display_id]
    )
    with pytest.raises(DomainError) as error:
        service.confirm(mechanism.display_id)
    assert _code(error) is DomainErrorCode.FINDING_REFERENCE_INVALID
    with pytest.raises(DomainError) as error:  # a link without a hypothesis
        service.create("CASE-0001", "link", "x", findings=[draft_evidence.display_id])
    assert _code(error) is DomainErrorCode.FINDING_REFERENCE_INVALID


def test_referenced_findings_cannot_change(root: Path) -> None:
    service = FindingService(root)
    hypothesis, evidence, link, _ = _chain(service)
    actions: list[Callable[[], object]] = [
        lambda: service.edit(evidence, text="changed"),
        lambda: service.withdraw(hypothesis, "no"),
        lambda: service.withdraw(evidence, "no"),
    ]
    for action in actions:
        with pytest.raises(DomainError) as error:
            action()
        assert _code(error) is DomainErrorCode.FINDING_IN_USE
    service.withdraw(link, "rewording")
    service.edit(hypothesis, verdict="weakened")  # no longer referenced
    assert service.show(hypothesis).state is FindingState.DRAFT


def test_closed_case_is_read_only(root: Path) -> None:
    service = FindingService(root)
    draft = service.create("CASE-0001", "hypothesis", "t", title="t")
    CaseService(root).close("CASE-0001")
    with pytest.raises(DomainError) as error:
        service.edit(draft.display_id, verdict="supported")
    assert _code(error) is DomainErrorCode.CASE_CLOSED
    assert service.list_findings("CASE-0001")[0].display_id == draft.display_id


def test_adopt_starts_a_draft_from_an_ai_suggestion(root: Path) -> None:
    analysis = AiAnalysisService(root).analyze("CASE-0001")
    candidate = next(
        s for s in analysis.suggestions if s.kind is SuggestionKind.HYPOTHESIS
    )
    other = next(
        s for s in analysis.suggestions if s.kind is not SuggestionKind.HYPOTHESIS
    )
    service = FindingService(root)
    adopted = service.adopt(analysis.display_id, candidate.sequence)
    assert adopted.state is FindingState.DRAFT
    assert adopted.source == f"ai:{analysis.display_id}#{candidate.sequence}"
    assert adopted.content.text == candidate.text
    with pytest.raises(DomainError) as error:
        service.adopt(analysis.display_id, other.sequence)
    assert _code(error) is DomainErrorCode.INVALID_FINDING


def test_report_body_contains_confirmed_findings_only(root: Path) -> None:
    service = FindingService(root)
    hypothesis, evidence, _, mechanism = _chain(service)
    service.create(
        "CASE-0001", "hypothesis", "DRAFT-ONLY statement", title="DRAFT-ONLY title"
    )
    AiAnalysisService(root).analyze("CASE-0001")
    report = ReportService(root, clock=lambda: GENERATED).build(
        "CASE-0001", Path("reports/case.md")
    )
    content = report.read_text(encoding="utf-8")
    body, _, appendix = content.partition("## Appendix A — Recorded Data")
    assert "## Confirmed Findings" in body
    assert f"#### {hypothesis} — Hidden PowerShell stager" in body
    assert "- Verdict: supported" in body
    assert "- Detection Hypothesis: HYP-0001" in body
    assert evidence in body and "ART-000002:11" in body
    assert f"#### {mechanism} — Staging" in body
    assert "Step 2" in body
    assert "DRAFT\\-ONLY" not in content
    assert "## Appendix B — AI-Assisted Analysis (inference, not confirmed)" in appendix
    assert "## Detection Hypotheses" in appendix

    empty = ReportService(root, clock=lambda: GENERATED).build(
        "CASE-0003", Path("reports/empty.md")
    )
    assert "No finding has been confirmed for this Case." in empty.read_text(
        encoding="utf-8"
    )


def test_validator_detects_tampering(root: Path) -> None:
    service = FindingService(root)
    hypothesis, evidence, link, _ = _chain(service)
    connection = sqlite3.connect(root / "project.db")
    with connection:
        connection.execute(
            "UPDATE findings SET revision = revision + 1, content_json = "
            "replace(content_json, 'hidden', 'HIDDEN') WHERE display_id = ?",
            (evidence,),
        )
        connection.execute(
            "UPDATE findings SET revision = revision + 1, state = 'draft', "
            "confirmed_at = NULL WHERE display_id = ?",
            (hypothesis,),
        )
    connection.close()
    codes = {(f.code, f.subject) for f in validate_workspace(root).findings}
    assert ("FINDING_HISTORY_INVALID", evidence) in codes
    assert ("FINDING_REFERENCE_BROKEN", link) in codes


def test_cli(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            [
                "finding",
                "add",
                "CASE-0001",
                "--kind",
                "evidence",
                "--text",
                "PowerShell writes out.bin.",
                "--evidence",
                "ART-000002:12",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.startswith("FND-0001\tevidence\tdraft\tr1\t")
    assert main(["finding", "confirm", "FND-0001", "--note", "checked"]) == 0
    capsys.readouterr()
    assert main(["finding", "show", "FND-0001"]) == 0
    shown = capsys.readouterr().out
    assert "state: confirmed" in shown and "evidence: ART-000002:12" in shown
    assert "r2\tconfirm\tconfirmed\t" in shown and "note=checked" in shown
    assert main(["finding", "list", "CASE-0001", "--state", "confirmed"]) == 0
    assert capsys.readouterr().out.count("\n") == 1
    assert main(["finding", "edit", "FND-0001", "--clear", "verdict"]) == 2
    assert "FINDING_STATE_INVALID" in capsys.readouterr().err  # no change
