"""AI-assisted analysis skeleton: offline provider, review, report and UI (W7).

No network, API key or external provider is involved anywhere in this file.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from analysis_fixture import CHILD_GUID, UNTRUSTED, build_workspace

from loader_detection_workbench.ai.digest import DIGEST_SCOPE, safe_name
from loader_detection_workbench.ai.domain import (
    MAX_SUGGESTIONS,
    ProviderOutput,
    ProviderSuggestion,
    ReviewState,
    SuggestionKind,
)
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.cli import main
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.validation import ValidationScope
from loader_detection_workbench.project.validator import validate_workspace
from loader_detection_workbench.web import create_app


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    return path


class FakeProvider:
    """Test double with a scripted output; ``requires_network`` is configurable."""

    name = "fake"
    model = "fake-1"

    def __init__(self, output: object, *, requires_network: bool = False) -> None:
        self._output = output
        self.requires_network = requires_network
        self.calls: list[Mapping[str, Any]] = []

    def analyze(self, digest: Mapping[str, Any]) -> ProviderOutput:
        self.calls.append(digest)
        if isinstance(self._output, Exception):
            raise self._output
        return self._output  # type: ignore[return-value]


def _service(
    root: Path, output: object, **kwargs: bool
) -> tuple[AiAnalysisService, FakeProvider]:
    provider = FakeProvider(output, **kwargs)
    return AiAnalysisService(root, {"fake": provider}), provider


def test_digest_is_structural_and_holds_no_sensitive_value(root: Path) -> None:
    before = (root / "project.db").read_bytes()
    preview = AiAnalysisService(root).preview("CASE-0001")
    text = preview.serialized

    assert preview.scope == DIGEST_SCOPE == "structural"
    assert json.loads(text) == preview.digest
    assert preview.size_bytes == len(text.encode())
    for forbidden in (
        "C:\\\\",  # any Windows directory (JSON-escaped backslash)
        "synthetic",
        "System32",
        "-enc",
        "AAAA",
        "hidden",
        "SYNTHETIC-LOADER-MARKER",
        "example.invalid",
        "HKCU",
        CHILD_GUID.strip("{}"),
        "dev sample",  # Case name is analyst free text
        "Hidden encoded PowerShell",  # hypothesis title
        UNTRUSTED,
        str(root).replace("\\", "\\\\"),
    ):
        assert forbidden not in text
    digest = preview.digest
    assert digest["case"] == {"display_id": "CASE-0001", "kind": "malware"}
    assert [a["id"] for a in digest["artifacts"]] == [
        "ART-000001",
        "ART-000002",
        "ART-000003",
    ]
    static = digest["static"][0]
    assert static["imports"] == [
        {"dll": "KERNEL32.dll", "functions": ["VirtualAlloc", "LoadLibraryA"]}
    ]
    assert static["indicator_counts"]["url"] == 1  # count, never the value
    assert "sha256" not in text and "imphash" not in text
    sysmon = digest["sysmon"]
    assert sysmon["event_id_counts"] == {"1": 2, "11": 1, "22": 1}
    child = sysmon["processes"][1]
    assert child["image_name"] == "powershell.exe" and child["parent_index"] == 0
    assert child["activity"] == {"dns": 1} and child["file_extensions"] == [".bin"]
    assert child["source_artifact"] == "ART-000002"
    assert digest["recorded"] == {"hypotheses": 1, "rules": 2, "validation_runs": 5}
    # Deterministic and read-only.
    assert AiAnalysisService(root).preview("CASE-0001").sha256 == preview.sha256
    assert (root / "project.db").read_bytes() == before
    assert safe_name("ok_Name-1.dll") == "ok_Name-1.dll"
    assert safe_name("<script>") == "(non-standard name)"
    assert safe_name("x" * 65) == "(non-standard name)"


def test_offline_provider_analysis_is_stored_as_pending(root: Path) -> None:
    service = AiAnalysisService(root)
    assert [(p.name, p.requires_network, p.enabled) for p in service.providers()] == [
        ("deepseek", True, False),
        ("gemini", True, False),
        ("offline-template", False, True),
        ("openai", True, False),
    ]
    analysis = service.analyze("CASE-0001")

    assert analysis.display_id == "AIA-0001" and analysis.case_display_id == "CASE-0001"
    assert analysis.provider == "offline-template" and analysis.model == "template-v1"
    assert analysis.input_sha256 == service.preview("CASE-0001").sha256
    kinds = [s.kind for s in analysis.suggestions]
    assert (
        kinds[0] is SuggestionKind.SUMMARY and kinds.count(SuggestionKind.SUMMARY) == 1
    )
    assert all(s.state is ReviewState.PENDING for s in analysis.suggestions)
    hypotheses = [
        s for s in analysis.suggestions if s.kind is SuggestionKind.HYPOTHESIS
    ]
    titles = {s.title for s in hypotheses}
    assert "dev.exe spawns powershell.exe" in titles
    assert "Imports used for dynamic code loading" in titles
    for suggestion in hypotheses:
        assert suggestion.evidence_artifact_ids
        assert set(suggestion.evidence_artifact_ids) <= {"ART-000002", "ART-000003"}
        assert suggestion.expected_benign
    assert service.show("AIA-0001") == analysis
    assert service.list_analyses("CASE-0001") == [analysis]
    assert service.list_analyses("CASE-0002") == []
    # Nothing but the AI tables changed: the Case still has one Hypothesis.
    assert len(DetectionService(root).list_hypotheses("CASE-0001")) == 1
    assert validate_workspace(root).findings == ()

    empty = service.analyze("CASE-0004")
    assert [s.kind for s in empty.suggestions].count(SuggestionKind.REVIEW_ITEM) >= 2
    assert not [s for s in empty.suggestions if s.kind is SuggestionKind.HYPOTHESIS]


def test_accepting_a_candidate_creates_a_hypothesis_once(root: Path) -> None:
    service = AiAnalysisService(root)
    analysis = service.analyze("CASE-0001")
    candidate = next(
        s for s in analysis.suggestions if s.kind is SuggestionKind.HYPOTHESIS
    )
    summary = analysis.suggestions[0]

    accepted = service.accept("AIA-0001", candidate.sequence, "checked the parent")
    reviewed = accepted.suggestion(candidate.sequence)
    assert reviewed.state is ReviewState.ACCEPTED
    assert reviewed.hypothesis_display_id == "HYP-0002"
    assert reviewed.review_note == "checked the parent" and reviewed.reviewed_at
    created = DetectionService(root).show_hypothesis("HYP-0002")
    assert created.case_display_id == "CASE-0001"
    assert created.title == candidate.title and created.statement == candidate.text
    assert created.evidence_artifact_ids == candidate.evidence_artifact_ids
    assert created.status.value == "proposed"  # still the analyst's to judge

    rejected = service.reject("AIA-0001", summary.sequence)
    assert rejected.suggestion(summary.sequence).state is ReviewState.REJECTED
    assert rejected.suggestion(summary.sequence).hypothesis_display_id is None

    for action in (service.accept, service.reject):
        with pytest.raises(DomainError) as error:
            action("AIA-0001", candidate.sequence)
        assert error.value.code is DomainErrorCode.AI_SUGGESTION_ALREADY_REVIEWED
    assert len(DetectionService(root).list_hypotheses("CASE-0001")) == 2
    with pytest.raises(DomainError) as error:
        service.accept("AIA-0001", 99)
    assert error.value.code is DomainErrorCode.AI_ANALYSIS_NOT_FOUND
    with pytest.raises(DomainError) as error:
        service.accept("AIA-0009", 1)
    assert error.value.code is DomainErrorCode.AI_ANALYSIS_NOT_FOUND
    with pytest.raises(DomainError) as error:
        service.reject("AIA-0001", 0)
    assert error.value.code is DomainErrorCode.INVALID_AI_REQUEST
    assert validate_workspace(root).findings == ()


def _hypothesis(**overrides: object) -> ProviderSuggestion:
    values: dict[str, Any] = {
        "kind": SuggestionKind.HYPOTHESIS,
        "text": "statement",
        "title": "title",
        "evidence_artifact_ids": ("ART-000002",),
    }
    values.update(overrides)
    return ProviderSuggestion(**values)


@pytest.mark.parametrize(
    "output",
    [
        "not an output object",
        ProviderOutput(()),
        ProviderOutput(tuple(_hypothesis() for _ in range(MAX_SUGGESTIONS + 1))),
        ProviderOutput(
            (_hypothesis(evidence_artifact_ids=("ART-000004",)),)
        ),  # other Case
        ProviderOutput((_hypothesis(evidence_artifact_ids=("ART-999999",)),)),
        ProviderOutput((_hypothesis(evidence_artifact_ids=("../x",)),)),
        ProviderOutput((_hypothesis(title=None),)),
        ProviderOutput((_hypothesis(text="x" * 2001),)),
        ProviderOutput((_hypothesis(text="   "),)),
        ProviderOutput((_hypothesis(text=123),)),
        ProviderOutput(
            (
                ProviderSuggestion(SuggestionKind.SUMMARY, "one"),
                ProviderSuggestion(SuggestionKind.SUMMARY, "two"),
            )
        ),
        ProviderOutput(
            (ProviderSuggestion(SuggestionKind.REVIEW_ITEM, "t", title="x"),)
        ),
        ProviderOutput((ProviderSuggestion("summary", "text"),)),  # type: ignore[arg-type]
    ],
)
def test_invalid_provider_output_is_rejected_and_nothing_is_stored(
    root: Path, output: object
) -> None:
    service, provider = _service(root, output)
    before = (root / "project.db").read_bytes()
    with pytest.raises(DomainError) as error:
        service.analyze("CASE-0001", "fake")
    assert error.value.code is DomainErrorCode.AI_OUTPUT_INVALID
    assert len(provider.calls) == 1
    assert (root / "project.db").read_bytes() == before
    assert service.list_analyses() == []


def test_provider_text_is_normalized_and_stored_separately(root: Path) -> None:
    service, provider = _service(
        root,
        ProviderOutput(
            (
                ProviderSuggestion(
                    SuggestionKind.SUMMARY, f"line one\n## fake {UNTRUSTED}"
                ),
                _hypothesis(
                    title="  spaced\ttitle ",
                    evidence_artifact_ids=("ART-000002", "ART-000002"),
                ),
            )
        ),
    )
    analysis = service.analyze("CASE-0001", "fake")
    assert "\n" not in analysis.suggestions[0].text
    assert analysis.suggestions[1].title == "spaced title"
    assert analysis.suggestions[1].evidence_artifact_ids == ("ART-000002",)
    assert provider.calls[0]["scope"] == "structural"
    assert analysis.input_json == service.preview("CASE-0001").serialized


def test_external_and_failing_providers_never_run_or_store(root: Path) -> None:
    good = ProviderOutput((ProviderSuggestion(SuggestionKind.SUMMARY, "text"),))
    service, provider = _service(root, good, requires_network=True)
    assert [p.enabled for p in service.providers()] == [False]
    with pytest.raises(DomainError) as error:
        service.analyze("CASE-0001", "fake")
    assert error.value.code is DomainErrorCode.AI_PROVIDER_UNAVAILABLE
    assert provider.calls == []  # the digest never left the service

    with pytest.raises(DomainError) as error:
        AiAnalysisService(root).analyze("CASE-0001", "claude")
    assert error.value.code is DomainErrorCode.AI_PROVIDER_UNAVAILABLE

    failing, _ = _service(root, RuntimeError("secret C:\\path token=abc"))
    with pytest.raises(DomainError) as error:
        failing.analyze("CASE-0001", "fake")
    assert error.value.code is DomainErrorCode.AI_PROVIDER_FAILED
    assert "secret" not in str(error.value) and "token" not in str(error.value)
    assert AiAnalysisService(root).list_analyses() == []
    with pytest.raises(DomainError) as error:
        AiAnalysisService(root).analyze("CASE-9999")
    assert error.value.code is DomainErrorCode.CASE_NOT_FOUND


def test_stored_analysis_and_reviews_are_immutable(root: Path) -> None:
    service = AiAnalysisService(root)
    service.analyze("CASE-0001")
    service.reject("AIA-0001", 1)
    statements = (
        "UPDATE ai_analyses SET provider = 'x'",
        "DELETE FROM ai_analyses",
        "DELETE FROM ai_suggestions",
        "UPDATE ai_suggestions SET content_json = '{}' WHERE sequence = 2",
        "UPDATE ai_suggestions SET kind = 'summary' WHERE sequence = 2",
        "UPDATE ai_suggestions SET state = 'accepted' WHERE sequence = 1",
    )
    with closing(sqlite3.connect(root / "project.db")) as connection:
        for statement in statements:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
            connection.rollback()
    assert service.show("AIA-0001").suggestions[0].state is ReviewState.REJECTED


def test_cli_flow(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ai", "providers"]) == 0
    assert "offline-template\ttemplate-v1\tenabled\n" in capsys.readouterr().out
    assert main(["ai", "preview", "CASE-0001"]) == 0
    output = capsys.readouterr().out
    assert "input_scope: structural" in output and '"digest_version": 2' in output
    assert main(["ai", "list"]) == 0 and capsys.readouterr().out == ""

    assert main(["ai", "analyze", "CASE-0001"]) == 0
    output = capsys.readouterr().out
    assert "analysis: AIA-0001" in output
    assert "note: suggestions are inferences, not observed evidence" in output
    assert "[1] summary (pending)" in output
    number = next(
        line.split("]")[0].lstrip("[")
        for line in output.splitlines()
        if "] hypothesis (pending)" in line
    )
    assert main(["ai", "accept", "AIA-0001", number, "--note", "ok"]) == 0
    output = capsys.readouterr().out
    assert f"[{number}] hypothesis (accepted)" in output
    assert "hypothesis: HYP-0002" in output and "review_note: ok" in output
    assert main(["ai", "reject", "AIA-0001", "1"]) == 0
    assert "[1] summary (rejected)" in capsys.readouterr().out
    assert main(["ai", "show", "AIA-0001"]) == 0
    capsys.readouterr()
    assert main(["ai", "list", "--case", "CASE-0001"]) == 0
    assert "AIA-0001\tCASE-0001\tlegacy\toffline-template" in capsys.readouterr().out

    for arguments, code in (
        (["ai", "accept", "AIA-0001", number], "AI_SUGGESTION_ALREADY_REVIEWED"),
        (
            ["ai", "analyze", "CASE-0001", "--provider", "gpt"],
            "AI_PROVIDER_UNAVAILABLE",
        ),
        (["ai", "show", "AIA-0404"], "AI_ANALYSIS_NOT_FOUND"),
        (["ai", "show", "bad"], "INVALID_DISPLAY_ID"),
        (["ai", "preview", "CASE-9999"], "CASE_NOT_FOUND"),
    ):
        assert main(arguments) == 2
        captured = capsys.readouterr()
        assert captured.out == "" and code in captured.err
        assert str(root) not in captured.err


def test_report_and_ui_mark_ai_output_as_inference(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    service, _ = _service(
        root,
        ProviderOutput(
            (
                ProviderSuggestion(SuggestionKind.SUMMARY, f"summary {UNTRUSTED}"),
                _hypothesis(title="candidate title", text="candidate statement"),
            )
        ),
    )
    service.analyze("CASE-0001", "fake")
    service.accept("AIA-0001", 2, "reviewed")

    assert main(["report", "build", "CASE-0001", "ai.md"]) == 0
    assert main(["report", "build", "CASE-0001", "ai.html"]) == 0
    capsys.readouterr()
    markdown = (root / "ai.md").read_text(encoding="utf-8")
    page = (root / "ai.html").read_text(encoding="utf-8")
    heading = "## AI-Assisted Analysis (inference, not observed evidence)"
    assert heading in markdown
    assert markdown.index("## Validation Results") < markdown.index(heading)
    assert markdown.index(heading) < markdown.index("## Collection / Analysis Limits")
    assert "- AI-Assisted Analyses (inference): 1" in markdown
    assert "### AIA-0001 — fake \\/ fake\\-1" in markdown
    assert (
        "| 2 | hypothesis | accepted | candidate title\\: candidate statement |"
        in markdown
    )
    assert "HYP\\-0002 \\(reviewed\\)" in markdown
    assert "### HYP-0002 — candidate title" in markdown  # accepted -> real Hypothesis
    assert "only suggestions accepted by a person become Hypotheses" in markdown
    assert UNTRUSTED not in markdown and UNTRUSTED not in page
    assert "<script>" not in page and "&lt;script&gt;" in page

    client = create_app(root, test_config={"TESTING": True}).test_client()
    text = client.get(
        "/cases/CASE-0001/analysis", base_url="http://127.0.0.1:8080"
    ).text
    assert "Inference, not observed evidence." in text
    assert "AIA-0001 · fake / fake-1" in text
    assert 'class="badge review-accepted">accepted' in text
    assert "<strong>candidate title</strong>: candidate statement" in text
    assert "<script>alert" not in text
    other = client.get(
        "/cases/CASE-0002/analysis", base_url="http://127.0.0.1:8080"
    ).text
    assert "이 Case의 AI 보조 분석이 없습니다." in other


def test_core_pipeline_is_unchanged_without_ai_records(root: Path) -> None:
    """ADR-004: nothing requires the AI module to have ever been used."""
    with closing(sqlite3.connect(root / "project.db")) as connection:
        tables = {
            row[0] for row in connection.execute("SELECT name FROM sqlite_master")
        }
    assert not any(name.startswith("ai_") for name in tables)
    service = AiAnalysisService(root)
    assert service.list_analyses() == [] and service.list_analyses("CASE-0001") == []
    with pytest.raises(DomainError) as error:
        service.show("AIA-0001")
    assert error.value.code is DomainErrorCode.AI_ANALYSIS_NOT_FOUND
    assert main(["report", "build", "CASE-0001", "plain.md"]) == 0
    assert "AI-Assisted" not in (root / "plain.md").read_text(encoding="utf-8")


def _found(root: Path) -> set[tuple[str, str | None]]:
    return {(f.code, f.subject) for f in validate_workspace(root).findings}


def _mutate(root: Path, *statements: str) -> None:
    with closing(sqlite3.connect(root / "project.db")) as connection, connection:
        for statement in statements:
            connection.execute(statement)


def test_project_validate_checks_ai_tables(root: Path) -> None:
    service = AiAnalysisService(root)
    analysis = service.analyze("CASE-0001")
    candidate = next(
        s for s in analysis.suggestions if s.kind is SuggestionKind.HYPOTHESIS
    )
    service.accept("AIA-0001", candidate.sequence)
    assert validate_workspace(root).findings == ()

    # Tampering needs the guard triggers gone; that is reported as well.
    _mutate(
        root,
        "DROP TRIGGER ai_analyses_immutable",
        "DROP TRIGGER ai_suggestions_reviewed_immutable",
        "UPDATE ai_analyses SET input_json = replace(input_json, 'CASE-0001', "
        "'CASE-0002')",
        f"UPDATE ai_suggestions SET hypothesis_display_id = 'HYP-0099' "
        f"WHERE sequence = {candidate.sequence}",
        "UPDATE ai_suggestions SET state = 'accepted', reviewed_at = NULL "
        "WHERE sequence = 1",
        "UPDATE ai_counters SET next_value = 1",
    )
    report = validate_workspace(root)
    assert not report.is_valid
    assert {f.scope for f in report.findings} == {ValidationScope.AI}
    assert _found(root) == {
        ("MODULE_SCHEMA_INCOMPLETE", "ai_analyses_immutable"),
        ("MODULE_SCHEMA_INCOMPLETE", "ai_suggestions_reviewed_immutable"),
        ("AI_INPUT_TAMPERED", "AIA-0001"),
        ("AI_REFERENCE_BROKEN", f"AIA-0001#{candidate.sequence}"),
        ("AI_RECORD_INVALID", "AIA-0001#1"),
        ("AI_COUNTER_INVALID", "analysis"),
    }


def test_project_validate_reports_unsupported_ai_schema(root: Path) -> None:
    AiAnalysisService(root).analyze("CASE-0001")
    _mutate(root, "UPDATE ai_schema SET version = 9")
    assert _found(root) == {("MODULE_SCHEMA_UNSUPPORTED", "ai_schema")}
