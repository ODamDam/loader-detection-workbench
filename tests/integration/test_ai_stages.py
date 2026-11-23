"""Two-stage AI opinions over the evidence and confirmed findings (ADR-031)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from analysis_fixture import build_workspace

from loader_detection_workbench.ai.domain import (
    MIN_CITATIONS,
    STAGE_KINDS,
    AnalysisStage,
    ProviderOutput,
    ProviderSuggestion,
    SuggestionKind,
    validate_output,
)
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.ai.sqlite_repository import _SCHEMA, AI_SCHEMA_VERSION
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.findings.domain import FindingKind, FindingState
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.project.validator import validate_workspace

COLLECTION = AnalysisStage.COLLECTION
SYNTHESIS = AnalysisStage.SYNTHESIS
K = SuggestionKind


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    return path


def _confirmed_chain(root: Path) -> tuple[str, str]:
    service = FindingService(root)
    hypothesis = service.create(
        "CASE-0001",
        "hypothesis",
        "The sample starts hidden PowerShell that stages a file.",
        title="Hidden PowerShell stager",
        verdict="supported",
    ).display_id
    evidence = service.create(
        "CASE-0001",
        "evidence",
        "dev.exe starts PowerShell, which writes out.bin.",
        evidence=["ART-000002:11"],
    ).display_id
    service.confirm(hypothesis)
    service.confirm(evidence)
    link = service.create(
        "CASE-0001",
        "link",
        "The staged file supports the stager hypothesis.",
        findings=[hypothesis, evidence],
    ).display_id
    service.confirm(link)
    return hypothesis, evidence


def test_collection_stage_opinions_cite_case_evidence(root: Path) -> None:
    service = AiAnalysisService(root)
    preview = service.preview("CASE-0001", "collection")
    assert preview.digest["stage"] == "collection"
    assert preview.scope == "structural" and "findings" not in preview.digest

    analysis = service.analyze("CASE-0001", stage="collection")
    assert analysis.stage is COLLECTION
    assert analysis.input_sha256 == preview.sha256
    kinds = {s.kind for s in analysis.suggestions}
    assert kinds <= STAGE_KINDS[COLLECTION]
    assert K.HYPOTHESIS_CANDIDATE in kinds and K.EVIDENCE_LINK in kinds
    artifacts = {str(item["id"]) for item in preview.digest["artifacts"]}
    for suggestion in analysis.suggestions:
        assert len(suggestion.evidence_artifact_ids) >= MIN_CITATIONS[suggestion.kind]
        assert set(suggestion.evidence_artifact_ids) <= artifacts
    # Analyses made before stages keep reading as legacy.
    assert service.analyze("CASE-0001").stage is AnalysisStage.LEGACY
    assert validate_workspace(root, full=True).findings == ()


def test_synthesis_needs_and_uses_confirmed_findings(root: Path) -> None:
    service = AiAnalysisService(root)
    with pytest.raises(DomainError) as error:
        service.analyze("CASE-0001", stage="synthesis")
    assert error.value.code is DomainErrorCode.INVALID_AI_REQUEST

    hypothesis, evidence = _confirmed_chain(root)
    preview = service.preview("CASE-0001", "synthesis")
    assert preview.scope == "structural+findings"
    assert {item["id"] for item in preview.digest["findings"]} >= {hypothesis, evidence}

    analysis = service.analyze("CASE-0001", stage="synthesis")
    assert analysis.stage is SYNTHESIS
    by_kind = {s.kind: s for s in analysis.suggestions}
    assert set(by_kind) == {K.KEY_HYPOTHESIS, K.MECHANISM}
    assert by_kind[K.KEY_HYPOTHESIS].evidence_artifact_ids == (hypothesis, evidence)
    assert by_kind[K.MECHANISM].evidence_artifact_ids == (evidence,)

    findings = FindingService(root)
    mechanism = findings.adopt(analysis.display_id, by_kind[K.MECHANISM].sequence)
    assert mechanism.kind is FindingKind.MECHANISM
    assert mechanism.state is FindingState.DRAFT
    assert mechanism.content.finding_refs == (evidence,)
    key = findings.adopt(analysis.display_id, by_kind[K.KEY_HYPOTHESIS].sequence)
    assert key.kind is FindingKind.HYPOTHESIS and key.state is FindingState.DRAFT
    assert (
        key.source == f"ai:{analysis.display_id}#{by_kind[K.KEY_HYPOTHESIS].sequence}"
    )
    assert validate_workspace(root, full=True).findings == ()


def test_collection_links_and_next_steps_are_not_adoptable(root: Path) -> None:
    analysis = AiAnalysisService(root).analyze("CASE-0001", stage="collection")
    link = next(s for s in analysis.suggestions if s.kind is K.EVIDENCE_LINK)
    with pytest.raises(DomainError) as error:
        FindingService(root).adopt(analysis.display_id, link.sequence)
    assert error.value.code is DomainErrorCode.INVALID_FINDING
    candidate = next(
        s for s in analysis.suggestions if s.kind is K.HYPOTHESIS_CANDIDATE
    )
    draft = FindingService(root).adopt(analysis.display_id, candidate.sequence)
    assert draft.kind is FindingKind.HYPOTHESIS


@pytest.mark.parametrize(
    ("stage", "suggestion", "message"),
    [
        (
            COLLECTION,
            ProviderSuggestion(
                K.MECHANISM, "steps", evidence_artifact_ids=("ART-000001",)
            ),
            "not a collection stage",
        ),
        (
            COLLECTION,
            ProviderSuggestion(
                K.EVIDENCE_LINK, "a with b", evidence_artifact_ids=("ART-000001",)
            ),
            "at least 2",
        ),
        (
            COLLECTION,
            ProviderSuggestion(
                K.NEXT_STEP,
                "Download the payload from https://example.invalid/x",
                evidence_artifact_ids=("ART-000001",),
            ),
            "link or an instruction",
        ),
        (
            COLLECTION,
            ProviderSuggestion(
                K.NEXT_STEP,
                "Run this: cmd /c whoami",
                evidence_artifact_ids=("ART-000001",),
            ),
            "link or an instruction",
        ),
        (
            SYNTHESIS,
            ProviderSuggestion(
                K.MECHANISM, "steps", evidence_artifact_ids=("FND-0099",)
            ),
            "not in the Case",
        ),
        (
            SYNTHESIS,
            ProviderSuggestion(
                K.KEY_HYPOTHESIS, "no title", evidence_artifact_ids=("FND-0001",)
            ),
            "title",
        ),
        (
            AnalysisStage.LEGACY,
            ProviderSuggestion(K.NEXT_STEP, "x", evidence_artifact_ids=("ART-000001",)),
            "not a legacy stage",
        ),
    ],
)
def test_staged_output_fails_closed(
    stage: AnalysisStage, suggestion: ProviderSuggestion, message: str
) -> None:
    allowed = frozenset({"ART-000001", "ART-000002", "FND-0001"})
    with pytest.raises(DomainError) as error:
        validate_output(ProviderOutput((suggestion,)), allowed, stage)
    assert error.value.code is DomainErrorCode.AI_OUTPUT_INVALID
    assert message in str(error.value)


def test_stage_parse_rejects_legacy_and_unknown() -> None:
    for value in ("legacy", "final", ""):
        with pytest.raises(DomainError):
            AnalysisStage.parse(value)


def test_v1_ai_schema_is_read_and_migrated_on_write(root: Path) -> None:
    service = AiAnalysisService(root)
    first = service.analyze("CASE-0001")
    database = root / "project.db"
    connection = sqlite3.connect(database)
    with connection:
        # Rebuild the v1 table and schema marker as ADR-026 created them.
        for trigger in (
            "ai_suggestions_reviewed_immutable",
            "ai_suggestions_content_immutable",
            "ai_suggestions_no_delete",
        ):
            connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute("ALTER TABLE ai_suggestions RENAME TO old_suggestions")
        connection.execute(
            "CREATE TABLE ai_suggestions (analysis_display_id TEXT NOT NULL, "
            "sequence INTEGER NOT NULL CHECK (sequence >= 1), kind TEXT NOT NULL "
            "CHECK (kind IN ('summary', 'hypothesis', 'review_item')), content_json "
            "TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending', "
            "'accepted', 'rejected')), reviewed_at TEXT, review_note TEXT, "
            "hypothesis_display_id TEXT, PRIMARY KEY (analysis_display_id, sequence), "
            "FOREIGN KEY (analysis_display_id) REFERENCES ai_analyses(display_id) "
            "ON DELETE RESTRICT)"
        )
        connection.execute("INSERT INTO ai_suggestions SELECT * FROM old_suggestions")
        for statement in _SCHEMA:  # the v1 triggers, unchanged in v2
            if "TRIGGER" in statement and "ON ai_suggestions" in statement:
                connection.execute(statement)
        connection.execute("DROP TABLE old_suggestions")
        connection.execute("UPDATE ai_schema SET version = 1")
    connection.close()

    assert service.show(first.display_id).suggestions == first.suggestions
    assert validate_workspace(root, full=True).findings == ()
    staged = service.analyze("CASE-0001", stage="collection")
    assert staged.stage is COLLECTION
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("SELECT version FROM ai_schema").fetchall() == [
            (AI_SCHEMA_VERSION,)
        ]
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND tbl_name = 'ai_suggestions'"
            )
        }
    finally:
        connection.close()
    assert len(triggers) == 3
    assert service.show(first.display_id).suggestions == first.suggestions
    assert validate_workspace(root, full=True).findings == ()


def test_cli_stage_and_several_providers(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["ai", "preview", "CASE-0001", "--stage", "collection"]) == 0
    preview = capsys.readouterr().out
    assert '"stage": "collection"' in preview
    assert main(["ai", "analyze", "CASE-0001", "--stage", "collection"]) == 0
    out = capsys.readouterr().out
    assert "stage: collection" in out and "hypothesis_candidate" in out
    code = main(
        [
            "ai",
            "analyze",
            "CASE-0001",
            "--stage",
            "collection",
            "--provider",
            "offline-template,offline-template",
        ]
    )
    assert code == 2 and "INVALID_AI_REQUEST" in capsys.readouterr().err
    assert main(["ai", "list", "--case", "CASE-0001"]) == 0
    assert "\tcollection\t" in capsys.readouterr().out
    assert main(["ai", "analyze", "CASE-0001", "--stage", "synthesis"]) == 2
    assert "confirmed evidence finding" in capsys.readouterr().err


def test_stages_never_share_an_input(root: Path) -> None:
    """Comparison groups by input SHA-256; the stage is part of the input."""
    service = AiAnalysisService(root)
    collection = service.analyze("CASE-0001", stage="collection")
    legacy = service.analyze("CASE-0001")
    assert collection.input_sha256 != legacy.input_sha256
    assert "stage" not in json.loads(legacy.input_json)
