"""W8 multi-provider comparison of stored AI analyses (offline, keyless)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from analysis_fixture import build_workspace

from loader_detection_workbench.ai.compare import (
    compare_analyses,
    latest_per_provider,
    similarity,
)
from loader_detection_workbench.ai.domain import (
    ProviderOutput,
    ProviderSuggestion,
    SuggestionKind,
)
from loader_detection_workbench.ai.provider import OfflineTemplateProvider
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.validator import validate_workspace


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    return path


class ScriptedProvider:
    requires_network = False

    def __init__(self, name: str, output: ProviderOutput) -> None:
        self.name = name
        self.model = f"{name}-1"
        self._output = output
        self.calls = 0

    def analyze(self, digest: Mapping[str, Any]) -> ProviderOutput:
        self.calls += 1
        return self._output


def _service(root: Path) -> tuple[AiAnalysisService, ProviderSuggestion]:
    offline = OfflineTemplateProvider()
    baseline = AiAnalysisService(root).preview("CASE-0001").digest
    template = next(
        s for s in offline.analyze(baseline).suggestions if s.title is not None
    )
    second = ScriptedProvider(
        "second",
        ProviderOutput(
            (
                ProviderSuggestion(SuggestionKind.SUMMARY, "Second summary."),
                # Same citation, overlapping title: the same opinion.
                ProviderSuggestion(
                    SuggestionKind.HYPOTHESIS,
                    "Reworded explanation of the same parent and child pair.",
                    title=f"{template.title} (observed)",
                    evidence_artifact_ids=template.evidence_artifact_ids,
                ),
                # Same title but different evidence: a different opinion.
                ProviderSuggestion(
                    SuggestionKind.HYPOTHESIS,
                    "Only this provider raised it.",
                    title="Unusual section entropy",
                ),
            )
        ),
    )
    service = AiAnalysisService(root, {offline.name: offline, "second": second})
    return service, template


def test_compare_splits_shared_and_single_provider_opinions(root: Path) -> None:
    service, template = _service(root)
    service.analyze("CASE-0001")
    service.analyze("CASE-0001", "second")

    comparison = service.compare("CASE-0001")
    assert [a.provider for a in comparison.analyses] == ["offline-template", "second"]
    assert [s.provider for s in comparison.summaries] == ["offline-template", "second"]
    shared = [g for g in comparison.common if g.opinions[0].title == template.title]
    assert len(shared) == 1
    assert shared[0].providers == ("offline-template", "second")
    assert shared[0].evidence_artifact_ids == tuple(
        sorted(template.evidence_artifact_ids)
    )
    singles = {
        (group.providers, group.opinions[0].title) for group in comparison.individual
    }
    assert (("second",), "Unusual section entropy") in singles
    assert all(not group.shared for group in comparison.individual)
    # Explicit selection gives the same result; nothing new is stored.
    explicit = service.compare("CASE-0001", ["AIA-0001", "AIA-0002"])
    assert explicit == comparison
    assert len(service.list_analyses()) == 2
    assert validate_workspace(root).findings == ()


def test_compare_refuses_inputs_that_are_not_comparable(root: Path) -> None:
    service, _ = _service(root)
    first = service.analyze("CASE-0001")
    with pytest.raises(DomainError) as error:
        service.compare("CASE-0001")
    assert error.value.code is DomainErrorCode.INVALID_AI_REQUEST
    second = service.analyze("CASE-0001", "second")
    for analyses in (
        [first, replace(second, input_sha256="0" * 64)],
        [first, replace(second, case_display_id="CASE-0002")],
        [first, replace(second, provider="offline-template")],
        [first, first],
    ):
        with pytest.raises(DomainError) as error:
            compare_analyses(analyses)
        assert error.value.code is DomainErrorCode.INVALID_AI_REQUEST
    with pytest.raises(DomainError) as error:
        service.compare("CASE-0002", ["AIA-0001", "AIA-0002"])
    assert error.value.code is DomainErrorCode.INVALID_AI_REQUEST


def test_default_selection_uses_newest_input_and_newest_per_provider(
    root: Path,
) -> None:
    service, _ = _service(root)
    old = service.analyze("CASE-0001")
    again = service.analyze("CASE-0001")
    other = service.analyze("CASE-0001", "second")
    stale = replace(other, input_sha256="f" * 64, display_id="AIA-0000")
    chosen = latest_per_provider([old, again, other, stale])
    assert [a.display_id for a in chosen] == [again.display_id, other.display_id]


def test_similarity_is_token_based() -> None:
    assert (
        similarity("cmd.exe spawns powershell.exe", "CMD.EXE spawns powershell.exe")
        == 1
    )
    assert similarity("registry modification", "network activity") == 0
    assert similarity("", "") == 1


def test_cli_and_report_show_the_comparison(
    root: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, template = _service(root)
    service.analyze("CASE-0001")
    service.analyze("CASE-0001", "second")
    monkeypatch.setattr(
        "loader_detection_workbench.cli.AiAnalysisService", lambda _root: service
    )
    capsys.readouterr()
    assert main(["ai", "compare", "CASE-0001"]) == 0
    out = capsys.readouterr().out
    assert "note: suggestions are inferences, not observed evidence" in out
    assert "shared opinions: " in out and "single-provider opinions: " in out
    assert f"[offline-template, second] {template.title}" in out

    assert main(["report", "build", "CASE-0001", "compare.md"]) == 0
    markdown = (root / "compare.md").read_text(encoding="utf-8")
    assert "### Provider Comparison" in markdown
    assert "2 providers analyzed the same input" in markdown
    assert r"| shared | offline\-template\, second | hypothesis |" in markdown
