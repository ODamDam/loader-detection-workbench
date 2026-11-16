"""Application service for AI-assisted analysis (ADR-026).

Flow: query the Case once -> build the structural digest -> call one provider
-> validate its output (fail closed) -> store the input and the suggestions as
``pending``. Nothing a provider says changes evidence, hypotheses or rules.
Only ``accept`` of a hypothesis candidate, by a person, creates a Detection
Hypothesis through the existing ``DetectionService``.

This build runs offline providers only. A provider that would send the digest
off this machine is refused before it is called.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loader_detection_workbench.ai.digest import (
    DIGEST_SCOPE,
    build_digest,
    digest_sha256,
    serialize_digest,
)
from loader_detection_workbench.ai.domain import (
    MAX_INPUT_BYTES,
    MAX_TEXT,
    AiAnalysis,
    ReviewState,
    SuggestionKind,
    require_analysis_id,
    validate_output,
)
from loader_detection_workbench.ai.provider import AnalysisProvider, default_providers
from loader_detection_workbench.ai.store import AiAnalysisReader, ai_repository
from loader_detection_workbench.case.relations import CaseProcessRelationsQuery
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.presentation import single_line
from loader_detection_workbench.report.analysis import CaseAnalysisQuery

DEFAULT_PROVIDER = "offline-template"


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    name: str
    model: str
    requires_network: bool
    enabled: bool


@dataclass(frozen=True, slots=True)
class InputPreview:
    """Exactly what a provider would receive; produced without calling one."""

    case_display_id: str
    scope: str
    sha256: str
    size_bytes: int
    serialized: str
    digest: dict[str, Any]


class AiAnalysisService:
    def __init__(
        self, root: Path, providers: dict[str, AnalysisProvider] | None = None
    ) -> None:
        self._root = root
        self._providers = default_providers() if providers is None else providers
        self._reader = AiAnalysisReader(root)

    # -- providers ------------------------------------------------------------

    def providers(self) -> list[ProviderInfo]:
        return [
            ProviderInfo(
                provider.name,
                provider.model,
                provider.requires_network,
                enabled=not provider.requires_network,
            )
            for _, provider in sorted(self._providers.items())
        ]

    def _provider(self, name: str) -> AnalysisProvider:
        provider = self._providers.get(name)
        if provider is None:
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_UNAVAILABLE, "unknown analysis provider"
            )
        if provider.requires_network:
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_UNAVAILABLE,
                "external providers are not enabled: sending evidence off this "
                "machine needs an approved data scope (ADR-026)",
            )
        return provider

    # -- analysis -------------------------------------------------------------

    def preview(self, case_display_id: str) -> InputPreview:
        timeline = CaseTimelineQuery(self._root).query(case_display_id)
        analysis = CaseAnalysisQuery(self._root).query(timeline)
        relations = CaseProcessRelationsQuery(self._root).query(timeline)
        digest = build_digest(timeline, analysis, relations)
        serialized = serialize_digest(digest)
        size = len(serialized.encode("utf-8"))
        if size > MAX_INPUT_BYTES:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "evidence digest exceeds the 256 KiB input limit",
            )
        return InputPreview(
            timeline.case.case_id.display_id,
            DIGEST_SCOPE,
            digest_sha256(serialized),
            size,
            serialized,
            digest,
        )

    def analyze(
        self, case_display_id: str, provider_name: str = DEFAULT_PROVIDER
    ) -> AiAnalysis:
        provider = self._provider(provider_name)
        preview = self.preview(case_display_id)
        allowed = frozenset(str(item["id"]) for item in preview.digest["artifacts"])
        try:
            output = provider.analyze(preview.digest)
        except DomainError:
            raise
        except Exception as exc:  # a provider failure must never look like success
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_FAILED,
                f"analysis provider failed ({type(exc).__name__})",
            ) from exc
        suggestions = validate_output(output, allowed)
        with ai_repository(self._root, write=True) as repository:
            display_id = repository.insert_analysis(
                preview.case_display_id,
                provider.name,
                provider.model,
                preview.scope,
                preview.sha256,
                preview.serialized,
                suggestions,
            )
            return repository.get(display_id)

    def list_analyses(self, case_display_id: str | None = None) -> list[AiAnalysis]:
        return self._reader.list(case_display_id)

    def show(self, analysis_display_id: str) -> AiAnalysis:
        return self._reader.show(analysis_display_id)

    # -- human review ---------------------------------------------------------

    def _note(self, note: str | None) -> str | None:
        if note is None:
            return None
        cleaned = " ".join(single_line(note).split())
        if not 1 <= len(cleaned) <= MAX_TEXT:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                f"review note must contain 1 to {MAX_TEXT} characters",
            )
        return cleaned

    def _pending(self, analysis_display_id: str, sequence: int) -> AiAnalysis:
        require_analysis_id(analysis_display_id)
        if type(sequence) is not int or sequence < 1:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST, "suggestion number is invalid"
            )
        analysis = self._reader.show(analysis_display_id)
        if analysis.suggestion(sequence).state is not ReviewState.PENDING:
            raise DomainError(
                DomainErrorCode.AI_SUGGESTION_ALREADY_REVIEWED,
                "suggestion was already reviewed",
            )
        return analysis

    def accept(
        self, analysis_display_id: str, sequence: int, note: str | None = None
    ) -> AiAnalysis:
        """Record a person's acceptance; a hypothesis candidate becomes a Hypothesis."""
        cleaned = self._note(note)
        analysis = self._pending(analysis_display_id, sequence)
        suggestion = analysis.suggestion(sequence)
        hypothesis_id: str | None = None
        if suggestion.kind is SuggestionKind.HYPOTHESIS:
            assert suggestion.title is not None
            hypothesis_id = (
                DetectionService(self._root)
                .add_hypothesis(
                    analysis.case_display_id,
                    suggestion.title,
                    suggestion.text,
                    evidence=suggestion.evidence_artifact_ids,
                    expected_benign=suggestion.expected_benign,
                )
                .display_id
            )
        with ai_repository(self._root, write=True) as repository:
            repository.review(
                analysis_display_id,
                sequence,
                ReviewState.ACCEPTED,
                cleaned,
                hypothesis_id,
                utc_now(),
            )
            return repository.get(analysis_display_id)

    def reject(
        self, analysis_display_id: str, sequence: int, note: str | None = None
    ) -> AiAnalysis:
        cleaned = self._note(note)
        self._pending(analysis_display_id, sequence)
        with ai_repository(self._root, write=True) as repository:
            repository.review(
                analysis_display_id,
                sequence,
                ReviewState.REJECTED,
                cleaned,
                None,
                utc_now(),
            )
            return repository.get(analysis_display_id)
