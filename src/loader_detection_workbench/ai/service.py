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

from loader_detection_workbench.ai.compare import (
    Comparison,
    compare_analyses,
    latest_per_provider,
)
from loader_detection_workbench.ai.digest import (
    APPROVED_SCOPES,
    build_digest,
    digest_sha256,
    serialize_digest,
)
from loader_detection_workbench.ai.domain import (
    MAX_INPUT_BYTES,
    MAX_TEXT,
    AiAnalysis,
    AnalysisStage,
    ReviewState,
    SuggestionKind,
    require_analysis_id,
    validate_output,
)
from loader_detection_workbench.ai.external import KEY_ENV, api_key, external_providers
from loader_detection_workbench.ai.provider import AnalysisProvider, default_providers
from loader_detection_workbench.ai.store import AiAnalysisReader, ai_repository
from loader_detection_workbench.ai.translate import (
    LANGUAGE,
    parse_translation,
    translation_request,
)
from loader_detection_workbench.ai.translate import (
    SYSTEM_PROMPT as TRANSLATE_SYSTEM_PROMPT,
)
from loader_detection_workbench.case.relations import CaseProcessRelationsQuery
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.config import AiConfig
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.findings.domain import FindingKind
from loader_detection_workbench.presentation import single_line
from loader_detection_workbench.report.analysis import CaseAnalysisQuery

DEFAULT_PROVIDER = "offline-template"


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    name: str
    model: str
    requires_network: bool
    enabled: bool
    # Why an external provider cannot be called now, or ``None``.
    blocked_by: str | None = None


@dataclass(frozen=True, slots=True)
class TranslationResult:
    analysis_display_id: str
    provider: str
    stored: int  # translated by this call
    total: int  # translations the analysis now has


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
    """External providers run only when both gates are open (ADR-031).

    ``ai_config.allow_network`` comes from the configuration file and
    ``allow_network`` of each ``analyze`` call from the command line; either
    one alone refuses the call before any input leaves this machine.
    """

    def __init__(
        self,
        root: Path,
        providers: dict[str, AnalysisProvider] | None = None,
        *,
        ai_config: AiConfig | None = None,
    ) -> None:
        self._root = root
        self._config = AiConfig() if ai_config is None else ai_config
        if providers is None:
            providers = {
                **default_providers(),
                **external_providers(self._config.models),
            }
        self._providers = providers
        self._reader = AiAnalysisReader(root)

    # -- providers ------------------------------------------------------------

    def _blocked(self, provider: AnalysisProvider, allow_network: bool) -> str | None:
        if not provider.requires_network:
            return None
        if not self._config.allow_network:
            return "network use is off in the configuration ([ai] allow_network)"
        if provider.name in KEY_ENV and api_key(provider.name) is None:
            return f"{KEY_ENV[provider.name]} is not set"
        if not allow_network:
            return "this command did not allow network use (--allow-network)"
        return None

    def providers(self) -> list[ProviderInfo]:
        infos = []
        for _, provider in sorted(self._providers.items()):
            reason = self._blocked(provider, allow_network=True)
            infos.append(
                ProviderInfo(
                    provider.name,
                    provider.model,
                    provider.requires_network,
                    enabled=reason is None,
                    blocked_by=reason,
                )
            )
        return infos

    def _provider(self, name: str, allow_network: bool = False) -> AnalysisProvider:
        provider = self._providers.get(name)
        if provider is None:
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_UNAVAILABLE, "unknown analysis provider"
            )
        reason = self._blocked(provider, allow_network)
        if reason is not None:
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_UNAVAILABLE,
                f"external provider {name} is not enabled: {reason}",
            )
        return provider

    # -- analysis -------------------------------------------------------------

    def preview(self, case_display_id: str, stage: str | None = None) -> InputPreview:
        """Build the exact provider input; ``stage`` selects ADR-031 opinions."""
        parsed = None if stage is None else AnalysisStage.parse(stage)
        timeline = CaseTimelineQuery(self._root).query(case_display_id)
        analysis = CaseAnalysisQuery(self._root).query(timeline)
        if parsed is AnalysisStage.SYNTHESIS and not any(
            finding.kind is FindingKind.EVIDENCE for finding in analysis.findings
        ):
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "synthesis needs at least one confirmed evidence finding",
            )
        relations = CaseProcessRelationsQuery(self._root).query(timeline)
        digest = build_digest(
            timeline, analysis, relations, None if parsed is None else parsed.value
        )
        serialized = serialize_digest(digest)
        size = len(serialized.encode("utf-8"))
        if size > MAX_INPUT_BYTES:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "evidence digest exceeds the 256 KiB input limit",
            )
        return InputPreview(
            timeline.case.case_id.display_id,
            str(digest["scope"]),
            digest_sha256(serialized),
            size,
            serialized,
            digest,
        )

    def analyze(
        self,
        case_display_id: str,
        provider_name: str = DEFAULT_PROVIDER,
        stage: str | None = None,
        *,
        allow_network: bool = False,
    ) -> AiAnalysis:
        """Ask one provider; without ``stage`` the ADR-026 kinds are produced."""
        provider = self._provider(provider_name, allow_network)
        preview = self.preview(case_display_id, stage)
        if preview.scope not in APPROVED_SCOPES:  # never send anything wider
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST, "input scope is not approved"
            )
        allowed = frozenset(
            [str(item["id"]) for item in preview.digest["artifacts"]]
            + [str(item["id"]) for item in preview.digest.get("findings", [])]
        )
        parsed = AnalysisStage(preview.digest.get("stage", AnalysisStage.LEGACY.value))
        try:
            output = provider.analyze(preview.digest)
        except DomainError:
            raise
        except Exception as exc:  # a provider failure must never look like success
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_FAILED,
                f"analysis provider failed ({type(exc).__name__})",
            ) from exc
        suggestions = validate_output(output, allowed, parsed)
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

    def compare(
        self,
        case_display_id: str,
        analysis_display_ids: list[str] | None = None,
    ) -> Comparison:
        """Compare stored analyses of one input (W8); calls no provider.

        Without explicit IDs the newest analysis of each provider for the
        Case's most recent input is used.
        """
        if analysis_display_ids:
            chosen = [
                self._reader.show(require_analysis_id(display_id))
                for display_id in analysis_display_ids
            ]
            if any(a.case_display_id != case_display_id for a in chosen):
                raise DomainError(
                    DomainErrorCode.INVALID_AI_REQUEST,
                    "compared analyses must belong to the given Case",
                )
        else:
            chosen = latest_per_provider(self._reader.list(case_display_id))
        return compare_analyses(chosen)

    def list_analyses(self, case_display_id: str | None = None) -> list[AiAnalysis]:
        return self._reader.list(case_display_id)

    def show(self, analysis_display_id: str) -> AiAnalysis:
        return self._reader.show(analysis_display_id)

    # -- reading aid (ADR-033) -----------------------------------------------

    def translations(
        self, analysis_display_id: str
    ) -> dict[int, tuple[str | None, str]]:
        """Stored Korean translations of one analysis, by suggestion sequence."""
        require_analysis_id(analysis_display_id)
        with ai_repository(self._root) as repository:
            return repository.translations(analysis_display_id, LANGUAGE)

    def translate(
        self,
        analysis_display_id: str,
        provider_name: str = "deepseek",
        *,
        allow_network: bool = False,
    ) -> TranslationResult:
        """Translate the not yet translated suggestions of one analysis.

        Sends only each suggestion's sequence, title and text. The answer is
        validated fail closed before anything is stored.
        """
        analysis = self.show(analysis_display_id)
        provider = self._provider(provider_name, allow_network)
        complete = getattr(provider, "complete_json", None)
        if complete is None:
            raise DomainError(
                DomainErrorCode.AI_PROVIDER_UNAVAILABLE,
                f"provider {provider_name} cannot translate",
            )
        done = self.translations(analysis_display_id)
        todo = [s for s in analysis.suggestions if s.sequence not in done]
        if not todo:
            return TranslationResult(analysis_display_id, provider_name, 0, len(done))
        request = translation_request(todo)
        answer = complete(TRANSLATE_SYSTEM_PROMPT, request.json)
        items = parse_translation(answer, todo)
        with ai_repository(self._root, write=True) as repository:
            stored = repository.insert_translations(
                analysis_display_id,
                LANGUAGE,
                provider.name,
                provider.model,
                request.sha256,
                items,
            )
        return TranslationResult(
            analysis_display_id, provider_name, stored, len(done) + stored
        )

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
        if suggestion.kind in (
            SuggestionKind.HYPOTHESIS,
            SuggestionKind.HYPOTHESIS_CANDIDATE,
        ) and all(item.startswith("ART-") for item in suggestion.evidence_artifact_ids):
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
