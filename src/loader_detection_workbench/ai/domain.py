"""AI-assisted analysis records (ADR-026).

A provider turns a bounded evidence digest into *suggestions*: one summary,
hypothesis candidates and review items. Suggestions are inferences, never
observed facts. They are stored apart from evidence and only a person's review
can turn a hypothesis candidate into a Detection Hypothesis.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.presentation import single_line

ANALYSIS_PREFIX = "AIA"
MAX_INPUT_BYTES = 256 * 1024
MAX_SUGGESTIONS = 16
MAX_TITLE = 200
MAX_TEXT = 2000
MAX_CITATIONS = 16
_ANALYSIS_ID = re.compile(rf"{ANALYSIS_PREFIX}-[0-9]{{4,}}", re.ASCII)
_ARTIFACT_ID = re.compile(r"ART-[0-9]{6,}", re.ASCII)
_FINDING_ID = re.compile(r"FND-[0-9]{4,}", re.ASCII)
# An opinion may describe what was observed; it must not send the analyst
# somewhere or tell them to run something (ADR-031).
_LINK = re.compile(r"(?i)\b(?:https?|ftp|file)://|\bwww\.[a-z0-9-]+\.")
_INSTRUCTION = re.compile(
    r"(?i)\b(?:run|execute|paste|type)\s+(?:this|the following)\b"
    r"|\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-(?:c|e|enc|command)\b)"
)


class SuggestionKind(StrEnum):
    # ADR-026 kinds; stored analyses without a stage keep using them.
    SUMMARY = "summary"
    HYPOTHESIS = "hypothesis"
    REVIEW_ITEM = "review_item"
    # ADR-031 collection stage: while evidence is being gathered.
    HYPOTHESIS_CANDIDATE = "hypothesis_candidate"
    EVIDENCE_LINK = "evidence_link"
    NEXT_STEP = "next_step"
    # ADR-031 synthesis stage: over the analyst's confirmed findings.
    KEY_HYPOTHESIS = "key_hypothesis"
    MECHANISM = "mechanism"


class AnalysisStage(StrEnum):
    """Which opinions were asked for (ADR-031). ``legacy`` predates stages."""

    LEGACY = "legacy"
    COLLECTION = "collection"
    SYNTHESIS = "synthesis"

    @classmethod
    def parse(cls, value: str) -> AnalysisStage:
        if value == cls.LEGACY.value:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "analysis stage must be collection or synthesis",
            )
        try:
            return cls(value)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "analysis stage must be collection or synthesis",
            ) from exc


STAGE_KINDS: dict[AnalysisStage, frozenset[SuggestionKind]] = {
    AnalysisStage.LEGACY: frozenset(
        {SuggestionKind.SUMMARY, SuggestionKind.HYPOTHESIS, SuggestionKind.REVIEW_ITEM}
    ),
    AnalysisStage.COLLECTION: frozenset(
        {
            SuggestionKind.HYPOTHESIS_CANDIDATE,
            SuggestionKind.EVIDENCE_LINK,
            SuggestionKind.NEXT_STEP,
        }
    ),
    AnalysisStage.SYNTHESIS: frozenset(
        {SuggestionKind.KEY_HYPOTHESIS, SuggestionKind.MECHANISM}
    ),
}
# Kinds that carry a title, and the fewest citations each kind must make.
TITLED_KINDS = frozenset(
    {
        SuggestionKind.HYPOTHESIS,
        SuggestionKind.HYPOTHESIS_CANDIDATE,
        SuggestionKind.KEY_HYPOTHESIS,
    }
)
MIN_CITATIONS: dict[SuggestionKind, int] = {
    SuggestionKind.HYPOTHESIS_CANDIDATE: 1,
    SuggestionKind.EVIDENCE_LINK: 2,
    SuggestionKind.NEXT_STEP: 1,
    SuggestionKind.KEY_HYPOTHESIS: 1,
    SuggestionKind.MECHANISM: 1,
}


class ReviewState(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


def require_analysis_id(value: str) -> str:
    if not isinstance(value, str) or _ANALYSIS_ID.fullmatch(value) is None:
        raise DomainError(
            DomainErrorCode.INVALID_DISPLAY_ID,
            f"analysis ID must use {ANALYSIS_PREFIX}-0001 format",
        )
    return value


@dataclass(frozen=True, slots=True)
class ProviderSuggestion:
    """One provider statement before validation; every field is untrusted."""

    kind: SuggestionKind
    text: str
    title: str | None = None
    evidence_artifact_ids: tuple[str, ...] = ()
    expected_benign: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderOutput:
    suggestions: tuple[ProviderSuggestion, ...]


@dataclass(frozen=True, slots=True)
class Suggestion:
    sequence: int
    kind: SuggestionKind
    title: str | None
    text: str
    evidence_artifact_ids: tuple[str, ...]
    expected_benign: str | None
    state: ReviewState
    reviewed_at: datetime | None = None
    review_note: str | None = None
    hypothesis_display_id: str | None = None


@dataclass(frozen=True, slots=True)
class AiAnalysis:
    display_id: str
    case_display_id: str
    provider: str
    model: str
    input_scope: str
    input_sha256: str
    input_json: str
    created_at: datetime
    suggestions: tuple[Suggestion, ...]

    @property
    def stage(self) -> AnalysisStage:
        """Read from the stored input; analyses before ADR-031 have none."""
        try:
            value = json.loads(self.input_json).get("stage")
        except (ValueError, AttributeError):
            return AnalysisStage.LEGACY
        try:
            return AnalysisStage(value) if value else AnalysisStage.LEGACY
        except ValueError:
            return AnalysisStage.LEGACY

    def suggestion(self, sequence: int) -> Suggestion:
        for item in self.suggestions:
            if item.sequence == sequence:
                return item
        raise DomainError(
            DomainErrorCode.AI_ANALYSIS_NOT_FOUND, "suggestion was not found"
        )


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.AI_OUTPUT_INVALID, message)


def _text(value: object, field: str, maximum: int, *, optional: bool = False) -> str:
    if value is None and optional:
        return ""
    if not isinstance(value, str):
        raise _invalid(f"{field} must be text")
    cleaned = " ".join(single_line(value).split())
    if not 1 <= len(cleaned) <= maximum:
        raise _invalid(f"{field} must contain 1 to {maximum} characters")
    return cleaned


def _plain(text: str, field: str) -> str:
    if _LINK.search(text) is not None or _INSTRUCTION.search(text) is not None:
        raise _invalid(f"{field} contains a link or an instruction to run something")
    return text


def validate_output(
    output: object,
    allowed_artifact_ids: frozenset[str],
    stage: AnalysisStage = AnalysisStage.LEGACY,
) -> tuple[ProviderSuggestion, ...]:
    """Fail closed on anything a provider returned outside the contract.

    A suggestion that cites an ID the Case does not have is treated as a
    fabricated reference and rejects the whole output; nothing is stored.
    ``allowed_artifact_ids`` holds every citable ID: Artifacts, and for the
    synthesis stage the Case's confirmed findings. Staged outputs (ADR-031)
    must use their stage's kinds, cite at least the minimum per kind and
    contain no links or instructions to run something.
    """
    if not isinstance(output, ProviderOutput) or not isinstance(
        output.suggestions, tuple
    ):
        raise _invalid("provider output has an unexpected type")
    if not 1 <= len(output.suggestions) <= MAX_SUGGESTIONS:
        raise _invalid(f"provider output must hold 1 to {MAX_SUGGESTIONS} suggestions")
    validated: list[ProviderSuggestion] = []
    summaries = 0
    for raw in output.suggestions:
        if not isinstance(raw, ProviderSuggestion) or not isinstance(
            raw.kind, SuggestionKind
        ):
            raise _invalid("suggestion has an unexpected type")
        if raw.kind not in STAGE_KINDS[stage]:
            raise _invalid(f"{raw.kind.value} is not a {stage.value} stage suggestion")
        if not isinstance(raw.evidence_artifact_ids, tuple) or (
            len(raw.evidence_artifact_ids) > MAX_CITATIONS
        ):
            raise _invalid("suggestion evidence list is invalid")
        citations: list[str] = []
        for artifact_id in raw.evidence_artifact_ids:
            if (
                not isinstance(artifact_id, str)
                or (
                    _ARTIFACT_ID.fullmatch(artifact_id) is None
                    and _FINDING_ID.fullmatch(artifact_id) is None
                )
                or artifact_id not in allowed_artifact_ids
            ):
                raise _invalid("suggestion cites evidence that is not in the Case")
            if artifact_id not in citations:
                citations.append(artifact_id)
        if len(citations) < MIN_CITATIONS.get(raw.kind, 0):
            raise _invalid(
                f"a {raw.kind.value} suggestion must cite at least "
                f"{MIN_CITATIONS[raw.kind]} Workbench IDs"
            )
        title: str | None = None
        benign: str | None = None
        if raw.kind in TITLED_KINDS:
            title = _text(raw.title, "hypothesis title", MAX_TITLE)
            benign = (
                _text(
                    raw.expected_benign, "benign counterpart", MAX_TEXT, optional=True
                )
                or None
            )
        elif raw.title is not None or raw.expected_benign is not None:
            raise _invalid("only hypothesis suggestions carry a title")
        if raw.kind is SuggestionKind.SUMMARY:
            summaries += 1
        text = _text(raw.text, "suggestion text", MAX_TEXT)
        if stage is not AnalysisStage.LEGACY:
            _plain(text, "suggestion text")
            if title is not None:
                _plain(title, "suggestion title")
        validated.append(
            ProviderSuggestion(
                raw.kind,
                text,
                title,
                tuple(citations),
                benign,
            )
        )
    if summaries > 1:
        raise _invalid("provider output holds more than one summary")
    return tuple(validated)
