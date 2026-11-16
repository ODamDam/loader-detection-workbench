"""AI-assisted analysis records (ADR-026).

A provider turns a bounded evidence digest into *suggestions*: one summary,
hypothesis candidates and review items. Suggestions are inferences, never
observed facts. They are stored apart from evidence and only a person's review
can turn a hypothesis candidate into a Detection Hypothesis.
"""

from __future__ import annotations

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


class SuggestionKind(StrEnum):
    SUMMARY = "summary"
    HYPOTHESIS = "hypothesis"
    REVIEW_ITEM = "review_item"


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


def validate_output(
    output: object, allowed_artifact_ids: frozenset[str]
) -> tuple[ProviderSuggestion, ...]:
    """Fail closed on anything a provider returned outside the contract.

    A suggestion that cites an Artifact the Case does not have is treated as a
    fabricated reference and rejects the whole output; nothing is stored.
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
        if not isinstance(raw.evidence_artifact_ids, tuple) or (
            len(raw.evidence_artifact_ids) > MAX_CITATIONS
        ):
            raise _invalid("suggestion evidence list is invalid")
        citations: list[str] = []
        for artifact_id in raw.evidence_artifact_ids:
            if (
                not isinstance(artifact_id, str)
                or _ARTIFACT_ID.fullmatch(artifact_id) is None
                or artifact_id not in allowed_artifact_ids
            ):
                raise _invalid("suggestion cites evidence that is not in the Case")
            if artifact_id not in citations:
                citations.append(artifact_id)
        title: str | None = None
        benign: str | None = None
        if raw.kind is SuggestionKind.HYPOTHESIS:
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
        validated.append(
            ProviderSuggestion(
                raw.kind,
                _text(raw.text, "suggestion text", MAX_TEXT),
                title,
                tuple(citations),
                benign,
            )
        )
    if summaries > 1:
        raise _invalid("provider output holds more than one summary")
    return tuple(validated)
