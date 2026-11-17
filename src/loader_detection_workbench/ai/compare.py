"""Multi-provider comparison of stored AI analyses (W8, ADR-027).

Several providers analyze the *same* structural digest independently. This
module lines their suggestions up and separates opinions that two or more
providers share from opinions only one provider gave. It is deterministic and
reads stored analyses only: it never calls a provider, so it works the same
with offline providers, with external ones once they are approved, or with a
mix of both.

Two suggestions count as the same opinion when they have the same kind, cite
the same evidence Artifacts and their wording overlaps enough (token Jaccard
similarity of the hypothesis title, or of the text for review items). This is a
transparent heuristic, not a semantic judgment; the report shows every member
of a group so a person can check the grouping.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from loader_detection_workbench.ai.domain import AiAnalysis, SuggestionKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

SIMILARITY_THRESHOLD = 0.5
_TOKEN = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*", re.ASCII)
_STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "this", "that", "from", "into", "its",
        "are", "was", "were", "has", "have", "check", "whether", "process",
    }
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Opinion:
    analysis_display_id: str
    provider: str
    model: str
    sequence: int
    kind: SuggestionKind
    title: str | None
    text: str
    evidence_artifact_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OpinionGroup:
    kind: SuggestionKind
    opinions: tuple[Opinion, ...]

    @property
    def providers(self) -> tuple[str, ...]:
        return tuple(sorted({opinion.provider for opinion in self.opinions}))

    @property
    def shared(self) -> bool:
        return len(self.providers) >= 2

    @property
    def evidence_artifact_ids(self) -> tuple[str, ...]:
        return self.opinions[0].evidence_artifact_ids


@dataclass(frozen=True, slots=True)
class ComparedAnalysis:
    display_id: str
    provider: str
    model: str


@dataclass(frozen=True, slots=True)
class Comparison:
    case_display_id: str
    input_sha256: str
    analyses: tuple[ComparedAnalysis, ...]
    summaries: tuple[Opinion, ...]
    common: tuple[OpinionGroup, ...]
    individual: tuple[OpinionGroup, ...]


def tokens(value: str) -> frozenset[str]:
    return frozenset(
        token
        for token in _TOKEN.findall(value.lower())
        if len(token) >= 3 and token not in _STOPWORDS
    )


def similarity(left: str, right: str) -> float:
    a, b = tokens(left), tokens(right)
    if not a and not b:
        return 1.0 if left.strip().lower() == right.strip().lower() else 0.0
    return len(a & b) / len(a | b)


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.INVALID_AI_REQUEST, message)


def latest_per_provider(analyses: Iterable[AiAnalysis]) -> list[AiAnalysis]:
    """Default selection: the newest input of the Case, newest analysis per provider.

    Only analyses of the most recent input are comparable; older inputs saw
    different evidence.
    """
    ordered = sorted(analyses, key=lambda a: (a.created_at, a.display_id))
    if not ordered:
        return []
    current = ordered[-1].input_sha256
    chosen: dict[str, AiAnalysis] = {}
    for analysis in ordered:
        if analysis.input_sha256 == current:
            chosen[analysis.provider] = analysis
    return sorted(chosen.values(), key=lambda a: a.display_id)


def _opinion(analysis: AiAnalysis, index: int) -> Opinion:
    suggestion = analysis.suggestions[index]
    return Opinion(
        analysis.display_id,
        analysis.provider,
        analysis.model,
        suggestion.sequence,
        suggestion.kind,
        suggestion.title,
        suggestion.text,
        tuple(sorted(suggestion.evidence_artifact_ids)),
    )


def _same(left: Opinion, right: Opinion) -> bool:
    if left.kind is not right.kind or left.provider == right.provider:
        return False
    if left.evidence_artifact_ids != right.evidence_artifact_ids:
        return False
    if left.kind is SuggestionKind.HYPOTHESIS:
        return similarity(left.title or "", right.title or "") >= SIMILARITY_THRESHOLD
    return similarity(left.text, right.text) >= SIMILARITY_THRESHOLD


def _group(opinions: Sequence[Opinion]) -> list[OpinionGroup]:
    parent = list(range(len(opinions)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for i in range(len(opinions)):
        for j in range(i + 1, len(opinions)):
            if _same(opinions[i], opinions[j]):
                parent[find(j)] = find(i)
    members: dict[int, list[Opinion]] = {}
    for index, opinion in enumerate(opinions):
        members.setdefault(find(index), []).append(opinion)
    return [
        OpinionGroup(group[0].kind, tuple(group))
        for _, group in sorted(members.items())
    ]


def compare_analyses(analyses: Sequence[AiAnalysis]) -> Comparison:
    """Compare analyses of one Case that received the identical input."""
    if len(analyses) < 2:
        raise _invalid("comparison needs analyses from at least two providers")
    first = analyses[0]
    ids = [analysis.display_id for analysis in analyses]
    if len(set(ids)) != len(ids):
        raise _invalid("an analysis is listed twice")
    if any(a.case_display_id != first.case_display_id for a in analyses):
        raise _invalid("compared analyses must belong to the same Case")
    if any(a.input_sha256 != first.input_sha256 for a in analyses):
        raise _invalid(
            "compared analyses must share the same input (input SHA-256 differs)"
        )
    providers = [analysis.provider for analysis in analyses]
    if len(set(providers)) != len(providers):
        raise _invalid("compare one analysis per provider")
    ordered = sorted(analyses, key=lambda a: a.display_id)
    summaries: list[Opinion] = []
    candidates: list[Opinion] = []
    for analysis in ordered:
        for index, suggestion in enumerate(analysis.suggestions):
            opinion = _opinion(analysis, index)
            if suggestion.kind is SuggestionKind.SUMMARY:
                summaries.append(opinion)
            else:
                candidates.append(opinion)
    groups = _group(candidates)
    return Comparison(
        first.case_display_id,
        first.input_sha256,
        tuple(ComparedAnalysis(a.display_id, a.provider, a.model) for a in ordered),
        tuple(summaries),
        tuple(group for group in groups if group.shared),
        tuple(group for group in groups if not group.shared),
    )
