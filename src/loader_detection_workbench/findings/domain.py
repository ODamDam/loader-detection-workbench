"""Analyst findings: the only content a Case report body is built from (ADR-031).

A finding is a statement an analyst has written or adopted and then confirmed.
Kinds and their references:

- ``hypothesis``: a hypothesis with a verdict; may point at a Detection
  Hypothesis (``HYP-NNNN``).
- ``evidence``: what one or more Artifacts (optionally single events) show.
- ``link``: why confirmed evidence supports or weakens a confirmed hypothesis;
  references exactly one hypothesis finding and at least one evidence finding.
- ``mechanism``: one step of how the sample works, citing evidence findings.

State is ``draft`` -> ``confirmed`` -> ``withdrawn``. Editing returns a
finding to ``draft``. Only a person confirms or withdraws; every change is kept
as a revision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

FINDING_PREFIX = "FND"
MAX_TITLE = 200
MAX_TEXT = 8000
MAX_NOTE = 1000
MAX_REFERENCES = 50

_FINDING_ID = re.compile(r"FND-[0-9]{4,}", re.ASCII)
_ARTIFACT_ID = re.compile(r"ART-[0-9]{6,}", re.ASCII)
_HYPOTHESIS_ID = re.compile(r"HYP-[0-9]{4,}", re.ASCII)
_RECORD_ID = re.compile(r"[0-9]{1,20}", re.ASCII)
_SOURCE = re.compile(r"analyst|ai:AIA-[0-9]{4,}#[0-9]{1,4}", re.ASCII)


class FindingKind(StrEnum):
    HYPOTHESIS = "hypothesis"
    EVIDENCE = "evidence"
    LINK = "link"
    MECHANISM = "mechanism"

    @classmethod
    def parse(cls, value: str) -> FindingKind:
        try:
            return cls(value)
        except ValueError as exc:
            raise _invalid(
                "finding kind must be hypothesis|evidence|link|mechanism"
            ) from exc


class FindingState(StrEnum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    WITHDRAWN = "withdrawn"

    @classmethod
    def parse(cls, value: str) -> FindingState:
        try:
            return cls(value)
        except ValueError as exc:
            raise _invalid("finding state must be draft|confirmed|withdrawn") from exc


class Verdict(StrEnum):
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    REJECTED = "rejected"

    @classmethod
    def parse(cls, value: str) -> Verdict:
        try:
            return cls(value)
        except ValueError as exc:
            raise _invalid("verdict must be supported|weakened|rejected") from exc


class RevisionAction(StrEnum):
    CREATE = "create"
    EDIT = "edit"
    CONFIRM = "confirm"
    WITHDRAW = "withdraw"


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.INVALID_FINDING, message)


def require_finding_id(value: str) -> str:
    if not isinstance(value, str) or _FINDING_ID.fullmatch(value) is None:
        raise DomainError(
            DomainErrorCode.INVALID_DISPLAY_ID,
            f"finding ID must use {FINDING_PREFIX}-0001 format",
        )
    return value


def _clean(
    value: str | None, field: str, maximum: int, *, optional: bool
) -> str | None:
    if value is None:
        if optional:
            return None
        raise _invalid(f"{field} is required")
    if not isinstance(value, str):
        raise _invalid(f"{field} must be text")
    text = value.replace("\r\n", "\n").strip()
    if not text:
        if optional:
            return None
        raise _invalid(f"{field} is required")
    if len(text) > maximum:
        raise _invalid(f"{field} must be at most {maximum} characters")
    if any(ord(c) < 32 and c not in "\n\t" for c in text):
        raise _invalid(f"{field} contains control characters")
    return text


@dataclass(frozen=True, slots=True, order=True)
class EvidenceRef:
    """One Artifact, optionally narrowed to one event (EventRecordID)."""

    artifact_display_id: str
    record_id: str | None = None

    def __post_init__(self) -> None:
        if _ARTIFACT_ID.fullmatch(self.artifact_display_id) is None:
            raise _invalid("evidence must reference ART-NNNNNN")
        if self.record_id is not None and _RECORD_ID.fullmatch(self.record_id) is None:
            raise _invalid("event record ID must be decimal digits")

    @classmethod
    def parse(cls, value: str) -> EvidenceRef:
        artifact, _, record = value.strip().partition(":")
        return cls(artifact, record or None)

    def __str__(self) -> str:
        return (
            self.artifact_display_id
            if self.record_id is None
            else f"{self.artifact_display_id}:{self.record_id}"
        )


@dataclass(frozen=True, slots=True)
class FindingContent:
    """The editable part of a finding; validated per kind on construction."""

    kind: FindingKind
    text: str
    title: str | None = None
    verdict: Verdict | None = None
    evidence: tuple[EvidenceRef, ...] = ()
    hypothesis_display_id: str | None = None
    finding_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        text = _clean(self.text, "text", MAX_TEXT, optional=False)
        title = _clean(self.title, "title", MAX_TITLE, optional=True)
        object.__setattr__(self, "text", text)
        object.__setattr__(self, "title", title)
        evidence = tuple(sorted(set(self.evidence)))
        refs = tuple(sorted(set(self.finding_refs), key=_numeric))
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "finding_refs", refs)
        for ref in refs:
            require_finding_id(ref)
        if len(evidence) > MAX_REFERENCES or len(refs) > MAX_REFERENCES:
            raise _invalid(f"at most {MAX_REFERENCES} references are allowed")
        hypothesis = self.hypothesis_display_id
        if hypothesis is not None and _HYPOTHESIS_ID.fullmatch(hypothesis) is None:
            raise _invalid("hypothesis must reference HYP-NNNN")
        kind = self.kind
        if kind is FindingKind.HYPOTHESIS:
            if title is None:
                raise _invalid("a hypothesis finding needs a title")
            if evidence or refs:
                raise _invalid(
                    "a hypothesis finding cites evidence through link findings"
                )
        elif kind is FindingKind.EVIDENCE:
            if not evidence:
                raise _invalid("an evidence finding must reference an Artifact")
            if self.verdict is not None or refs or hypothesis is not None:
                raise _invalid("an evidence finding only references Artifacts")
        else:
            if self.verdict is not None or evidence or hypothesis is not None:
                raise _invalid(f"a {kind.value} finding only references findings")
            if not refs:
                raise _invalid(f"a {kind.value} finding must reference findings")


def _numeric(display_id: str) -> int:
    number = display_id.rpartition("-")[2]
    return int(number) if number.isdigit() else 0


@dataclass(frozen=True, slots=True)
class FindingRevision:
    revision: int
    action: RevisionAction
    state: FindingState
    content: FindingContent
    at: datetime
    note: str | None


@dataclass(frozen=True, slots=True)
class AnalystFinding:
    display_id: str
    case_display_id: str
    content: FindingContent
    state: FindingState
    source: str
    revision: int
    created_at: datetime
    updated_at: datetime
    confirmed_at: datetime | None
    history: tuple[FindingRevision, ...] = ()

    @property
    def kind(self) -> FindingKind:
        return self.content.kind


def require_source(value: str) -> str:
    if not isinstance(value, str) or _SOURCE.fullmatch(value) is None:
        raise _invalid("source must be analyst or ai:AIA-NNNN#N")
    return value


def require_note(value: str | None) -> str | None:
    return _clean(value, "note", MAX_NOTE, optional=True)
