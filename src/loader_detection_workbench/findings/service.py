"""Application service for analyst findings (ADR-031).

Rules enforced here, on top of the per-kind content checks in the domain:

- Writes need an open Case. References must belong to the same Case.
- ``confirm`` needs a ``draft``. A hypothesis needs a verdict. A link needs
  exactly one confirmed hypothesis finding and at least one confirmed evidence
  finding; a mechanism needs at least one confirmed evidence finding. An event
  reference must name an event that exists in the cited Sysmon Artifact.
- ``edit`` returns a finding to ``draft``; ``withdraw`` is final. Neither is
  allowed while a confirmed finding still references it (``FINDING_IN_USE``),
  so a report never cites something that is no longer confirmed.
- ``adopt`` turns an AI suggestion into a ``draft`` with its source recorded;
  a person still edits and confirms it. The AI record itself is not changed.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loader_detection_workbench.ai.domain import SuggestionKind
from loader_detection_workbench.ai.store import AiAnalysisReader
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import CaseId
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.findings.domain import (
    AnalystFinding,
    EvidenceRef,
    FindingContent,
    FindingKind,
    FindingState,
    RevisionAction,
    Verdict,
    require_finding_id,
    require_note,
    require_source,
)
from loader_detection_workbench.findings.sqlite_repository import (
    SQLiteFindingRepository,
)
from loader_detection_workbench.project.service import ProjectService

_CLEARABLE = frozenset({"title", "verdict", "hypothesis"})


def _reference(message: str) -> DomainError:
    return DomainError(DomainErrorCode.FINDING_REFERENCE_INVALID, message)


def _state(message: str) -> DomainError:
    return DomainError(DomainErrorCode.FINDING_STATE_INVALID, message)


@contextmanager
def finding_repository(
    root: Path, *, write: bool = False
) -> Iterator[SQLiteFindingRepository]:
    repository: SQLiteFindingRepository | None = None
    try:
        repository = SQLiteFindingRepository(ProjectService().open(root), write=write)
        with repository.transaction():
            yield repository
    except sqlite3.Error as exc:
        raise DomainError(
            DomainErrorCode.FINDING_PERSISTENCE_FAILED,
            "finding database operation failed",
        ) from exc
    finally:
        if repository is not None:
            repository.close()


class FindingService:
    def __init__(self, root: Path, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._root = root
        self._clock = clock

    # -- reads ----------------------------------------------------------------

    def list_findings(
        self, case_display_id: str, state: FindingState | None = None
    ) -> list[AnalystFinding]:
        CaseId("00000000000000000000000000", case_display_id)
        with finding_repository(self._root) as repository:
            case_ulid, _ = repository.case(case_display_id)
            items = repository.list(case_ulid)
        return [item for item in items if state is None or item.state is state]

    def show(self, display_id: str) -> AnalystFinding:
        require_finding_id(display_id)
        with finding_repository(self._root) as repository:
            return repository.get(display_id)

    def confirmed(self, case_display_id: str) -> list[AnalystFinding]:
        return self.list_findings(case_display_id, FindingState.CONFIRMED)

    # -- writes ---------------------------------------------------------------

    def create(
        self,
        case_display_id: str,
        kind: str,
        text: str,
        *,
        title: str | None = None,
        verdict: str | None = None,
        evidence: Sequence[str] = (),
        hypothesis: str | None = None,
        findings: Sequence[str] = (),
        note: str | None = None,
        source: str = "analyst",
    ) -> AnalystFinding:
        CaseId("00000000000000000000000000", case_display_id)
        content = FindingContent(
            FindingKind.parse(kind),
            text,
            title,
            None if verdict is None else Verdict.parse(verdict),
            tuple(EvidenceRef.parse(item) for item in evidence),
            hypothesis,
            tuple(findings),
        )
        require_source(source)
        clean_note = require_note(note)
        with finding_repository(self._root, write=True) as repository:
            case_ulid = self._open_case(repository, case_display_id)
            self._check_references(repository, case_ulid, content, confirming=False)
            display_id = repository.insert(
                case_ulid, content, source, self._clock(), clean_note
            )
            return repository.get(display_id)

    def edit(
        self,
        display_id: str,
        *,
        text: str | None = None,
        title: str | None = None,
        verdict: str | None = None,
        evidence: Sequence[str] | None = None,
        hypothesis: str | None = None,
        findings: Sequence[str] | None = None,
        clear: Sequence[str] = (),
        note: str | None = None,
    ) -> AnalystFinding:
        """Change the given fields (``None`` keeps a field; ``clear`` empties one)."""
        require_finding_id(display_id)
        unknown = set(clear) - _CLEARABLE
        if unknown:
            raise DomainError(
                DomainErrorCode.INVALID_FINDING,
                "only title, verdict and hypothesis can be cleared",
            )
        clean_note = require_note(note)
        with finding_repository(self._root, write=True) as repository:
            finding = repository.get(display_id)
            case_ulid = self._open_case(repository, finding.case_display_id)
            if finding.state is FindingState.WITHDRAWN:
                raise _state("a withdrawn finding cannot be edited")
            self._require_unused(repository, case_ulid, finding)
            old = finding.content
            content = FindingContent(
                old.kind,
                old.text if text is None else text,
                None if "title" in clear else (old.title if title is None else title),
                None
                if "verdict" in clear
                else (old.verdict if verdict is None else Verdict.parse(verdict)),
                old.evidence
                if evidence is None
                else tuple(EvidenceRef.parse(item) for item in evidence),
                None
                if "hypothesis" in clear
                else (old.hypothesis_display_id if hypothesis is None else hypothesis),
                old.finding_refs if findings is None else tuple(findings),
            )
            if content == old:
                raise _state("the edit changes nothing")
            self._check_references(repository, case_ulid, content, confirming=False)
            repository.update(
                finding,
                content,
                FindingState.DRAFT,
                RevisionAction.EDIT,
                self._clock(),
                clean_note,
            )
            return repository.get(display_id)

    def confirm(self, display_id: str, note: str | None = None) -> AnalystFinding:
        require_finding_id(display_id)
        clean_note = require_note(note)
        with finding_repository(self._root, write=True) as repository:
            finding = repository.get(display_id)
            case_ulid = self._open_case(repository, finding.case_display_id)
            if finding.state is not FindingState.DRAFT:
                raise _state(
                    f"only a draft can be confirmed (is {finding.state.value})"
                )
            content = finding.content
            if content.kind is FindingKind.HYPOTHESIS and content.verdict is None:
                raise DomainError(
                    DomainErrorCode.INVALID_FINDING,
                    "a hypothesis finding needs a verdict before it is confirmed",
                )
            self._check_references(repository, case_ulid, content, confirming=True)
            if content.kind is FindingKind.EVIDENCE:
                self._check_events(finding.case_display_id, content)
            repository.update(
                finding,
                content,
                FindingState.CONFIRMED,
                RevisionAction.CONFIRM,
                self._clock(),
                clean_note,
            )
            return repository.get(display_id)

    def withdraw(self, display_id: str, note: str) -> AnalystFinding:
        require_finding_id(display_id)
        clean_note = require_note(note)
        if clean_note is None:
            raise DomainError(
                DomainErrorCode.INVALID_FINDING, "withdrawing needs a reason (note)"
            )
        with finding_repository(self._root, write=True) as repository:
            finding = repository.get(display_id)
            case_ulid = self._open_case(repository, finding.case_display_id)
            if finding.state is FindingState.WITHDRAWN:
                raise _state("the finding is already withdrawn")
            self._require_unused(repository, case_ulid, finding)
            repository.update(
                finding,
                finding.content,
                FindingState.WITHDRAWN,
                RevisionAction.WITHDRAW,
                self._clock(),
                clean_note,
            )
            return repository.get(display_id)

    def adopt(
        self, analysis_display_id: str, sequence: int, note: str | None = None
    ) -> AnalystFinding:
        """Start a draft from an AI suggestion; the analyst edits and confirms it.

        Hypothesis-type suggestions become hypothesis drafts. A synthesis
        ``mechanism`` becomes a mechanism draft that cites the confirmed
        findings it was built on. Links, next steps and summaries are opinions
        for the analyst and are not adoptable.
        """
        analysis = AiAnalysisReader(self._root).show(analysis_display_id)
        suggestion = analysis.suggestion(sequence)
        source = f"ai:{analysis.display_id}#{suggestion.sequence}"
        if suggestion.kind in (
            SuggestionKind.HYPOTHESIS,
            SuggestionKind.HYPOTHESIS_CANDIDATE,
            SuggestionKind.KEY_HYPOTHESIS,
        ):
            return self.create(
                analysis.case_display_id,
                FindingKind.HYPOTHESIS.value,
                suggestion.text,
                title=suggestion.title or suggestion.text[:120],
                note=note,
                source=source,
            )
        if suggestion.kind is SuggestionKind.MECHANISM:
            cited = [
                item
                for item in suggestion.evidence_artifact_ids
                if item.startswith("FND-")
            ]
            if not cited:
                raise DomainError(
                    DomainErrorCode.INVALID_FINDING,
                    "a mechanism suggestion must cite confirmed findings to be adopted",
                )
            return self.create(
                analysis.case_display_id,
                FindingKind.MECHANISM.value,
                suggestion.text,
                findings=cited,
                note=note,
                source=source,
            )
        raise DomainError(
            DomainErrorCode.INVALID_FINDING,
            f"a {suggestion.kind.value} suggestion cannot be adopted as a finding",
        )

    # -- checks ---------------------------------------------------------------

    @staticmethod
    def _open_case(repository: SQLiteFindingRepository, case_display_id: str) -> str:
        case_ulid, status = repository.case(case_display_id)
        if status != "open":
            raise DomainError(DomainErrorCode.CASE_CLOSED, "closed case is read-only")
        return case_ulid

    @staticmethod
    def _require_unused(
        repository: SQLiteFindingRepository, case_ulid: str, finding: AnalystFinding
    ) -> None:
        users = [
            other.display_id
            for other in repository.list(case_ulid)
            if other.state is FindingState.CONFIRMED
            and finding.display_id in other.content.finding_refs
        ]
        if users:
            raise DomainError(
                DomainErrorCode.FINDING_IN_USE,
                "confirmed findings reference it: " + ", ".join(users),
            )

    @staticmethod
    def _check_references(
        repository: SQLiteFindingRepository,
        case_ulid: str,
        content: FindingContent,
        *,
        confirming: bool,
    ) -> None:
        artifacts = repository.case_artifacts(case_ulid)
        for ref in content.evidence:
            kind = artifacts.get(ref.artifact_display_id)
            if kind is None:
                raise _reference(
                    f"{ref.artifact_display_id} is not attached to this Case"
                )
            if ref.record_id is not None and kind != "sysmon":
                raise _reference("an event reference needs a sysmon Artifact")
        hypothesis = content.hypothesis_display_id
        if hypothesis is not None and hypothesis not in repository.case_hypotheses(
            case_ulid
        ):
            raise _reference(f"{hypothesis} is not a hypothesis of this Case")
        if not content.finding_refs:
            return
        others = {item.display_id: item for item in repository.list(case_ulid)}
        kinds: list[FindingKind] = []
        for linked in content.finding_refs:
            other = others.get(linked)
            if other is None:
                raise _reference(f"{linked} is not a finding of this Case")
            if other.state is FindingState.WITHDRAWN:
                raise _reference(f"{linked} is withdrawn")
            if confirming and other.state is not FindingState.CONFIRMED:
                raise _reference(f"{linked} must be confirmed first")
            kinds.append(other.kind)
        evidence = kinds.count(FindingKind.EVIDENCE)
        hypotheses = kinds.count(FindingKind.HYPOTHESIS)
        if content.kind is FindingKind.LINK:
            if hypotheses != 1 or evidence < 1 or evidence + hypotheses != len(kinds):
                raise _reference(
                    "a link references one hypothesis finding and evidence findings"
                )
        elif content.kind is FindingKind.MECHANISM and (
            evidence < 1 or evidence != len(kinds)
        ):
            raise _reference("a mechanism references evidence findings only")

    def _check_events(self, case_display_id: str, content: FindingContent) -> None:
        wanted = [ref for ref in content.evidence if ref.record_id is not None]
        if not wanted:
            return
        timeline = CaseTimelineQuery(self._root).query(case_display_id)
        present: set[tuple[str, str]] = set()
        for record in timeline.other_records:
            if record.source_artifact_id is not None and record.record_id is not None:
                present.add((record.source_artifact_id.display_id, record.record_id))
        for event in timeline.observations:
            present.add((event.source_artifact_id.display_id, event.source_record_id))
        for ref in wanted:
            if (ref.artifact_display_id, ref.record_id) not in present:
                raise _reference(f"event {ref} was not found in the Case")
