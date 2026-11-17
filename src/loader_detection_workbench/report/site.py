"""Static report site for every Case of a Project (M4, ADR-011, ADR-029).

``index.html`` (overview, quantitative goals, Case list, validation summary),
``rules.html`` (rule versions and runs) and one page per Case. Pages are the
same inert, self-contained HTML as ``report build`` plus relative links between
them. Every page is de-identified (``report.redact``) because a site is made to
be shared; the per-Case report command is unchanged.

The site is written to a new staging directory next to the target and renamed
into place, so a failed build leaves nothing behind and an existing directory
is never overwritten. Publishing it anywhere is a separate, approved step.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.detection.domain import (
    DetectionRule,
    RuleFormat,
    RuleVersionStatus,
    ValidationRun,
)
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.case import Case, CaseKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.report import document as doc
from loader_detection_workbench.report.analysis import CaseAnalysisQuery
from loader_detection_workbench.report.document import (
    Block,
    Bullets,
    Code,
    Document,
    Heading,
    Links,
    Paragraph,
    Table,
    item,
    trusted,
    untrusted,
)
from loader_detection_workbench.report.redact import Redactor
from loader_detection_workbench.report.render import build_document, ratio

GOAL = 6  # 수행계획서 정량 목표: 사례·YARA·Sigma·보고서 각 6


@dataclass(frozen=True, slots=True)
class SiteSummary:
    output: Path
    pages: int
    cases: int
    redactions: int


def _case_page(display_id: str) -> str:
    return f"cases/{display_id}.html"


def _metrics(run: ValidationRun) -> tuple[str, str, str]:
    metrics = run.metrics
    return (
        ratio(metrics.tp, metrics.malicious_total),
        ratio(metrics.fp, metrics.benign_total),
        str(metrics.not_evaluable),
    )


def _rules_document(
    rules: list[DetectionRule], runs: list[ValidationRun], generated_at: datetime
) -> Document:
    blocks: list[Block] = [
        Links((("index.html", trusted("Back to the site index")),)),
        Paragraph(trusted(f"Generated at {format_utc(generated_at)}.")),
    ]
    if not rules:
        blocks.append(Paragraph(trusted("No detection rule is recorded.")))
    for rule in rules:
        blocks.append(
            Heading(
                2, untrusted(rule.name), f"{rule.display_id} ({rule.format.value}) — "
            )
        )
        blocks.append(
            Table(
                ("Version", "Status", "SHA-256", "Frozen At", "Note"),
                tuple(
                    (
                        trusted(f"v{version.version}"),
                        trusted(version.status.value),
                        trusted(version.sha256),
                        trusted(
                            "—"
                            if version.frozen_at is None
                            else format_utc(version.frozen_at)
                        ),
                        untrusted(version.note or "—"),
                    )
                    for version in rule.versions
                ),
            )
        )
        frozen = [v for v in rule.versions if v.status is RuleVersionStatus.FROZEN]
        shown = frozen[-1] if frozen else rule.latest
        blocks.extend(
            [
                Heading(3, trusted(f"Rule body (v{shown.version})")),
                Code(shown.content),
            ]
        )
        rule_runs = [run for run in runs if run.rule_display_id == rule.display_id]
        if rule_runs:
            blocks.append(
                Table(
                    (
                        "Run",
                        "Version",
                        "Benchmark",
                        "Kind",
                        "TP / malicious",
                        "FP / benign",
                        "Not evaluable",
                    ),
                    tuple(
                        (
                            trusted(run.display_id),
                            trusted(f"v{run.rule_version}"),
                            trusted(run.benchmark_display_id),
                            trusted(run.kind.value),
                            *(trusted(value) for value in _metrics(run)),
                        )
                        for run in rule_runs
                    ),
                    frozenset({4, 5, 6}),
                )
            )
    return Document("Detection Rules and Validation", tuple(blocks))


def _index_document(
    project_name: str,
    cases: list[Case],
    rules: list[DetectionRule],
    runs: list[ValidationRun],
    generated_at: datetime,
) -> Document:
    analyzed = [c for c in cases if c.kind is CaseKind.MALWARE]
    simulators = [c for c in cases if c.kind is CaseKind.SIMULATOR]

    def frozen(fmt: RuleFormat) -> int:
        return sum(
            1
            for rule in rules
            if rule.format is fmt
            and any(v.status is RuleVersionStatus.FROZEN for v in rule.versions)
        )

    def total(fmt: RuleFormat) -> int:
        return sum(1 for rule in rules if rule.format is fmt)

    latest: dict[str, ValidationRun] = {}
    for run in runs:
        latest[run.rule_display_id] = run
    blocks: list[Block] = [
        Bullets(
            (
                item("Project", project_name),
                item("Generated At", format_utc(generated_at), is_trusted=True),
                item("Cases", len(cases), is_trusted=True),
            )
        ),
        Paragraph(
            trusted(
                "All pages are generated from the Project database. Evidence text is "
                "escaped and de-identified (user names, host names, SIDs). Validation "
                "counts are shown with their denominators. No page states a "
                "maliciousness verdict."
            )
        ),
        Links((("rules.html", trusted("Detection rules and validation runs")),)),
        Heading(2, trusted("Quantitative Goals")),
        Table(
            ("Goal", "Target", "Current", "Note"),
            (
                (
                    trusted("Analyzed malware Cases"),
                    trusted(GOAL),
                    trusted(len(analyzed)),
                    trusted(f"simulator Cases are not counted ({len(simulators)})"),
                ),
                (
                    trusted("YARA rules"),
                    trusted(GOAL),
                    trusted(frozen(RuleFormat.YARA)),
                    trusted(f"frozen; {total(RuleFormat.YARA)} recorded"),
                ),
                (
                    trusted("Sigma rules"),
                    trusted(GOAL),
                    trusted(frozen(RuleFormat.SIGMA)),
                    trusted(f"frozen; {total(RuleFormat.SIGMA)} recorded"),
                ),
                (
                    trusted("Case reports"),
                    trusted(GOAL),
                    trusted(len(analyzed)),
                    trusted("one page per analyzed malware Case in this site"),
                ),
            ),
            frozenset({1, 2}),
        ),
        Heading(2, trusted("Cases")),
    ]
    if cases:
        blocks.append(
            Table(
                ("Case", "Kind", "Status", "Name"),
                tuple(
                    (
                        trusted(case.case_id.display_id),
                        trusted(case.kind.value),
                        trusted(case.status.value),
                        untrusted(case.name),
                    )
                    for case in cases
                ),
            )
        )
        blocks.append(
            Links(
                tuple(
                    (
                        _case_page(case.case_id.display_id),
                        trusted(f"{case.case_id.display_id} report"),
                    )
                    for case in cases
                )
            )
        )
    else:
        blocks.append(Paragraph(trusted("No Case is recorded.")))
    blocks.append(Heading(2, trusted("Latest Validation per Rule")))
    if latest:
        blocks.append(
            Table(
                (
                    "Rule",
                    "Run",
                    "Version",
                    "Kind",
                    "TP / malicious",
                    "FP / benign",
                    "Not evaluable",
                ),
                tuple(
                    (
                        trusted(rule_id),
                        trusted(run.display_id),
                        trusted(f"v{run.rule_version}"),
                        trusted(run.kind.value),
                        *(trusted(value) for value in _metrics(run)),
                    )
                    for rule_id, run in sorted(latest.items())
                ),
                frozenset({4, 5, 6}),
            )
        )
    else:
        blocks.append(Paragraph(trusted("No validation run is recorded.")))
    return Document("Detection Workbench Report Site", tuple(blocks))


class SiteService:
    def __init__(self, root: Path, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._root = root
        self._clock = clock

    def _documents(self) -> tuple[dict[str, Document], set[str], set[str]]:
        generated_at = self._clock()
        project_name = self._project_name()
        cases = CaseService(self._root).list_cases()
        reader = DetectionService(self._root)
        rules = reader.list_rules()
        runs = reader.list_runs()
        documents: dict[str, Document] = {
            "index.html": _index_document(
                project_name, cases, rules, runs, generated_at
            ),
            "rules.html": _rules_document(rules, runs, generated_at),
        }
        timelines = CaseTimelineQuery(self._root)
        analyses = CaseAnalysisQuery(self._root)
        hosts: set[str] = set()
        accounts: set[str] = set()
        for case in cases:
            timeline = timelines.query(case.case_id.display_id)
            for record in timeline.other_records:
                if record.computer:
                    hosts.add(record.computer)
                for name in ("User", "SourceUser", "TargetUser"):
                    value = record.fields.get(name)
                    if value:
                        accounts.add(value)
            report = build_document(timeline, generated_at, analyses.query(timeline))
            back = Links((("../index.html", trusted("Back to the site index")),))
            documents[_case_page(case.case_id.display_id)] = Document(
                report.title, (back, *report.blocks)
            )
        return documents, hosts, accounts

    def _project_name(self) -> str:
        return ProjectService().show(self._root).manifest.name

    def build(self, output: Path) -> SiteSummary:
        destination = self._root / output
        if os.path.lexists(destination):
            raise DomainError(
                DomainErrorCode.REPORT_OUTPUT_EXISTS, "site output already exists"
            )
        documents, hosts, accounts = self._documents()
        redactor = Redactor.learn(
            documents.values(), hosts_seen=hosts, accounts_seen=accounts
        )
        rendered = {
            path: doc.render_html(redactor.document(document))
            for path, document in documents.items()
        }
        staging: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=".site-", dir=destination.parent))
            for relative, content in rendered.items():
                target = staging / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", newline="\n")
            os.rename(staging, destination)
            staging = None
        except FileExistsError as exc:
            raise DomainError(
                DomainErrorCode.REPORT_OUTPUT_EXISTS, "site output already exists"
            ) from exc
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.REPORT_WRITE_FAILED, "site output could not be written"
            ) from exc
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
        case_pages = sum(1 for path in rendered if path.startswith("cases/"))
        return SiteSummary(destination, len(rendered), case_pages, redactor.replaced)
