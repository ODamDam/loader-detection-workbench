"""Query once, render, then atomically publish a new Markdown or HTML file."""

import os
import tempfile
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.report.analysis import CaseAnalysisQuery
from loader_detection_workbench.report.render import render_html, render_markdown


class ReportFormat(StrEnum):
    MARKDOWN = "markdown"
    HTML = "html"

    @classmethod
    def for_output(cls, output: Path) -> "ReportFormat":
        """``.html``/``.htm`` selects HTML; every other name stays Markdown."""
        return cls.HTML if output.suffix.lower() in {".html", ".htm"} else cls.MARKDOWN


def _publish(staging: Path, output: Path) -> None:
    # Same no-clobber publication convention as the Artifact store.
    if os.name == "nt":
        os.rename(staging, output)
    else:
        os.link(staging, output)


def write_report(output: Path, content: str) -> None:
    staging: Path | None = None
    try:
        if os.path.lexists(output):
            raise DomainError(
                DomainErrorCode.REPORT_OUTPUT_EXISTS, "report output already exists"
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=output.parent)
        staging = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            _publish(staging, output)
        except FileExistsError as exc:
            raise DomainError(
                DomainErrorCode.REPORT_OUTPUT_EXISTS, "report output already exists"
            ) from exc
    except (OSError, ValueError) as exc:
        raise DomainError(
            DomainErrorCode.REPORT_WRITE_FAILED, "report output could not be written"
        ) from exc
    finally:
        if staging is not None:
            try:
                staging.unlink(missing_ok=True)
            except OSError as exc:
                raise DomainError(
                    DomainErrorCode.REPORT_WRITE_FAILED, "report staging cleanup failed"
                ) from exc


class ReportService:
    def __init__(self, root: Path, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._root = root
        self._clock = clock

    def build(
        self,
        case_display_id: str,
        output: Path,
        report_format: ReportFormat | None = None,
    ) -> Path:
        timeline = CaseTimelineQuery(self._root).query(case_display_id)
        analysis = CaseAnalysisQuery(self._root).query(timeline)
        selected = report_format or ReportFormat.for_output(output)
        render = render_html if selected is ReportFormat.HTML else render_markdown
        content = render(timeline, self._clock(), analysis)
        destination = self._root / output
        write_report(destination, content)
        return destination
