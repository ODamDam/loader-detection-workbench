from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.artifact import (
    Artifact,
    ArtifactKind,
    canonical_path,
)
from loader_detection_workbench.domain.case import (
    Case,
    CaseKind,
    CaseLifecycle,
    CaseStatus,
)
from loader_detection_workbench.domain.events import NormalizedSysmonEvent
from loader_detection_workbench.domain.ids import ArtifactId, CaseId
from loader_detection_workbench.sysmon.normalizer import normalize_sysmon_event
from loader_detection_workbench.sysmon.service import SysmonService

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"
NOW = datetime(2026, 10, 6, tzinfo=UTC)


def test_all_sort_keys_and_immutable_result(monkeypatch: pytest.MonkeyPatch) -> None:
    case = Case(
        CaseId("0" * 26, "CASE-0001"),
        "0" * 26,
        CaseKind.BENIGN,
        "Demo",
        None,
        NOW,
        CaseLifecycle(CaseStatus.OPEN, NOW),
    )
    first = ArtifactId("0" * 25 + "1", "ART-000001")
    second = ArtifactId("0" * 25 + "2", "ART-000002")
    artifact = Artifact(
        first,
        "0" * 26,
        case.case_id.ulid,
        ArtifactKind.SYSMON,
        canonical_path("a" * 64),
        "a" * 64,
        1,
        NOW,
    )
    process = normalize_sysmon_event(
        (FIXTURES / "process-create.xml").read_bytes(), first
    )[0]
    file = normalize_sysmon_event((FIXTURES / "file-create.xml").read_bytes(), first)[0]
    earliest = replace(file, timestamp=NOW)
    tied_file = replace(file, timestamp=process.timestamp)
    record10 = replace(process, source_record_id="10")
    record2 = replace(process, source_record_id="2")
    other_artifact = replace(process, source_artifact_id=second)
    unordered: list[NormalizedSysmonEvent] = [
        tied_file,
        other_artifact,
        record2,
        record10,
        earliest,
    ]
    monkeypatch.setattr(CaseService, "show", lambda self, selector: case)
    monkeypatch.setattr(
        ArtifactService, "list_artifacts", lambda self, selector: [artifact]
    )
    monkeypatch.setattr(
        SysmonService, "normalize", lambda self, case, artifact: unordered
    )
    query = CaseTimelineQuery(Path("unused"))
    result = query.query("CASE-0001")
    assert result.observations == (
        earliest,
        record10,
        record2,
        other_artifact,
        tied_file,
    )
    unordered.reverse()
    assert query.query("CASE-0001") == result
    with pytest.raises(FrozenInstanceError):
        result.sysmon_artifact_count = 0  # type: ignore[misc]
