import shutil
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Timeline")
    CaseService(root).create("Demo", "benign")
    return root


def test_query_orders_events_and_preserves_sources_after_move(root: Path) -> None:
    artifacts = ArtifactService(root)
    file = artifacts.add("CASE-0001", FIXTURES / "file-create.xml", "sysmon")
    process = artifacts.add("CASE-0001", FIXTURES / "process-create.xml", "sysmon")
    artifacts.add("CASE-0001", FIXTURES / "file-create.xml", "other")
    detached = artifacts.add("CASE-0001", FIXTURES / "file-create.xml", "sysmon")
    artifacts.detach("CASE-0001", detached.artifact_id.display_id)
    CaseService(root).create("Other", "benign")
    artifacts.add("CASE-0002", FIXTURES / "file-create.xml", "sysmon")
    CaseService(root).close("CASE-0001")
    moved = root.with_name("moved")
    shutil.move(root, moved)
    before = (moved / "project.db").read_bytes()
    timeline = CaseTimelineQuery(moved).query("CASE-0001")
    assert timeline.sysmon_artifact_count == 2
    assert [event.event_id for event in timeline.observations] == [1, 11]
    assert [event.source_artifact_id for event in timeline.observations] == [
        process.artifact_id,
        file.artifact_id,
    ]
    assert [event.source_record_id for event in timeline.observations] == ["42", "43"]
    assert timeline.case.case_id.display_id == "CASE-0001"
    assert (moved / "project.db").read_bytes() == before


def test_empty_case_success(root: Path) -> None:
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    assert timeline.observations == ()
    assert timeline.sysmon_artifact_count == 0


def test_missing_case(root: Path) -> None:
    with pytest.raises(DomainError) as caught:
        CaseTimelineQuery(root).query("CASE-9999")
    assert caught.value.code is DomainErrorCode.CASE_NOT_FOUND


@pytest.mark.parametrize("mode", ["corrupt", "invalid"])
def test_one_bad_source_fails_entire_query(root: Path, mode: str) -> None:
    artifacts = ArtifactService(root)
    artifacts.add("CASE-0001", FIXTURES / "process-create.xml", "sysmon")
    bad = root.parent / "bad.xml"
    bad.write_bytes(b"<Event>")
    artifact = artifacts.add("CASE-0001", bad, "sysmon")
    if mode == "corrupt":
        artifact.relative_path.resolve_under(root).write_bytes(b"tampered")
    before = (root / "project.db").read_bytes()
    with pytest.raises(DomainError) as caught:
        CaseTimelineQuery(root).query("CASE-0001")
    expected = (
        DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH
        if mode == "corrupt"
        else DomainErrorCode.INVALID_SYSMON_XML
    )
    assert caught.value.code is expected
    assert (root / "project.db").read_bytes() == before
