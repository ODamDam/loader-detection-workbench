import shutil
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import (
    FileCreateEvent,
    NormalizedSysmonEvent,
    ProcessCreateEvent,
)
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.sysmon.service import SysmonService

FIXTURE = Path(__file__).parents[1] / "fixtures/public/sysmon/process-create.xml"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Synthetic Sysmon")
    CaseService(root).create("Benign process", "benign")
    return root


def test_case_artifact_normalization_survives_workspace_move(root: Path) -> None:
    artifact = ArtifactService(root).add("CASE-0001", FIXTURE, "sysmon")
    moved = root.with_name("moved-project")
    shutil.move(root, moved)
    before = (moved / "project.db").read_bytes()
    events = SysmonService(moved).normalize(
        "CASE-0001", artifact.artifact_id.display_id
    )
    assert len(events) == 1
    event = events[0]
    assert event.process_id == 1234 and event.event_id == 1
    assert event.source_record_id == "42"
    attached = ArtifactService(moved).list_artifacts("CASE-0001")
    source = next(a for a in attached if a.artifact_id == event.source_artifact_id)
    assert source.case_id == CaseService(moved).show("CASE-0001").case_id.ulid
    assert (
        source.relative_path.resolve_under(moved).read_bytes() == FIXTURE.read_bytes()
    )
    assert (moved / "project.db").read_bytes() == before


@pytest.mark.parametrize("mode", ["other_case", "detached", "missing"])
def test_unattached_source_rejected(root: Path, mode: str) -> None:
    artifact = ArtifactService(root).add("CASE-0001", FIXTURE, "sysmon")
    case_id = "CASE-0001"
    artifact_id = artifact.artifact_id.display_id
    if mode == "other_case":
        CaseService(root).create("Other", "benign")
        case_id = "CASE-0002"
    elif mode == "detached":
        ArtifactService(root).detach(case_id, artifact_id)
    else:
        artifact_id = "ART-999999"
    with pytest.raises(DomainError) as caught:
        SysmonService(root).normalize(case_id, artifact_id)
    assert caught.value.code is DomainErrorCode.ARTIFACT_NOT_ATTACHED


@pytest.mark.parametrize("mode", ["tampered", "missing", "oversized"])
def test_content_integrity_failure(root: Path, mode: str) -> None:
    artifact = ArtifactService(root).add("CASE-0001", FIXTURE, "sysmon")
    path = artifact.relative_path.resolve_under(root)
    if mode == "missing":
        path.unlink()
    elif mode == "oversized":
        path.write_bytes(b" " * (1024 * 1024 + 1))
    else:
        path.write_bytes(path.read_bytes().replace(b"1234", b"4321"))
    with pytest.raises(DomainError) as caught:
        SysmonService(root).normalize("CASE-0001", artifact.artifact_id.display_id)
    assert caught.value.code is DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH


def test_wrong_kind_rejected(root: Path) -> None:
    artifact = ArtifactService(root).add("CASE-0001", FIXTURE, "other")
    with pytest.raises(DomainError) as caught:
        SysmonService(root).normalize("CASE-0001", artifact.artifact_id.display_id)
    assert caught.value.code is DomainErrorCode.INVALID_ARTIFACT_KIND


def test_malformed_registered_source_has_no_success_or_mutation(root: Path) -> None:
    malformed = root.parent / "malformed.xml"
    malformed.write_bytes(b"<Event>")
    artifact = ArtifactService(root).add("CASE-0001", malformed, "sysmon")
    before = (root / "project.db").read_bytes()
    with pytest.raises(DomainError) as caught:
        SysmonService(root).normalize("CASE-0001", artifact.artifact_id.display_id)
    assert caught.value.code is DomainErrorCode.INVALID_SYSMON_XML
    assert (root / "project.db").read_bytes() == before


def test_closed_case_can_be_read(root: Path) -> None:
    artifact = ArtifactService(root).add("CASE-0001", FIXTURE, "sysmon")
    CaseService(root).close("CASE-0001")
    assert (
        len(SysmonService(root).normalize("CASE-0001", artifact.artifact_id.display_id))
        == 1
    )


def test_same_case_dispatch_provenance_and_time_order_after_move(root: Path) -> None:
    sources = [FIXTURE, FIXTURE.with_name("file-create.xml")]
    artifacts = [ArtifactService(root).add("CASE-0001", p, "sysmon") for p in sources]
    CaseService(root).close("CASE-0001")
    moved = root.with_name("moved-events")
    shutil.move(root, moved)
    before = (moved / "project.db").read_bytes()
    service = SysmonService(moved)
    process = service.normalize("CASE-0001", artifacts[0].artifact_id.display_id)
    file = service.normalize("CASE-0001", artifacts[1].artifact_id.display_id)
    assert len(process) == len(file) == 1
    assert isinstance(process[0], ProcessCreateEvent)
    assert isinstance(file[0], FileCreateEvent)
    assert file[0].target_filename == "synthetic-demo/output.txt"
    assert file[0].process_guid == process[0].process_guid
    events: list[NormalizedSysmonEvent] = [file[0], process[0]]
    events.sort(key=lambda event: event.timestamp)
    assert [event.event_id for event in events] == [1, 11]
    assert [event.source_record_id for event in events] == ["42", "43"]
    attached = ArtifactService(moved).list_artifacts("CASE-0001")
    for event, artifact, source in zip(events, artifacts, sources, strict=True):
        assert event.source_artifact_id == artifact.artifact_id
        assert artifact in attached
        assert (
            artifact.relative_path.resolve_under(moved).read_bytes()
            == source.read_bytes()
        )
    assert (moved / "project.db").read_bytes() == before
    assert not (moved / file[0].target_filename).exists()


def test_invalid_file_create_artifact_has_no_result_or_db_mutation(root: Path) -> None:
    invalid = root.parent / "invalid-file.xml"
    invalid.write_bytes(
        FIXTURE.with_name("file-create.xml")
        .read_bytes()
        .replace(b"synthetic-demo/output.txt", b"")
    )
    artifact = ArtifactService(root).add("CASE-0001", invalid, "sysmon")
    before = (root / "project.db").read_bytes()
    with pytest.raises(DomainError) as caught:
        SysmonService(root).normalize("CASE-0001", artifact.artifact_id.display_id)
    assert caught.value.code is DomainErrorCode.INVALID_FILE_CREATE
    assert (root / "project.db").read_bytes() == before
