import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.collection.service import CollectionIngestionService
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.report.service import ReportService

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"


@pytest.fixture
def collection(tmp_path: Path) -> Path:
    path = tmp_path / "collection"
    shutil.copytree(FIXTURES, path)
    return path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "project"
    ProjectService().create(path, "Collection")
    CaseService(path).create("Open", "benign")
    CaseService(path).create("Closed", "benign")
    CaseService(path).close("CASE-0002")
    return path


def _rows(root: Path, statement: str) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(root / "project.db")) as connection:
        return connection.execute(statement).fetchall()


def _artifact_files(root: Path) -> list[Path]:
    base = root / "artifacts"
    return (
        [] if not base.exists() else sorted(p for p in base.rglob("*") if p.is_file())
    )


def _downgrade_to_v1(root: Path) -> None:
    with sqlite3.connect(root / "project.db") as connection:
        connection.execute("DROP TABLE artifact_provenance")
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")


@pytest.mark.parametrize("schema_version", [1, 2])
def test_import_supports_v1_and_v2_and_reuses_on_retry(
    root: Path, collection: Path, schema_version: int, tmp_path: Path
) -> None:
    if schema_version == 1:
        _downgrade_to_v1(root)
    service = CollectionIngestionService(root)

    first = service.import_collection("CASE-0001", collection)
    second = service.import_collection("CASE-0001", collection)

    assert first.status == "imported"
    assert first.created_count == 3 and first.reused_count == 0
    assert first.process_artifact.kind is ArtifactKind.SYSMON
    assert first.file_artifact.kind is ArtifactKind.SYSMON
    assert first.metadata_artifact.kind is ArtifactKind.OTHER
    assert second.status == "already-present"
    assert second.created_count == 0 and second.reused_count == 3
    assert second.process_artifact == first.process_artifact
    assert second.file_artifact == first.file_artifact
    assert second.metadata_artifact == first.metadata_artifact
    assert len(ArtifactService(root).list_artifacts("CASE-0001")) == 3
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    assert [event.event_id for event in timeline.observations] == [1, 11]
    assert timeline.sysmon_artifact_count == 2
    report = ReportService(root).build("CASE-0001", tmp_path / "report.md")
    assert "Normalized Observations: 2" in report.read_text(encoding="utf-8")


def test_manual_evidence_and_collection_coexist_without_provenance_change(
    root: Path, collection: Path, tmp_path: Path
) -> None:
    note = tmp_path / "note.txt"
    note.write_text("benign analyst note", encoding="utf-8")
    evidence = ManualEvidenceService(root).register(
        "CASE-0001", note, source="analyst", evidence_type="analyst_note"
    )
    before = _rows(root, "SELECT * FROM artifact_provenance")

    result = CollectionIngestionService(root).import_collection("CASE-0001", collection)

    assert result.created_count == 3
    assert _rows(root, "SELECT * FROM artifact_provenance") == before
    assert ManualEvidenceService(root).list_evidence("CASE-0001") == [evidence]
    assert len(ArtifactService(root).list_artifacts("CASE-0001")) == 4


@pytest.mark.parametrize(
    ("case_id", "expected"),
    [
        ("CASE-9999", DomainErrorCode.CASE_NOT_FOUND),
        ("CASE-0002", DomainErrorCode.CASE_CLOSED),
    ],
)
def test_invalid_case_is_rejected_before_collection_access(
    root: Path, tmp_path: Path, case_id: str, expected: DomainErrorCode
) -> None:
    with pytest.raises(DomainError) as caught:
        CollectionIngestionService(root).import_collection(
            case_id, tmp_path / "missing"
        )
    assert caught.value.code is expected
    assert _rows(root, "SELECT * FROM artifacts") == []
    assert not (root / "artifacts").exists()


def test_existing_matching_xml_is_reused_by_role(root: Path, collection: Path) -> None:
    existing = ArtifactService(root).add(
        "CASE-0001", collection / "process-create.xml", "sysmon"
    )

    result = CollectionIngestionService(root).import_collection("CASE-0001", collection)

    assert result.status == "imported-with-reuse"
    assert result.created_count == 2 and result.reused_count == 1
    assert result.process_artifact == existing
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    assert [event.event_id for event in timeline.observations] == [1, 11]


def test_changed_metadata_reuses_xml_without_timeline_duplicates(
    root: Path, collection: Path
) -> None:
    service = CollectionIngestionService(root)
    first = service.import_collection("CASE-0001", collection)
    metadata_path = collection / "collection-metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["run_id"] = "b" * 32
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    second = service.import_collection("CASE-0001", collection)

    assert second.status == "imported-with-reuse"
    assert second.created_count == 1 and second.reused_count == 2
    assert second.process_artifact == first.process_artifact
    assert second.file_artifact == first.file_artifact
    assert second.metadata_artifact != first.metadata_artifact
    timeline = CaseTimelineQuery(root).query("CASE-0001")
    assert timeline.sysmon_artifact_count == 2
    assert [event.event_id for event in timeline.observations] == [1, 11]


def test_corrupt_reuse_candidate_fails_closed(root: Path, collection: Path) -> None:
    existing = ArtifactService(root).add(
        "CASE-0001", collection / "process-create.xml", "sysmon"
    )
    existing.relative_path.resolve_under(root).write_bytes(b"tampered")
    before = _rows(root, "SELECT * FROM artifacts")

    with pytest.raises(DomainError) as caught:
        CollectionIngestionService(root).import_collection("CASE-0001", collection)

    assert caught.value.code is DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH
    assert _rows(root, "SELECT * FROM artifacts") == before


def test_second_insert_failure_rolls_back_rows_counter_and_content(
    root: Path, collection: Path
) -> None:
    with sqlite3.connect(root / "project.db") as connection:
        connection.execute(
            "CREATE TRIGGER reject_second BEFORE INSERT ON artifacts "
            "WHEN NEW.display_id = 'ART-000002' "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
    before_counter = _rows(
        root, "SELECT next_value FROM counters WHERE name = 'artifact'"
    )

    with pytest.raises(DomainError) as caught:
        CollectionIngestionService(root).import_collection("CASE-0001", collection)

    assert caught.value.code is DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED
    assert _rows(root, "SELECT * FROM artifacts") == []
    assert (
        _rows(root, "SELECT next_value FROM counters WHERE name = 'artifact'")
        == before_counter
    )
    assert _artifact_files(root) == []


def test_failure_after_publication_is_compensated(
    root: Path, collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ArtifactStore.publish_bytes
    calls = 0

    def fail_second(self: ArtifactStore, data: bytes) -> object:
        nonlocal calls
        calls += 1
        result = original(self, data)
        if calls == 2:
            raise DomainError(
                DomainErrorCode.ARTIFACT_STORE_FAILED,
                "injected failure after publication",
            )
        return result

    monkeypatch.setattr(ArtifactStore, "publish_bytes", fail_second)
    with pytest.raises(DomainError) as caught:
        CollectionIngestionService(root).import_collection("CASE-0001", collection)

    assert caught.value.code is DomainErrorCode.ARTIFACT_STORE_FAILED
    assert _rows(root, "SELECT * FROM artifacts") == []
    assert _rows(root, "SELECT next_value FROM counters WHERE name = 'artifact'") == [
        (1,)
    ]
    assert _artifact_files(root) == []


def test_cleanup_failure_is_reported(
    root: Path,
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with sqlite3.connect(root / "project.db") as connection:
        connection.execute(
            "CREATE TRIGGER reject_first BEFORE INSERT ON artifacts "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )

    def fail_cleanup(*args: object, **kwargs: object) -> None:
        raise OSError("injected cleanup failure")

    monkeypatch.setattr(ArtifactStore, "cleanup", fail_cleanup)
    with pytest.raises(DomainError) as caught:
        CollectionIngestionService(root).import_collection("CASE-0001", collection)

    assert caught.value.code is DomainErrorCode.ARTIFACT_CLEANUP_FAILED
    assert _rows(root, "SELECT * FROM artifacts") == []
    assert _rows(root, "SELECT next_value FROM counters WHERE name = 'artifact'") == [
        (1,)
    ]
    assert len(_artifact_files(root)) == 1
