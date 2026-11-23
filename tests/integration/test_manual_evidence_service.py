import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.bundle.service import BundleService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.evidence import sqlite_repository as repository_module
from loader_detection_workbench.evidence.domain import MANUAL_EVIDENCE_MAX_BYTES
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.project.database import connect_database
from loader_detection_workbench.project.service import ProjectService


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Evidence")
    CaseService(root).create("Open", "benign")
    CaseService(root).create("Closed", "benign")
    CaseService(root).close("CASE-0002")
    return root


def _rows(root: Path, table: str) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(root / "project.db")) as connection:
        return connection.execute(f"SELECT * FROM {table}").fetchall()


def _files(root: Path) -> list[Path]:
    return sorted(path for path in (root / "artifacts").rglob("*") if path.is_file())


def test_register_list_and_show_manual_evidence(root: Path, tmp_path: Path) -> None:
    source = tmp_path / "Events.JSON"
    source.write_bytes(b'{"benign": true}\n')

    evidence = ManualEvidenceService(root).register(
        "CASE-0001",
        source,
        source="analyst export",
        evidence_type="event_export",
        description="Sanitized fixture",
    )

    assert evidence.artifact.kind is ArtifactKind.EVIDENCE
    assert evidence.artifact.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert evidence.provenance.original_filename == "Events.JSON"
    assert ManualEvidenceService(root).list_evidence("CASE-0001") == [evidence]
    assert (
        ManualEvidenceService(root).show(
            "CASE-0001", evidence.artifact.artifact_id.display_id
        )
        == evidence
    )
    assert len(_rows(root, "artifacts")) == 1
    assert len(_rows(root, "artifact_provenance")) == 1


def test_same_bytes_create_distinct_rows_and_share_content(
    root: Path, tmp_path: Path
) -> None:
    first_path = tmp_path / "first.txt"
    second_path = tmp_path / "second.log"
    first_path.write_bytes(b"same benign bytes")
    second_path.write_bytes(first_path.read_bytes())
    service = ManualEvidenceService(root)

    first = service.register(
        "CASE-0001", first_path, source="analyst", evidence_type="analyst_note"
    )
    second = service.register(
        "CASE-0001", second_path, source="tool", evidence_type="tool_output"
    )

    assert first.artifact.artifact_id != second.artifact.artifact_id
    assert first.artifact.relative_path == second.artifact.relative_path
    assert len(_files(root)) == 1
    assert len(_rows(root, "artifact_provenance")) == 2


@pytest.mark.parametrize(
    ("case_id", "expected"),
    [
        ("CASE-9999", DomainErrorCode.CASE_NOT_FOUND),
        ("CASE-0002", DomainErrorCode.CASE_CLOSED),
    ],
)
def test_invalid_or_closed_case_is_rejected_before_source_access(
    root: Path, tmp_path: Path, case_id: str, expected: DomainErrorCode
) -> None:
    missing = tmp_path / "missing.txt"
    with pytest.raises(DomainError) as caught:
        ManualEvidenceService(root).register(
            case_id, missing, source="analyst", evidence_type="other"
        )
    assert caught.value.code is expected
    assert _rows(root, "artifacts") == []
    assert _rows(root, "artifact_provenance") == []


def test_extension_and_size_policy_are_manual_only(root: Path, tmp_path: Path) -> None:
    service = ManualEvidenceService(root)
    blocked = tmp_path / "evidence.exe"
    blocked.write_bytes(b"harmless")
    with pytest.raises(DomainError) as caught:
        service.register("CASE-0001", blocked, source="analyst", evidence_type="other")
    assert caught.value.code is DomainErrorCode.EVIDENCE_EXTENSION_NOT_ALLOWED

    oversized = tmp_path / "evidence.txt"
    oversized.write_bytes(b"x" * (MANUAL_EVIDENCE_MAX_BYTES + 1))
    with pytest.raises(DomainError) as caught:
        service.register(
            "CASE-0001", oversized, source="analyst", evidence_type="other"
        )
    assert caught.value.code is DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED
    assert _rows(root, "artifacts") == []
    assert _files(root) == []

    # The generic Artifact Store contract remains unbounded and extension-agnostic.
    generic = tmp_path / "generic.exe"
    generic.write_bytes(b"g" * (MANUAL_EVIDENCE_MAX_BYTES + 1))
    artifact = ArtifactService(root).add("CASE-0001", generic, "other")
    assert artifact.size_bytes == MANUAL_EVIDENCE_MAX_BYTES + 1


@pytest.mark.parametrize("size", [0, MANUAL_EVIDENCE_MAX_BYTES])
def test_manual_evidence_accepts_empty_and_exact_limit(
    root: Path, tmp_path: Path, size: int
) -> None:
    source = tmp_path / f"boundary-{size}.txt"
    source.write_bytes(b"x" * size)

    result = ManualEvidenceService(root).register(
        "CASE-0001", source, source="analyst", evidence_type="other"
    )

    assert result.artifact.size_bytes == size


def test_v1_requires_explicit_migration_before_source_access(
    root: Path, tmp_path: Path
) -> None:
    connection = connect_database(root / "project.db")
    try:
        with connection:
            connection.execute("DROP TABLE artifact_provenance")
            connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    finally:
        connection.close()

    with pytest.raises(DomainError) as caught:
        ManualEvidenceService(root).register(
            "CASE-0001",
            tmp_path / "missing.txt",
            source="analyst",
            evidence_type="other",
        )
    assert caught.value.code is DomainErrorCode.PROJECT_MIGRATION_REQUIRED


def test_provenance_failure_rolls_back_artifact_counter_and_owned_content(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence.txt"
    source.write_bytes(b"benign")

    def fail(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("injected provenance failure")

    monkeypatch.setattr(
        repository_module.SQLiteEvidenceRepository, "insert_provenance", fail
    )
    with pytest.raises(DomainError) as caught:
        ManualEvidenceService(root).register(
            "CASE-0001", source, source="analyst", evidence_type="other"
        )

    assert caught.value.code is DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED
    assert _rows(root, "artifacts") == []
    assert _rows(root, "artifact_provenance") == []
    assert dict(_rows(root, "counters"))["artifact"] == 1
    assert _files(root) == []


def test_store_failure_after_publish_cleans_content_and_preserves_database(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence.txt"
    source.write_bytes(b"benign store failure fixture")
    publish = ArtifactStore.publish

    def fail_after_publish(
        self: ArtifactStore, path: Path, *, max_bytes: int | None = None
    ) -> object:
        publish(self, path, max_bytes=max_bytes)
        raise DomainError(
            DomainErrorCode.ARTIFACT_STORE_FAILED,
            "injected failure after publication",
        )

    monkeypatch.setattr(ArtifactStore, "publish", fail_after_publish)
    with pytest.raises(DomainError) as caught:
        ManualEvidenceService(root).register(
            "CASE-0001", source, source="analyst", evidence_type="other"
        )

    assert caught.value.code is DomainErrorCode.ARTIFACT_STORE_FAILED
    assert _rows(root, "artifacts") == []
    assert _rows(root, "artifact_provenance") == []
    assert dict(_rows(root, "counters"))["artifact"] == 1
    assert _files(root) == []


def test_cleanup_failure_is_reported_after_database_rollback(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence.txt"
    source.write_bytes(b"benign cleanup fixture")

    def fail_insert(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("injected provenance failure")

    def fail_cleanup(*args: object, **kwargs: object) -> None:
        raise OSError("injected cleanup failure")

    monkeypatch.setattr(
        repository_module.SQLiteEvidenceRepository, "insert_provenance", fail_insert
    )
    monkeypatch.setattr(ArtifactStore, "cleanup", fail_cleanup)
    with pytest.raises(DomainError) as caught:
        ManualEvidenceService(root).register(
            "CASE-0001", source, source="analyst", evidence_type="other"
        )

    assert caught.value.code is DomainErrorCode.ARTIFACT_CLEANUP_FAILED
    assert _rows(root, "artifacts") == []
    assert _rows(root, "artifact_provenance") == []
    assert len(_files(root)) == 1


def test_project_validation_detects_invalid_provenance(
    root: Path, tmp_path: Path
) -> None:
    source = tmp_path / "generic.txt"
    source.write_bytes(b"benign")
    artifact = ArtifactService(root).add("CASE-0001", source, "evidence")
    connection = connect_database(root / "project.db")
    try:
        with connection:
            connection.execute(
                "INSERT INTO artifact_provenance VALUES (?, ?, ?, ?, ?)",
                (artifact.artifact_id.ulid, "bad/name.txt", "analyst", None, "other"),
            )
    finally:
        connection.close()

    report = ProjectService().validate_report(root)

    assert not report.is_valid
    assert any(
        finding.code == DomainErrorCode.INVALID_ARTIFACT_PROVENANCE.value
        for finding in report.findings
    )


def test_bundle_v1_keeps_artifact_but_omits_provenance(
    root: Path, tmp_path: Path
) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("benign notes", encoding="utf-8")
    registered = ManualEvidenceService(root).register(
        "CASE-0001",
        source,
        source="analyst",
        evidence_type="analyst_note",
        description="not represented by Bundle v1",
    )
    bundle = tmp_path / "case.zip"

    BundleService(root).export("CASE-0001", bundle)
    target = tmp_path / "target"
    ProjectService().create(target, "Target")
    result = BundleService(target).import_bundle(bundle)

    imported = ArtifactService(target).list_artifacts(result["case_display_id"])
    assert [item.kind for item in imported] == [ArtifactKind.EVIDENCE]
    assert imported[0].sha256 == registered.artifact.sha256
    assert ManualEvidenceService(target).list_evidence(result["case_display_id"]) == []
