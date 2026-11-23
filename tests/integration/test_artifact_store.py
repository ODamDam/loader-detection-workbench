import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from typing import BinaryIO

import pytest

from loader_detection_workbench.artifact import store as store_module
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.sqlite_repository import (
    SQLiteArtifactRepository,
)
from loader_detection_workbench.artifact.store import ArtifactStore, PublishedContent
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.artifact import Artifact, canonical_path
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.paths import ProjectRelativePath
from loader_detection_workbench.project.service import ProjectService


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Artifacts")
    cases = CaseService(root)
    cases.create("First", "benign")
    cases.create("Second", "benign")
    return root


@pytest.fixture
def source(tmp_path: Path) -> Path:
    source = tmp_path / "harmless 한글 file.txt"
    source.write_bytes(b"benign fixture\n")
    return source


def query(root: Path, sql: str) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(root / "project.db")) as connection, connection:
        return connection.execute(sql).fetchall()


def snapshot(root: Path) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    return (
        query(root, "SELECT * FROM artifacts ORDER BY display_id"),
        query(root, "SELECT * FROM counters ORDER BY name"),
    )


def files(root: Path) -> list[Path]:
    return sorted(path for path in (root / "artifacts").rglob("*") if path.is_file())


def test_add_metadata_and_dedup_provenance(root: Path, source: Path) -> None:
    service = ArtifactService(root)
    data = source.read_bytes()
    first = service.add("CASE-0001", source, "evidence")
    other = source.with_name("another name.txt")
    other.write_bytes(data)
    second = service.add("CASE-0001", other, "report")
    third = service.add("CASE-0002", source, "other")
    fourth = service.add("CASE-0001", source, "evidence")
    assert first.sha256 == hashlib.sha256(data).hexdigest()
    assert first.size_bytes == len(data)
    assert first.relative_path == canonical_path(first.sha256)
    assert len({a.artifact_id.ulid for a in (first, second, third, fourth)}) == 4
    assert [a.artifact_id.display_id for a in (first, second, third, fourth)] == [
        "ART-000001",
        "ART-000002",
        "ART-000003",
        "ART-000004",
    ]
    assert all(a.relative_path == first.relative_path for a in (second, third, fourth))
    assert files(root) == [first.relative_path.resolve_under(root)]
    assert files(root)[0].read_bytes() == data
    assert service.list_artifacts("CASE-0001") == [first, second, fourth]
    assert service.list_artifacts("CASE-0002") == [third]
    assert query(root, "SELECT created_at FROM artifacts")[0][
        0
    ] == first.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert query(root, "SELECT version FROM schema_migrations ORDER BY version") == [
        (1,),
        (2,),
    ]


def test_same_filename_different_bytes_and_empty_file(root: Path, source: Path) -> None:
    service = ArtifactService(root)
    first = service.add("CASE-0001", source, "other")
    source.write_bytes(b"")
    second = service.add("CASE-0001", source, "other")
    assert first.relative_path != second.relative_path
    assert second.size_bytes == 0
    assert second.sha256 == hashlib.sha256(b"").hexdigest()
    assert len(files(root)) == 2


def test_detach_preserves_metadata_bytes_and_counter(root: Path, source: Path) -> None:
    service = ArtifactService(root)
    artifact = service.add("CASE-0001", source, "other")
    counter = query(root, "SELECT * FROM counters")
    detached = service.detach("CASE-0001", artifact.artifact_id.display_id)
    assert detached.case_id is None
    assert query(root, "SELECT case_id FROM artifacts") == [(None,)]
    assert files(root)[0].read_bytes() == source.read_bytes()
    assert service.list_artifacts("CASE-0001") == []
    assert query(root, "SELECT * FROM counters") == counter
    with pytest.raises(DomainError) as caught:
        service.detach("CASE-0001", artifact.artifact_id.display_id)
    assert caught.value.code is DomainErrorCode.ARTIFACT_NOT_ATTACHED
    assert (
        service.add("CASE-0002", source, "other").artifact_id.display_id == "ART-000002"
    )
    assert len(files(root)) == 1


def test_wrong_case_and_missing_artifact(root: Path, source: Path) -> None:
    service = ArtifactService(root)
    artifact = service.add("CASE-0001", source, "other")
    before = snapshot(root)
    for display_id, code in [
        (artifact.artifact_id.display_id, "ARTIFACT_NOT_ATTACHED"),
        ("ART-999999", "ARTIFACT_NOT_FOUND"),
    ]:
        with pytest.raises(DomainError) as caught:
            service.detach("CASE-0002", display_id)
        assert caught.value.code.value == code
        assert snapshot(root) == before


def test_closed_case_rejects_mutations_without_source_access(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = ArtifactService(root)
    artifact = service.add("CASE-0001", source, "other")
    CaseService(root).close("CASE-0001")
    before = snapshot(root)

    def unexpected(*args: object) -> None:
        pytest.fail("closed Case touched content")

    monkeypatch.setattr(ArtifactStore, "publish", unexpected)
    for operation in (
        lambda: service.add("CASE-0001", source, "other"),
        lambda: service.detach("CASE-0001", artifact.artifact_id.display_id),
    ):
        with pytest.raises(DomainError) as caught:
            operation()
        assert caught.value.code is DomainErrorCode.CASE_CLOSED
    assert service.list_artifacts("CASE-0001") == [artifact]
    assert snapshot(root) == before
    assert files(root)[0].read_bytes() == source.read_bytes()


@pytest.mark.parametrize("invalid", ["missing", "directory", "unreadable", "special"])
def test_invalid_sources_have_no_effect(
    root: Path,
    source: Path,
    invalid: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = snapshot(root)
    if invalid == "missing":
        source = source.with_name("missing")
    elif invalid == "directory":
        source = source.parent
    elif invalid == "special":
        monkeypatch.setattr(store_module.stat, "S_ISREG", lambda _: False)
    else:

        def denied(*args: object, **kwargs: object) -> int:
            raise PermissionError("private path must not leak")

        monkeypatch.setattr(store_module.os, "open", denied)
    with pytest.raises(DomainError) as caught:
        ArtifactService(root).add("CASE-0001", source, "other")
    assert caught.value.code is DomainErrorCode.ARTIFACT_SOURCE_INVALID
    assert snapshot(root) == before and files(root) == []


@pytest.mark.parametrize(
    "value", ["../escape", "/escape", "C:/escape", r"\\host\share\x"]
)
def test_path_escape_rejected(root: Path, value: str) -> None:
    with pytest.raises(DomainError):
        ArtifactStore(root).resolve(ProjectRelativePath.parse(value))


def test_linked_content_root_rejected(root: Path, tmp_path: Path, source: Path) -> None:
    external = tmp_path / "outside"
    external.mkdir()
    try:
        (root / "artifacts").symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks require host privileges")
    with pytest.raises(DomainError) as caught:
        ArtifactService(root).add("CASE-0001", source, "other")
    assert caught.value.code is DomainErrorCode.PATH_ESCAPE
    assert list(external.iterdir()) == []
    assert query(root, "SELECT * FROM artifacts") == []


@pytest.mark.parametrize("tamper", [b"wrong", b"X" * 15])
def test_existing_content_tamper_is_never_overwritten(
    root: Path,
    source: Path,
    tamper: bytes,
) -> None:
    service = ArtifactService(root)
    artifact = service.add("CASE-0001", source, "other")
    content = artifact.relative_path.resolve_under(root)
    content.write_bytes(tamper)
    before = snapshot(root)
    with pytest.raises(DomainError) as caught:
        service.add("CASE-0002", source, "other")
    assert caught.value.code is DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH
    assert snapshot(root) == before and content.read_bytes() == tamper


@pytest.mark.parametrize("failure", ["create", "write", "publish", "source_changed"])
def test_staging_failures_cleanup(
    root: Path,
    source: Path,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = snapshot(root)

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("injected benign failure")

    if failure == "create":
        monkeypatch.setattr(store_module.tempfile, "mkstemp", fail)
    elif failure == "publish":
        monkeypatch.setattr(store_module, "_publish_exclusive", fail)
    else:
        original = store_module._digest

        def digest(stream: BinaryIO, target: BinaryIO | None = None) -> tuple[str, int]:
            if target is not None:
                target.write(b"partial benign bytes")
                if failure == "write":
                    raise OSError("write failed")
                return "0" * 64, 20
            return original(stream, target)

        monkeypatch.setattr(store_module, "_digest", digest)
    with pytest.raises(DomainError):
        ArtifactService(root).add("CASE-0001", source, "other")
    assert snapshot(root) == before
    assert files(root) == []


@pytest.mark.parametrize("existing", [False, True])
def test_db_insert_failure_rolls_back_counter_and_cleans_only_owned_content(
    root: Path,
    source: Path,
    existing: bool,
) -> None:
    service = ArtifactService(root)
    if existing:
        service.add("CASE-0001", source, "other")
    before = snapshot(root)
    previous_files = files(root)
    query(
        root,
        "CREATE TRIGGER reject_artifact BEFORE INSERT ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    with pytest.raises(DomainError) as caught:
        service.add("CASE-0002", source, "other")
    assert caught.value.code is DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED
    assert snapshot(root) == before
    assert files(root) == previous_files
    query(root, "DROP TRIGGER reject_artifact")
    result = service.add("CASE-0002", source, "other")
    assert result.artifact_id.display_id == ("ART-000002" if existing else "ART-000001")


def test_failure_after_insert_rolls_back_row_and_counter(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = SQLiteArtifactRepository.insert

    def insert(self: SQLiteArtifactRepository, artifact: Artifact) -> None:
        original(self, artifact)
        raise sqlite3.OperationalError("failure after insert")

    monkeypatch.setattr(SQLiteArtifactRepository, "insert", insert)
    before = snapshot(root)
    with pytest.raises(DomainError):
        ArtifactService(root).add("CASE-0001", source, "other")
    assert snapshot(root) == before and files(root) == []


def test_cleanup_failure_reports_error_leaves_no_committed_artifact(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query(
        root,
        "CREATE TRIGGER reject_artifact BEFORE INSERT ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )

    def fail(self: ArtifactStore, content: PublishedContent) -> None:
        raise PermissionError("cleanup denied")

    monkeypatch.setattr(ArtifactStore, "cleanup", fail)
    before = snapshot(root)
    with pytest.raises(DomainError) as caught:
        ArtifactService(root).add("CASE-0001", source, "other")
    assert caught.value.code is DomainErrorCode.ARTIFACT_CLEANUP_FAILED
    assert snapshot(root) == before and len(files(root)) == 1
    assert files(root)[0].read_bytes() == source.read_bytes()


def test_concurrent_adds_share_bytes_preserve_all_rows(
    root: Path, source: Path
) -> None:
    barrier = Barrier(4)

    def add(index: int) -> Artifact:
        barrier.wait(timeout=10)
        return ArtifactService(root).add(f"CASE-{index % 2 + 1:04d}", source, "other")

    with ThreadPoolExecutor(max_workers=4) as executor:
        artifacts = list(executor.map(add, range(4)))
    assert len({a.artifact_id.ulid for a in artifacts}) == 4
    assert len({a.artifact_id.display_id for a in artifacts}) == 4
    assert len(files(root)) == 1
    assert query(root, "SELECT next_value FROM counters WHERE name = 'artifact'") == [
        (5,)
    ]
    assert files(root)[0].read_bytes() == source.read_bytes()


def test_publish_race_switches_to_dedup_without_owning_winner(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = store_module._publish_exclusive

    def race(staging: Path, destination: Path) -> None:
        # An independent publisher wins immediately before exclusive publication.
        destination.write_bytes(source.read_bytes())
        original(staging, destination)

    monkeypatch.setattr(store_module, "_publish_exclusive", race)
    query(
        root,
        "CREATE TRIGGER reject_artifact BEFORE INSERT ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    with pytest.raises(DomainError):
        ArtifactService(root).add("CASE-0001", source, "other")
    assert len(files(root)) == 1
    assert files(root)[0].read_bytes() == source.read_bytes()
    assert query(root, "SELECT * FROM artifacts") == []


def test_committed_racing_reference_prevents_compensating_delete(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_insert = SQLiteArtifactRepository.insert
    original_compensate = ArtifactService._compensate

    def insert(self: SQLiteArtifactRepository, artifact: Artifact) -> None:
        original_insert(self, artifact)
        raise sqlite3.OperationalError("failed first writer")

    def compensate(
        self: ArtifactService, store: ArtifactStore, content: PublishedContent
    ) -> None:
        # Deterministic interleaving after rollback, before the cleanup lock.
        monkeypatch.setattr(SQLiteArtifactRepository, "insert", original_insert)
        ArtifactService(root).add("CASE-0002", source, "other")
        original_compensate(self, store, content)

    monkeypatch.setattr(SQLiteArtifactRepository, "insert", insert)
    monkeypatch.setattr(ArtifactService, "_compensate", compensate)
    with pytest.raises(DomainError):
        ArtifactService(root).add("CASE-0001", source, "other")
    assert ArtifactService(root).list_artifacts("CASE-0001") == []
    assert len(ArtifactService(root).list_artifacts("CASE-0002")) == 1
    assert files(root)[0].read_bytes() == source.read_bytes()


def test_numeric_order_beyond_minimum_width(root: Path, source: Path) -> None:
    service = ArtifactService(root)
    first = service.add("CASE-0001", source, "other")
    query(root, "UPDATE counters SET next_value = 999999 WHERE name = 'artifact'")
    second = service.add("CASE-0001", source, "other")
    third = service.add("CASE-0001", source, "other")
    assert third.artifact_id.display_id == "ART-1000000"
    assert [a.artifact_id.display_id for a in service.list_artifacts("CASE-0001")] == [
        first.artifact_id.display_id,
        second.artifact_id.display_id,
        "ART-1000000",
    ]


@pytest.mark.parametrize(
    "column,value",
    [
        ("sha256", "bad"),
        ("relative_path", "../outside"),
        ("kind", "UNKNOWN"),
        ("created_at", "not UTC"),
        ("internal_id", "invalid"),
        ("project_id", "invalid"),
    ],
)
def test_corrupt_metadata_fails_closed(
    root: Path,
    source: Path,
    column: str,
    value: str,
) -> None:
    service = ArtifactService(root)
    service.add("CASE-0001", source, "other")
    with closing(sqlite3.connect(root / "project.db")) as connection, connection:
        connection.execute(f"UPDATE artifacts SET {column} = ?", (value,))
    with pytest.raises(DomainError) as caught:
        service.list_artifacts("CASE-0001")
    assert caught.value.code is DomainErrorCode.INVALID_ARTIFACT_RECORD


def test_workspace_move_preserves_artifact_paths(root: Path, source: Path) -> None:
    artifact = ArtifactService(root).add("CASE-0001", source, "other")
    moved = root.with_name("moved project")
    root.rename(moved)
    assert ArtifactService(moved).list_artifacts("CASE-0001") == [artifact]
    assert (
        artifact.relative_path.resolve_under(moved).read_bytes() == source.read_bytes()
    )


def test_commit_failure_rolls_back_and_cleans_publication(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from loader_detection_workbench.artifact import sqlite_repository as module

    class FailingCommit(sqlite3.Connection):
        def commit(self) -> None:
            raise sqlite3.OperationalError("injected commit failure")

    original = module.connect_database
    calls = 0

    def connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
        nonlocal calls
        calls += 1
        if calls != 1:
            return original(path, read_only=read_only)
        connection = sqlite3.connect(path, factory=FailingCommit)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    monkeypatch.setattr(module, "connect_database", connect)
    before = snapshot(root)
    with pytest.raises(DomainError) as caught:
        ArtifactService(root).add("CASE-0001", source, "other")
    assert caught.value.code is DomainErrorCode.ARTIFACT_PERSISTENCE_FAILED
    assert snapshot(root) == before and files(root) == []


def test_staging_unlink_failure_is_not_success(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_unlink = Path.unlink

    def unlink(path: Path, missing_ok: bool = False) -> None:
        if path.name.startswith(".artifact-"):
            raise PermissionError("injected staging cleanup failure")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)
    # Use the POSIX publication primitive to exercise a real leftover staging link
    # on Windows too. Both links are still operation-owned.
    monkeypatch.setattr(store_module, "_publish_exclusive", os.link)
    before = snapshot(root)
    with pytest.raises(DomainError) as caught:
        ArtifactService(root).add("CASE-0001", source, "other")
    assert caught.value.code is DomainErrorCode.ARTIFACT_CLEANUP_FAILED
    assert snapshot(root) == before
    assert len(files(root)) == 1 and files(root)[0].name.startswith(".artifact-")


def test_replaced_content_is_not_deleted_by_failed_owner(
    root: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ArtifactService._compensate

    def compensate(
        self: ArtifactService, store: ArtifactStore, content: PublishedContent
    ) -> None:
        path = content.relative_path.resolve_under(root)
        replacement = path.with_name("replacement")
        replacement.write_bytes(b"other operation content")
        os.replace(replacement, path)
        original(self, store, content)

    monkeypatch.setattr(ArtifactService, "_compensate", compensate)
    query(
        root,
        "CREATE TRIGGER reject_artifact BEFORE INSERT ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    with pytest.raises(DomainError):
        ArtifactService(root).add("CASE-0001", source, "other")
    assert files(root)[0].read_bytes() == b"other operation content"
    assert query(root, "SELECT * FROM artifacts") == []


def test_detach_database_failure_rolls_back_relationship(
    root: Path,
    source: Path,
) -> None:
    service = ArtifactService(root)
    artifact = service.add("CASE-0001", source, "other")
    query(
        root,
        "CREATE TRIGGER reject_detach AFTER UPDATE ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    before = snapshot(root)
    with pytest.raises(DomainError):
        service.detach("CASE-0001", artifact.artifact_id.display_id)
    assert snapshot(root) == before
    assert files(root)[0].read_bytes() == source.read_bytes()


def test_large_source_is_streamed(root: Path, source: Path) -> None:
    data = b"benign large fixture\n" * 150000
    source.write_bytes(data)
    result = ArtifactService(root).add("CASE-0001", source, "static")
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.size_bytes == len(data)
    assert files(root)[0].read_bytes() == data


def test_failure_preserves_recreated_content_with_detached_reference(
    root: Path,
    source: Path,
) -> None:
    service = ArtifactService(root)
    artifact = service.add("CASE-0001", source, "other")
    service.detach("CASE-0001", artifact.artifact_id.display_id)
    artifact.relative_path.resolve_under(root).unlink()
    query(
        root,
        "CREATE TRIGGER reject_artifact BEFORE INSERT ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    before = snapshot(root)
    with pytest.raises(DomainError):
        service.add("CASE-0002", source, "other")
    assert snapshot(root) == before
    assert files(root)[0].read_bytes() == source.read_bytes()


def test_missing_case_does_not_create_content(root: Path, source: Path) -> None:
    before = snapshot(root)
    with pytest.raises(DomainError) as caught:
        ArtifactService(root).add("CASE-9999", source, "other")
    assert caught.value.code is DomainErrorCode.CASE_NOT_FOUND
    assert snapshot(root) == before and not (root / "artifacts").exists()
