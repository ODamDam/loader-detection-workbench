import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.sqlite_repository import SQLiteCaseRepository
from loader_detection_workbench.domain.case import Case, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService

T0 = datetime(2026, 9, 8, 12, tzinfo=UTC)


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CaseService:
    ProjectService().create(tmp_path, "Project")
    monkeypatch.setattr("loader_detection_workbench.case.service.utc_now", lambda: T0)
    return CaseService(tmp_path)


def execute(root: Path, sql: str, values: tuple[object, ...] = ()) -> None:
    with closing(sqlite3.connect(root / "project.db")) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(sql, values)


def snapshot(root: Path) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    with closing(sqlite3.connect(root / "project.db")) as connection:
        return (
            connection.execute("SELECT * FROM cases ORDER BY display_id").fetchall(),
            connection.execute("SELECT * FROM counters ORDER BY name").fetchall(),
        )


def mutate(service: CaseService, operation: str) -> Case:
    if operation == "rename":
        return service.rename("CASE-0001", "New name")
    if operation == "close":
        return service.close("CASE-0001")
    return service.reopen("CASE-0001")


@pytest.mark.parametrize("kind", ["malware", "simulator", "benign"])
def test_creation_and_independent_projects(
    service: CaseService,
    tmp_path: Path,
    kind: str,
) -> None:
    assert service.list_cases() == []
    first = service.create(" Name ", kind)
    second = service.create("Second", kind, "  description\n")
    assert first.case_id.display_id == "CASE-0001"
    assert second.case_id.display_id == "CASE-0002"
    assert first.case_id.ulid != second.case_id.ulid
    assert first.case_id.ulid == first.case_id.ulid.upper()
    assert len(first.case_id.ulid) == 26
    assert first.status is CaseStatus.OPEN
    assert first.created_at == first.updated_at == T0
    assert first.closed_at is None and first.description is None
    assert first.name == " Name " and first.kind.value == kind
    assert service.show("CASE-0002").description == "  description\n"
    assert first.project_id == ProjectService().open(tmp_path).manifest.project_id.ulid
    with closing(sqlite3.connect(tmp_path / "project.db")) as connection:
        assert connection.execute(
            "SELECT created_at, updated_at, closed_at, description "
            "FROM cases WHERE display_id = 'CASE-0001'"
        ).fetchone() == ("2026-09-08T12:00:00Z", "2026-09-08T12:00:00Z", None, None)
    assert {p.name for p in tmp_path.iterdir()} == {"project.json", "project.db"}
    other_root = tmp_path / "other"
    ProjectService().create(other_root, "Other")
    other = CaseService(other_root).create("Other", kind)
    assert other.case_id.display_id == "CASE-0001"
    assert other.project_id != first.project_id


def test_numeric_order_and_counter_not_max(
    service: CaseService, tmp_path: Path
) -> None:
    first = service.create("First", "benign")
    execute(tmp_path, "UPDATE counters SET next_value = 9999 WHERE name = 'case'")
    last_four = service.create("9999", "benign")
    first_five = service.create("10000", "benign")
    assert [c.case_id.display_id for c in service.list_cases()] == [
        "CASE-0001",
        "CASE-9999",
        "CASE-10000",
    ]
    assert service.list_cases() == [first, last_four, first_five]
    assert service.close("CASE-0001").case_id == first.case_id
    assert service.create("Next", "benign").case_id.display_id == "CASE-10001"


@pytest.mark.parametrize("description", ["", "  ", " text "])
def test_description_preserved(service: CaseService, description: str) -> None:
    case = service.create("Name", "benign", description)
    assert service.show(case.case_id.display_id).description == description


@pytest.mark.parametrize("seconds", [0, 1])
def test_lifecycle_and_immutable_fields(
    service: CaseService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seconds: int,
) -> None:
    first = service.create("First", "benign", "Description")
    monkeypatch.setattr(
        "loader_detection_workbench.case.service.utc_now",
        lambda: T0 + timedelta(seconds=seconds),
    )
    renamed = service.rename("CASE-0001", " Renamed ")
    assert renamed == replace(
        first,
        name=" Renamed ",
        lifecycle=replace(first.lifecycle, updated_at=T0 + timedelta(seconds=seconds)),
    )
    assert renamed.updated_at >= first.updated_at
    closed = service.close("CASE-0001")
    assert closed.status is CaseStatus.CLOSED
    assert closed.closed_at == closed.updated_at
    assert service.show("CASE-0001") == closed
    before = snapshot(tmp_path)
    rejected: list[tuple[Callable[[], Case], DomainErrorCode]] = [
        (lambda: service.rename("CASE-0001", "No"), DomainErrorCode.CASE_CLOSED),
        (lambda: service.close("CASE-0001"), DomainErrorCode.INVALID_CASE_TRANSITION),
    ]
    for operation, code in rejected:
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code is code
        assert snapshot(tmp_path) == before
    reopened = service.reopen("CASE-0001")
    assert reopened.status is CaseStatus.OPEN and reopened.closed_at is None
    assert reopened.case_id == first.case_id
    assert reopened.created_at == first.created_at
    assert reopened.project_id == first.project_id and reopened.kind == first.kind
    before = snapshot(tmp_path)
    with pytest.raises(DomainError) as error:
        service.reopen("CASE-0001")
    assert error.value.code is DomainErrorCode.INVALID_CASE_TRANSITION
    assert snapshot(tmp_path) == before
    assert service.rename("CASE-0001", "Allowed").name == "Allowed"


@pytest.mark.parametrize("name", ["", " ", "\n\t"])
def test_invalid_name_never_writes(
    service: CaseService, tmp_path: Path, name: str
) -> None:
    service.create("First", "benign")
    before = snapshot(tmp_path)
    operations: tuple[Callable[[], Case], ...] = (
        lambda: service.rename("CASE-0001", name),
        lambda: service.create(name, "benign"),
    )
    for operation in operations:
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code is DomainErrorCode.INVALID_CASE_NAME
        assert snapshot(tmp_path) == before


@pytest.mark.parametrize("operation", ["show", "rename", "close", "reopen"])
def test_missing_case(service: CaseService, operation: str) -> None:
    with pytest.raises(DomainError) as error:
        if operation == "show":
            service.show("CASE-0001")
        else:
            mutate(service, operation)
    assert error.value.code is DomainErrorCode.CASE_NOT_FOUND


@pytest.mark.parametrize(
    "field,value",
    [
        ("internal_id", "invalid"),
        ("internal_id", "01arz3ndektsv4rrffq69g5fav"),
        ("internal_id", None),
        ("project_id", "00000000000000000000000001"),
        ("project_id", "broken"),
        ("kind", "other"),
        ("status", "completed"),
        ("name", " "),
        ("description", b"blob"),
        ("created_at", "2026-9-08T12:00:00Z"),
        ("created_at", "2026-09-09T12:00:00Z"),
        ("updated_at", "2026-09-08T11:59:59Z"),
        ("updated_at", "2026-09-08T12:00:00.000Z"),
        ("updated_at", "2026-09-08T12:00:00+00:00"),
        ("closed_at", "2026-09-08T12:00:00Z"),
        ("closed_at", "bad"),
    ],
)
def test_corrupt_rows_fail_closed(
    service: CaseService,
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    service.create("Name", "benign")
    execute(tmp_path, f"UPDATE cases SET {field} = ?", (value,))
    before = snapshot(tmp_path)
    operations: tuple[Callable[[], object], ...] = (
        service.list_cases,
        lambda: service.show("CASE-0001"),
        lambda: service.rename("CASE-0001", "No"),
        lambda: service.close("CASE-0001"),
        lambda: service.reopen("CASE-0001"),
    )
    for operation in operations:
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code is DomainErrorCode.INVALID_CASE_RECORD
        assert snapshot(tmp_path) == before


@pytest.mark.parametrize("closed_at", [None, "2026-09-08T11:59:59Z"])
def test_closed_row_requires_matching_closed_timestamp(
    service: CaseService,
    tmp_path: Path,
    closed_at: str | None,
) -> None:
    service.create("Name", "benign")
    service.close("CASE-0001")
    execute(tmp_path, "UPDATE cases SET closed_at = ?", (closed_at,))
    before = snapshot(tmp_path)
    operations: tuple[Callable[[], Case], ...] = (
        lambda: service.show("CASE-0001"),
        lambda: service.reopen("CASE-0001"),
    )
    for operation in operations:
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code is DomainErrorCode.INVALID_CASE_RECORD
        assert snapshot(tmp_path) == before


def test_invalid_persisted_display_id(service: CaseService, tmp_path: Path) -> None:
    service.create("Name", "benign")
    execute(tmp_path, "UPDATE cases SET display_id = 'CASE-001'")
    with pytest.raises(DomainError) as error:
        service.list_cases()
    assert error.value.code is DomainErrorCode.INVALID_CASE_RECORD


@pytest.mark.parametrize(
    "sql,code",
    [
        ("DELETE FROM projects", DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH),
        (
            "UPDATE projects SET name = 'Mismatch'",
            DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH,
        ),
        (
            "UPDATE projects SET internal_id = 'bad'",
            DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH,
        ),
        (
            "DELETE FROM counters WHERE name = 'case'",
            DomainErrorCode.INVALID_SQLITE_SCHEMA,
        ),
        (
            "UPDATE counters SET next_value = 'bad' WHERE name = 'case'",
            DomainErrorCode.INVALID_SQLITE_SCHEMA,
        ),
        (
            "UPDATE counters SET next_value = 0 WHERE name = 'case'",
            DomainErrorCode.INVALID_SQLITE_SCHEMA,
        ),
        (
            "UPDATE counters SET next_value = 1.5 WHERE name = 'case'",
            DomainErrorCode.INVALID_SQLITE_SCHEMA,
        ),
    ],
)
def test_workspace_and_counter_failures(
    service: CaseService,
    tmp_path: Path,
    sql: str,
    code: DomainErrorCode,
) -> None:
    service.create("Name", "benign")
    execute(tmp_path, sql)
    before = snapshot(tmp_path)
    for operation in (
        lambda: service.create("No", "benign"),
        service.list_cases,
        lambda: service.rename("CASE-0001", "No"),
    ):
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code is code
        assert snapshot(tmp_path) == before


def test_failed_insert_does_not_consume_counter(
    service: CaseService, tmp_path: Path
) -> None:
    before = snapshot(tmp_path)
    execute(
        tmp_path,
        "CREATE TRIGGER fail_insert AFTER INSERT ON cases "
        "BEGIN SELECT RAISE(ABORT, 'private insert failure'); END",
    )
    with pytest.raises(DomainError) as error:
        service.create("No", "benign")
    assert error.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA
    assert "private" not in str(error.value)
    assert snapshot(tmp_path) == before
    execute(tmp_path, "DROP TRIGGER fail_insert")
    assert service.create("Yes", "benign").case_id.display_id == "CASE-0001"


@pytest.mark.parametrize("operation", ["rename", "close", "reopen"])
def test_failed_update_rolls_back(
    service: CaseService,
    tmp_path: Path,
    operation: str,
) -> None:
    service.create("Name", "benign")
    if operation == "reopen":
        service.close("CASE-0001")
    before = snapshot(tmp_path)
    execute(
        tmp_path,
        "CREATE TRIGGER fail_update AFTER UPDATE ON cases "
        "BEGIN SELECT RAISE(ABORT, 'private update failure'); END",
    )
    with pytest.raises(DomainError) as error:
        mutate(service, operation)
    assert error.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("operation", ["rename", "close", "reopen"])
def test_backwards_clock_does_not_write(
    service: CaseService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    service.create("Name", "benign")
    if operation == "reopen":
        service.close("CASE-0001")
    before = snapshot(tmp_path)
    monkeypatch.setattr(
        "loader_detection_workbench.case.service.utc_now",
        lambda: T0 - timedelta(seconds=1),
    )
    with pytest.raises(DomainError) as error:
        mutate(service, operation)
    assert error.value.code is DomainErrorCode.INVALID_TIMESTAMP
    assert snapshot(tmp_path) == before


def test_concurrent_creates_and_closes(service: CaseService, tmp_path: Path) -> None:
    def create(index: int) -> Case:
        return CaseService(tmp_path).create(str(index), "benign")

    with ThreadPoolExecutor(max_workers=4) as pool:
        cases = list(pool.map(create, range(8)))
    assert len({c.case_id.ulid for c in cases}) == 8
    assert [c.case_id.display_id for c in service.list_cases()] == [
        f"CASE-{i:04d}" for i in range(1, 9)
    ]

    def close(index: int) -> str:
        try:
            CaseService(tmp_path).close("CASE-0001")
            return "closed"
        except DomainError as error:
            return error.code.value

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(close, range(2)))
    assert sorted(results) == ["INVALID_CASE_TRANSITION", "closed"]


def test_repository_rejects_stale_same_second_write(
    service: CaseService,
    tmp_path: Path,
) -> None:
    old = service.create("Name", "benign")
    service.rename("CASE-0001", "Current")
    before = snapshot(tmp_path)
    workspace = ProjectService().open(tmp_path)
    with (
        closing(SQLiteCaseRepository(workspace, write=True)) as repository,
        pytest.raises(DomainError),
        repository.transaction(),
    ):
        repository.rename(old, "Stale", T0)
    assert snapshot(tmp_path) == before


def test_project_rechecked_inside_transaction(
    service: CaseService, tmp_path: Path
) -> None:
    workspace = ProjectService().open(tmp_path)
    execute(tmp_path, "UPDATE projects SET name = 'Changed'")
    with (
        closing(SQLiteCaseRepository(workspace, write=True)) as repository,
        pytest.raises(DomainError) as error,
        repository.transaction(),
    ):
        repository.allocate_display_id()
    assert error.value.code is DomainErrorCode.WORKSPACE_IDENTITY_MISMATCH


def test_relocation_preserves_cases(service: CaseService, tmp_path: Path) -> None:
    case = service.create("Name", "benign")
    moved = tmp_path.with_name(tmp_path.name + "-moved")
    tmp_path.rename(moved)
    try:
        assert CaseService(moved).show("CASE-0001") == case
        assert ProjectService().validate(moved).is_valid
    finally:
        moved.rename(tmp_path)


@pytest.mark.parametrize("operation", ["create", "rename", "close", "reopen"])
def test_commit_failure_rolls_back(
    service: CaseService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    service.create("Name", "benign")
    if operation == "reopen":
        service.close("CASE-0001")
    before = snapshot(tmp_path)

    class FailingCommit(sqlite3.Connection):
        def commit(self) -> None:
            raise sqlite3.OperationalError("private commit details")

    def connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
        connection = sqlite3.connect(path, factory=FailingCommit)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    monkeypatch.setattr(
        "loader_detection_workbench.case.sqlite_repository.connect_database", connect
    )
    with pytest.raises(DomainError) as error:
        if operation == "create":
            service.create("No", "benign")
        else:
            mutate(service, operation)
    assert error.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA
    assert "private" not in str(error.value)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("failure", ["ABORT", "IGNORE"])
def test_counter_write_failure_is_atomic(
    service: CaseService,
    tmp_path: Path,
    failure: str,
) -> None:
    before = snapshot(tmp_path)
    action = "RAISE(ABORT, 'failure')" if failure == "ABORT" else "RAISE(IGNORE)"
    execute(
        tmp_path,
        "CREATE TRIGGER fail_counter BEFORE UPDATE ON counters "
        f"BEGIN SELECT {action}; END",
    )
    with pytest.raises(DomainError) as error:
        service.create("No", "benign")
    assert error.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA
    assert snapshot(tmp_path) == before


def test_display_collision_rolls_back_without_counter_repair(
    service: CaseService,
    tmp_path: Path,
) -> None:
    service.create("Name", "benign")
    execute(tmp_path, "UPDATE counters SET next_value = 1 WHERE name = 'case'")
    before = snapshot(tmp_path)
    with pytest.raises(DomainError) as error:
        service.create("Collision", "benign")
    assert error.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA
    assert snapshot(tmp_path) == before


def test_post_write_corruption_is_rolled_back(
    service: CaseService, tmp_path: Path
) -> None:
    service.create("Name", "benign")
    before = snapshot(tmp_path)
    execute(
        tmp_path,
        "CREATE TRIGGER corrupt_update AFTER UPDATE ON cases "
        "BEGIN UPDATE cases SET closed_at = 'bad'; END",
    )
    with pytest.raises(DomainError) as error:
        service.rename("CASE-0001", "No")
    assert error.value.code is DomainErrorCode.INVALID_CASE_RECORD
    assert snapshot(tmp_path) == before


def test_counter_rechecked_inside_transaction(
    service: CaseService, tmp_path: Path
) -> None:
    workspace = ProjectService().open(tmp_path)
    execute(tmp_path, "DELETE FROM counters WHERE name = 'case'")
    with (
        closing(SQLiteCaseRepository(workspace, write=True)) as repository,
        pytest.raises(DomainError) as error,
        repository.transaction(),
    ):
        repository.allocate_display_id()
    assert error.value.code is DomainErrorCode.INVALID_SQLITE_SCHEMA


def test_explicit_write_boundary_and_foreign_keys(
    service: CaseService, tmp_path: Path
) -> None:
    workspace = ProjectService().open(tmp_path)
    with closing(SQLiteCaseRepository(workspace, write=True)) as repository:
        assert repository._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(RuntimeError):
            repository.allocate_display_id()
    assert snapshot(tmp_path)[0] == []
