import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.project.validator import validate_workspace


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    ProjectService().create(root, "Validation Project")
    return root


def db(root: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(root / "project.db")
    connection.row_factory = sqlite3.Row
    return connection


def mutate(root: Path, sql: str, values: tuple[object, ...] = ()) -> None:
    with closing(db(root)) as connection, connection:
        connection.execute(sql, values)


def codes(root: Path, *, full: bool = False) -> list[str]:
    return [finding.code for finding in validate_workspace(root, full=full).findings]


def test_clean_default_and_full_validation(workspace: Path, tmp_path: Path) -> None:
    CaseService(workspace).create("Benign", "benign")
    source = tmp_path / "fixture.txt"
    source.write_bytes(b"benign validation fixture")
    ArtifactService(workspace).add("CASE-0001", source, "evidence")
    assert validate_workspace(workspace).findings == ()
    assert validate_workspace(workspace, full=True).findings == ()


def test_default_validation_does_not_read_artifact_bytes(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from loader_detection_workbench.case.service import CaseService
    from loader_detection_workbench.project import validator

    CaseService(workspace).create("Benign", "benign")
    source = tmp_path / "fixture.txt"
    source.write_bytes(b"fixture")
    ArtifactService(workspace).add("CASE-0001", source, "other")

    def unexpected(*args: object, **kwargs: object) -> object:
        pytest.fail("default validation read Artifact bytes")

    monkeypatch.setattr(validator, "_open_regular", unexpected)
    assert validate_workspace(workspace).findings == ()


def test_full_missing_size_and_hash_findings(workspace: Path, tmp_path: Path) -> None:
    from loader_detection_workbench.case.service import CaseService

    CaseService(workspace).create("Benign", "benign")
    source = tmp_path / "fixture.txt"
    source.write_bytes(b"fixture")
    artifact = ArtifactService(workspace).add("CASE-0001", source, "other")
    content = artifact.relative_path.resolve_under(workspace)

    content.unlink()
    assert "ARTIFACT_MISSING" in codes(workspace, full=True)
    content.write_bytes(b"changed bytes")
    full_codes = codes(workspace, full=True)
    assert "ARTIFACT_SIZE_MISMATCH" in full_codes
    assert "ARTIFACT_SHA256_MISMATCH" in full_codes


def test_orphan_and_staging_are_warning_only(workspace: Path) -> None:
    orphan_hash = "a" * 64
    shard = workspace / "artifacts" / "sha256" / "aa"
    shard.mkdir(parents=True)
    (shard / orphan_hash).write_bytes(b"orphan")
    (shard / ".artifact-leftover.tmp").write_bytes(b"staging")
    report = validate_workspace(workspace, full=True)
    assert report.is_valid
    assert [finding.code for finding in report.findings] == [
        "STALE_STAGING_CONTENT",
        "ORPHAN_ARTIFACT_CONTENT",
    ]


def test_manifest_and_database_structural_findings(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = json.loads((workspace / "project.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = "2"
    (workspace / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["project", "validate", str(workspace)]) == 1
    output = capsys.readouterr()
    assert "UNSUPPORTED_CONTRACT_VERSION" in output.err
    assert output.out == ""


def test_database_missing_has_specific_finding(workspace: Path) -> None:
    (workspace / "project.db").unlink()
    report = validate_workspace(workspace)
    assert report.findings[0].code == "DATABASE_MISSING"
    assert not report.is_valid


def test_project_identity_and_counter_findings(workspace: Path) -> None:
    mutate(
        workspace,
        "UPDATE projects SET name = 'changed'",
    )
    assert "WORKSPACE_IDENTITY_MISMATCH" in codes(workspace)

    # Restore the DB identity, then exercise the relational counter check.
    manifest = json.loads((workspace / "project.json").read_text(encoding="utf-8"))
    mutate(workspace, "UPDATE projects SET name = ?", (manifest["project"]["name"],))
    with closing(db(workspace)) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE counters SET next_value = 0 WHERE name = 'case'")
    assert "COUNTER_INVALID" in codes(workspace)


def test_case_artifact_corruption_and_detached_semantics(
    workspace: Path, tmp_path: Path
) -> None:
    CaseService(workspace).create("Benign", "benign")
    source = tmp_path / "fixture.txt"
    source.write_bytes(b"fixture")
    artifact = ArtifactService(workspace).add("CASE-0001", source, "other")
    mutate(
        workspace,
        "UPDATE artifacts SET relative_path = 'artifacts/sha256/bb/' || sha256",
    )
    assert "ARTIFACT_PATH_INVALID" in codes(workspace)

    mutate(
        workspace,
        "UPDATE artifacts SET relative_path = ?",
        (artifact.relative_path.as_posix(),),
    )
    with closing(db(workspace)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "UPDATE artifacts SET case_id = '01ARZ3NDEKTSV4RRFFQ69G5FAW'"
        )
    assert "BROKEN_CASE_REFERENCE" in codes(workspace)

    mutate(workspace, "UPDATE artifacts SET case_id = NULL")
    assert "BROKEN_CASE_REFERENCE" not in codes(workspace)


def test_invalid_case_row_and_invalid_artifact_record(
    workspace: Path, tmp_path: Path
) -> None:
    CaseService(workspace).create("Benign", "benign")
    source = tmp_path / "fixture.txt"
    source.write_bytes(b"fixture")
    ArtifactService(workspace).add("CASE-0001", source, "other")
    with closing(db(workspace)) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE cases SET status = 'invalid'")
    finding_codes = codes(workspace)
    assert "INVALID_CASE_RECORD" in finding_codes

    with closing(db(workspace)) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE cases SET status = 'open'")
        connection.execute("UPDATE artifacts SET kind = 'invalid'")
    finding_codes = codes(workspace)
    assert "INVALID_ARTIFACT_RECORD" in finding_codes


def test_deterministic_order_and_no_mutation(workspace: Path, tmp_path: Path) -> None:
    CaseService(workspace).create("Benign", "benign")
    source = tmp_path / "fixture.txt"
    source.write_bytes(b"fixture")
    ArtifactService(workspace).add("CASE-0001", source, "other")
    before_db = (workspace / "project.db").read_bytes()
    before_files = sorted(
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if path.is_file()
    )
    first = validate_workspace(workspace, full=True)
    second = validate_workspace(workspace, full=True)
    assert first.findings == second.findings
    assert (workspace / "project.db").read_bytes() == before_db
    after_files = sorted(
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if path.is_file()
    )
    assert after_files == before_files


def test_cli_warning_and_error_exit_codes(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shard = workspace / "artifacts" / "sha256" / "aa"
    shard.mkdir(parents=True)
    (shard / ("a" * 64)).write_bytes(b"orphan")
    assert main(["project", "validate", str(workspace), "--full"]) == 0
    warning_output = capsys.readouterr().err
    assert "warning ORPHAN_ARTIFACT_CONTENT" in warning_output
    assert "valid" not in warning_output

    mutate(workspace, "DROP TABLE artifacts")
    assert main(["project", "validate", str(workspace)]) == 1
    assert "error INVALID_SQLITE_SCHEMA" in capsys.readouterr().err
