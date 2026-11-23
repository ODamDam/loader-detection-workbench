import hashlib
from pathlib import Path

from loader_detection_workbench.cli import main

PASS = [
    "--real-world",
    "pass",
    "--windows-target",
    "pass",
    "--loader-downloader",
    "pass",
    "--provenance",
    "pass",
    "--binary-valid",
    "pass",
    "--supported-analysis",
    "pass",
    "--duplicate-clear",
    "pass",
]


def invoke(db: Path, *args: str) -> int:
    return main(["--database", str(db), "sample", *args])


def add(db: Path, path: Path) -> None:
    assert (
        invoke(
            db,
            "add",
            str(path),
            "--source",
            "test_repository",
            "--source-reference",
            path.name,
        )
        == 0
    )


def test_add_hash_screen_eligible_and_json(tmp_path: Path, capsys: object) -> None:
    fixture = tmp_path / "benign.bin"
    fixture.write_bytes(b"benign fixture")
    db = tmp_path / "samples.db"
    add(db, fixture)
    assert invoke(db, "screen", "SMP-000001", *PASS) == 0
    assert invoke(db, "eligible", "SMP-000001") == 0
    assert invoke(db, "show", "SMP-000001", "--format", "json") == 0
    import pytest

    captured = (
        pytest.CaptureFixture
    )  # keep runtime free of fixture-specific API assumptions
    del captured
    # SHA is persisted and emitted; binary contents are never emitted.
    assert hashlib.sha256(b"benign fixture").hexdigest() in capsys.readouterr().out  # type: ignore[attr-defined]


def test_incomplete_excluded_and_assignment_failures(tmp_path: Path) -> None:
    fixture = tmp_path / "one.txt"
    fixture.write_text("one", encoding="utf-8")
    db = tmp_path / "db.sqlite"
    add(db, fixture)
    assert invoke(db, "eligible", "SMP-000001") == 1
    assert invoke(db, "exclude", "SMP-000001", "--reason", "screening_failed") == 0
    assert (
        invoke(
            db,
            "assign",
            "SMP-000001",
            "--role",
            "malware_dev",
            "--reason",
            "manual_balance_adjustment",
        )
        == 1
    )


def test_split_freeze_post_freeze_and_eval_open(tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite"
    for index in range(2):
        fixture = tmp_path / f"{index}.txt"
        fixture.write_text(str(index), encoding="utf-8")
        add(db, fixture)
        sample_id = f"SMP-{index + 1:06d}"
        assert invoke(db, "screen", sample_id, *PASS) == 0
        assert invoke(db, "eligible", sample_id) == 0
    assert (
        invoke(
            db,
            "split",
            "--dev-count",
            "1",
            "--eval-count",
            "1",
            "--seed",
            "7",
            "--split-id",
            "SPLIT-1",
        )
        == 0
    )
    assert (
        invoke(db, "freeze", "--benchmark-id", "BMK-000001", "--benchmark-version", "1")
        == 0
    )
    assert (
        invoke(
            db,
            "assign",
            "SMP-000001",
            "--role",
            "malware_dev",
            "--reason",
            "replacement_before_freeze",
        )
        == 1
    )
    data = []
    for sample_id in ("SMP-000001", "SMP-000002"):
        from loader_detection_workbench.sample.sqlite_repository import (
            SQLiteSampleRepository,
        )

        repo = SQLiteSampleRepository(db)
        data.append(repo.get(sample_id))
        repo.close()
    evaluation = next(
        item for item in data if item.assigned_dataset_role.value == "malware_eval"
    )
    assert invoke(db, "eval-open", evaluation.sample_id) == 0
    from loader_detection_workbench.sample.sqlite_repository import (
        SQLiteSampleRepository,
    )

    repo = SQLiteSampleRepository(db)
    opened = repo.get(evaluation.sample_id)
    repo.close()
    assert (
        opened.first_execution_at is None
        and opened.first_detailed_access_at is not None
    )


def test_freeze_rejects_contaminated_eval(tmp_path: Path) -> None:
    fixture = tmp_path / "clean.txt"
    fixture.write_text("benign", encoding="utf-8")
    db = tmp_path / "db.sqlite"
    add(db, fixture)
    assert invoke(db, "screen", "SMP-000001", *PASS) == 0
    assert invoke(db, "eligible", "SMP-000001") == 0
    assert (
        invoke(
            db,
            "assign",
            "SMP-000001",
            "--role",
            "malware_eval",
            "--reason",
            "manual_balance_adjustment",
        )
        == 0
    )

    # Simulate pre-existing manifest exposure metadata; no fixture is executed.
    from dataclasses import replace

    from loader_detection_workbench.sample.sqlite_repository import (
        SQLiteSampleRepository,
    )

    repository = SQLiteSampleRepository(db)
    contaminated = replace(
        repository.get("SMP-000001"),
        detailed_behavior_inspected=True,
    )
    with repository.transaction():
        repository.save(contaminated)
    repository.close()

    assert (
        invoke(
            db,
            "freeze",
            "--benchmark-id",
            "BMK-000001",
            "--benchmark-version",
            "1",
        )
        == 1
    )
