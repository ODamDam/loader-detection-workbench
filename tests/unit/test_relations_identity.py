"""Process images identical to a recorded sample are named by display ID."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from loader_detection_workbench.sample.sqlite_repository import read_sample_hashes
from loader_detection_workbench.sysmon.records import SysmonRecord
from loader_detection_workbench.sysmon.relations import (
    build_process_relations,
    image_sha256,
)

SAMPLE = "b8" * 32
OTHER = "88" * 32


def _create(record: int, guid: str, image: str, hashes: str | None) -> SysmonRecord:
    fields = {"ProcessGuid": guid, "Image": image, "ParentProcessGuid": "{p}"}
    if hashes is not None:
        fields["Hashes"] = hashes
    return SysmonRecord(
        1, str(record), datetime(2026, 11, 19, 1, 0, record, tzinfo=UTC), fields
    )


def test_sha256_is_taken_from_the_hashes_field() -> None:
    assert image_sha256(f"SHA256={SAMPLE.upper()},IMPHASH={'0' * 32}") == SAMPLE
    assert image_sha256(f"MD5={'1' * 32},SHA256={SAMPLE}") == SAMPLE
    assert image_sha256(f"MD5={'1' * 32}") is None
    assert image_sha256("SHA256=xyz") is None
    assert image_sha256(None) is None


def test_copy_and_registered_sample_are_named_unknown_stays_unnamed() -> None:
    relations = build_process_relations(
        [
            _create(
                1, "{t}", r"C:\WorkbenchRun\target-b8b8b8b8b8b8.exe", f"SHA256={SAMPLE}"
            ),
            _create(
                2,
                "{c}",
                r"C:\Users\u\AppData\Local\Temp\x\copy.exe",
                f"SHA256={SAMPLE.upper()}",
            ),
            _create(
                3, "{d}", r"C:\Users\u\AppData\Roaming\synchost.exe", f"SHA256={OTHER}"
            ),
            _create(4, "{n}", r"C:\Windows\System32\cmd.exe", f"SHA256={'cd' * 32}"),
            _create(5, "{h}", r"C:\Windows\System32\svchost.exe", None),
        ],
        {SAMPLE: "ART-000001", OTHER: "SMP-000004"},
    )
    same = {p.image_name: p.same_as for p in relations.processes if p.captured}
    assert same == {
        "target-b8b8b8b8b8b8.exe": "ART-000001",
        "copy.exe": "ART-000001",
        "synchost.exe": "SMP-000004",
        "cmd.exe": None,
        "svchost.exe": None,
    }


def test_without_known_files_nothing_is_named() -> None:
    relations = build_process_relations(
        [_create(1, "{t}", "a.exe", f"SHA256={SAMPLE}")]
    )
    assert relations.processes[0].same_as is None
    assert relations.processes[0].sha256 == SAMPLE


def test_sample_hashes_are_read_without_creating_tables(tmp_path: Path) -> None:
    database = tmp_path / "project.db"
    assert read_sample_hashes(database) == {}
    sqlite3.connect(database).close()
    assert read_sample_hashes(database) == {}
    with sqlite3.connect(database) as connection:
        tables = connection.execute("SELECT name FROM sqlite_master").fetchall()
        assert tables == []
        connection.execute(
            "CREATE TABLE candidate_samples (sample_id TEXT, sha256 TEXT)"
        )
        connection.execute(
            "INSERT INTO candidate_samples VALUES ('SMP-000004', ?)", (OTHER.upper(),)
        )
    assert read_sample_hashes(database) == {OTHER: "SMP-000004"}
