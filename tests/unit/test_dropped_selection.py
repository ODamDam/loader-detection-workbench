"""Host-side choice of dropped files to collect (ADR-032)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from loader_detection_workbench.execution.dropped import (
    MAX_DROPPED_FILES,
    collectable_path,
    select_dropped,
)
from loader_detection_workbench.sysmon.records import SysmonRecord

TEMP = "C:\\Users\\analyst\\AppData\\Local\\Temp\\"
RUNNER = "powershell.exe -File C:\\WorkbenchRun\\VMR-0001\\Invoke-WorkbenchGuestRun.ps1"


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        (TEMP + "is-ABCDE.tmp\\host.exe", True),
        ("C:\\Users\\analyst\\AppData\\Roaming\\synchost.exe", True),
        ("c:\\users\\public\\x.dll", True),
        ("C:\\ProgramData\\vendor\\a.bin", True),
        ("C:\\Windows\\Tasks\\synchost.job", False),
        ("C:\\WorkbenchRun\\VMR-0001\\target-0123456789ab.exe", False),
        ("C:\\Users\\analyst\\Desktop\\a.exe", False),
        (TEMP + "..\\..\\..\\Windows\\a.exe", False),
        (TEMP + ".\\a.exe", False),
        (TEMP + "a.exe:stream", False),
        ("\\\\?\\C:\\ProgramData\\a.exe", False),
        (TEMP + "a\\\\b.exe", False),
        (TEMP, False),
        (TEMP + "A.EXE-12345678.pf", False),
        (TEMP + "a" * 260, False),
        (TEMP + "caf\u00e9.exe", False),
        (TEMP + "bad\x01name", False),
        ("", False),
    ],
)
def test_only_fixed_guest_locations_pass(path: str, allowed: bool) -> None:
    assert collectable_path(path) is allowed


def _record(record: int, event: int, **fields: str) -> SysmonRecord:
    return SysmonRecord(
        event,
        str(record),
        datetime(2026, 11, 19, 1, 0, record % 60, tzinfo=UTC),
        fields,
    )


def _create(
    record: int, guid: str, image: str, parent: str, cmd: str = ""
) -> SysmonRecord:
    return _record(
        record,
        1,
        ProcessGuid=guid,
        Image=image,
        ParentProcessGuid=parent,
        ParentCommandLine=cmd,
    )


def _write(record: int, guid: str, path: str) -> SysmonRecord:
    return _record(record, 11, ProcessGuid=guid, TargetFilename=path)


def test_sample_tree_writes_are_selected_once_in_record_order() -> None:
    records = [
        _create(
            1,
            "{t}",
            "C:\\WorkbenchRun\\VMR-0001\\target-0123456789ab.exe",
            "{r}",
            RUNNER,
        ),
        _create(2, "{s}", TEMP + "is-A.tmp\\setup.tmp", "{t}"),
        _write(4, "{s}", TEMP + "is-B.tmp\\side.dll"),
        _write(3, "{t}", TEMP + "is-A.tmp\\setup.tmp"),
        _write(5, "{s}", TEMP + "IS-B.TMP\\SIDE.DLL"),  # same path, other case
        _write(6, "{s}", "C:\\Windows\\Tasks\\x.job"),
        _write(7, "{noise}", TEMP + "other.exe"),  # not the sample tree
        _create(8, "{w}", "C:\\Windows\\System32\\wevtutil.exe", "{r}", RUNNER),
        _write(9, "{w}", TEMP + "export.tmp"),  # Workbench process
    ]
    selection = select_dropped(records)
    assert [(c.name, c.record_id) for c in selection.candidates] == [
        ("setup.tmp", "3"),
        ("side.dll", "4"),
    ]
    assert selection.written_total == 3
    assert selection.outside_allowed == 1
    assert selection.over_limit == 0


def test_files_beyond_the_limit_are_counted_not_selected() -> None:
    target = "C:\\WorkbenchRun\\VMR-0001\\target-0123456789ab.exe"
    records = [_create(1, "{t}", target, "{r}", RUNNER)] + [
        _write(10 + i, "{t}", f"{TEMP}f{i}.bin") for i in range(MAX_DROPPED_FILES + 3)
    ]
    selection = select_dropped(records)
    assert len(selection.candidates) == MAX_DROPPED_FILES
    assert selection.over_limit == 3


def test_without_a_started_target_nothing_is_selected() -> None:
    records = [_write(1, "{x}", TEMP + "a.exe")]
    assert select_dropped(records).candidates == ()
