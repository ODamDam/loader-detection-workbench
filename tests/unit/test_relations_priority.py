"""Sample-related processes come before background noise (ADR-031)."""

from __future__ import annotations

from datetime import UTC, datetime

from loader_detection_workbench.sysmon.records import SysmonRecord
from loader_detection_workbench.sysmon.relations import (
    FileNode,
    ProcessNode,
    build_process_relations,
    prioritized_processes,
)


def _node(key: str, image: str, parent: str | None = None) -> ProcessNode:
    return ProcessNode(key, image, None, captured=True, parent_key=parent)


def test_target_tree_and_dropped_copies_come_first() -> None:
    noise = [_node(f"n{i}", "svchost.exe") for i in range(3)]
    target = _node("t", "target-b849766681b1.exe", parent="runner")
    target.files.append(FileNode("Ogogycaf.exe", None))
    child = _node("c", "cmd.exe", parent="t")
    dropped = _node("d", "ogogycaf.exe", parent="svc")  # started later by a service
    later = _node("x", "svchost.exe")
    ordered = prioritized_processes([*noise, target, later, child, dropped])
    assert [p.key for p in ordered] == ["t", "c", "d", "n0", "n1", "n2", "x"]


def test_without_a_target_the_order_is_unchanged() -> None:
    nodes = [_node("a", "a.exe"), _node("b", "b.exe", parent="a")]
    assert prioritized_processes(nodes) == nodes


def _create(
    record: int, guid: str, image: str, parent: str, parent_cmd: str = ""
) -> SysmonRecord:
    return SysmonRecord(
        1,
        str(record),
        datetime(2026, 11, 18, 7, 0, record, tzinfo=UTC),
        {
            "ProcessGuid": guid,
            "Image": image,
            "ParentProcessGuid": parent,
            "ParentImage": r"C:\Windows\System32\powershell.exe",
            "ParentCommandLine": parent_cmd,
        },
    )


def test_guest_runner_and_its_helpers_are_marked_not_the_sample() -> None:
    runner = (
        r"powershell.exe -File C:\WorkbenchRun\VMR-0001\Invoke-WorkbenchGuestRun.ps1"
    )
    relations = build_process_relations(
        [
            _create(
                1,
                "{t}",
                r"C:\WorkbenchRun\VMR-0001\target-0123456789ab.exe",
                "{r}",
                runner,
            ),
            _create(2, "{c}", r"C:\Windows\System32\cmd.exe", "{t}"),
            _create(3, "{w}", r"C:\Windows\System32\wevtutil.exe", "{r}", runner),
            _create(4, "{s}", r"C:\Windows\System32\svchost.exe", "{x}"),
        ]
    )
    marked = {p.key for p in relations.processes if p.workbench}
    assert marked == {"{r}", "{w}"}
    assert relations.workbench_total == 2
    assert [p.key for p in relations.processes][:2] == ["{t}", "{c}"]
    assert [p.key for p in relations.processes][-2:] == ["{r}", "{w}"]
