"""Sample-related processes come before background noise (ADR-031)."""

from __future__ import annotations

from loader_detection_workbench.sysmon.relations import (
    FileNode,
    ProcessNode,
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
