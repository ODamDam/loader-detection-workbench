"""Process relations from Sysmon records and the layered SVG layout."""

from __future__ import annotations

from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.sysmon.records import SysmonRecord, parse_sysmon_time
from loader_detection_workbench.sysmon.relations import (
    MAX_FILES_PER_PROCESS,
    MAX_NAME_LENGTH,
    MAX_PROCESSES,
    build_process_relations,
    leaf_name,
)
from loader_detection_workbench.web.graph import (
    NODE_WIDTH,
    NodeSpec,
    clip,
    layered_graph,
    process_graph,
)

SOURCE = ArtifactId("0" * 26, "ART-000001")


def record(event_id: int, number: int, **fields: str) -> SysmonRecord:
    return SysmonRecord(
        event_id,
        str(number),
        parse_sysmon_time(f"2026-11-17 01:00:{number % 60:02d}.000"),
        fields,
        SOURCE,
    )


def create(
    number: int, guid: str, parent: str | None = None, **extra: str
) -> SysmonRecord:
    fields = {
        "ProcessGuid": guid,
        "ProcessId": str(100 + number),
        "Image": f"C:\\dir\\sub\\proc{number}.exe",
        **extra,
    }
    if parent is not None:
        fields["ParentProcessGuid"] = parent
    return record(1, number, **fields)


def test_leaf_name_drops_directories_and_controls() -> None:
    assert leaf_name("C:\\Users\\someone\\AppData\\drop.exe") == "drop.exe"
    assert leaf_name("/opt/tool/bin/run") == "run"
    assert leaf_name("C:\\dir\\") == "dir"
    assert leaf_name(None) == "(unknown)" and leaf_name("\\") == "(unknown)"
    assert leaf_name("a\x1b[31mb\nc") == "a [31mb c"
    long = leaf_name("C:\\x\\" + "n" * 200)
    assert len(long) == MAX_NAME_LENGTH and long.endswith("…")


def test_parent_child_files_and_activity() -> None:
    relations = build_process_relations(
        [
            create(2, "child", parent="root"),
            create(1, "root"),
            record(
                11,
                3,
                ProcessGuid="child",
                TargetFilename="C:\\Users\\someone\\out.bin",
            ),
            record(22, 4, ProcessGuid="child", QueryName="example.invalid"),
            record(13, 5, ProcessGuid="child", TargetObject="HKCU\\x"),
            record(12, 6, ProcessGuid="child", TargetObject="HKCU\\x"),
            record(3, 7, ProcessGuid="other", Image="C:\\w\\net.exe", ProcessId="9"),
            record(5, 8),  # no ProcessGuid: ignored
        ]
    )
    by_key = {node.key: node for node in relations.processes}
    assert relations.record_total == 8 and relations.process_total == 3
    assert by_key["root"].parent_key is None and by_key["root"].captured
    child = by_key["child"]
    assert child.parent_key == "root" and child.image_name == "proc2.exe"
    assert child.pid == "102" and child.source == "ART-000001#2"
    assert [(f.name, f.source) for f in child.files] == [("out.bin", "ART-000001#3")]
    assert child.activity == {"dns": 1, "registry": 2}
    other = by_key["other"]
    assert not other.captured and other.image_name == "net.exe" and other.pid == "9"
    assert other.activity == {"network": 1}
    assert [relations.depth(by_key[k]) for k in ("root", "child", "other")] == [0, 1, 0]


def test_uncaptured_parent_and_late_create_keep_activity() -> None:
    relations = build_process_relations(
        [
            record(
                11, 1, ProcessGuid="p", Image="C:\\a\\early.exe", TargetFilename="f"
            ),
            create(2, "p", parent="gone", ParentImage="C:\\w\\explorer.exe"),
        ]
    )
    by_key = {node.key: node for node in relations.processes}
    assert by_key["p"].captured and by_key["p"].file_total == 1
    assert by_key["p"].image_name == "proc2.exe"
    assert not by_key["gone"].captured
    assert by_key["gone"].image_name == "explorer.exe" and by_key["gone"].pid is None


def test_limits_and_cycles_are_bounded() -> None:
    files = [
        record(11, n, ProcessGuid="p", TargetFilename=f"C:\\o\\f{n}.txt")
        for n in range(2, 14)
    ]
    relations = build_process_relations([create(1, "p"), *files])
    node = relations.processes[0]
    assert len(node.files) == MAX_FILES_PER_PROCESS and node.file_total == 12
    graph = process_graph(relations)
    assert any(n.label == "+4 more files" for n in graph.nodes)

    many = build_process_relations(
        [create(n, f"g{n}") for n in range(MAX_PROCESSES + 5)]
    )
    assert len(many.processes) == MAX_PROCESSES and many.truncated
    assert many.process_total == MAX_PROCESSES + 5

    cyclic = build_process_relations(
        [create(1, "a", parent="b"), create(2, "b", parent="a")]
    )
    assert all(cyclic.depth(node) <= 2 for node in cyclic.processes)
    assert create(3, "self", parent="self").fields["ParentProcessGuid"] == "self"
    alone = build_process_relations([create(3, "self", parent="self")])
    assert alone.processes[0].parent_key is None


def test_layered_layout_positions_and_edges() -> None:
    graph = layered_graph(
        [
            ("Left", [NodeSpec("a", "A", "first", "artifact", "/a")]),
            (
                "Right",
                [NodeSpec("b", "B" * 40, "s", "rule"), NodeSpec("c", "C", "", "x")],
            ),
        ],
        [("a", "b", "supports"), ("a", "c", "supports"), ("a", "missing", "skipped")],
    )
    left, right, lower = graph.nodes
    assert left.x < right.x and right.x == lower.x and right.y < lower.y
    assert right.x - left.x > NODE_WIDTH
    assert left.href == "/a" and right.href is None
    assert len(right.label) == 24 and right.label.endswith("…")
    assert len(graph.edges) == 2
    assert graph.edges[0].path.startswith(
        f"M {left.x + left.width} {left.y + left.height // 2} C "
    )
    assert graph.width >= right.x + right.width
    assert graph.height >= lower.y + lower.height
    assert [column.title for column in graph.columns] == ["Left", "Right"]

    empty = layered_graph([], [])
    assert empty.is_empty and empty.width > 0 and empty.height > 0
    assert clip("  many   spaces\nhere ") == "many spaces here"
