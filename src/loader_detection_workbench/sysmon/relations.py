"""Process and file relationships derived from Sysmon records.

Process Create (Event ID 1) records link a process to its parent through
``ParentProcessGuid``. File Create (Event ID 11) records link a process to the
files it wrote. Every other Event ID is counted per process as activity.

Only the last path element of an image or target file is kept (``image_name``,
``name``); directories, command lines and ProcessGuids never leave this module
except as opaque node keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from loader_detection_workbench.sysmon.records import SysmonRecord

MAX_NAME_LENGTH = 48
MAX_PROCESSES = 60
MAX_FILES_PER_PROCESS = 8
ACTIVITY_LABELS = {
    3: "network",
    7: "image load",
    12: "registry",
    13: "registry",
    14: "registry",
    22: "dns",
}


def leaf_name(path: str | None) -> str:
    """Last path element only, on one line and bounded."""
    if not path:
        return "(unknown)"
    leaf = path.replace("\\", "/").rstrip("/").rpartition("/")[2]
    cleaned = "".join(c if c.isprintable() else " " for c in leaf).strip()
    if not cleaned:
        return "(unknown)"
    if len(cleaned) > MAX_NAME_LENGTH:
        return cleaned[: MAX_NAME_LENGTH - 1] + "…"
    return cleaned


def _reference(record: SysmonRecord) -> str | None:
    if record.source_artifact_id is None or record.record_id is None:
        return None
    return f"{record.source_artifact_id.display_id}#{record.record_id}"


@dataclass(slots=True)
class ProcessNode:
    key: str
    image_name: str
    pid: str | None
    captured: bool
    first_seen: datetime | None = None
    source: str | None = None
    parent_key: str | None = None
    activity: dict[str, int] = field(default_factory=dict)
    files: list[FileNode] = field(default_factory=list)
    file_total: int = 0


@dataclass(frozen=True, slots=True)
class FileNode:
    name: str
    source: str | None


@dataclass(frozen=True, slots=True)
class ProcessRelations:
    processes: tuple[ProcessNode, ...]
    process_total: int
    record_total: int

    @property
    def truncated(self) -> bool:
        return self.process_total > len(self.processes)

    def depth(self, node: ProcessNode) -> int:
        by_key = {item.key: item for item in self.processes}
        depth, seen, current = 0, {node.key}, node
        while current.parent_key is not None and current.parent_key in by_key:
            current = by_key[current.parent_key]
            if current.key in seen:  # defensive: never loop on cyclic input
                break
            seen.add(current.key)
            depth += 1
        return depth


def _pid(value: str | None) -> str | None:
    return value if value is not None and value.isdigit() else None


def build_process_relations(records: list[SysmonRecord]) -> ProcessRelations:
    nodes: dict[str, ProcessNode] = {}

    def placeholder(guid: str, image: str | None, pid: str | None) -> ProcessNode:
        node = nodes.get(guid)
        if node is None:
            node = ProcessNode(guid, leaf_name(image), _pid(pid), captured=False)
            nodes[guid] = node
        return node

    ordered = sorted(
        records,
        key=lambda r: (
            "" if r.timestamp is None else r.timestamp.isoformat(),
            int(r.record_id or 0),
        ),
    )
    for record in ordered:
        guid = record.fields.get("ProcessGuid")
        if record.event_id == 1 and guid:
            node = nodes.get(guid)
            if node is None or not node.captured:
                node = ProcessNode(
                    guid,
                    leaf_name(record.fields.get("Image")),
                    _pid(record.fields.get("ProcessId")),
                    captured=True,
                    first_seen=record.timestamp,
                    source=_reference(record),
                    activity={} if node is None else node.activity,
                    files=[] if node is None else node.files,
                    file_total=0 if node is None else node.file_total,
                )
                nodes[guid] = node
            parent = record.fields.get("ParentProcessGuid")
            if parent and parent != guid:
                placeholder(
                    parent,
                    record.fields.get("ParentImage"),
                    record.fields.get("ParentProcessId"),
                )
                node.parent_key = parent
        elif guid:
            node = placeholder(
                guid, record.fields.get("Image"), record.fields.get("ProcessId")
            )
            if record.event_id == 11:
                node.file_total += 1
                if len(node.files) < MAX_FILES_PER_PROCESS:
                    node.files.append(
                        FileNode(
                            leaf_name(record.fields.get("TargetFilename")),
                            _reference(record),
                        )
                    )
            else:
                label = ACTIVITY_LABELS.get(record.event_id, f"event {record.event_id}")
                node.activity[label] = node.activity.get(label, 0) + 1
    processes = tuple(nodes.values())
    return ProcessRelations(processes[:MAX_PROCESSES], len(processes), len(records))
