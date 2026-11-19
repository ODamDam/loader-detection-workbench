"""Process and file relationships derived from Sysmon records.

Process Create (Event ID 1) records link a process to its parent through
``ParentProcessGuid``. File Create (Event ID 11) records link a process to the
files it wrote. Every other Event ID is counted per process as activity.

Only the last path element of an image or target file is kept (``image_name``,
``name``); directories, command lines and ProcessGuids never leave this module
except as opaque node keys. The image SHA-256 is kept only to name an
identical recorded file (``same_as``, a display ID); it is not displayed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
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
    # Started by the Workbench guest runner itself (not by the sample).
    workbench: bool = False
    # SHA-256 of the image from the Process Create ``Hashes`` field, if logged.
    sha256: str | None = None
    # Display ID of a Project sample or Case Artifact with the same SHA-256.
    same_as: str | None = None


@dataclass(frozen=True, slots=True)
class FileNode:
    name: str
    source: str | None


@dataclass(frozen=True, slots=True)
class ProcessRelations:
    processes: tuple[ProcessNode, ...]
    process_total: int
    record_total: int
    # Workbench guest processes among all processes, before the cap.
    workbench_total: int = 0

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


# The guest runner starts a sample as ``target-<sha256[:12]>.exe`` (ADR-024).
_TARGET = re.compile(r"target-[0-9a-f]{12}\.exe", re.IGNORECASE | re.ASCII)


def prioritized_processes(processes: Sequence[ProcessNode]) -> list[ProcessNode]:
    """Sample-related processes first, then the rest in time order.

    A real VM run records many Windows background processes before the sample
    starts, so a plain time-ordered cut would keep only noise. Related means:
    the started target and its descendants, and any process whose image name
    is a file that this tree wrote (a dropped copy started later). Order inside
    each group stays as recorded.
    """
    related: set[str] = {p.key for p in processes if _TARGET.fullmatch(p.image_name)}
    changed = bool(related)
    while changed:
        changed = False
        written = {
            f.name.lower() for p in processes if p.key in related for f in p.files
        }
        for process in processes:
            if process.key in related:
                continue
            if process.parent_key in related or process.image_name.lower() in written:
                related.add(process.key)
                changed = True
    first = [p for p in processes if p.key in related]
    rest = [p for p in processes if p.key not in related]
    # Workbench's own guest processes go last: they are never sample behavior.
    return (
        first + [p for p in rest if not p.workbench] + [p for p in rest if p.workbench]
    )


_SHA256 = re.compile(r"(?:^|,)SHA256=([0-9A-Fa-f]{64})(?:,|$)", re.ASCII)


def image_sha256(hashes: str | None) -> str | None:
    """The SHA-256 entry of a Sysmon ``Hashes`` value, lowercase."""
    if not hashes:
        return None
    match = _SHA256.search(hashes.strip())
    return None if match is None else match.group(1).lower()


def mark_known_files(
    processes: Sequence[ProcessNode], known: Mapping[str, str]
) -> None:
    """Name the recorded file each process image is identical to.

    ``known`` maps a lowercase SHA-256 to a display ID (a Case Artifact or a
    Project sample). Only the image hash logged by Sysmon is compared, so a
    written file that was never started stays unknown.
    """
    for process in processes:
        if process.sha256 is not None:
            process.same_as = known.get(process.sha256)


# The guest runner (ADR-024) is a PowerShell process running this script.
_GUEST_RUNNER = "invoke-workbenchguestrun.ps1"


def mark_workbench_processes(nodes: Sequence[ProcessNode]) -> None:
    """Mark the runner and what it started, except the sample's own tree.

    The runner starts the target and, after the run window, ``wevtutil`` to
    export events; the target and its descendants stay unmarked.
    """
    marked = {node.key for node in nodes if node.workbench}
    changed = bool(marked)
    while changed:
        changed = False
        for node in nodes:
            if (
                not node.workbench
                and node.parent_key in marked
                and _TARGET.fullmatch(node.image_name) is None
            ):
                node.workbench = True
                marked.add(node.key)
                changed = True


def build_process_relations(
    records: list[SysmonRecord], known_files: Mapping[str, str] | None = None
) -> ProcessRelations:
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
            node.sha256 = image_sha256(record.fields.get("Hashes")) or node.sha256
            command = (record.fields.get("CommandLine") or "").lower()
            if _GUEST_RUNNER in command:
                node.workbench = True
            parent = record.fields.get("ParentProcessGuid")
            if parent and parent != guid:
                parent_node = placeholder(
                    parent,
                    record.fields.get("ParentImage"),
                    record.fields.get("ParentProcessId"),
                )
                # The runner starts before the capture baseline, so it is often
                # known only from its children's ParentCommandLine.
                parent_command = (record.fields.get("ParentCommandLine") or "").lower()
                if _GUEST_RUNNER in parent_command:
                    parent_node.workbench = True
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
    mark_workbench_processes(list(nodes.values()))
    if known_files:
        mark_known_files(list(nodes.values()), known_files)
    # Keep the sample's own tree inside the cap (real runs are mostly noise).
    processes = tuple(prioritized_processes(list(nodes.values())))
    return ProcessRelations(
        processes[:MAX_PROCESSES],
        len(processes),
        len(records),
        sum(1 for process in processes if process.workbench),
    )
