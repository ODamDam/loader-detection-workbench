"""Which files a sample run wrote, for collection from the guest (ADR-032).

Selection runs on the host over the already verified run events: File Create
(Event ID 11) records of sample-related processes (the started target, its
descendants and its dropped copies; never Workbench guest processes). Only
paths under fixed guest locations pass, and the guest script checks the same
rule again before it seals anything (``Test-WorkbenchCollectPath``).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from loader_detection_workbench.sysmon.records import SysmonRecord
from loader_detection_workbench.sysmon.relations import (
    build_process_relations,
    leaf_name,
    sample_related_keys,
)

# Keep identical to the guest script's limits and Test-WorkbenchCollectPath.
MAX_DROPPED_FILES = 32
MAX_DROPPED_FILE_BYTES = 32 * 1024 * 1024
MAX_DROPPED_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATH_LENGTH = 260
_ALLOWED = re.compile(
    r"C:\\(?:Users\\[^\\]+\\AppData\\(?:Local|Roaming)\\|Users\\Public\\|ProgramData\\)"
    r"[^\x00-\x1f:*?\"<>|]+",
    re.IGNORECASE | re.ASCII,
)
COLLECT_STATUSES = frozenset(
    {"collected", "missing", "not_file", "too_large", "unreadable", "rejected"}
)


def collectable_path(path: str) -> bool:
    """Whether a guest path may be collected (same rule as the guest script)."""
    if not path or len(path) > MAX_PATH_LENGTH or not path.isascii():
        return False
    if _ALLOWED.fullmatch(path) is None or path.endswith("\\"):
        return False
    segments = path.split("\\")
    if any(segment in ("", ".", "..") for segment in segments[1:]):
        return False
    return not path.lower().endswith(".pf")


@dataclass(frozen=True, slots=True)
class DroppedCandidate:
    """One guest path to collect, with the event that recorded it."""

    path: str
    name: str
    record_id: str


@dataclass(frozen=True, slots=True)
class DroppedSelection:
    candidates: tuple[DroppedCandidate, ...]
    written_total: int  # distinct paths the sample tree wrote
    outside_allowed: int  # of those, not in an allowed location
    over_limit: int  # allowed but beyond MAX_DROPPED_FILES


def select_dropped(records: Sequence[SysmonRecord]) -> DroppedSelection:
    """Distinct allowed paths written by the sample tree, first write first."""
    relations = build_process_relations(list(records))
    related = sample_related_keys(relations.processes)
    ordered = sorted(
        (r for r in records if r.event_id == 11),
        key=lambda r: int(r.record_id or "0") if (r.record_id or "").isdigit() else 0,
    )
    seen: set[str] = set()
    allowed: list[DroppedCandidate] = []
    outside = 0
    for record in ordered:
        if record.fields.get("ProcessGuid") not in related:
            continue
        path = (record.fields.get("TargetFilename") or "").strip()
        key = path.lower()
        if not path or key in seen:
            continue
        seen.add(key)
        if not collectable_path(path):
            outside += 1
            continue
        allowed.append(DroppedCandidate(path, leaf_name(path), record.record_id or ""))
    return DroppedSelection(
        tuple(allowed[:MAX_DROPPED_FILES]),
        len(seen),
        outside,
        max(0, len(allowed) - MAX_DROPPED_FILES),
    )
