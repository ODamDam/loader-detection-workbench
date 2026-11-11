"""Generic field-level Sysmon records for detection logic evaluation.

The typed Event ID 1/11 normalizer remains the Timeline contract. This module
keeps every EventData field of every Sysmon Event ID so Sigma-style logic can
be evaluated offline without losing source references.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId

MAX_RECORD_XML_BYTES = 32 * 1024 * 1024
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_TIME_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z?"
)


@dataclass(frozen=True, slots=True)
class SysmonRecord:
    """One Sysmon event with all EventData fields preserved as strings."""

    event_id: int
    record_id: str | None
    timestamp: datetime | None
    fields: Mapping[str, str]
    source_artifact_id: ArtifactId | None = None
    computer: str | None = field(default=None)

    def value(self, name: str) -> str | None:
        """Return a field value; ``EventID`` is exposed like an EventData field."""
        if name == "EventID":
            return str(self.event_id)
        return self.fields.get(name)

    def all_fields(self) -> dict[str, str]:
        result = dict(self.fields)
        result["EventID"] = str(self.event_id)
        return result


class _NoDTDBuilder(ET.TreeBuilder):
    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "DTD is not supported")


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _child(parent: ET.Element, name: str) -> ET.Element | None:
    matches = [child for child in parent if _local(child.tag) == name]
    if len(matches) > 1:
        raise DomainError(
            DomainErrorCode.INVALID_SYSMON_XML, f"duplicate {name} element"
        )
    return matches[0] if matches else None


def parse_sysmon_time(value: str | None) -> datetime | None:
    if value is None or _TIME_PATTERN.fullmatch(value.strip()) is None:
        return None
    text = value.strip().rstrip("Z").replace("T", " ")
    whole, _, fraction = text.partition(".")
    if fraction:
        text = f"{whole}.{fraction[:6]}"
    try:
        return datetime.fromisoformat(text).replace(tzinfo=UTC)
    except ValueError:
        return None


def _record(event: ET.Element, source: ArtifactId | None) -> SysmonRecord:
    system = _child(event, "System")
    if system is None:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "System is missing")
    provider = _child(system, "Provider")
    if provider is None or provider.get("Name") != _SYSMON_PROVIDER:
        raise DomainError(
            DomainErrorCode.INVALID_SYSMON_XML, "event provider is not Sysmon"
        )
    event_id_element = _child(system, "EventID")
    # ElementTree elements without children are falsy; compare with None.
    event_id_text = (
        (event_id_element.text or "").strip() if event_id_element is not None else ""
    )
    if re.fullmatch(r"[0-9]{1,5}", event_id_text) is None:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "EventID is invalid")
    record_element = _child(system, "EventRecordID")
    record_id = None
    if record_element is not None and record_element.text:
        record_id = record_element.text.strip()
        if re.fullmatch(r"[0-9]+", record_id) is None:
            raise DomainError(
                DomainErrorCode.INVALID_SYSMON_XML, "EventRecordID is invalid"
            )
    computer_element = _child(system, "Computer")
    computer = (
        computer_element.text.strip()
        if computer_element is not None and computer_element.text
        else None
    )
    fields: dict[str, str] = {}
    event_data = _child(event, "EventData")
    if event_data is not None:
        for data in event_data:
            if _local(data.tag) != "Data":
                continue
            name = data.get("Name")
            if name is None or not name or name in fields:
                raise DomainError(
                    DomainErrorCode.INVALID_SYSMON_XML,
                    "EventData field names must be present and unique",
                )
            fields[name] = data.text or ""
    timestamp = parse_sysmon_time(fields.get("UtcTime"))
    if timestamp is None:
        created = _child(system, "TimeCreated")
        timestamp = parse_sysmon_time(
            created.get("SystemTime") if created is not None else None
        )
    return SysmonRecord(
        event_id=int(event_id_text),
        record_id=record_id,
        timestamp=timestamp,
        fields=MappingProxyType(fields),
        source_artifact_id=source,
        computer=computer,
    )


def parse_sysmon_records(
    xml: bytes, source_artifact_id: ArtifactId | None = None
) -> list[SysmonRecord]:
    """Parse one ``<Event>`` or a container of ``<Event>`` elements.

    Any malformed Sysmon event rejects the whole document so detection results
    never silently depend on a partial parse.
    """
    if len(xml) > MAX_RECORD_XML_BYTES:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "XML exceeds size limit")
    try:
        root = ET.fromstring(xml, parser=ET.XMLParser(target=_NoDTDBuilder()))
    except (ET.ParseError, LookupError, ValueError) as exc:
        raise DomainError(
            DomainErrorCode.INVALID_SYSMON_XML, "Sysmon XML is malformed"
        ) from exc
    events = (
        [root]
        if _local(root.tag) == "Event"
        else [child for child in root if _local(child.tag) == "Event"]
    )
    if not events:
        raise DomainError(
            DomainErrorCode.INVALID_SYSMON_XML, "no Sysmon Event element was found"
        )
    return [_record(event, source_artifact_id) for event in events]


_SUMMARY_FIELDS: dict[int, tuple[str, ...]] = {
    2: ("Image", "TargetFilename"),
    3: ("Image", "Protocol", "DestinationIp", "DestinationPort", "DestinationHostname"),
    5: ("Image",),
    6: ("ImageLoaded", "Signed"),
    7: ("Image", "ImageLoaded", "Signed"),
    8: ("SourceImage", "TargetImage"),
    10: ("SourceImage", "TargetImage", "GrantedAccess"),
    12: ("EventType", "Image", "TargetObject"),
    13: ("EventType", "Image", "TargetObject", "Details"),
    14: ("EventType", "Image", "TargetObject", "NewName"),
    15: ("Image", "TargetFilename"),
    17: ("Image", "PipeName"),
    18: ("Image", "PipeName"),
    22: ("Image", "QueryName", "QueryStatus"),
    23: ("Image", "TargetFilename"),
    25: ("Image", "Type"),
    26: ("Image", "TargetFilename"),
}


def record_summary(record: SysmonRecord, *, include_paths: bool = True) -> str:
    """One-line ``Field=value`` summary of the most useful fields per Event ID."""
    names = _SUMMARY_FIELDS.get(record.event_id, ("Image",))
    parts: list[str] = []
    for name in names:
        if not include_paths and name in {
            "Image",
            "ImageLoaded",
            "SourceImage",
            "TargetImage",
            "TargetFilename",
        }:
            continue
        value = record.fields.get(name)
        if value:
            parts.append(f"{name}={' '.join(value.split())[:160]}")
    return " ".join(parts) if parts else "(no summary fields)"
