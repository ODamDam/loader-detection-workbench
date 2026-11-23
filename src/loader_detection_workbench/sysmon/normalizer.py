"""One namespaced Event ID 1 or 11 XML record; no EVTX or multi-event import."""

import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import (
    FileCreateEvent,
    NormalizedSysmonEvent,
    ProcessCreateEvent,
)
from loader_detection_workbench.domain.ids import ArtifactId

MAX_XML_BYTES = 1024 * 1024
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _invalid(
    code: DomainErrorCode = DomainErrorCode.INVALID_PROCESS_CREATE,
) -> DomainError:
    return DomainError(
        code,
        "required Sysmon fields are missing, ambiguous or invalid",
    )


class _NoDTDBuilder(ET.TreeBuilder):
    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "DTD is not supported")


def _one(
    parent: ET.Element,
    name: str,
    code: DomainErrorCode = DomainErrorCode.INVALID_PROCESS_CREATE,
) -> ET.Element:
    matches = parent.findall(_NS + name)
    if len(matches) != 1:
        raise _invalid(code)
    return matches[0]


def _text(
    element: ET.Element, code: DomainErrorCode = DomainErrorCode.INVALID_PROCESS_CREATE
) -> str:
    if len(element) or element.text is None or not element.text.strip():
        raise _invalid(code)
    return element.text


def normalize_process_create(
    xml: bytes, source_artifact_id: ArtifactId
) -> list[ProcessCreateEvent]:
    """Compatibility entry point: continue to accept Event ID 1 only."""
    event = _normalize(xml, source_artifact_id, supported=("1",))
    assert isinstance(event, ProcessCreateEvent)
    return [event]


def normalize_sysmon_event(
    xml: bytes, source_artifact_id: ArtifactId
) -> list[NormalizedSysmonEvent]:
    """Return one Process/File Create event, or a stable error, never partial data."""
    return [_normalize(xml, source_artifact_id, supported=("1", "11"))]


def _timestamp(value: str, code: DomainErrorCode) -> datetime:
    if (
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?",
            value,
        )
        is None
    ):
        raise _invalid(code)
    try:
        return datetime.fromisoformat(value).replace(tzinfo=UTC)
    except ValueError as exc:
        raise _invalid(code) from exc


def _normalize(
    xml: bytes, source_artifact_id: ArtifactId, *, supported: tuple[str, ...]
) -> NormalizedSysmonEvent:
    if len(xml) > MAX_XML_BYTES:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "XML exceeds size limit")
    try:
        event = ET.fromstring(xml, parser=ET.XMLParser(target=_NoDTDBuilder()))
    except (ET.ParseError, LookupError, ValueError) as exc:
        raise DomainError(
            DomainErrorCode.INVALID_SYSMON_XML, "Sysmon XML is malformed"
        ) from exc
    if event.tag != _NS + "Event":
        raise _invalid()
    system = _one(event, "System")
    if _one(system, "Provider").get("Name") != "Microsoft-Windows-Sysmon":
        raise _invalid()
    event_id = _text(_one(system, "EventID"))
    if re.fullmatch(r"[0-9]+", event_id) is None:
        raise _invalid()
    if event_id not in supported:
        raise DomainError(
            DomainErrorCode.UNSUPPORTED_SYSMON_EVENT,
            "Sysmon Event ID is not supported by this entry point",
        )
    code = (
        DomainErrorCode.INVALID_PROCESS_CREATE
        if event_id == "1"
        else DomainErrorCode.INVALID_FILE_CREATE
    )
    record_id = _text(_one(system, "EventRecordID", code), code)
    values: dict[str, str] = {}
    for data in _one(event, "EventData", code):
        name = data.get("Name")
        if data.tag != _NS + "Data" or name is None or name in values:
            raise _invalid(code)
        values[name] = data.text or ""
        if len(data):
            raise _invalid(code)
    required = ("UtcTime", "ProcessGuid", "ProcessId", "Image") + (
        ("CommandLine",) if event_id == "1" else ("TargetFilename", "CreationUtcTime")
    )
    if any(not values.get(name, "").strip() for name in required):
        raise _invalid(code)
    if re.fullmatch(r"[0-9]{1,10}", values["ProcessId"]) is None:
        raise _invalid(code)
    timestamp = _timestamp(values["UtcTime"], code)
    if event_id == "1":
        return ProcessCreateEvent(
            timestamp=timestamp,
            event_id=1,
            process_guid=values["ProcessGuid"],
            process_id=int(values["ProcessId"]),
            image=values["Image"],
            command_line=values["CommandLine"],
            source_artifact_id=source_artifact_id,
            source_record_id=record_id,
        )
    return FileCreateEvent(
        timestamp=timestamp,
        event_id=11,
        process_guid=values["ProcessGuid"],
        process_id=int(values["ProcessId"]),
        image=values["Image"],
        target_filename=values["TargetFilename"],
        creation_utc_time=_timestamp(values["CreationUtcTime"], code),
        source_artifact_id=source_artifact_id,
        source_record_id=record_id,
    )
