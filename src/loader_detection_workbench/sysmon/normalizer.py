"""One namespaced Event ID 1 XML record; no EVTX or multi-event import."""

import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import ProcessCreateEvent
from loader_detection_workbench.domain.ids import ArtifactId

MAX_XML_BYTES = 1024 * 1024
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _invalid() -> DomainError:
    return DomainError(
        DomainErrorCode.INVALID_PROCESS_CREATE,
        "required process create fields are missing, ambiguous or invalid",
    )


class _NoDTDBuilder(ET.TreeBuilder):
    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise DomainError(DomainErrorCode.INVALID_SYSMON_XML, "DTD is not supported")


def _one(parent: ET.Element, name: str) -> ET.Element:
    matches = parent.findall(_NS + name)
    if len(matches) != 1:
        raise _invalid()
    return matches[0]


def _text(element: ET.Element) -> str:
    if len(element) or element.text is None or not element.text.strip():
        raise _invalid()
    return element.text


def normalize_process_create(
    xml: bytes, source_artifact_id: ArtifactId
) -> list[ProcessCreateEvent]:
    """Return one event, or a stable error; never skip or fabricate a record."""
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
    if event_id != "1":
        raise DomainError(
            DomainErrorCode.UNSUPPORTED_SYSMON_EVENT,
            "only Sysmon Event ID 1 is supported",
        )
    record_id = _text(_one(system, "EventRecordID"))
    values: dict[str, str] = {}
    for data in _one(event, "EventData"):
        name = data.get("Name")
        if data.tag != _NS + "Data" or name is None or name in values:
            raise _invalid()
        values[name] = data.text or ""
        if len(data):
            raise _invalid()
    required = ("UtcTime", "ProcessGuid", "ProcessId", "Image", "CommandLine")
    if any(not values.get(name, "").strip() for name in required):
        raise _invalid()
    if re.fullmatch(r"[0-9]{1,10}", values["ProcessId"]) is None:
        raise _invalid()
    if (
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?",
            values["UtcTime"],
        )
        is None
    ):
        raise _invalid()
    try:
        timestamp = datetime.fromisoformat(values["UtcTime"]).replace(tzinfo=UTC)
    except ValueError as exc:
        raise _invalid() from exc
    return [
        ProcessCreateEvent(
            timestamp=timestamp,
            event_id=1,
            process_guid=values["ProcessGuid"],
            process_id=int(values["ProcessId"]),
            image=values["Image"],
            command_line=values["CommandLine"],
            source_artifact_id=source_artifact_id,
            source_record_id=record_id,
        )
    ]
