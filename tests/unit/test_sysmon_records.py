from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.sysmon.records import parse_sysmon_records

FIXTURES = Path(__file__).parents[1] / "fixtures" / "public" / "sysmon"
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event(event_id: int, record: int, **fields: str) -> str:
    data = "".join(
        f'<Data Name="{key}">{value}</Data>' for key, value in fields.items()
    )
    return (
        f'<Event xmlns="{_NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>"
        '<TimeCreated SystemTime="2026-11-11T01:02:03.1234567Z"/>'
        f"</System><EventData>{data}</EventData></Event>"
    )


def test_existing_public_fixture_is_parsed_with_all_fields() -> None:
    records = parse_sysmon_records((FIXTURES / "file-create.xml").read_bytes())

    assert len(records) == 1
    assert records[0].event_id == 11
    assert records[0].record_id == "43"
    assert records[0].value("TargetFilename") == "synthetic-demo/output.txt"
    assert records[0].value("EventID") == "11"
    assert records[0].timestamp is not None


def test_container_with_multiple_event_ids() -> None:
    xml = (
        "<Events>"
        + _event(3, 7, DestinationIp="10.0.0.5", DestinationPort="443")
        + _event(22, 8, QueryName="example.invalid")
        + "</Events>"
    ).encode()

    records = parse_sysmon_records(xml)

    assert [record.event_id for record in records] == [3, 22]
    assert records[1].value("QueryName") == "example.invalid"
    assert records[1].timestamp is not None  # TimeCreated fallback


@pytest.mark.parametrize(
    "xml",
    [
        b"<Events></Events>",
        b"<Event><System></System></Event>",
        b"not xml",
        b'<!DOCTYPE x [<!ENTITY a "b">]><Event/>',
        (
            f'<Event xmlns="{_NS}"><System><Provider Name="Other"/>'
            "<EventID>1</EventID></System></Event>"
        ).encode(),
        _event(1, 1, Image="a")
        .replace("</EventData>", '<Data Name="Image">b</Data></EventData>')
        .encode(),
    ],
)
def test_malformed_documents_are_rejected_without_partial_results(
    xml: bytes,
) -> None:
    with pytest.raises(DomainError) as error:
        parse_sysmon_records(xml)
    assert error.value.code is DomainErrorCode.INVALID_SYSMON_XML
