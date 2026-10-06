from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.sysmon.normalizer import normalize_process_create

FIXTURE = Path(__file__).parents[1] / "fixtures/public/sysmon/process-create.xml"
SOURCE = ArtifactId("00000000000000000000000001", "ART-000001")


def test_process_create_mapping_and_traceability() -> None:
    events = normalize_process_create(FIXTURE.read_bytes(), SOURCE)
    assert len(events) == 1
    event = events[0]
    assert event.timestamp == datetime(2026, 10, 6, 1, 2, 3, tzinfo=UTC)
    assert event.event_id == 1
    assert event.process_guid == "{11111111-2222-4333-8444-555555555555}"
    assert event.process_id == 1234
    assert event.image == "benign-demo.exe"
    assert event.command_line == 'benign-demo.exe --message "hello"'
    assert event.source_artifact_id == SOURCE
    assert event.source_record_id == "42"
    with pytest.raises(FrozenInstanceError):
        event.process_id = 12  # type: ignore[misc]  # Verify runtime immutability.
    with pytest.raises(DomainError):
        replace(event, process_id=-1)


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        (b'encoding="utf-8"', b'encoding="unknown"', "INVALID_SYSMON_XML"),
        (b"</Event>", b"", "INVALID_SYSMON_XML"),
        (b"<EventID>1</EventID>", b"<EventID>11</EventID>", "UNSUPPORTED_SYSMON_EVENT"),
        (b"<EventID>1</EventID>", b"<EventID>x</EventID>", "INVALID_PROCESS_CREATE"),
        (b"Microsoft-Windows-Sysmon", b"Other-Provider", "INVALID_PROCESS_CREATE"),
        (b"1234", b"-1", "INVALID_PROCESS_CREATE"),
        (b"1234", b"invalid", "INVALID_PROCESS_CREATE"),
        (b"2026-10-06", b"2026-99-99", "INVALID_PROCESS_CREATE"),
        (b"2026-10-06 01:02:03.456", b"unknown", "INVALID_PROCESS_CREATE"),
        (b"11111111-2222-4333-8444-555555555555", b"invalid", "INVALID_PROCESS_CREATE"),
        (b"<EventRecordID>42</EventRecordID>", b"", "INVALID_PROCESS_CREATE"),
        (
            b"<EventRecordID>42</EventRecordID>",
            b"<EventRecordID>x</EventRecordID>",
            "INVALID_PROCESS_CREATE",
        ),
        (b'<Data Name="Image">benign-demo.exe</Data>', b"", "INVALID_PROCESS_CREATE"),
        (
            b'<Data Name="CommandLine">',
            b'<Data Name="Image">',
            "INVALID_PROCESS_CREATE",
        ),
        (
            b'<Data Name="ProcessId">1234</Data>',
            b'<Data Name="ProcessId"> </Data>',
            "INVALID_PROCESS_CREATE",
        ),
    ],
)
def test_invalid_records_fail_closed(old: bytes, new: bytes, code: str) -> None:
    with pytest.raises(DomainError) as caught:
        normalize_process_create(FIXTURE.read_bytes().replace(old, new), SOURCE)
    assert caught.value.code.value == code
    assert "benign-demo" not in str(caught.value)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_dtd_is_rejected(encoding: str) -> None:
    xml = '<!DOCTYPE Event [<!ENTITY x "text">]><Event>&x;</Event>'
    with pytest.raises(DomainError) as caught:
        normalize_process_create(xml.encode(encoding), SOURCE)
    assert caught.value.code is DomainErrorCode.INVALID_SYSMON_XML


def test_multiple_records_are_not_silently_skipped() -> None:
    xml = FIXTURE.read_text(encoding="utf-8").split("?>", 1)[1]
    with pytest.raises(DomainError):
        normalize_process_create(f"<Events>{xml}{xml}</Events>".encode(), SOURCE)


def test_size_limit() -> None:
    with pytest.raises(DomainError) as caught:
        normalize_process_create(b" " * (1024 * 1024 + 1), SOURCE)
    assert caught.value.code is DomainErrorCode.INVALID_SYSMON_XML
