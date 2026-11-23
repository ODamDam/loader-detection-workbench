import hashlib
import json
import shutil
from pathlib import Path
from typing import cast

import pytest

from loader_detection_workbench.collection.domain import CollectionArtifactRole
from loader_detection_workbench.collection.validator import CollectionValidator
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.sysmon.normalizer import MAX_XML_BYTES

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"


@pytest.fixture
def collection(tmp_path: Path) -> Path:
    target = tmp_path / "collection"
    shutil.copytree(FIXTURES, target)
    return target


def _metadata(path: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads((path / "collection-metadata.json").read_text(encoding="utf-8")),
    )


def _write_metadata(path: Path, value: object) -> None:
    (path / "collection-metadata.json").write_text(json.dumps(value), encoding="utf-8")


def test_valid_collection_returns_exact_validated_bytes(collection: Path) -> None:
    result = CollectionValidator().validate(collection)

    assert result.process_create.role is CollectionArtifactRole.PROCESS_CREATE
    assert result.process_create.kind is ArtifactKind.SYSMON
    assert result.file_create.role is CollectionArtifactRole.FILE_CREATE
    assert result.file_create.kind is ArtifactKind.SYSMON
    assert result.metadata.role is CollectionArtifactRole.METADATA
    assert result.metadata.kind is ArtifactKind.OTHER
    for item in result.files_in_registration_order():
        assert item.data == (collection / item.filename).read_bytes()
        assert item.sha256 == hashlib.sha256(item.data).hexdigest()


@pytest.mark.parametrize("change", ["missing", "extra", "directory"])
def test_exact_layout_is_required(collection: Path, change: str) -> None:
    if change == "missing":
        (collection / "file-create.xml").unlink()
    elif change == "extra":
        (collection / "unexpected.txt").write_text("benign", encoding="utf-8")
    else:
        (collection / "file-create.xml").unlink()
        (collection / "file-create.xml").mkdir()

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code in {
        DomainErrorCode.INVALID_SYSMON_COLLECTION_LAYOUT,
        DomainErrorCode.INVALID_SYSMON_COLLECTION_FILE,
    }


def test_duplicate_metadata_property_is_rejected(collection: Path) -> None:
    path = collection / "collection-metadata.json"
    raw = path.read_text(encoding="utf-8")
    path.write_text(
        raw.replace('"version":', '"version": 1, "version":'), encoding="utf-8"
    )

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.INVALID_SYSMON_COLLECTION_METADATA


def test_hash_mismatch_is_distinct(collection: Path) -> None:
    metadata = _metadata(collection)
    events = metadata["events"]
    assert isinstance(events, list) and isinstance(events[0], dict)
    events[0]["sha256"] = "0" * 64
    _write_metadata(collection, metadata)

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.SYSMON_COLLECTION_HASH_MISMATCH


def test_metadata_and_xml_identity_mismatch_is_rejected(collection: Path) -> None:
    metadata = _metadata(collection)
    events = metadata["events"]
    assert isinstance(events, list) and isinstance(events[0], dict)
    events[0]["record_id"] = 99
    _write_metadata(collection, metadata)

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.SYSMON_COLLECTION_EVENT_MISMATCH


def test_malformed_xml_uses_existing_normalizer_error(collection: Path) -> None:
    xml = collection / "process-create.xml"
    data = b"<Event>"
    xml.write_bytes(data)
    metadata = _metadata(collection)
    events = metadata["events"]
    assert isinstance(events, list) and isinstance(events[0], dict)
    events[0]["sha256"] = hashlib.sha256(data).hexdigest()
    _write_metadata(collection, metadata)

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.INVALID_SYSMON_XML


def test_event_correlation_is_required(collection: Path) -> None:
    xml = collection / "file-create.xml"
    data = xml.read_bytes().replace(b">1234</Data>", b">5678</Data>")
    xml.write_bytes(data)
    metadata = _metadata(collection)
    events = metadata["events"]
    assert isinstance(events, list) and isinstance(events[1], dict)
    events[1]["sha256"] = hashlib.sha256(data).hexdigest()
    _write_metadata(collection, metadata)

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.SYSMON_COLLECTION_CORRELATION_INVALID


def test_xml_parser_limit_has_distinct_error(collection: Path) -> None:
    xml = collection / "process-create.xml"
    data = xml.read_bytes() + b" " * (MAX_XML_BYTES + 1 - xml.stat().st_size)
    xml.write_bytes(data)
    metadata = _metadata(collection)
    events = metadata["events"]
    assert isinstance(events, list) and isinstance(events[0], dict)
    events[0]["sha256"] = hashlib.sha256(data).hexdigest()
    _write_metadata(collection, metadata)

    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.SYSMON_COLLECTION_XML_SIZE_EXCEEDED


def test_file_change_during_validation_is_rejected(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from loader_detection_workbench.collection import validator as module

    original = module._read_stable_file

    def mutate(path: Path) -> tuple[bytes, module._FileSnapshot]:
        result = original(path)
        if path.name == "process-create.xml":
            target = path.with_name("file-create.xml")
            target.write_bytes(target.read_bytes() + b" ")
        return result

    monkeypatch.setattr(module, "_read_stable_file", mutate)
    with pytest.raises(DomainError) as caught:
        CollectionValidator().validate(collection)
    assert caught.value.code is DomainErrorCode.SYSMON_COLLECTION_INPUT_CHANGED
