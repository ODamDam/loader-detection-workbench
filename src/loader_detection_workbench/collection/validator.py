"""Strict validation of the existing Host demo Collection contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from loader_detection_workbench.collection.domain import (
    CollectionArtifactRole,
    ValidatedCollectionFile,
    ValidatedSysmonCollection,
)
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import FileCreateEvent, ProcessCreateEvent
from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.sysmon.normalizer import (
    MAX_XML_BYTES,
    normalize_sysmon_event,
)

COLLECTION_MAX_BYTES = 4 * 1024 * 1024
_FILES = frozenset(
    {"collection-metadata.json", "file-create.xml", "process-create.xml"}
)
_TOP_KEYS = frozenset(
    {
        "collector",
        "version",
        "run_id",
        "collection_started_at",
        "collection_completed_at",
        "events",
    }
)
_EVENT_KEYS = frozenset({"event_id", "record_id", "file", "sha256"})
_DUMMY_ARTIFACT = ArtifactId("00000000000000000000000000", "ART-000001")


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    device: int
    inode: int
    size: int
    modified_ns: int


def _error(code: DomainErrorCode, message: str) -> DomainError:
    return DomainError(code, message)


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _snapshot(info: os.stat_result) -> _FileSnapshot:
    return _FileSnapshot(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _reject_link_components(path: Path) -> None:
    current = path.absolute()
    for candidate in (current, *current.parents):
        try:
            info = candidate.lstat()
        except (OSError, ValueError) as exc:
            raise _error(
                DomainErrorCode.INVALID_SYSMON_COLLECTION_FILE,
                "Collection path cannot be inspected",
            ) from exc
        if _is_link(info):
            raise _error(
                DomainErrorCode.INVALID_SYSMON_COLLECTION_FILE,
                "Collection paths must not traverse filesystem links",
            )


def _read_stable_file(path: Path) -> tuple[bytes, _FileSnapshot]:
    try:
        before_info = path.lstat()
        if _is_link(before_info) or not stat.S_ISREG(before_info.st_mode):
            raise OSError("not regular content")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened_info = os.fstat(descriptor)
            if not stat.S_ISREG(opened_info.st_mode):
                raise OSError("not regular content")
            if _snapshot(before_info) != _snapshot(opened_info):
                raise _error(
                    DomainErrorCode.SYSMON_COLLECTION_INPUT_CHANGED,
                    "Collection input changed while it was opened",
                )
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                data = stream.read(COLLECTION_MAX_BYTES + 1)
                after_open_info = os.fstat(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        after_path_info = path.lstat()
    except DomainError:
        raise
    except (OSError, ValueError) as exc:
        raise _error(
            DomainErrorCode.INVALID_SYSMON_COLLECTION_FILE,
            "Collection entries must be readable regular files",
        ) from exc
    before = _snapshot(before_info)
    if before != _snapshot(after_open_info) or before != _snapshot(after_path_info):
        raise _error(
            DomainErrorCode.SYSMON_COLLECTION_INPUT_CHANGED,
            "Collection input changed while it was read",
        )
    if not data or len(data) > COLLECTION_MAX_BYTES:
        raise _error(
            DomainErrorCode.INVALID_SYSMON_COLLECTION_FILE,
            "Collection files must contain 1 byte through 4 MiB",
        )
    return data, before


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not text")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


class CollectionValidator:
    """Validate all three files and return the exact bytes that passed."""

    def validate(self, directory: Path) -> ValidatedSysmonCollection:
        _reject_link_components(directory)
        try:
            directory_info = directory.lstat()
            if not stat.S_ISDIR(directory_info.st_mode):
                raise OSError("not a directory")
            entries = {entry.name: entry for entry in directory.iterdir()}
        except (OSError, ValueError) as exc:
            raise _error(
                DomainErrorCode.INVALID_SYSMON_COLLECTION_LAYOUT,
                "Collection directory cannot be read",
            ) from exc
        if frozenset(entries) != _FILES or len(entries) != 3:
            raise _error(
                DomainErrorCode.INVALID_SYSMON_COLLECTION_LAYOUT,
                "Collection must contain exactly the three contract files",
            )

        contents: dict[str, bytes] = {}
        snapshots: dict[str, _FileSnapshot] = {}
        for name in sorted(_FILES):
            contents[name], snapshots[name] = _read_stable_file(entries[name])

        self._verify_unchanged(directory, directory_info, snapshots)
        metadata = self._parse_metadata(contents["collection-metadata.json"])
        events = metadata["events"]
        assert isinstance(events, list)

        process = self._validate_xml(
            contents["process-create.xml"],
            expected_event_id=1,
            metadata=events[0],
        )
        file_create = self._validate_xml(
            contents["file-create.xml"],
            expected_event_id=11,
            metadata=events[1],
        )
        assert isinstance(process, ProcessCreateEvent)
        assert isinstance(file_create, FileCreateEvent)
        if (
            UUID(process.process_guid) != UUID(file_create.process_guid)
            or process.process_id != file_create.process_id
            or int(process.source_record_id) >= int(file_create.source_record_id)
        ):
            raise _error(
                DomainErrorCode.SYSMON_COLLECTION_CORRELATION_INVALID,
                "Collection events do not form the required process/file pair",
            )

        process_file = self._validated_file(
            CollectionArtifactRole.PROCESS_CREATE,
            "process-create.xml",
            ArtifactKind.SYSMON,
            contents["process-create.xml"],
        )
        file_file = self._validated_file(
            CollectionArtifactRole.FILE_CREATE,
            "file-create.xml",
            ArtifactKind.SYSMON,
            contents["file-create.xml"],
        )
        metadata_file = self._validated_file(
            CollectionArtifactRole.METADATA,
            "collection-metadata.json",
            ArtifactKind.OTHER,
            contents["collection-metadata.json"],
        )
        return ValidatedSysmonCollection(process_file, file_file, metadata_file)

    @staticmethod
    def _verify_unchanged(
        directory: Path,
        directory_info: os.stat_result,
        snapshots: dict[str, _FileSnapshot],
    ) -> None:
        try:
            current_directory = directory.lstat()
            entries = {entry.name: entry for entry in directory.iterdir()}
            if (
                _snapshot(current_directory) != _snapshot(directory_info)
                or frozenset(entries) != _FILES
                or any(
                    _snapshot(entries[name].lstat()) != snapshots[name]
                    for name in _FILES
                )
            ):
                raise _error(
                    DomainErrorCode.SYSMON_COLLECTION_INPUT_CHANGED,
                    "Collection input changed during validation",
                )
        except DomainError:
            raise
        except (OSError, ValueError) as exc:
            raise _error(
                DomainErrorCode.SYSMON_COLLECTION_INPUT_CHANGED,
                "Collection input changed during validation",
            ) from exc

    @staticmethod
    def _parse_metadata(data: bytes) -> dict[str, Any]:
        try:
            decoded = data.decode("utf-8-sig")
            value = json.loads(decoded, object_pairs_hook=_unique_object)
            if not isinstance(value, dict) or frozenset(value) != _TOP_KEYS:
                raise ValueError("metadata object shape")
            if (
                value["collector"] != "sysmon-demo"
                or type(value["version"]) is not int
                or value["version"] != 1
                or not isinstance(value["run_id"], str)
                or re.fullmatch(r"[0-9a-f]{32}", value["run_id"], re.ASCII) is None
                or not isinstance(value["events"], list)
                or len(value["events"]) != 2
            ):
                raise ValueError("metadata values")
            started = _parse_utc(value["collection_started_at"])
            completed = _parse_utc(value["collection_completed_at"])
            if completed < started:
                raise ValueError("metadata time order")
            expected = ((1, "process-create.xml"), (11, "file-create.xml"))
            for entry, (event_id, filename) in zip(
                value["events"], expected, strict=True
            ):
                if (
                    not isinstance(entry, dict)
                    or frozenset(entry) != _EVENT_KEYS
                    or type(entry["event_id"]) is not int
                    or entry["event_id"] != event_id
                    or type(entry["record_id"]) is not int
                    or not 0 < entry["record_id"] <= 2**63 - 1
                    or entry["file"] != filename
                    or not isinstance(entry["sha256"], str)
                    or re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"], re.ASCII)
                    is None
                ):
                    raise ValueError("metadata event shape")
            return value
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise _error(
                DomainErrorCode.INVALID_SYSMON_COLLECTION_METADATA,
                "Collection metadata is invalid",
            ) from exc

    @staticmethod
    def _validate_xml(
        data: bytes, *, expected_event_id: int, metadata: object
    ) -> ProcessCreateEvent | FileCreateEvent:
        if len(data) > MAX_XML_BYTES:
            raise _error(
                DomainErrorCode.SYSMON_COLLECTION_XML_SIZE_EXCEEDED,
                "Sysmon Collection XML exceeds the 1 MiB parser limit",
            )
        assert isinstance(metadata, dict)
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != str(metadata["sha256"]).lower():
            raise _error(
                DomainErrorCode.SYSMON_COLLECTION_HASH_MISMATCH,
                "Collection XML hash does not match metadata",
            )
        event = normalize_sysmon_event(data, _DUMMY_ARTIFACT)[0]
        if (
            event.event_id != expected_event_id
            or event.source_record_id != str(metadata["record_id"])
            or event.process_id <= 0
            or not 0 < int(event.source_record_id) <= 2**63 - 1
            or UUID(event.process_guid).int == 0
        ):
            raise _error(
                DomainErrorCode.SYSMON_COLLECTION_EVENT_MISMATCH,
                "Sysmon event identity does not match its Collection role",
            )
        return event

    @staticmethod
    def _validated_file(
        role: CollectionArtifactRole,
        filename: str,
        kind: ArtifactKind,
        data: bytes,
    ) -> ValidatedCollectionFile:
        return ValidatedCollectionFile(
            role,
            filename,
            kind,
            hashlib.sha256(data).hexdigest(),
            len(data),
            data,
        )
