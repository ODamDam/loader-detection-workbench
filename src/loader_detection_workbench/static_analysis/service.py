"""Safe static PE inspection over verified Artifact Store bytes."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.static_analysis.domain import Section, StaticAnalysis

MAX_PE_BYTES = 64 * 1024 * 1024
TOOL_NAME = "workbench-pe-minimal"
TOOL_VERSION = "1"
_MACHINES = {
    0x014C: "x86",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0x8664: "x64",
    0xAA64: "ARM64",
}


def _u16(data: bytes, offset: int) -> int:
    return cast(int, struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return cast(int, struct.unpack_from("<I", data, offset)[0])


def _inspect(data: bytes) -> dict[str, Any]:
    empty: dict[str, Any] = {
        "architecture": None,
        "machine": None,
        "optional_header": None,
        "characteristics": None,
        "sections": [],
        "error": None,
    }
    if len(data) < 2 or data[:2] != b"MZ":
        return {**empty, "status": "not_pe", "is_pe": False}
    try:
        if len(data) < 0x40:
            raise ValueError("DOS header is truncated")
        pe_offset = _u32(data, 0x3C)
        if pe_offset < 0x40 or pe_offset + 24 > len(data):
            raise ValueError("PE header offset is invalid")
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("PE signature is missing")
        coff = pe_offset + 4
        machine = _u16(data, coff)
        section_count = _u16(data, coff + 2)
        optional_size = _u16(data, coff + 16)
        characteristics = _u16(data, coff + 18)
        if section_count > 96:
            raise ValueError("section count exceeds the safe limit")
        optional = coff + 20
        sections_offset = optional + optional_size
        if optional_size < 2 or sections_offset + section_count * 40 > len(data):
            raise ValueError("optional header or section table is truncated")
        magic = _u16(data, optional)
        optional_name = {0x010B: "PE32", 0x020B: "PE32+"}.get(magic)
        if optional_name is None:
            raise ValueError("optional header magic is unsupported")
        sections: list[dict[str, Any]] = []
        for index in range(section_count):
            offset = sections_offset + index * 40
            raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace") or "<unnamed>"
            virtual_size = _u32(data, offset + 8)
            virtual_address = _u32(data, offset + 12)
            raw_size = _u32(data, offset + 16)
            raw_pointer = _u32(data, offset + 20)
            flags = _u32(data, offset + 36)
            if raw_size and (raw_pointer == 0 or raw_pointer + raw_size > len(data)):
                raise ValueError(f"section {index} raw data is out of bounds")
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "characteristics": f"0x{flags:08x}",
                }
            )
        return {
            **empty,
            "status": "ok",
            "is_pe": True,
            "architecture": _MACHINES.get(machine, "unknown"),
            "machine": f"0x{machine:04x}",
            "optional_header": optional_name,
            "characteristics": f"0x{characteristics:04x}",
            "sections": sections,
        }
    except (ValueError, struct.error) as exc:
        return {
            **empty,
            "status": "malformed_pe",
            "is_pe": False,
            "error": str(exc),
        }


def _deserialize(artifact: Artifact, payload: dict[str, Any]) -> StaticAnalysis:
    try:
        analyzer = payload["analyzer"]
        source = payload["source"]
        pe = payload["pe"]
        sections = tuple(Section(**item) for item in pe["sections"])
        return StaticAnalysis(
            artifact=artifact,
            source_artifact_id=source["artifact_id"],
            source_sha256=source["sha256"],
            source_size_bytes=source["size_bytes"],
            analyzed_at=analyzer["analyzed_at"],
            tool_name=analyzer["name"],
            tool_version=analyzer["version"],
            status=payload["status"],
            is_pe=payload["is_pe"],
            architecture=pe["architecture"],
            machine=pe["machine"],
            optional_header=pe["optional_header"],
            characteristics=pe["characteristics"],
            sections=sections,
            error=payload["error"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DomainError(
            DomainErrorCode.INVALID_ARTIFACT_RECORD,
            "static analysis result is invalid",
        ) from exc


class StaticAnalysisService:
    def __init__(self, root: Path) -> None:
        self._root = root

    def analyze(self, case_display_id: str, source_artifact_id: str) -> StaticAnalysis:
        artifacts = ArtifactService(self._root)
        source = artifacts.show(case_display_id, source_artifact_id)
        if source.kind is ArtifactKind.STATIC:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_KIND,
                "a static result cannot be analyzed as source content",
            )
        data = ArtifactStore(self._root).read_verified(
            source.relative_path,
            (source.sha256, source.size_bytes),
            max_bytes=MAX_PE_BYTES,
        )
        inspected = _inspect(data)
        payload = {
            "schema_version": 1,
            "source": {
                "artifact_id": source.artifact_id.display_id,
                "sha256": source.sha256,
                "size_bytes": source.size_bytes,
            },
            "analyzer": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "analyzed_at": format_utc(utc_now()),
            },
            "status": inspected["status"],
            "is_pe": inspected["is_pe"],
            "pe": {
                key: inspected[key]
                for key in (
                    "architecture",
                    "machine",
                    "optional_header",
                    "characteristics",
                    "sections",
                )
            },
            "error": inspected["error"],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        with TemporaryDirectory(prefix="workbench-static-") as directory:
            output = Path(directory) / "result.json"
            output.write_bytes(encoded)
            artifact = artifacts.add(case_display_id, output, ArtifactKind.STATIC.value)
        return _deserialize(artifact, payload)

    def show(self, case_display_id: str, result_artifact_id: str) -> StaticAnalysis:
        artifact = ArtifactService(self._root).show(case_display_id, result_artifact_id)
        if artifact.kind is not ArtifactKind.STATIC:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_KIND,
                "a static analysis result artifact is required",
            )
        data = ArtifactStore(self._root).read_verified(
            artifact.relative_path,
            (artifact.sha256, artifact.size_bytes),
            max_bytes=1024 * 1024,
        )
        try:
            payload = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_RECORD,
                "static analysis result is invalid",
            ) from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_RECORD,
                "static analysis result is invalid",
            )
        return _deserialize(artifact, payload)
