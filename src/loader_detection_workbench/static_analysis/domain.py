"""Static PE analysis result contract (result schema v1 and v2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loader_detection_workbench.domain.artifact import Artifact


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    characteristics: str
    # v2 fields; absent in v1 results.
    raw_pointer: int = 0
    entropy: float | None = None
    executable: bool | None = None
    writable: bool | None = None


@dataclass(frozen=True, slots=True)
class ImportEntry:
    dll: str
    functions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExtractedString:
    encoding: str
    value: str


@dataclass(frozen=True, slots=True)
class StaticAnalysis:
    artifact: Artifact
    source_artifact_id: str
    source_sha256: str
    source_size_bytes: int
    analyzed_at: str
    tool_name: str
    tool_version: str
    status: str
    is_pe: bool
    architecture: str | None
    machine: str | None
    optional_header: str | None
    characteristics: str | None
    sections: tuple[Section, ...]
    error: str | None
    # v2 fields; v1 results keep the defaults.
    schema_version: int = 1
    file_entropy: float | None = None
    imports: tuple[ImportEntry, ...] = ()
    import_function_count: int = 0
    imports_truncated: bool = False
    imphash: str | None = None
    exports: tuple[str, ...] = ()
    export_count: int = 0
    compile_timestamp: str | None = None
    entry_point: str | None = None
    image_base: str | None = None
    subsystem: str | None = None
    is_dll: bool | None = None
    signature: str | None = None
    overlay_size: int = 0
    parser_warning: str | None = None
    flags: tuple[str, ...] = ()
    strings_total: int = 0
    strings_truncated: bool = False
    strings: tuple[ExtractedString, ...] = ()
    indicators: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def notable(self) -> dict[str, Any]:
        """Compact summary used by reports and the UI."""
        return {
            "imphash": self.imphash,
            "flags": list(self.flags),
            "indicators": {key: list(value) for key, value in self.indicators.items()},
        }
