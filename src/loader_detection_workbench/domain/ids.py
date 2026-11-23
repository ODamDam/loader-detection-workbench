"""Project, case, and artifact identity value objects."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import ClassVar, Self

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

_ULID_PATTERN = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}", re.ASCII)
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_ulid() -> str:
    """Generate a canonical ULID using epoch milliseconds and secure randomness."""
    timestamp = time.time_ns() // 1_000_000
    value = (timestamp << 80) | int.from_bytes(secrets.token_bytes(10), "big")
    encoded = ["0"] * 26
    for index in range(25, -1, -1):
        encoded[index] = _CROCKFORD_ALPHABET[value & 0x1F]
        value >>= 5
    return "".join(encoded)


@dataclass(frozen=True, slots=True)
class _EntityId:
    """An immutable canonical ULID paired with its immutable display ID."""

    ulid: str
    display_id: str

    _display_pattern: ClassVar[re.Pattern[str]]
    _display_description: ClassVar[str]

    def __post_init__(self) -> None:
        if self.ulid != self.ulid.strip():
            raise DomainError(
                DomainErrorCode.INVALID_ULID,
                "ULID must not have leading or trailing whitespace",
            )
        canonical = self.ulid.upper()
        if _ULID_PATTERN.fullmatch(canonical) is None or canonical[0] > "7":
            raise DomainError(
                DomainErrorCode.INVALID_ULID,
                "ULID must be 26 Crockford Base32 characters",
            )
        if self._display_pattern.fullmatch(self.display_id) is None:
            raise DomainError(
                DomainErrorCode.INVALID_DISPLAY_ID,
                f"display ID must use {self._display_description} format",
            )
        if int(self.display_id.rpartition("-")[2]) < 1:
            raise DomainError(
                DomainErrorCode.INVALID_DISPLAY_ID,
                "display ID sequence must be positive",
            )
        object.__setattr__(self, "ulid", canonical)

    @classmethod
    def parse(cls, ulid: str, display_id: str) -> Self:
        return cls(ulid=ulid, display_id=display_id)


@dataclass(frozen=True, slots=True)
class ProjectId(_EntityId):
    _display_pattern: ClassVar[re.Pattern[str]] = re.compile(r"PRJ-[0-9]{4,}", re.ASCII)
    _display_description: ClassVar[str] = "PRJ-0001"


@dataclass(frozen=True, slots=True)
class CaseId(_EntityId):
    _display_pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"CASE-[0-9]{4,}", re.ASCII
    )
    _display_description: ClassVar[str] = "CASE-0001"


@dataclass(frozen=True, slots=True)
class ArtifactId(_EntityId):
    _display_pattern: ClassVar[re.Pattern[str]] = re.compile(r"ART-[0-9]{6,}", re.ASCII)
    _display_description: ClassVar[str] = "ART-000001"
