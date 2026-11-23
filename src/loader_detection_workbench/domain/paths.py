"""Lexically contained project-relative path value object."""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode


@dataclass(frozen=True, slots=True)
class ProjectRelativePath:
    _value: str

    @classmethod
    def parse(cls, value: str | Path) -> ProjectRelativePath:
        raw = str(value)
        if not raw or raw == ".":
            raise DomainError(
                DomainErrorCode.INVALID_RELATIVE_PATH,
                "project-relative path must not be empty or '.'",
            )
        normalized_input = raw.replace("\\", "/")
        if (
            PurePosixPath(normalized_input).is_absolute()
            or ntpath.isabs(raw)
            or ntpath.splitdrive(raw)[0]
        ):
            raise DomainError(
                DomainErrorCode.INVALID_RELATIVE_PATH,
                "project-relative path must not be absolute",
            )
        parts = PurePosixPath(normalized_input).parts
        if ".." in parts:
            raise DomainError(
                DomainErrorCode.PATH_ESCAPE,
                "project-relative path must not contain '..'",
            )
        canonical_parts = tuple(part for part in parts if part != ".")
        if not canonical_parts:
            raise DomainError(
                DomainErrorCode.INVALID_RELATIVE_PATH,
                "project-relative path must identify a workspace entry",
            )
        return cls(PurePosixPath(*canonical_parts).as_posix())

    def as_posix(self) -> str:
        return self._value

    def resolve_under(self, root: Path) -> Path:
        """Resolve lexically under root without filesystem or symlink inspection."""
        root_absolute = root.absolute()
        candidate = root_absolute.joinpath(*PurePosixPath(self._value).parts)
        try:
            candidate.relative_to(root_absolute)
        except ValueError as exc:
            raise DomainError(
                DomainErrorCode.PATH_ESCAPE,
                "project-relative path resolves outside the workspace root",
            ) from exc
        return candidate

    def __str__(self) -> str:
        return self._value
