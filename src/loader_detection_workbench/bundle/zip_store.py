"""Safe ZIP member handling for Case Bundles."""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path, PurePosixPath

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode


def check_members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = zf.infolist()
    seen: set[str] = set()
    for info in infos:
        name = info.filename
        if name in seen:
            raise DomainError(
                DomainErrorCode.DUPLICATE_BUNDLE_ENTRY,
                "Bundle contains a duplicate entry",
            )
        seen.add(name)
        if "\\" in name or name.startswith("/") or name.startswith("\\"):
            raise DomainError(
                DomainErrorCode.UNSAFE_BUNDLE_ENTRY, "Bundle entry path is unsafe"
            )
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise DomainError(
                DomainErrorCode.UNSAFE_BUNDLE_ENTRY, "Bundle entry path is unsafe"
            )
        if (
            len(path.parts) == 1
            and name == "manifest.json"
            or (
                len(path.parts) == 4
                and path.parts[0:2] == ("artifacts", "sha256")
                and len(path.parts[2]) == 2
            )
        ):
            pass
        else:
            raise DomainError(
                DomainErrorCode.UNSAFE_BUNDLE_ENTRY,
                "Bundle entry is outside the approved layout",
            )
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode) or stat.S_ISDIR(mode):
            raise DomainError(
                DomainErrorCode.UNSAFE_BUNDLE_ENTRY,
                "Bundle entry is not a regular file",
            )
    if "manifest.json" not in seen:
        raise DomainError(
            DomainErrorCode.INVALID_BUNDLE_ARCHIVE, "Bundle manifest is missing"
        )
    return infos


def safe_extract(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], root: Path) -> None:
    root = root.resolve()
    for info in infos:
        target = (root / PurePosixPath(info.filename)).resolve()
        if not target.is_relative_to(root):
            raise DomainError(
                DomainErrorCode.UNSAFE_BUNDLE_ENTRY, "Bundle entry escapes staging"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, "r") as source, target.open("xb") as destination:
            while chunk := source.read(1024 * 1024):
                destination.write(chunk)
