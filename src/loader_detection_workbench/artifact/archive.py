"""Read one file of a password-protected sample archive in memory (ADR-030).

Sample feeds such as MalwareBazaar deliver each sample as a ZIP archive
protected with the password ``infected`` (AES or ZipCrypto). The member is
read into memory only; it is never extracted to disk. Member names are
untrusted and are not used as paths.
"""

from __future__ import annotations

import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

import pyzipper

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

DEFAULT_PASSWORD = "infected"
MAX_MEMBER_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    name: str
    data: bytes


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.ARCHIVE_INVALID, message)


def read_member(
    archive: Path,
    *,
    password: str = DEFAULT_PASSWORD,
    member: str | None = None,
    max_bytes: int = MAX_MEMBER_BYTES,
) -> ArchiveMember:
    """Return one regular file of ``archive``; exactly one unless ``member``."""
    if not archive.is_file():
        raise _invalid("archive must be an existing regular file")
    try:
        with pyzipper.AESZipFile(archive, "r") as zf:
            files = [info for info in zf.infolist() if not info.is_dir()]
            if member is None:
                if len(files) != 1:
                    raise _invalid(
                        f"archive contains {len(files)} files; choose one with --member"
                    )
                info = files[0]
            else:
                found = [info for info in files if info.filename == member]
                if not found:
                    raise _invalid("archive has no file with that name")
                info = found[0]
            if info.file_size > max_bytes:
                raise DomainError(
                    DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED,
                    "archive member exceeds the size limit",
                )
            zf.setpassword(password.encode("utf-8"))
            with zf.open(info, "r") as stream:
                data = stream.read(max_bytes + 1)
    except DomainError:
        raise
    except RuntimeError as exc:
        # pyzipper reports a wrong or missing password as RuntimeError.
        raise DomainError(
            DomainErrorCode.ARCHIVE_PASSWORD_REJECTED,
            "archive password was rejected",
        ) from exc
    except (
        OSError,
        EOFError,
        ValueError,
        NotImplementedError,
        zipfile.BadZipFile,
        pyzipper.BadZipFile,
        zlib.error,
    ) as exc:
        raise _invalid(
            "archive could not be read or failed its integrity check"
        ) from exc
    if len(data) > max_bytes:
        raise DomainError(
            DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED,
            "archive member exceeds the size limit",
        )
    return ArchiveMember(info.filename, data)
