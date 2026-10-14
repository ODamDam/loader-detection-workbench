"""Streaming content storage with atomic, exclusive publication."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from loader_detection_workbench.domain.artifact import canonical_path
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.paths import ProjectRelativePath

_CHUNK_SIZE = 1024 * 1024


def _publish_exclusive(staging: Path, destination: Path) -> None:
    if os.name == "nt":
        # Windows rename is atomic and refuses to replace an existing destination.
        os.rename(staging, destination)
    else:
        # POSIX rename replaces existing content; link gives no-clobber publication.
        os.link(staging, destination)


def _digest(
    stream: BinaryIO,
    target: BinaryIO | None = None,
    *,
    max_bytes: int | None = None,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(_CHUNK_SIZE):
        size += len(chunk)
        if max_bytes is not None and size > max_bytes:
            raise DomainError(
                DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED,
                "manual evidence exceeds the configured size limit",
            )
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    return digest.hexdigest(), size


def _open_regular(path: Path) -> BinaryIO:
    if not stat.S_ISREG(path.stat().st_mode):
        raise OSError("not a regular file")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("not a regular file")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(frozen=True, slots=True)
class PublishedContent:
    relative_path: ProjectRelativePath
    sha256: str
    size_bytes: int
    # Identity of the newly published inode, never an existing dedup destination.
    owned_identity: tuple[int, int] | None


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.published: PublishedContent | None = None

    def resolve(self, relative_path: ProjectRelativePath) -> Path:
        path = relative_path.resolve_under(self.root)
        current = self.root
        for part in path.relative_to(self.root).parts:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise DomainError(
                    DomainErrorCode.PATH_ESCAPE,
                    "artifact path must not traverse filesystem links",
                )
        if not path.resolve().is_relative_to(self.root):
            raise DomainError(
                DomainErrorCode.PATH_ESCAPE, "artifact path escapes the project"
            )
        return path

    def verify(self, path: Path, expected: tuple[str, int]) -> None:
        try:
            with _open_regular(path) as stream:
                actual = _digest(stream)
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH,
                "canonical content is not readable regular content",
            ) from exc
        if actual != expected:
            raise DomainError(
                DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH,
                "canonical content hash or size does not match",
            )

    def read_verified(
        self,
        relative_path: ProjectRelativePath,
        expected: tuple[str, int],
        *,
        max_bytes: int,
    ) -> bytes:
        """Read bounded regular content and verify exactly the returned bytes."""
        try:
            with _open_regular(self.resolve(relative_path)) as stream:
                data = stream.read(max_bytes + 1)
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH,
                "canonical content is not readable regular content",
            ) from exc
        if (
            len(data) > max_bytes
            or (hashlib.sha256(data).hexdigest(), len(data)) != expected
        ):
            raise DomainError(
                DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH,
                "canonical content exceeds the read limit or fails integrity checks",
            )
        return data

    def publish(
        self, source: Path, *, max_bytes: int | None = None
    ) -> PublishedContent:
        self.published = None
        # Read the same open source twice; detect changes before publication.
        try:
            stream = _open_regular(source)
        except (OSError, ValueError) as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_SOURCE_INVALID,
                "source must be a readable regular file",
            ) from exc
        staging: Path | None = None
        owned: PublishedContent | None = None
        try:
            with stream:
                try:
                    expected = (
                        _digest(stream)
                        if max_bytes is None
                        else _digest(stream, max_bytes=max_bytes)
                    )
                    stream.seek(0)
                except OSError as exc:
                    raise DomainError(
                        DomainErrorCode.ARTIFACT_SOURCE_INVALID,
                        "source could not be read",
                    ) from exc
                sha256, size = expected
                relative = canonical_path(sha256)
                destination = self.resolve(relative)
                if destination.exists():
                    self.verify(destination, expected)
                    return PublishedContent(relative, sha256, size, None)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination = self.resolve(relative)
                fd, name = tempfile.mkstemp(
                    prefix=".artifact-", suffix=".tmp", dir=destination.parent
                )
                staging = Path(name)
                with os.fdopen(fd, "wb") as target:
                    copied = (
                        _digest(stream, target)
                        if max_bytes is None
                        else _digest(stream, target, max_bytes=max_bytes)
                    )
                    target.flush()
                    os.fsync(target.fileno())
                if copied != expected:
                    raise DomainError(
                        DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH,
                        "source changed while staging content",
                    )
                self.verify(staging, expected)
                info = staging.stat()
                destination = self.resolve(relative)
                try:
                    _publish_exclusive(staging, destination)
                    owned = PublishedContent(
                        relative, sha256, size, (info.st_dev, info.st_ino)
                    )
                    self.published = owned
                except FileExistsError:
                    self.verify(self.resolve(relative), expected)
                return owned or PublishedContent(relative, sha256, size, None)
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_STORE_FAILED,
                "artifact staging or publication failed",
            ) from exc
        finally:
            if staging is not None:
                try:
                    staging.unlink(missing_ok=True)
                except OSError as exc:
                    # The service compensates any publication after DB rollback,
                    # including when this method cannot return its ownership token.
                    raise DomainError(
                        DomainErrorCode.ARTIFACT_CLEANUP_FAILED,
                        "artifact staging cleanup failed",
                    ) from exc

    def publish_bytes(self, data: bytes) -> PublishedContent:
        """Atomically publish already-validated immutable content."""
        self.published = None
        sha256 = hashlib.sha256(data).hexdigest()
        expected = (sha256, len(data))
        relative = canonical_path(sha256)
        staging: Path | None = None
        owned: PublishedContent | None = None
        try:
            destination = self.resolve(relative)
            if destination.exists():
                self.verify(destination, expected)
                return PublishedContent(relative, sha256, len(data), None)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination = self.resolve(relative)
            fd, name = tempfile.mkstemp(
                prefix=".artifact-", suffix=".tmp", dir=destination.parent
            )
            staging = Path(name)
            with os.fdopen(fd, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            self.verify(staging, expected)
            info = staging.stat()
            destination = self.resolve(relative)
            try:
                _publish_exclusive(staging, destination)
                owned = PublishedContent(
                    relative, sha256, len(data), (info.st_dev, info.st_ino)
                )
                self.published = owned
            except FileExistsError:
                self.verify(self.resolve(relative), expected)
            return owned or PublishedContent(relative, sha256, len(data), None)
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.ARTIFACT_STORE_FAILED,
                "artifact staging or publication failed",
            ) from exc
        finally:
            if staging is not None:
                try:
                    staging.unlink(missing_ok=True)
                except OSError as exc:
                    raise DomainError(
                        DomainErrorCode.ARTIFACT_CLEANUP_FAILED,
                        "artifact staging cleanup failed",
                    ) from exc

    def cleanup(self, content: PublishedContent) -> None:
        """Caller must hold the DB write lock and have checked committed references."""
        if content.owned_identity is None:
            return
        path = self.resolve(content.relative_path)
        try:
            info = path.stat()
        except FileNotFoundError:
            return
        if (info.st_dev, info.st_ino) != content.owned_identity:
            return
        path.unlink()
