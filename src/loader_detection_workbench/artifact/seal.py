"""Sealed at-rest form of stored content (ADR-030).

A sealed file is ``MAGIC`` followed by the content XORed with a fixed, public
4 KiB keystream. This is **not** encryption: the key is in the source code and
anyone can unseal. Its only purpose is that the original byte patterns of a
malware sample never appear on the host disk, so host anti-malware does not
quarantine the artifact store and nothing there can be run by a stray
double-click. Unsealing happens in memory on the host and inside the analysis
VM before execution.

Identity is always the *unsealed* content: the recorded SHA-256 and size, the
canonical path and every integrity check use the original bytes. Any stored
file or import source that starts with ``MAGIC`` is read as sealed.
"""

from __future__ import annotations

import hashlib
from types import TracebackType
from typing import BinaryIO

MAGIC = b"LDWSEAL1"
KEY_SIZE = 4096
_LABEL = b"loader-detection-workbench/seal/v1"


def _keystream() -> bytes:
    blocks = (
        hashlib.sha256(_LABEL + index.to_bytes(4, "big")).digest()
        for index in range(KEY_SIZE // 32)
    )
    return b"".join(blocks)


KEY = _keystream()
_WINDOW = 1024 * 1024
_PAD = KEY * (_WINDOW // KEY_SIZE + 1)


def xor_at(data: bytes, offset: int) -> bytes:
    """XOR ``data`` with the keystream starting at content offset ``offset``."""
    out = bytearray()
    position = 0
    while position < len(data):
        piece = data[position : position + _WINDOW]
        start = (offset + position) % KEY_SIZE
        pad = _PAD[start : start + len(piece)]
        mixed = int.from_bytes(piece, "big") ^ int.from_bytes(pad, "big")
        out += mixed.to_bytes(len(piece), "big")
        position += len(piece)
    return bytes(out)


def seal_bytes(plain: bytes) -> bytes:
    return MAGIC + xor_at(plain, 0)


def unseal_bytes(stored: bytes) -> bytes:
    if stored.startswith(MAGIC):
        return xor_at(stored[len(MAGIC) :], 0)
    return stored


class ContentReader:
    """Reads the unsealed content of a raw stream, sealed or not."""

    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        self._start()

    def _start(self) -> None:
        head = b""
        while len(head) < len(MAGIC):
            chunk = self._raw.read(len(MAGIC) - len(head))
            if not chunk:
                break
            head += chunk
        self.sealed = head == MAGIC
        self._pending = b"" if self.sealed else head
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            data = self._pending + self._raw.read()
            self._pending = b""
        else:
            data = self._pending[:size]
            self._pending = self._pending[size:]
            if len(data) < size:
                data += self._raw.read(size - len(data))
        if self.sealed and data:
            data = xor_at(data, self._offset)
        self._offset += len(data)
        return data

    def seek(self, position: int) -> int:
        if position != 0:
            raise OSError("content reader can only rewind")
        self._raw.seek(0)
        self._start()
        return 0

    def close(self) -> None:
        self._raw.close()

    def __enter__(self) -> ContentReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class SealingWriter:
    """Writes ``MAGIC`` then the sealed form of every chunk written."""

    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        self._offset = 0
        raw.write(MAGIC)

    def write(self, data: bytes) -> int:
        self._raw.write(xor_at(data, self._offset))
        self._offset += len(data)
        return len(data)
