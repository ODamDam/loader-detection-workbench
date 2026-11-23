"""Benign comparison files for YARA validation (Windows system binaries).

A YARA rule is only evaluated against ``sample`` Artifacts, so a ``benign``
Case without files makes every YARA result ``not_evaluable``. This service adds
a fixed, versioned list of Windows system binaries from the local
``System32`` directory to a benign Case as ``sample`` Artifacts. The list is
fixed so that FP counts of different rule versions refer to the same set; the
SHA-256 of every file is recorded by the Artifact store.

The files are copied into the Project's runtime Artifact store only. They are
operating system files, never committed to Git and never executed.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.case import CaseKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

SYSTEM_BINARY_SET = "windows-system32-v1"
# Common binaries plus script hosts and utilities that malware often abuses,
# so string and import rules meet realistic look-alikes.
SYSTEM_BINARIES: tuple[str, ...] = (
    "cmd.exe",
    "conhost.exe",
    "cscript.exe",
    "wscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "reg.exe",
    "sc.exe",
    "taskkill.exe",
    "tasklist.exe",
    "whoami.exe",
    "notepad.exe",
    "svchost.exe",
    "WindowsPowerShell/v1.0/powershell.exe",
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "advapi32.dll",
    "user32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "winhttp.dll",
    "crypt32.dll",
    "shell32.dll",
)


@dataclass(frozen=True, slots=True)
class BenignFileResult:
    name: str
    status: str  # added | present | missing
    artifact_display_id: str | None = None
    sha256: str | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def default_system_directory() -> Path:
    return Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"


class BenignFileService:
    def __init__(self, root: Path, system_directory: Path | None = None) -> None:
        self._root = root
        self._system = system_directory or default_system_directory()

    def plan(self) -> list[tuple[str, bool]]:
        """Which files of the set exist here; reads nothing else."""
        return [(name, (self._system / name).is_file()) for name in SYSTEM_BINARIES]

    def add_system_binaries(self, case_display_id: str) -> list[BenignFileResult]:
        case = CaseService(self._root).show(case_display_id)
        if case.kind is not CaseKind.BENIGN:
            raise DomainError(
                DomainErrorCode.INVALID_CASE_KIND,
                "benign comparison files belong in a benign Case",
            )
        artifacts = ArtifactService(self._root)
        present = {
            artifact.sha256: artifact.artifact_id.display_id
            for artifact in artifacts.list_artifacts(case_display_id)
            if artifact.kind is ArtifactKind.SAMPLE
        }
        results: list[BenignFileResult] = []
        for name in SYSTEM_BINARIES:
            source = self._system / name
            if not source.is_file():
                results.append(BenignFileResult(name, "missing"))
                continue
            digest = _sha256(source)
            if digest in present:
                results.append(
                    BenignFileResult(name, "present", present[digest], digest)
                )
                continue
            added = artifacts.add(case_display_id, source, ArtifactKind.SAMPLE.value)
            present[added.sha256] = added.artifact_id.display_id
            results.append(
                BenignFileResult(
                    name, "added", added.artifact_id.display_id, added.sha256
                )
            )
        return results
