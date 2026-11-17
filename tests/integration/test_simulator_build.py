"""Benign simulator (ADR-028): source safety and a compile-only build check.

The built executable is never run here. Running it is a VM action that needs
the project owner's approval (AGENTS.md).
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
import yara  # type: ignore[import-not-found,unused-ignore]

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "tools" / "simulator" / "WorkbenchSimulator.cs"
BUILD = REPO / "scripts" / "simulator" / "Build-WorkbenchSimulator.ps1"
RULES = REPO / "tools" / "simulator" / "rules"
CSC = Path(os.environ.get("WINDIR", r"C:\Windows")) / (
    r"Microsoft.NET\Framework64\v4.0.30319\csc.exe"
)
MARKER = "WORKBENCH-SIMULATOR-MARKER-v1"


def test_source_stays_within_the_benign_contract() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    assert f'Marker = "{MARKER}"' in text
    # Only reserved, never-routed network destinations.
    assert re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text) == ["192.0.2.1"] * 2
    assert "example.invalid" in text
    for forbidden in (
        "WebClient",
        "HttpClient",
        "DownloadFile",
        "LocalMachine",
        "VirtualAlloc",
        "CreateRemoteThread",
        "Assembly.Load",
        "ServiceController",
        "runas",
    ):
        assert forbidden not in text, forbidden
    # Everything it writes is removed before exit.
    assert "DeleteValue(RunValue)" in text
    assert "DeleteSubKeyTree(ConfigKey" in text
    assert "Directory.Delete(work, true)" in text


@pytest.mark.skipif(
    os.name != "nt" or not CSC.is_file() or shutil.which("powershell") is None,
    reason="needs Windows with the .NET Framework 4.x C# compiler",
)
def test_build_produces_an_x64_pe_with_the_marker(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(BUILD),
            "-OutputDirectory",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    binary = tmp_path / "workbench-simulator.exe"
    data = binary.read_bytes()
    match = re.search(r"sha256: ([0-9a-f]{64})", completed.stdout)
    assert match is not None
    assert data[:2] == b"MZ"
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
    assert struct.unpack_from("<H", data, pe_offset + 4)[0] == 0x8664  # x64
    assert MARKER.encode("utf-16-le") in data

    rules = yara.compile(filepath=str(RULES / "simulator-marker.yar"))
    assert [m.rule for m in rules.match(data=data)] == ["workbench_simulator_marker_v1"]
    assert rules.match(data=b"MZ" + b"\0" * 64) == []
