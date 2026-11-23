"""Bounded static feature extraction: entropy, strings, imports and flags.

Everything here reads bytes only. Results are capped so a hostile or very large
sample cannot produce an unbounded result Artifact.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import pefile

MIN_STRING_LENGTH = 6
MAX_STRINGS = 2000
MAX_STRING_CHARS = 200
MAX_IMPORT_DLLS = 256
MAX_IMPORT_FUNCTIONS = 4096
MAX_EXPORTS = 256
MAX_INDICATORS_PER_KIND = 100
HIGH_ENTROPY = 7.2

_ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LENGTH)
_INDICATORS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.IGNORECASE),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "registry": re.compile(
        r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"']{3,}", re.IGNORECASE
    ),
    "windows_path": re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]{3,}"),
    "executable_name": re.compile(
        r"\b[\w.-]{1,64}\.(?:exe|dll|scr|ps1|vbs|js|bat|cmd|hta|lnk)\b", re.IGNORECASE
    ),
    "script_keyword": re.compile(
        r"\b(?:powershell|invoke-expression|iex|frombase64string|downloadstring|"
        r"wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|schtasks)\b",
        re.IGNORECASE,
    ),
}
# Imports often associated with injection, download or anti-analysis behavior.
# A hit is a lead for analyst review, not a verdict.
_NOTABLE_IMPORTS = frozenset(
    name.lower()
    for name in (
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "SetThreadContext",
        "ResumeThread",
        "QueueUserAPC",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "WinHttpOpen",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
        "WinExec",
        "RegSetValueExA",
        "RegSetValueExW",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "CryptEncrypt",
        "CryptDecrypt",
    )
)
_PACKER_SECTIONS = frozenset(
    {"upx0", "upx1", "upx2", ".aspack", ".adata", ".packed", ".mpress1", ".themida"}
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in Counter(data).values()
    )
    return round(entropy, 4)


def extract_strings(data: bytes) -> dict[str, Any]:
    """Return capped ASCII and UTF-16LE strings plus indicator candidates."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    total = 0
    for encoding, pattern in (("ascii", _ASCII), ("utf-16le", _UTF16)):
        for match in pattern.finditer(data):
            raw = match.group()
            start = match.start()
            if encoding == "utf-16le" and start > 0 and 0x20 <= data[start - 1] <= 0x7E:
                # The first pair is the tail of a NUL-terminated ASCII string.
                raw = raw[2:]
                if len(raw) // 2 < MIN_STRING_LENGTH:
                    continue
            total += 1
            text = (
                raw.decode("ascii")
                if encoding == "ascii"
                else raw.decode("utf-16-le", errors="replace")
            )
            key = (encoding, text)
            if key in seen or len(found) >= MAX_STRINGS:
                continue
            seen.add(key)
            found.append({"encoding": encoding, "value": text[:MAX_STRING_CHARS]})
    indicators: dict[str, list[str]] = {}
    for kind, regex in _INDICATORS.items():
        values: list[str] = []
        for item in found:
            for hit in regex.findall(item["value"]):
                if hit not in values:
                    values.append(hit)
                if len(values) >= MAX_INDICATORS_PER_KIND:
                    break
        if values:
            indicators[kind] = sorted(values, key=str.lower)
    return {
        "total": total,
        "kept": len(found),
        "truncated": total > len(found),
        "items": found,
        "indicators": indicators,
    }


def section_entropy(data: bytes, sections: list[dict[str, Any]]) -> None:
    """Add entropy and permission summaries to parsed section dictionaries."""
    for section in sections:
        start = section.get("raw_pointer", 0)
        size = section.get("raw_size", 0)
        section["entropy"] = shannon_entropy(data[start : start + size])
        flags = int(section["characteristics"], 16)
        section["executable"] = bool(flags & 0x20000000)
        section["writable"] = bool(flags & 0x80000000)


def pe_details(data: bytes) -> dict[str, Any]:
    """Imports, exports, imphash and header extras via pefile (bytes only)."""
    result: dict[str, Any] = {
        "imports": [],
        "import_function_count": 0,
        "imports_truncated": False,
        "imphash": None,
        "exports": [],
        "export_count": 0,
        "compile_timestamp": None,
        "entry_point": None,
        "image_base": None,
        "subsystem": None,
        "is_dll": None,
        "signature": "absent",
        "overlay_size": 0,
        "parser_warning": None,
    }
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        result["parser_warning"] = f"pefile: {exc}"
        return result
    try:
        directories = [
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
        pe.parse_data_directories(directories=directories)
        header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER
        stamp = int(header.TimeDateStamp)
        result["compile_timestamp"] = (
            datetime.fromtimestamp(stamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            if 0 < stamp < 4_102_444_800
            else None
        )
        result["entry_point"] = f"0x{int(optional.AddressOfEntryPoint):08x}"
        result["image_base"] = f"0x{int(optional.ImageBase):x}"
        result["subsystem"] = pefile.SUBSYSTEM_TYPE.get(
            int(optional.Subsystem), str(optional.Subsystem)
        )
        result["is_dll"] = bool(int(header.Characteristics) & 0x2000)
        security = optional.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if int(security.VirtualAddress) and int(security.Size):
            result["signature"] = "present_unverified"
        overlay = pe.get_overlay_data_start_offset()
        result["overlay_size"] = 0 if overlay is None else max(0, len(data) - overlay)
        functions = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:MAX_IMPORT_DLLS]:
            names: list[str] = []
            for symbol in entry.imports:
                if functions >= MAX_IMPORT_FUNCTIONS:
                    result["imports_truncated"] = True
                    break
                functions += 1
                names.append(
                    symbol.name.decode("ascii", errors="replace")
                    if symbol.name
                    else f"ordinal#{symbol.ordinal}"
                )
            result["imports"].append(
                {"dll": entry.dll.decode("ascii", errors="replace"), "functions": names}
            )
        result["import_function_count"] = functions
        imphash = pe.get_imphash()
        result["imphash"] = imphash or None
        export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export is not None:
            symbols = list(export.symbols)
            result["export_count"] = len(symbols)
            result["exports"] = [
                symbol.name.decode("ascii", errors="replace")
                if symbol.name
                else f"ordinal#{symbol.ordinal}"
                for symbol in symbols[:MAX_EXPORTS]
            ]
    except Exception as exc:  # pefile raises many error types on hostile input
        result["parser_warning"] = f"pefile: {type(exc).__name__}"
    finally:
        pe.close()
    return result


def suspicion_flags(
    sections: list[dict[str, Any]], details: dict[str, Any]
) -> list[str]:
    """Deterministic analyst leads; none of them is a maliciousness verdict."""
    flags: list[str] = []
    for section in sections:
        name = str(section["name"]).lower()
        if section.get("entropy", 0.0) >= HIGH_ENTROPY:
            flags.append(f"high_entropy_section:{section['name']}")
        if section.get("executable") and section.get("writable"):
            flags.append(f"writable_executable_section:{section['name']}")
        if name in _PACKER_SECTIONS:
            flags.append(f"packer_section_name:{section['name']}")
    if details["parser_warning"] is None and details["import_function_count"] < 5:
        flags.append("few_imports")
    notable = sorted(
        {
            function
            for entry in details["imports"]
            for function in entry["functions"]
            if function.lower() in _NOTABLE_IMPORTS
        }
    )
    if notable:
        flags.append("notable_imports:" + ",".join(notable))
    if details["overlay_size"]:
        flags.append(f"overlay:{details['overlay_size']}")
    if details["signature"] == "absent":
        flags.append("no_authenticode_signature")
    return flags
