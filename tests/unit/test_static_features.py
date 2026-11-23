"""Static feature extraction over a hand-built, non-executable synthetic PE."""

import struct

from loader_detection_workbench.static_analysis.features import (
    extract_strings,
    pe_details,
    shannon_entropy,
    suspicion_flags,
)


def synthetic_pe_with_imports(extra: bytes = b"") -> bytes:
    """PE32+ with one .idata section importing two KERNEL32 functions.

    The entry point and code are zero bytes; the file is never executed.
    """
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    # COFF: machine x64, 1 section, timestamp, no symbols, optional size, flags
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0x65000000, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)  # PE32+
    struct.pack_into("<I", data, optional + 16, 0x1000)  # entry point RVA
    struct.pack_into("<Q", data, optional + 24, 0x140000000)  # image base
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)  # alignments
    struct.pack_into("<HH", data, optional + 40, 6, 0)  # OS version
    struct.pack_into("<HH", data, optional + 48, 6, 0)  # subsystem version
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)  # image/headers
    struct.pack_into("<HH", data, optional + 68, 3, 0)  # console subsystem
    struct.pack_into("<I", data, optional + 108, 16)  # data directory count
    struct.pack_into("<II", data, optional + 112 + 8, 0x1000, 40)  # import dir
    section = optional + 0xF0
    data[section : section + 8] = b".idata\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    base_raw, base_rva = 0x200, 0x1000

    def at(offset: int) -> int:
        return base_raw + offset

    ilt, iat, hint1, hint2, name = 0x40, 0x60, 0x80, 0xA0, 0xC0
    struct.pack_into(
        "<IIIII", data, at(0), base_rva + ilt, 0, 0, base_rva + name, base_rva + iat
    )
    for table in (ilt, iat):
        struct.pack_into("<QQQ", data, at(table), base_rva + hint1, base_rva + hint2, 0)
    data[at(hint1) : at(hint1) + 15] = b"\0\0VirtualAlloc\0"
    data[at(hint2) : at(hint2) + 15] = b"\0\0LoadLibraryA\0"
    data[at(name) : at(name) + 13] = b"KERNEL32.dll\0"
    strings = (
        b"http://example.invalid/stage2\0"
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\demo\0"
        + "powershell -enc".encode("utf-16-le")
        + b"\0\0"
    )
    data[at(0x100) : at(0x100) + len(strings)] = strings
    return bytes(data) + extra


def test_pe_details_imports_imphash_and_header_extras() -> None:
    details = pe_details(synthetic_pe_with_imports())

    assert details["parser_warning"] is None
    assert details["imports"] == [
        {"dll": "KERNEL32.dll", "functions": ["VirtualAlloc", "LoadLibraryA"]}
    ]
    assert details["import_function_count"] == 2
    assert details["imphash"] and len(details["imphash"]) == 32
    assert details["subsystem"] == "IMAGE_SUBSYSTEM_WINDOWS_CUI"
    assert details["is_dll"] is False
    assert details["signature"] == "absent"
    assert details["entry_point"] == "0x00001000"
    assert details["compile_timestamp"] is not None


def test_overlay_and_flags_are_leads_not_verdicts() -> None:
    data = synthetic_pe_with_imports(extra=b"OVERLAY" * 10)
    details = pe_details(data)
    sections = [
        {"name": ".idata", "entropy": 7.9, "executable": True, "writable": True}
    ]

    flags = suspicion_flags(sections, details)

    assert details["overlay_size"] == 70
    assert "high_entropy_section:.idata" in flags
    assert "writable_executable_section:.idata" in flags
    assert "few_imports" in flags
    assert "notable_imports:LoadLibraryA,VirtualAlloc" in flags
    assert "overlay:70" in flags
    assert "no_authenticode_signature" in flags


def test_strings_and_indicators_are_bounded() -> None:
    result = extract_strings(synthetic_pe_with_imports())

    assert result["indicators"]["url"] == ["http://example.invalid/stage2"]
    assert result["indicators"]["registry"][0].startswith("HKCU\\Software")
    assert "powershell" in result["indicators"]["script_keyword"]
    assert {"encoding": "utf-16le", "value": "powershell -enc"} in result["items"]
    assert result["truncated"] is False


def test_entropy_bounds_and_garbage_input() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\0" * 64) == 0.0
    assert shannon_entropy(bytes(range(256))) == 8.0
    garbage = pe_details(b"MZ" + b"\xff" * 10)
    assert garbage["parser_warning"] is not None
    assert garbage["imports"] == []
