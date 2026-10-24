import struct
from datetime import UTC, datetime
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.static_analysis.service import StaticAnalysisService
from loader_detection_workbench.web import create_app


def _minimal_pe() -> bytes:
    data = bytearray(0x204)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    struct.pack_into("<H", data, 0x98, 0x20B)
    section = 0x98 + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        4,
        0x1000,
        4,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[0x200:0x204] = b"SAFE"
    return bytes(data)


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Static")
    CaseService(root).create("Benign PE", "benign")
    return root


def test_static_analysis_collects_pe_header_sections_and_ui_relation(
    tmp_path: Path,
) -> None:
    root = _workspace(tmp_path)
    source_path = tmp_path / "benign-fixture.exe"
    source_path.write_bytes(_minimal_pe())
    source = ArtifactService(root).add("CASE-0001", source_path, "sample")

    result = StaticAnalysisService(root).analyze(
        "CASE-0001", source.artifact_id.display_id
    )

    assert result.status == "ok"
    assert result.is_pe is True
    assert result.architecture == "x64"
    assert result.optional_header == "PE32+"
    assert result.source_sha256 == source.sha256
    assert result.source_size_bytes == source.size_bytes
    assert result.sections[0].name == ".text"
    assert result.sections[0].raw_size == 4

    response = (
        create_app(root, secret_key=b"test")
        .test_client()
        .get(
            f"/cases/CASE-0001/artifacts/{result.artifact.artifact_id.display_id}",
            base_url="http://127.0.0.1:8080",
        )
    )
    assert response.status_code == 200
    assert "Static PE result" in response.text
    assert source.artifact_id.display_id in response.text
    assert "x64" in response.text
    assert ".text" in response.text
    assert str(root) not in response.text
    assert "artifacts/sha256" not in response.text


def test_static_analysis_distinguishes_non_pe_and_malformed_pe(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    plain_path = tmp_path / "plain.bin"
    plain_path.write_bytes(b"safe text")
    broken_path = tmp_path / "broken.exe"
    broken_path.write_bytes(b"MZ" + b"\0" * 10)
    artifacts = ArtifactService(root)
    plain = artifacts.add("CASE-0001", plain_path, "sample")
    broken = artifacts.add("CASE-0001", broken_path, "sample")
    service = StaticAnalysisService(root)

    non_pe = service.analyze("CASE-0001", plain.artifact_id.display_id)
    malformed = service.analyze("CASE-0001", broken.artifact_id.display_id)

    assert (non_pe.status, non_pe.is_pe, non_pe.error) == ("not_pe", False, None)
    assert malformed.status == "malformed_pe"
    assert malformed.is_pe is False
    assert malformed.error == "DOS header is truncated"


def test_static_result_reuses_store_dedup_and_preserves_source(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    root = _workspace(tmp_path)
    source_path = tmp_path / "fixture.exe"
    source_bytes = _minimal_pe()
    source_path.write_bytes(source_bytes)
    source = ArtifactService(root).add("CASE-0001", source_path, "sample")
    fixed = datetime(2026, 10, 24, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(
        "loader_detection_workbench.static_analysis.service.utc_now", lambda: fixed
    )
    service = StaticAnalysisService(root)

    first = service.analyze("CASE-0001", source.artifact_id.display_id)
    second = service.analyze("CASE-0001", source.artifact_id.display_id)

    assert first.artifact.artifact_id != second.artifact.artifact_id
    assert first.artifact.sha256 == second.artifact.sha256
    assert first.artifact.relative_path == second.artifact.relative_path
    assert source_path.read_bytes() == source_bytes


def test_static_analysis_cli(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    root = _workspace(tmp_path)
    source_path = tmp_path / "fixture.exe"
    source_path.write_bytes(_minimal_pe())
    source = ArtifactService(root).add("CASE-0001", source_path, "sample")
    monkeypatch.chdir(root)

    status = main(
        [
            "case",
            "static",
            "analyze",
            "CASE-0001",
            source.artifact_id.display_id,
        ]
    )

    output = capsys.readouterr()
    assert status == 0
    assert "result_artifact: ART-000002" in output.out
    assert f"source_artifact: {source.artifact_id.display_id}" in output.out
    assert "status: ok" in output.out
    assert "architecture: x64" in output.out
    assert str(root) not in output.out
    assert output.err == ""
