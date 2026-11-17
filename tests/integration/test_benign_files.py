"""Benign comparison files for YARA validation (fixed system binary set)."""

from __future__ import annotations

from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.detection.benign_files import (
    SYSTEM_BINARIES,
    BenignFileService,
)
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.project.validator import validate_workspace

MARKER_RULE = """rule marker { strings: $a = "MARKER-XYZ" condition: $a }"""


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "project"
    ProjectService().create(project, "Benign files")
    monkeypatch.chdir(project)
    cases = CaseService(project)
    cases.create("system binaries", "benign")
    cases.create("simulator", "simulator")
    return project


@pytest.fixture
def system32(tmp_path: Path) -> Path:
    directory = tmp_path / "System32"
    for index, name in enumerate(SYSTEM_BINARIES[:-2]):
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"MZ harmless synthetic file %d" % index)
    # Two names share content: the second is reported as already present.
    (directory / SYSTEM_BINARIES[-2]).write_bytes(b"MZ harmless synthetic file 0")
    return directory


def test_adds_the_fixed_set_once(root: Path, system32: Path) -> None:
    service = BenignFileService(root, system32)
    assert [available for _, available in service.plan()].count(False) == 1

    results = service.add_system_binaries("CASE-0001")
    assert [r.name for r in results] == list(SYSTEM_BINARIES)
    statuses = [r.status for r in results]
    assert statuses.count("added") == len(SYSTEM_BINARIES) - 2
    assert statuses[-2:] == ["present", "missing"]
    assert results[-2].artifact_display_id == results[0].artifact_display_id

    again = service.add_system_binaries("CASE-0001")
    assert {r.status for r in again} == {"present", "missing"}
    samples = ArtifactService(root).list_artifacts("CASE-0001")
    assert len(samples) == len(SYSTEM_BINARIES) - 2
    assert {a.kind.value for a in samples} == {"sample"}
    assert validate_workspace(root).findings == ()


def test_refuses_a_case_that_is_not_benign(root: Path, system32: Path) -> None:
    with pytest.raises(DomainError) as error:
        BenignFileService(root, system32).add_system_binaries("CASE-0002")
    assert error.value.code is DomainErrorCode.INVALID_CASE_KIND
    assert ArtifactService(root).list_artifacts("CASE-0002") == []


def test_yara_rule_is_evaluated_against_the_benign_files(
    root: Path, system32: Path, tmp_path: Path
) -> None:
    BenignFileService(root, system32).add_system_binaries("CASE-0001")
    sample = tmp_path / "sim.bin"
    sample.write_bytes(b"MZ MARKER-XYZ")
    ArtifactService(root).add("CASE-0002", sample, "sample")
    detection = DetectionService(root)
    detection.add_rule("marker", "yara", MARKER_RULE)
    detection.create_benchmark("yara benign")
    detection.add_member("BMK-0001", "CASE-0002", "dev")
    detection.add_member("BMK-0001", "CASE-0001", "benign_common")
    run = detection.run_validation("RULE-0001", "BMK-0001")
    outcomes = {r.case_display_id: r.outcome.value for r in run.results}
    assert outcomes == {"CASE-0002": "TP", "CASE-0001": "TN"}


def test_cli(
    root: Path,
    system32: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "loader_detection_workbench.detection.benign_files.default_system_directory",
        lambda: system32,
    )
    assert main(["case", "benign-files", "CASE-0001", "--list"]) == 0
    listing = capsys.readouterr().out
    assert listing.startswith("set: windows-system32-v1\n")
    assert f"{SYSTEM_BINARIES[-1]}\tmissing" in listing
    assert ArtifactService(root).list_artifacts("CASE-0001") == []

    assert main(["case", "benign-files", "CASE-0001"]) == 0
    out = capsys.readouterr().out
    assert f"added: {len(SYSTEM_BINARIES) - 2}, already present: 1, missing: 1" in out
    assert main(["case", "benign-files", "CASE-0002"]) == 2
    assert "INVALID_CASE_KIND" in capsys.readouterr().err
