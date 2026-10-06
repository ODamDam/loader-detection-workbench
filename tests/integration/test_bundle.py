import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from loader_detection_workbench.artifact import store as store_module
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.bundle.service import BundleService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.errors import DomainError
from loader_detection_workbench.project.service import ProjectService


def test_bundle_e2e_cross_project_and_dedup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    ProjectService().create(source, "Source")
    ProjectService().create(target, "Target")
    CaseService(source).create("Demo", "benign")
    first = tmp_path / "one.bin"
    second = tmp_path / "two.bin"
    first.write_bytes(b"same benign bytes")
    second.write_bytes(first.read_bytes())
    ArtifactService(source).add("CASE-0001", first, "static")
    ArtifactService(source).add("CASE-0001", second, "report")
    bundle = source / "case.zip"
    monkeypatch.chdir(source)
    assert main(["bundle", "export", "CASE-0001", str(bundle)]) == 0
    assert main(["bundle", "validate", str(bundle)]) == 0
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        assert len([name for name in names if name.startswith("artifacts/")]) == 1
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["classification"] == "internal"
        assert len(manifest["artifacts"]) == 2
        assert len(manifest["contents"]) == 1
    monkeypatch.chdir(target)
    assert main(["bundle", "import", str(bundle)]) == 0
    assert main(["project", "validate", ".", "--full"]) == 0
    assert (target / "artifacts").exists()
    with sqlite3.connect(target / "project.db") as connection:
        counters = dict(connection.execute("SELECT name, next_value FROM counters"))
        assert counters["case"] >= 2
        assert counters["artifact"] >= 3
        assert connection.execute("SELECT display_id FROM cases").fetchone() == (
            "CASE-0001",
        )


def test_bundle_closed_case_preserves_lifecycle_and_excludes_detached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ProjectService().create(tmp_path, "Project")
    CaseService(tmp_path).create("Closed", "benign")
    source = tmp_path / "fixture"
    source.write_bytes(b"fixture")
    ArtifactService(tmp_path).add("CASE-0001", source, "other")
    ArtifactService(tmp_path).detach("CASE-0001", "ART-000001")
    CaseService(tmp_path).close("CASE-0001")
    bundle = tmp_path / "closed.zip"
    monkeypatch.chdir(tmp_path)
    assert main(["bundle", "export", "CASE-0001", str(bundle)]) == 0
    with zipfile.ZipFile(bundle) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["case"]["status"] == "closed"
        assert manifest["case"]["closed_at"] is not None
        assert manifest["artifacts"] == []
        assert manifest["contents"] == []


def test_bundle_tamper_and_collision_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    ProjectService().create(source, "Source")
    ProjectService().create(target, "Target")
    CaseService(source).create("Demo", "benign")
    fixture = tmp_path / "fixture"
    fixture.write_bytes(b"bytes")
    ArtifactService(source).add("CASE-0001", fixture, "other")
    bundle = source / "case.zip"
    BundleService(source).export("CASE-0001", bundle)
    with zipfile.ZipFile(bundle) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    manifest["case"]["project_id"] = "01M2QAV5E04Y2H5T6W06354916"
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle) as original, zipfile.ZipFile(tampered, "w") as output:
        for info in original.infolist():
            data = original.read(info)
            if info.filename == "manifest.json":
                data = json.dumps(manifest).encode()
            output.writestr(info, data)
    assert BundleService(target).validate(tampered).is_valid is False
    monkeypatch.chdir(target)
    assert main(["bundle", "import", str(tampered)]) == 2
    assert "INVALID_BUNDLE_MANIFEST" in capsys.readouterr().err


def test_bundle_identity_collision_rejects_even_identical_metadata(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    ProjectService().create(source, "Source")
    ProjectService().create(target, "Target")
    CaseService(source).create("Demo", "benign")
    fixture = tmp_path / "fixture"
    fixture.write_bytes(b"bytes")
    ArtifactService(source).add("CASE-0001", fixture, "other")
    bundle = source / "case.zip"
    BundleService(source).export("CASE-0001", bundle)
    BundleService(target).import_bundle(bundle)
    with pytest.raises(DomainError) as caught:
        BundleService(target).import_bundle(bundle)
    assert caught.value.code.value == "CASE_ID_COLLISION"


def test_bundle_archive_path_and_manifest_validation_are_fail_closed(
    tmp_path: Path,
) -> None:
    ProjectService().create(tmp_path, "Project")
    CaseService(tmp_path).create("Demo", "benign")
    bundle = tmp_path / "case.zip"
    BundleService(tmp_path).export("CASE-0001", bundle)
    with zipfile.ZipFile(bundle) as original:
        manifest = json.loads(original.read("manifest.json"))
        content = {info.filename: original.read(info) for info in original.infolist()}
    manifest["source_project"]["internal_id"] = 42
    malformed = tmp_path / "malformed.zip"
    with zipfile.ZipFile(malformed, "w") as output:
        for name, data in content.items():
            output.writestr(
                name,
                json.dumps(manifest).encode() if name == "manifest.json" else data,
            )
    assert not BundleService(tmp_path).validate(malformed).is_valid

    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as output:
        output.writestr("manifest.json", b"{}")
        output.writestr("../escape", b"fixture")
    assert not BundleService(tmp_path).validate(unsafe).is_valid


def test_bundle_import_publication_failure_rolls_back_rows_and_owned_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    ProjectService().create(source, "Source")
    ProjectService().create(target, "Target")
    CaseService(source).create("Demo", "benign")
    fixture = tmp_path / "fixture"
    fixture.write_bytes(b"bytes")
    ArtifactService(source).add("CASE-0001", fixture, "other")
    bundle = source / "case.zip"
    BundleService(source).export("CASE-0001", bundle)
    original = store_module.ArtifactStore.publish

    def fail_after_publish(self: object, path: Path) -> object:
        original(self, path)  # type: ignore[arg-type]
        raise OSError("injected publication failure")

    monkeypatch.setattr(store_module.ArtifactStore, "publish", fail_after_publish)
    with pytest.raises(OSError):
        BundleService(target).import_bundle(bundle)
    with sqlite3.connect(target / "project.db") as connection:
        assert connection.execute("SELECT count(*) FROM cases").fetchone() == (0,)
    assert not any(
        path.is_file() for path in (target / "artifacts" / "sha256").rglob("*")
    )
