"""Sealed sample storage and in-memory archive import (ADR-030).

All content here is harmless synthetic bytes; the marker stands in for the
byte patterns of a real sample that must never appear on the host disk.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

import pytest
import pyzipper

from loader_detection_workbench.artifact.archive import read_member
from loader_detection_workbench.artifact.seal import (
    KEY_SIZE,
    MAGIC,
    ContentReader,
    SealingWriter,
    seal_bytes,
    unseal_bytes,
    xor_at,
)
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.bundle.service import BundleService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.project.validator import validate_workspace

MARKER = b"HARMLESS-SEALED-SAMPLE-MARKER"
CONTENT = b"MZ" + b"\x90" * 5000 + MARKER + b"\x00" * 3000
SHA = hashlib.sha256(CONTENT).hexdigest()


def _aes_zip(path: Path, members: dict[str, bytes], password: bytes) -> Path:
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(password)
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def _files_containing(root: Path, needle: bytes) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and needle in path.read_bytes()
    ]


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "project"
    ProjectService().create(project, "Sealed")
    CaseService(project).create("sample case", "malware")
    monkeypatch.chdir(project)
    return project


def test_seal_round_trip_across_key_and_chunk_boundaries() -> None:
    sealed = seal_bytes(CONTENT)
    assert sealed.startswith(MAGIC) and MARKER not in sealed
    assert unseal_bytes(sealed) == CONTENT
    assert unseal_bytes(CONTENT) == CONTENT  # unsealed content passes through
    assert (
        xor_at(CONTENT[KEY_SIZE - 3 :], KEY_SIZE - 3)
        == sealed[len(MAGIC) + KEY_SIZE - 3 :]
    )
    for size in (1, 7, KEY_SIZE + 1):
        reader = ContentReader(io.BytesIO(sealed))
        parts = []
        while chunk := reader.read(size):
            parts.append(chunk)
        assert reader.sealed and b"".join(parts) == CONTENT
        reader.seek(0)
        assert reader.read() == CONTENT
    plain = ContentReader(io.BytesIO(b"abc"))
    assert not plain.sealed and plain.read(2) == b"ab" and plain.read() == b"c"
    assert ContentReader(io.BytesIO(b"")).read() == b""
    target = io.BytesIO()
    writer = SealingWriter(target)
    writer.write(CONTENT[:10])
    writer.write(CONTENT[10:])
    assert target.getvalue() == sealed


def test_samples_are_stored_sealed_and_read_unsealed(
    root: Path, tmp_path: Path
) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(CONTENT)
    other = tmp_path / "notes.txt"
    other.write_bytes(b"plain analyst notes")
    service = ArtifactService(root)
    sample = service.add("CASE-0001", source, "sample")
    notes = service.add("CASE-0001", other, "other")
    assert (sample.sha256, sample.size_bytes) == (SHA, len(CONTENT))
    store = ArtifactStore(root)
    stored = store.resolve(sample.relative_path).read_bytes()
    assert stored.startswith(MAGIC) and len(stored) == len(CONTENT) + len(MAGIC)
    assert _files_containing(root, MARKER) == []
    assert store.resolve(notes.relative_path).read_bytes() == b"plain analyst notes"
    assert (
        store.read_verified(
            sample.relative_path, (SHA, len(CONTENT)), max_bytes=1 << 20
        )
        == CONTENT
    )
    assert validate_workspace(root, full=True).findings == ()
    # Adding the same content again reuses the sealed copy.
    assert service.add("CASE-0001", source, "sample").relative_path == (
        sample.relative_path
    )


def test_unsealed_legacy_samples_still_verify(root: Path, tmp_path: Path) -> None:
    source = tmp_path / "legacy.bin"
    source.write_bytes(b"MZ legacy harmless sample")
    content = ArtifactStore(root).publish(source)  # pre-ADR-030 form
    assert ArtifactStore(root).resolve(content.relative_path).read_bytes() == (
        b"MZ legacy harmless sample"
    )
    artifact = ArtifactService(root).add("CASE-0001", source, "sample")
    assert artifact.relative_path == content.relative_path
    assert validate_workspace(root, full=True).findings == ()


def test_tampered_sealed_content_fails_integrity(root: Path, tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(CONTENT)
    artifact = ArtifactService(root).add("CASE-0001", source, "sample")
    path = ArtifactStore(root).resolve(artifact.relative_path)
    data = bytearray(path.read_bytes())
    data[100] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(DomainError) as caught:
        ArtifactStore(root).read_verified(
            artifact.relative_path, (SHA, len(CONTENT)), max_bytes=1 << 20
        )
    assert caught.value.code is DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH
    codes = {f.code for f in validate_workspace(root, full=True).findings}
    assert "ARTIFACT_SHA256_MISMATCH" in codes


def test_unsealed_content_with_the_header_is_refused(root: Path) -> None:
    with pytest.raises(DomainError) as caught:
        ArtifactStore(root).publish_bytes(MAGIC + b"looks sealed")
    assert caught.value.code is DomainErrorCode.ARTIFACT_SOURCE_INVALID
    sealed = ArtifactStore(root).publish_bytes(MAGIC + b"looks sealed", seal=True)
    assert sealed.sha256 == hashlib.sha256(MAGIC + b"looks sealed").hexdigest()


def test_yara_validation_reads_the_sealed_sample(root: Path, tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(CONTENT)
    ArtifactService(root).add("CASE-0001", source, "sample")
    detection = DetectionService(root)
    detection.add_rule(
        "marker",
        "yara",
        'rule marker { strings: $a = "HARMLESS-SEALED-SAMPLE-MARKER" condition: $a }',
    )
    detection.create_benchmark("sealed")
    detection.add_member("BMK-0001", "CASE-0001", "dev")
    run = detection.run_validation("RULE-0001", "BMK-0001")
    assert [r.outcome.value for r in run.results] == ["TP"]


def test_bundle_round_trip_keeps_samples_sealed(root: Path, tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(CONTENT)
    ArtifactService(root).add("CASE-0001", source, "sample")
    bundle = tmp_path / "case.zip"
    BundleService(root).export("CASE-0001", bundle)
    with zipfile.ZipFile(bundle) as archive:
        member = archive.read(f"artifacts/sha256/{SHA[:2]}/{SHA}")
    assert member.startswith(MAGIC) and MARKER not in member
    target = tmp_path / "target"
    ProjectService().create(target, "Target")
    assert BundleService(target).validate(bundle).is_valid
    BundleService(target).import_bundle(bundle)
    assert _files_containing(target, MARKER) == []
    assert validate_workspace(target, full=True).findings == ()


def test_import_zip_never_writes_the_sample_unsealed(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    archive = _aes_zip(downloads / f"{SHA}.zip", {f"{SHA}.exe": CONTENT}, b"infected")
    assert main(["case", "artifact", "import-zip", "CASE-0001", str(archive)]) == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith("ART-000001\tsample\t" + SHA)
    assert _files_containing(root, MARKER) == []
    assert _files_containing(downloads, MARKER) == []  # nothing extracted
    stored = next((root / "artifacts").rglob(SHA))
    assert stored.read_bytes().startswith(MAGIC)


def test_import_zip_errors(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    single = _aes_zip(tmp_path / "one.zip", {"a.exe": CONTENT}, b"infected")
    assert (
        main(
            ["case", "artifact", "import-zip", "CASE-0001", str(single)]
            + ["--password", "wrong"]
        )
        == 2
    )
    assert "ARCHIVE_PASSWORD_REJECTED" in capsys.readouterr().err
    several = _aes_zip(
        tmp_path / "two.zip", {"a.exe": CONTENT, "b.txt": b"readme"}, b"infected"
    )
    assert main(["case", "artifact", "import-zip", "CASE-0001", str(several)]) == 2
    assert "ARCHIVE_INVALID" in capsys.readouterr().err
    args = ["case", "artifact", "import-zip", "CASE-0001", str(several)]
    assert main([*args, "--member", "a.exe"]) == 0
    capsys.readouterr()
    assert main([*args, "--member", "missing.exe"]) == 2
    assert "ARCHIVE_INVALID" in capsys.readouterr().err
    not_zip = tmp_path / "not.zip"
    not_zip.write_bytes(b"not an archive")
    assert main(["case", "artifact", "import-zip", "CASE-0001", str(not_zip)]) == 2
    assert "ARCHIVE_INVALID" in capsys.readouterr().err
    assert len(ArtifactService(root).list_artifacts("CASE-0001")) == 1


def test_read_member_limits_and_plain_archives(tmp_path: Path) -> None:
    archive = _aes_zip(tmp_path / "a.zip", {"a.exe": CONTENT}, b"infected")
    with pytest.raises(DomainError) as caught:
        read_member(archive, max_bytes=100)
    assert caught.value.code is DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED
    with pytest.raises(DomainError) as caught:
        read_member(tmp_path / "missing.zip")
    assert caught.value.code is DomainErrorCode.ARCHIVE_INVALID
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as handle:
        handle.writestr("x/", b"")
        handle.writestr("x/a.bin", b"plain member")
    member = read_member(plain)
    assert (member.name, member.data) == ("x/a.bin", b"plain member")
    # A corrupted member fails its integrity check instead of returning bytes.
    data = bytearray(archive.read_bytes())
    data[data.index(b"a.exe") + 5 + 40] ^= 0xFF
    broken = tmp_path / "broken.zip"
    broken.write_bytes(bytes(data))
    with pytest.raises(DomainError) as caught:
        read_member(broken)
    assert caught.value.code in {
        DomainErrorCode.ARCHIVE_INVALID,
        DomainErrorCode.ARCHIVE_PASSWORD_REJECTED,
    }


def test_sample_intake_from_archive(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _aes_zip(tmp_path / "s.zip", {"s.exe": CONTENT}, b"infected")
    labels = ["--source", "MalwareBazaar", "--source-reference", f"sha256:{SHA}"]
    assert main(["sample", "add", str(archive), "--zip", *labels]) == 0
    assert SHA in capsys.readouterr().out
    assert main(["sample", "add", str(archive), "--zip", *labels]) == 1
    assert "duplicate" in capsys.readouterr().err
    assert main(["sample", "add", str(archive), "--member", "s.exe", *labels]) == 1
    assert "--member requires --zip" in capsys.readouterr().err
    assert _files_containing(root, MARKER) == []
