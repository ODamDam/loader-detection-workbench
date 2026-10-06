from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

import pytest

from loader_detection_workbench.domain.artifact import (
    Artifact,
    ArtifactKind,
    canonical_path,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, generate_ulid
from loader_detection_workbench.domain.paths import ProjectRelativePath


def metadata() -> Artifact:
    return Artifact(
        ArtifactId(generate_ulid(), "ART-000001"),
        generate_ulid(),
        generate_ulid(),
        ArtifactKind.OTHER,
        canonical_path("a" * 64),
        "a" * 64,
        0,
        datetime(2026, 9, 17, tzinfo=UTC),
    )


@pytest.mark.parametrize("kind", list(ArtifactKind))
def test_kind_vocabulary(kind: ArtifactKind) -> None:
    assert ArtifactKind.parse(kind.value) is kind


@pytest.mark.parametrize("kind", ["", "Other", "OTHER", " other", "other ", "unknown"])
def test_kind_rejects_non_exact_values(kind: str) -> None:
    with pytest.raises(DomainError) as caught:
        ArtifactKind.parse(kind)
    assert caught.value.code is DomainErrorCode.INVALID_ARTIFACT_KIND


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "g" * 64, "../", ""])
def test_hash_validation(digest: str) -> None:
    with pytest.raises(DomainError):
        canonical_path(digest)


def test_immutable_metadata_and_canonical_path() -> None:
    artifact = metadata()
    assert artifact.relative_path.as_posix() == "artifacts/sha256/aa/" + "a" * 64
    with pytest.raises(FrozenInstanceError):
        artifact.size_bytes = 1
    for size in (-1, True):
        with pytest.raises(DomainError):
            replace(artifact, size_bytes=size)
    with pytest.raises(DomainError):
        replace(artifact, relative_path=ProjectRelativePath.parse("artifacts/wrong"))
    with pytest.raises(DomainError):
        replace(artifact, created_at=datetime(2026, 9, 17))
