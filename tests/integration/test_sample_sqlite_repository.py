from pathlib import Path

import pytest

from loader_detection_workbench.sample.domain import (
    CandidateSample,
    DuplicateSampleError,
)
from loader_detection_workbench.sample.sqlite_repository import SQLiteSampleRepository


def test_bootstrap_crud_duplicate_and_round_trip(tmp_path: Path) -> None:
    repository = SQLiteSampleRepository(tmp_path / "samples.db")
    sample = CandidateSample(
        sample_id=repository.allocate_sample_id(),
        sha256="a" * 64,
        source="repo",
        source_reference="record",
        created_at="2026-01-01T00:00:00Z",
    )
    with repository.transaction():
        repository.add(sample)
    assert repository.get(sample.sample_id) == sample
    with pytest.raises(DuplicateSampleError), repository.transaction():
        repository.add(sample)
    assert repository._connection.execute("PRAGMA user_version").fetchone()[0] == 1
    repository.close()


def test_transaction_rolls_back(tmp_path: Path) -> None:
    repository = SQLiteSampleRepository(tmp_path / "samples.db")
    sample = CandidateSample(
        sample_id="SMP-000001",
        sha256="b" * 64,
        source="repo",
        source_reference="record",
        created_at="2026-01-01T00:00:00Z",
    )
    with pytest.raises(RuntimeError), repository.transaction():
        repository.add(sample)
        raise RuntimeError
    assert repository.list_samples() == []
    repository.close()
