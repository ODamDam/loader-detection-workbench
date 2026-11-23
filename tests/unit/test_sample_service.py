from pathlib import Path

import pytest

from loader_detection_workbench.sample.domain import (
    SCREENING_FIELDS,
    ContractViolation,
    CriterionStatus,
)
from loader_detection_workbench.sample.service import SampleService
from loader_detection_workbench.sample.sqlite_repository import SQLiteSampleRepository


def test_service_screen_then_eligible(tmp_path: Path) -> None:
    fixture = tmp_path / "benign.txt"
    fixture.write_text("harmless", encoding="utf-8")
    repository = SQLiteSampleRepository(tmp_path / "samples.db")
    service = SampleService(repository)
    added = service.add(fixture, source="test", source_reference="fixture")
    service.screen(
        added.sample_id, {key: CriterionStatus.PASS for key in SCREENING_FIELDS}
    )
    assert service.eligible(added.sample_id).manifest_status.value == "eligible"
    repository.close()


def test_incomplete_screen_cannot_be_eligible(tmp_path: Path) -> None:
    fixture = tmp_path / "benign.txt"
    fixture.write_text("harmless", encoding="utf-8")
    repository = SQLiteSampleRepository(tmp_path / "samples.db")
    service = SampleService(repository)
    added = service.add(fixture, source="test", source_reference="fixture")
    with pytest.raises(ContractViolation):
        service.eligible(added.sample_id)
    repository.close()
