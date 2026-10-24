from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.web.presentation import (
    artifact_views,
    timeline_event_views,
)

FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"


def test_presenters_expose_only_approved_fields(tmp_path: Path) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Web")
    CaseService(root).create("Case", "benign")
    source = tmp_path / "note.txt"
    source.write_text("benign", encoding="utf-8")
    ManualEvidenceService(root).register(
        "CASE-0001",
        source,
        source="analyst",
        evidence_type="analyst_note",
        description="safe description",
    )
    ArtifactService(root).add("CASE-0001", FIXTURES / "process-create.xml", "sysmon")

    artifacts = artifact_views(
        ArtifactService(root).list_artifacts("CASE-0001"),
        ManualEvidenceService(root).list_evidence("CASE-0001"),
        CaseTimelineQuery(root).query("CASE-0001").observations,
    )
    events = timeline_event_views(
        CaseTimelineQuery(root).query("CASE-0001").observations
    )

    assert artifacts[0].classification == "Manual evidence"
    assert artifacts[0].original_filename == "note.txt"
    assert artifacts[0].observation_count == 0
    assert artifacts[1].observation_count == 1
    assert not hasattr(artifacts[0], "relative_path")
    assert not hasattr(artifacts[0], "internal_id")
    assert events[0].event_id == 1
    assert not hasattr(events[0], "command_line")
    assert not hasattr(events[0], "image")
    assert not hasattr(events[0], "process_guid")


def test_other_artifact_is_not_claimed_as_collection_metadata(tmp_path: Path) -> None:
    root = tmp_path / "project"
    ProjectService().create(root, "Web")
    CaseService(root).create("Case", "benign")
    source = tmp_path / "other.json"
    source.write_text("{}", encoding="utf-8")
    ArtifactService(root).add("CASE-0001", source, "other")

    views = artifact_views(ArtifactService(root).list_artifacts("CASE-0001"), [])

    assert views[0].classification == "Other artifact"
