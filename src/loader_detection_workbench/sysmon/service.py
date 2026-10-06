"""Read-only normalization of a Sysmon Artifact attached to an existing Case."""

from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.events import NormalizedSysmonEvent
from loader_detection_workbench.domain.ids import ArtifactId
from loader_detection_workbench.sysmon.normalizer import (
    MAX_XML_BYTES,
    normalize_sysmon_event,
)


class SysmonService:
    def __init__(self, root: Path) -> None:
        self._root = root

    def normalize(
        self, case_display_id: str, artifact_display_id: str
    ) -> list[NormalizedSysmonEvent]:
        ArtifactId("00000000000000000000000000", artifact_display_id)
        artifacts = ArtifactService(self._root).list_artifacts(case_display_id)
        artifact = next(
            (a for a in artifacts if a.artifact_id.display_id == artifact_display_id),
            None,
        )
        if artifact is None:
            raise DomainError(
                DomainErrorCode.ARTIFACT_NOT_ATTACHED,
                "requested artifact is not attached to this case",
            )
        if artifact.kind is not ArtifactKind.SYSMON:
            raise DomainError(
                DomainErrorCode.INVALID_ARTIFACT_KIND, "a Sysmon artifact is required"
            )
        data = ArtifactStore(self._root).read_verified(
            artifact.relative_path,
            (artifact.sha256, artifact.size_bytes),
            max_bytes=MAX_XML_BYTES,
        )
        return normalize_sysmon_event(data, artifact.artifact_id)
