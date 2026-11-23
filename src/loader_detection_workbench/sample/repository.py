"""Persistence abstraction for candidate samples."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol

from loader_detection_workbench.sample.domain import (
    CandidateSample,
    DatasetRole,
    ManifestStatus,
)


class SampleRepository(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...
    def allocate_sample_id(self) -> str: ...
    def add(self, sample: CandidateSample) -> None: ...
    def get(self, sample_id: str) -> CandidateSample: ...
    def find_by_sha256(self, sha256: str) -> CandidateSample | None: ...
    def list_samples(
        self, status: ManifestStatus | None = None, role: DatasetRole | None = None
    ) -> list[CandidateSample]: ...
    def save(self, sample: CandidateSample) -> None: ...
