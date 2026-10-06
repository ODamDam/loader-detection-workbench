"""SQLite candidate-sample repository (schema version 1)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from loader_detection_workbench.sample.domain import (
    AssignmentReason,
    CandidateSample,
    Confidence,
    CriterionStatus,
    DatasetRole,
    DuplicateSampleError,
    DuplicateStatus,
    EligibilityStatus,
    ExclusionReason,
    ExposureState,
    ManifestStatus,
    NotFoundError,
    ReportedRole,
    SampleError,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_samples (
 sample_id TEXT PRIMARY KEY,
 sha256 TEXT NOT NULL UNIQUE,
 source TEXT NOT NULL,
 source_reference TEXT NOT NULL,
 source_record_id TEXT,
 reported_role TEXT NOT NULL,
 role_label_source TEXT,
 role_label_confidence TEXT NOT NULL,
 reported_family TEXT,
 family_label_source TEXT,
 family_label_confidence TEXT NOT NULL,
 manifest_status TEXT NOT NULL,
 eligibility_status TEXT NOT NULL,
 duplicate_status TEXT NOT NULL,
 screening_json TEXT NOT NULL,
 assigned_dataset_role TEXT NOT NULL,
 assignment_reason TEXT,
 assignment_detail TEXT,
 assigned_at TEXT,
 split_id TEXT,
 split_seed INTEGER,
 exclusion_reason TEXT,
 exclusion_detail TEXT,
 exposure_state TEXT NOT NULL,
 detailed_behavior_inspected INTEGER NOT NULL
   CHECK (detailed_behavior_inspected IN (0, 1)),
 first_detailed_access_at TEXT,
 first_execution_at TEXT,
 first_validation_at TEXT,
 benchmark_id TEXT,
 benchmark_version INTEGER,
 benchmark_frozen_at TEXT,
 created_at TEXT NOT NULL
);
"""


class SQLiteSampleRepository:
    """Explicit stdlib SQLite implementation of the repository boundary."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._depth = 0
        self._bootstrap()

    def close(self) -> None:
        self._connection.close()

    def _bootstrap(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, 1}:
            raise SampleError(f"unsupported sample database schema version: {version}")
        if version == 0:
            with self._connection:
                self._connection.executescript(_SCHEMA)
                self._connection.execute("PRAGMA user_version = 1")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        outermost = self._depth == 0
        if outermost:
            self._connection.execute("BEGIN IMMEDIATE")
        self._depth += 1
        try:
            yield
        except Exception:
            if outermost:
                self._connection.rollback()
            raise
        else:
            if outermost:
                self._connection.commit()
        finally:
            self._depth -= 1

    def allocate_sample_id(self) -> str:
        row = self._connection.execute(
            "SELECT MAX(CAST(SUBSTR(sample_id, 5) AS INTEGER)) FROM candidate_samples"
        ).fetchone()
        return f"SMP-{int(row[0] or 0) + 1:06d}"

    def add(self, sample: CandidateSample) -> None:
        columns, values = self._serialize(sample)
        placeholders = ", ".join("?" for _ in columns)
        try:
            self._connection.execute(
                f"INSERT INTO candidate_samples "
                f"({', '.join(columns)}) VALUES ({placeholders})",  # noqa: S608
                values,
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateSampleError(
                "a sample with this SHA-256 already exists"
            ) from exc

    def save(self, sample: CandidateSample) -> None:
        columns, values = self._serialize(sample)
        assignments = ", ".join(
            f"{column} = ?" for column in columns if column != "sample_id"
        )
        update_values = [
            value
            for column, value in zip(columns, values, strict=True)
            if column != "sample_id"
        ]
        cursor = self._connection.execute(
            f"UPDATE candidate_samples SET {assignments} WHERE sample_id = ?",  # noqa: S608
            [*update_values, sample.sample_id],
        )
        if cursor.rowcount != 1:
            raise NotFoundError("candidate sample was not found")

    def get(self, sample_id: str) -> CandidateSample:
        row = self._connection.execute(
            "SELECT * FROM candidate_samples WHERE sample_id = ?", (sample_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("candidate sample was not found")
        return self._deserialize(row)

    def find_by_sha256(self, sha256: str) -> CandidateSample | None:
        row = self._connection.execute(
            "SELECT * FROM candidate_samples WHERE sha256 = ?", (sha256,)
        ).fetchone()
        return None if row is None else self._deserialize(row)

    def list_samples(
        self, status: ManifestStatus | None = None, role: DatasetRole | None = None
    ) -> list[CandidateSample]:
        clauses: list[str] = []
        values: list[str] = []
        if status is not None:
            clauses.append("manifest_status = ?")
            values.append(status.value)
        if role is not None:
            clauses.append("assigned_dataset_role = ?")
            values.append(role.value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self._connection.execute(
            f"SELECT * FROM candidate_samples{where} ORDER BY sample_id",
            values,  # noqa: S608
        ).fetchall()
        return [self._deserialize(row) for row in rows]

    @staticmethod
    def _serialize(sample: CandidateSample) -> tuple[list[str], list[Any]]:
        data: dict[str, Any] = {
            "sample_id": sample.sample_id,
            "sha256": sample.sha256,
            "source": sample.source,
            "source_reference": sample.source_reference,
            "source_record_id": sample.source_record_id,
            "reported_role": sample.reported_role.value,
            "role_label_source": sample.role_label_source,
            "role_label_confidence": sample.role_label_confidence.value,
            "reported_family": sample.reported_family,
            "family_label_source": sample.family_label_source,
            "family_label_confidence": sample.family_label_confidence.value,
            "manifest_status": sample.manifest_status.value,
            "eligibility_status": sample.eligibility_status.value,
            "duplicate_status": sample.duplicate_status.value,
            "screening_json": json.dumps(
                {key: value.value for key, value in sample.screening.items()},
                sort_keys=True,
            ),
            "assigned_dataset_role": sample.assigned_dataset_role.value,
            "assignment_reason": sample.assignment_reason.value
            if sample.assignment_reason
            else None,
            "assignment_detail": sample.assignment_detail,
            "assigned_at": sample.assigned_at,
            "split_id": sample.split_id,
            "split_seed": sample.split_seed,
            "exclusion_reason": sample.exclusion_reason.value
            if sample.exclusion_reason
            else None,
            "exclusion_detail": sample.exclusion_detail,
            "exposure_state": sample.exposure_state.value,
            "detailed_behavior_inspected": int(sample.detailed_behavior_inspected),
            "first_detailed_access_at": sample.first_detailed_access_at,
            "first_execution_at": sample.first_execution_at,
            "first_validation_at": sample.first_validation_at,
            "benchmark_id": sample.benchmark_id,
            "benchmark_version": sample.benchmark_version,
            "benchmark_frozen_at": sample.benchmark_frozen_at,
            "created_at": sample.created_at,
        }
        return list(data), list(data.values())

    @staticmethod
    def _deserialize(row: sqlite3.Row) -> CandidateSample:
        screening = {
            key: CriterionStatus(value)
            for key, value in json.loads(row["screening_json"]).items()
        }
        return CandidateSample(
            sample_id=row["sample_id"],
            sha256=row["sha256"],
            source=row["source"],
            source_reference=row["source_reference"],
            source_record_id=row["source_record_id"],
            reported_role=ReportedRole(row["reported_role"]),
            role_label_source=row["role_label_source"],
            role_label_confidence=Confidence(row["role_label_confidence"]),
            reported_family=row["reported_family"],
            family_label_source=row["family_label_source"],
            family_label_confidence=Confidence(row["family_label_confidence"]),
            manifest_status=ManifestStatus(row["manifest_status"]),
            eligibility_status=EligibilityStatus(row["eligibility_status"]),
            duplicate_status=DuplicateStatus(row["duplicate_status"]),
            screening=screening,
            assigned_dataset_role=DatasetRole(row["assigned_dataset_role"]),
            assignment_reason=AssignmentReason(row["assignment_reason"])
            if row["assignment_reason"]
            else None,
            assignment_detail=row["assignment_detail"],
            assigned_at=row["assigned_at"],
            split_id=row["split_id"],
            split_seed=row["split_seed"],
            exclusion_reason=ExclusionReason(row["exclusion_reason"])
            if row["exclusion_reason"]
            else None,
            exclusion_detail=row["exclusion_detail"],
            exposure_state=ExposureState(row["exposure_state"]),
            detailed_behavior_inspected=bool(row["detailed_behavior_inspected"]),
            first_detailed_access_at=row["first_detailed_access_at"],
            first_execution_at=row["first_execution_at"],
            first_validation_at=row["first_validation_at"],
            benchmark_id=row["benchmark_id"],
            benchmark_version=row["benchmark_version"],
            benchmark_frozen_at=row["benchmark_frozen_at"],
            created_at=row["created_at"],
        )
