from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd  # type: ignore[import-untyped]
import pytest
from sklearn.impute import SimpleImputer  # type: ignore[import-untyped]
from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AI_SOURCE = _REPO_ROOT / "experiments" / "ai" / "src"
sys.path.insert(0, str(_AI_SOURCE))

from train_logistic_baseline import (  # noqa: E402
    AUDIT_COLUMNS,
    EXPECTED_COLUMNS,
    FEATURE_COLUMNS,
    RANDOM_STATE,
    TEST_SIZE,
    DatasetValidationError,
    classification_metrics,
    fit_pipeline,
    prepare_dataset,
    run_experiment,
    split_dataset,
)

_FIXTURE = _REPO_ROOT / "case_summary_fixture_v0.1.csv"


def _fixture_frame() -> pd.DataFrame:
    return pd.read_csv(_FIXTURE)


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_fixture_schema_and_exact_duplicate_cleanup() -> None:
    frame = _fixture_frame()
    prepared = prepare_dataset(frame)

    assert tuple(frame.columns) == EXPECTED_COLUMNS
    assert prepared.original_row_count == 13
    assert prepared.cleaned_row_count == 12
    assert prepared.exact_duplicate_rows_removed == 1
    assert prepared.duplicate_case_ids_detected == ("C010",)
    assert prepared.metadata["case_id"].is_unique
    assert list(prepared.features.columns) == list(FEATURE_COLUMNS)
    assert list(prepared.metadata.columns) == list(AUDIT_COLUMNS)


@pytest.mark.parametrize("change", ["missing", "extra", "nonnumeric"])
def test_invalid_schema_or_feature_type_is_rejected(change: str) -> None:
    frame = _fixture_frame()
    if change == "missing":
        frame = frame.drop(columns=["dns_query_count"])
    elif change == "extra":
        frame["analyst_verdict"] = "synthetic"
    else:
        frame["process_count"] = "not-numeric"

    with pytest.raises(DatasetValidationError):
        prepare_dataset(frame)


def test_conflicting_case_id_is_rejected() -> None:
    frame = _fixture_frame()
    conflict = frame.iloc[[0]].copy()
    conflict.loc[:, "process_count"] = 999
    frame = pd.concat([frame, conflict], ignore_index=True)

    with pytest.raises(DatasetValidationError, match="conflicting records"):
        prepare_dataset(frame)


def test_feature_leakage_columns_are_kept_outside_model_input() -> None:
    prepared = prepare_dataset(_fixture_frame())

    assert set(prepared.features.columns) == set(FEATURE_COLUMNS)
    assert not set((*AUDIT_COLUMNS, "label")) & set(prepared.features.columns)
    assert prepared.target.name == "label"


def test_split_is_case_disjoint_stratified_and_deterministic() -> None:
    prepared = prepare_dataset(_fixture_frame())
    first = split_dataset(prepared)
    second = split_dataset(prepared)

    assert set(first.train_metadata["case_id"]).isdisjoint(
        first.test_metadata["case_id"]
    )
    assert first.train_metadata.equals(second.train_metadata)
    assert first.test_metadata.equals(second.test_metadata)
    assert first.train_target.tolist() == second.train_target.tolist()
    assert len(first.train_target) == 8
    assert len(first.test_target) == 4
    assert first.train_target.value_counts().to_dict() == {0: 5, 1: 3}
    assert first.test_target.value_counts().to_dict() == {0: 3, 1: 1}


def test_preprocessing_is_fit_from_training_partition_only() -> None:
    prepared = prepare_dataset(_fixture_frame())
    partitions = split_dataset(prepared)
    pipeline = fit_pipeline(partitions)
    imputer = pipeline.named_steps["imputer"]
    scaler = pipeline.named_steps["scaler"]

    assert isinstance(imputer, SimpleImputer)
    assert isinstance(scaler, StandardScaler)
    np.testing.assert_allclose(
        imputer.statistics_, partitions.train_features.median().to_numpy()
    )
    imputed_training = imputer.transform(partitions.train_features)
    np.testing.assert_allclose(scaler.mean_, imputed_training.mean(axis=0))


def test_missing_value_is_imputed_without_becoming_behavioral_absence() -> None:
    prepared = prepare_dataset(_fixture_frame())
    assert prepared.features["dns_query_count"].isna().sum() == 1
    partitions = split_dataset(prepared)
    pipeline = fit_pipeline(partitions)

    assert not np.isnan(pipeline.predict(partitions.test_features)).any()
    assert (
        pipeline.named_steps["imputer"].statistics_[
            list(FEATURE_COLUMNS).index("dns_query_count")
        ]
        != 0
    )


def test_undefined_metrics_are_named_and_zeroed() -> None:
    metrics = classification_metrics(np.array([0, 1]), np.array([0, 0]))

    assert metrics["precision"] == 0.0
    assert metrics["f1"] == 0.0
    assert metrics["undefined_metrics"] == ["precision"]


def test_experiment_is_reproducible_and_fixture_is_unchanged() -> None:
    before = _hash(_FIXTURE)
    first = run_experiment(_FIXTURE)
    second = run_experiment(_FIXTURE)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["configuration"]["random_state"] == RANDOM_STATE
    assert first["configuration"]["test_size"] == TEST_SIZE
    assert first["dataset"]["partial_telemetry_cases_retained"] == ["C011"]
    assert first["partitions"]["case_ids_disjoint"] is True
    assert _hash(_FIXTURE) == before
