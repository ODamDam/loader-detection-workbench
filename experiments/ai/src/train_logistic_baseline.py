"""Run the reproducible AI-E2 Logistic Regression baseline.

The experiment consumes only the synthetic Case Summary v0.1 fixture. It keeps
audit metadata outside the feature matrix, fits preprocessing on the training
partition, and emits deterministic JSON without paths or execution timestamps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd  # type: ignore[import-untyped]
import sklearn  # type: ignore[import-untyped]
from pandas.api.types import (  # type: ignore[import-untyped]
    is_bool_dtype,
    is_numeric_dtype,
)
from sklearn.impute import SimpleImputer  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.metrics import (  # type: ignore[import-untyped]
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split  # type: ignore[import-untyped]
from sklearn.pipeline import Pipeline  # type: ignore[import-untyped]
from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FIXTURE = _REPO_ROOT / "case_summary_fixture_v0.1.csv"
DEFAULT_RESULT = (
    _REPO_ROOT / "experiments" / "ai" / "results" / "ai_e2_logistic_baseline_v0.1.json"
)

FEATURE_COLUMNS = (
    "process_count",
    "child_process_count",
    "file_create_count",
    "module_load_count",
    "registry_modify_count",
    "network_connect_count",
    "dns_query_count",
    "episode_duration_sec",
)
AUDIT_COLUMNS = ("case_id", "pool", "telemetry_quality")
TARGET_COLUMN = "label"
EXPECTED_COLUMNS = (
    "case_id",
    "pool",
    TARGET_COLUMN,
    *FEATURE_COLUMNS,
    "telemetry_quality",
)
RANDOM_STATE = 42
TEST_SIZE = 1.0 / 3.0


class DatasetValidationError(ValueError):
    """Raised when the Case Summary input violates the frozen AI-E2 contract."""


@dataclass(frozen=True)
class PreparedDataset:
    """Validated Case-level model inputs and separately retained audit metadata."""

    original_row_count: int
    cleaned_row_count: int
    exact_duplicate_rows_removed: int
    duplicate_case_ids_detected: tuple[str, ...]
    features: pd.DataFrame
    target: pd.Series
    metadata: pd.DataFrame


@dataclass(frozen=True)
class DatasetSplit:
    """Deterministic, Case-disjoint train and test partitions."""

    train_features: pd.DataFrame
    test_features: pd.DataFrame
    train_target: pd.Series
    test_target: pd.Series
    train_metadata: pd.DataFrame
    test_metadata: pd.DataFrame


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_dataset(frame: pd.DataFrame) -> PreparedDataset:
    """Validate schema, drop exact rows, and reject conflicting Case records."""

    if tuple(frame.columns) != EXPECTED_COLUMNS:
        raise DatasetValidationError("fixture schema does not match Case Summary v0.1")
    if frame.empty:
        raise DatasetValidationError("fixture must contain at least one Case")
    if (
        frame["case_id"].isna().any()
        or not frame["case_id"]
        .map(lambda value: isinstance(value, str) and bool(value.strip()))
        .all()
    ):
        raise DatasetValidationError("case_id values must be non-empty strings")

    for column in (*FEATURE_COLUMNS, TARGET_COLUMN):
        if not is_numeric_dtype(frame[column]) or is_bool_dtype(frame[column]):
            raise DatasetValidationError(f"{column} must be numeric")
        finite = frame[column].dropna().map(np.isfinite)
        if not finite.all():
            raise DatasetValidationError(f"{column} must contain finite values")

    if frame[TARGET_COLUMN].isna().any() or not set(
        frame[TARGET_COLUMN].unique().tolist()
    ).issubset({0, 1}):
        raise DatasetValidationError("label must contain only binary 0/1 values")

    original_row_count = len(frame)
    duplicate_case_ids_detected = tuple(
        sorted(
            frame.loc[frame["case_id"].duplicated(keep=False), "case_id"]
            .astype(str)
            .unique()
            .tolist()
        )
    )
    cleaned = frame.drop_duplicates(keep="first").copy()
    duplicate_case_ids = cleaned["case_id"].duplicated(keep=False)
    if duplicate_case_ids.any():
        raise DatasetValidationError("conflicting records share the same case_id")

    features = cleaned.loc[:, FEATURE_COLUMNS].copy()
    target = cleaned.loc[:, TARGET_COLUMN].astype(int).copy()
    metadata = cleaned.loc[:, AUDIT_COLUMNS].copy()
    return PreparedDataset(
        original_row_count=original_row_count,
        cleaned_row_count=len(cleaned),
        exact_duplicate_rows_removed=original_row_count - len(cleaned),
        duplicate_case_ids_detected=duplicate_case_ids_detected,
        features=features,
        target=target,
        metadata=metadata,
    )


def split_dataset(
    dataset: PreparedDataset,
    *,
    random_state: int = RANDOM_STATE,
    test_size: float = TEST_SIZE,
) -> DatasetSplit:
    """Create a deterministic stratified split and enforce Case separation."""

    try:
        train_indexes, test_indexes = train_test_split(
            dataset.features.index,
            test_size=test_size,
            random_state=random_state,
            stratify=dataset.target,
        )
    except ValueError as error:
        raise DatasetValidationError("stratified Case split is not possible") from error

    train_indexes = sorted(
        train_indexes, key=lambda index: str(dataset.metadata.loc[index, "case_id"])
    )
    test_indexes = sorted(
        test_indexes, key=lambda index: str(dataset.metadata.loc[index, "case_id"])
    )
    train_metadata = dataset.metadata.loc[train_indexes].reset_index(drop=True)
    test_metadata = dataset.metadata.loc[test_indexes].reset_index(drop=True)
    train_ids = set(train_metadata["case_id"].tolist())
    test_ids = set(test_metadata["case_id"].tolist())
    if train_ids & test_ids:
        raise DatasetValidationError("a case_id appears in both partitions")

    return DatasetSplit(
        train_features=dataset.features.loc[train_indexes].reset_index(drop=True),
        test_features=dataset.features.loc[test_indexes].reset_index(drop=True),
        train_target=dataset.target.loc[train_indexes].reset_index(drop=True),
        test_target=dataset.target.loc[test_indexes].reset_index(drop=True),
        train_metadata=train_metadata,
        test_metadata=test_metadata,
    )


def build_pipeline() -> Pipeline:
    """Build the single frozen AI-E2 baseline pipeline."""

    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    C=1.0,
                    class_weight=None,
                    fit_intercept=True,
                    l1_ratio=0.0,
                    max_iter=1000,
                    random_state=RANDOM_STATE,
                    solver="lbfgs",
                    tol=0.0001,
                ),
            ),
        ]
    )


def fit_pipeline(partitions: DatasetSplit) -> Pipeline:
    """Fit preprocessing and the model using the training partition only."""

    pipeline = build_pipeline()
    pipeline.fit(partitions.train_features, partitions.train_target)
    return pipeline


def classification_metrics(
    actual: pd.Series | np.ndarray[Any, Any],
    predicted: pd.Series | np.ndarray[Any, Any],
) -> dict[str, Any]:
    """Calculate binary metrics with an explicit undefined-value policy."""

    actual_array = np.asarray(actual, dtype=int)
    predicted_array = np.asarray(predicted, dtype=int)
    undefined: list[str] = []
    if int(np.sum(predicted_array == 1)) == 0:
        undefined.append("precision")
    if int(np.sum(actual_array == 1)) == 0:
        undefined.append("recall")
    if (
        int(
            2 * np.sum((actual_array == 1) & (predicted_array == 1))
            + np.sum((actual_array == 0) & (predicted_array == 1))
            + np.sum((actual_array == 1) & (predicted_array == 0))
        )
        == 0
    ):
        undefined.append("f1")
    return {
        "confusion_matrix": confusion_matrix(
            actual_array, predicted_array, labels=[0, 1]
        ).tolist(),
        "confusion_matrix_labels": [0, 1],
        "precision": float(
            precision_score(actual_array, predicted_array, zero_division=0.0)
        ),
        "recall": float(recall_score(actual_array, predicted_array, zero_division=0.0)),
        "f1": float(f1_score(actual_array, predicted_array, zero_division=0.0)),
        "undefined_metrics": undefined,
        "undefined_metric_policy": "report 0.0 and name the undefined metric",
    }


def _label_distribution(target: pd.Series) -> dict[str, int]:
    counts = target.value_counts().to_dict()
    return {"0": int(counts.get(0, 0)), "1": int(counts.get(1, 0))}


def _audit_rows(metadata: pd.DataFrame) -> list[dict[str, str]]:
    return [
        {
            "case_id": str(row.case_id),
            "pool": str(row.pool),
            "telemetry_quality": str(row.telemetry_quality),
        }
        for row in metadata.itertuples(index=False)
    ]


def _prediction_rows(
    metadata: pd.DataFrame, actual: pd.Series, predicted: np.ndarray[Any, Any]
) -> list[dict[str, Any]]:
    return [
        {
            "case_id": str(case_id),
            "actual_label": int(actual_value),
            "predicted_label": int(predicted_value),
        }
        for case_id, actual_value, predicted_value in zip(
            metadata["case_id"], actual, predicted, strict=True
        )
    ]


def run_experiment(fixture: Path) -> dict[str, Any]:
    """Load, validate, split, train, and evaluate the frozen baseline once."""

    frame = pd.read_csv(fixture)
    dataset = prepare_dataset(frame)
    partitions = split_dataset(dataset)
    pipeline = fit_pipeline(partitions)
    train_predictions = pipeline.predict(partitions.train_features)
    test_predictions = pipeline.predict(partitions.test_features)
    partial_cases = dataset.metadata.loc[
        dataset.metadata["telemetry_quality"] == "partial", "case_id"
    ].astype(str)

    return {
        "experiment": "AI-E2 Logistic Regression Baseline",
        "dataset": {
            "name": "Case Summary v0.1 synthetic fixture",
            "sha256": _sha256(fixture),
            "original_row_count": dataset.original_row_count,
            "cleaned_row_count": dataset.cleaned_row_count,
            "exact_duplicate_rows_removed": dataset.exact_duplicate_rows_removed,
            "duplicate_case_ids_detected": list(dataset.duplicate_case_ids_detected),
            "unique_case_count": int(dataset.metadata["case_id"].nunique()),
            "partial_telemetry_cases_retained": sorted(partial_cases.tolist()),
        },
        "configuration": {
            "random_state": RANDOM_STATE,
            "test_size": TEST_SIZE,
            "stratify_by": TARGET_COLUMN,
            "feature_order": list(FEATURE_COLUMNS),
            "excluded_from_features": [*AUDIT_COLUMNS, TARGET_COLUMN],
            "pipeline": [
                {"step": "SimpleImputer", "strategy": "median"},
                {"step": "StandardScaler"},
                {
                    "step": "LogisticRegression",
                    "C": 1.0,
                    "class_weight": None,
                    "fit_intercept": True,
                    "l1_ratio": 0.0,
                    "max_iter": 1000,
                    "random_state": RANDOM_STATE,
                    "solver": "lbfgs",
                    "tol": 0.0001,
                },
            ],
            "test_set_use": "single final evaluation; no model selection or tuning",
        },
        "environment": {
            "python": (
                f"{sys.version_info.major}.{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "partitions": {
            "train_case_count": len(partitions.train_target),
            "test_case_count": len(partitions.test_target),
            "train_label_distribution": _label_distribution(partitions.train_target),
            "test_label_distribution": _label_distribution(partitions.test_target),
            "case_ids_disjoint": True,
        },
        "audit_metadata": {
            "train": _audit_rows(partitions.train_metadata),
            "test": _audit_rows(partitions.test_metadata),
        },
        "predictions": {
            "train": _prediction_rows(
                partitions.train_metadata,
                partitions.train_target,
                train_predictions,
            ),
            "test": _prediction_rows(
                partitions.test_metadata,
                partitions.test_target,
                test_predictions,
            ),
        },
        "test_metrics": classification_metrics(
            partitions.test_target, test_predictions
        ),
        "limitations": [
            (
                "Only 12 unique synthetic Cases are available; the test partition "
                "has 4 Cases."
            ),
            (
                "The partial-telemetry Case C011 is retained and may not be "
                "comparable to complete Cases."
            ),
            (
                "Median imputation represents a missing measurement, not observed "
                "behavioral absence."
            ),
            (
                "This result is not real-world malware detection performance or a "
                "final unseen evaluation."
            ),
        ],
    }


def _render_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "fixture",
        nargs="?",
        type=Path,
        default=DEFAULT_FIXTURE,
        help="synthetic Case Summary CSV",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write deterministic JSON here instead of stdout",
    )
    arguments = parser.parse_args()
    if arguments.output is not None and (
        arguments.output.resolve() == arguments.fixture.resolve()
    ):
        parser.error("output must not replace the input fixture")
    try:
        result = run_experiment(arguments.fixture)
    except (OSError, DatasetValidationError, pd.errors.ParserError) as error:
        parser.error(str(error))
    rendered = _render_json(result)
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
