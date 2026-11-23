"""Print an honest first look at the synthetic Case Summary fixture.

This is an exploration script, not a training pipeline.  It intentionally
does not drop duplicates, fill missing values, normalize fields, encode
categories, or split the data.  Those decisions belong to a later, reviewed
AI-E2 preparation step.
"""

from __future__ import annotations

import argparse
from io import StringIO
from pathlib import Path

import pandas as pd
from case_summary_data import load_case_summary, numeric_outlier_candidates

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_FIXTURE = _REPO_ROOT / "case_summary_fixture_v0.1.csv"
_TELEMETRY_NAMES = (
    "telemetry",
    "process",
    "file",
    "module",
    "registry",
    "network",
    "dns",
    "duration",
)
_LABEL_NAMES = ("label", "target", "class", "verdict", "ground_truth")
_POOL_NAMES = ("pool", "dataset", "split", "source")


def _find_column(frame: pd.DataFrame, names: tuple[str, ...]) -> str | None:
    """Find the first column whose normalized name matches a known concept."""

    for column in frame.columns:
        normalized = str(column).lower()
        if any(name == normalized or name in normalized for name in names):
            return str(column)
    return None


def _print_series(title: str, values: pd.Series) -> None:
    print(f"\n{title}")
    print(values.to_string())


def explore_case_summary(frame: pd.DataFrame) -> None:
    """Print structural, quality, label, telemetry, and outlier observations."""

    print("=== first rows ===")
    print(frame.head().to_string(index=False))
    print(f"\n=== shape ===\n{frame.shape}")
    print(f"\n=== columns ===\n{list(frame.columns)}")
    print("\n=== dtypes ===")
    print(frame.dtypes.to_string())
    info = StringIO()
    frame.info(buf=info)
    print("\n=== info ===")
    print(info.getvalue(), end="")
    print("\n=== describe(include='all') ===")
    print(frame.describe(include="all").to_string())

    _print_series("=== missing-value counts ===", frame.isna().sum())
    print(
        "\n=== exact duplicate rows ===\n"
        f"{int(frame.duplicated(keep=False).sum())} rows in duplicate groups"
    )
    print(
        "=== duplicate row count after first occurrence ===\n"
        f"{int(frame.duplicated().sum())}"
    )

    case_column = _find_column(frame, ("case_id", "caseid", "case"))
    if case_column is not None:
        print(
            f"\n=== unique Case count ({case_column}) ===\n"
            f"{frame[case_column].nunique(dropna=False)}"
        )
    label_column = _find_column(frame, _LABEL_NAMES)
    if label_column is not None:
        _print_series(
            f"=== label distribution ({label_column}) ===",
            frame[label_column].value_counts(dropna=False),
        )
    pool_column = _find_column(frame, _POOL_NAMES)
    if pool_column is not None:
        _print_series(
            f"=== pool distribution ({pool_column}) ===",
            frame[pool_column].value_counts(dropna=False),
        )

    telemetry_columns = [
        str(column)
        for column in frame.columns
        if any(token in str(column).lower() for token in _TELEMETRY_NAMES)
    ]
    print(f"\n=== telemetry-quality columns ===\n{telemetry_columns}")
    for column in telemetry_columns:
        _print_series(
            f"distribution: {column}", frame[column].value_counts(dropna=False)
        )

    outliers = numeric_outlier_candidates(frame)
    print("\n=== numeric outlier candidates (IQR, no removal) ===")
    if not outliers:
        print("none")
    else:
        for column, rows in outliers.items():
            print(f"{column}: row indexes {rows}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "fixture",
        nargs="?",
        type=Path,
        default=_DEFAULT_FIXTURE,
        help="Case Summary CSV (default: repository fixture)",
    )
    arguments = parser.parse_args()
    frame = load_case_summary(arguments.fixture)
    explore_case_summary(frame)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
