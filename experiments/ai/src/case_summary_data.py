"""Small, deliberately non-destructive helpers for Case Summary exploration.

The helpers in this module describe the fixture without changing it.  In
particular, missing values, duplicate rows, and unusual numeric values are
reported to the caller instead of being repaired or removed.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def load_case_summary(path: Path) -> pd.DataFrame:
    """Load a Case Summary CSV exactly as pandas infers it."""

    return pd.read_csv(path)


def numeric_outlier_candidates(
    frame: pd.DataFrame, *, multiplier: float = 1.5
) -> dict[str, list[object]]:
    """Return values outside the IQR fences, without removing any rows.

    IQR fences are a screening heuristic.  A candidate can be a legitimate
    high-activity Case, so callers must inspect the corresponding row and
    telemetry context before making any data decision.
    """

    candidates: dict[str, list[object]] = {}
    for column in frame.select_dtypes(include="number").columns:
        values = frame[column].dropna()
        if values.empty:
            continue
        first_quartile = values.quantile(0.25)
        third_quartile = values.quantile(0.75)
        spread = third_quartile - first_quartile
        lower = first_quartile - multiplier * spread
        upper = third_quartile + multiplier * spread
        mask = (frame[column] < lower) | (frame[column] > upper)
        if mask.any():
            candidates[column] = frame.index[mask].tolist()
    return candidates
