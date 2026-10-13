# AI-E2 Behavioral Feature Logistic Regression Baseline

AI-E2 is the first reproducible training experiment over the synthetic
`case_summary_fixture_v0.1.csv`. It trains exactly one Logistic Regression
baseline. The test partition is used once for the recorded evaluation, not for
feature selection, model selection or hyperparameter tuning.

## Data preparation contract

The input must match the Case Summary v0.1 schema exactly. The eight ordered
model features are:

```text
process_count
child_process_count
file_create_count
module_load_count
registry_modify_count
network_connect_count
dns_query_count
episode_duration_sec
```

`case_id`, `pool` and `telemetry_quality` are retained separately as audit
metadata. `label` is the binary target. None of these four fields enters the
feature matrix. Unknown columns are rejected so identifiers, sources, verdicts,
rule results and target-derived fields cannot silently enter this baseline.

The fixture has 13 original rows. `C010` occurs twice as an exactly identical
row, so one duplicate row is removed. The cleaned dataset has 12 unique Case
IDs. After exact-row removal, any repeated Case ID is treated as a conflicting
record and fails closed. The original fixture is read only and its SHA-256 is
recorded in the result.

The missing `dns_query_count` measurement for `C003` is retained. Median
imputation is fitted from the training partition only. An imputed measurement
means that the value was unavailable; it does not mean the behavior was
observed to be absent or zero. `C011` remains in the dataset with
`telemetry_quality=partial` and is called out as a quality limitation.

## Frozen experiment configuration

- Split: Case-level stratified train/test split by `label`.
- Seed: `random_state=42`.
- Test size: `1/3`.
- Pipeline: `SimpleImputer(strategy="median")`, `StandardScaler`, then
  `LogisticRegression`.
- Logistic Regression: `C=1.0`, `solver="lbfgs"`, `l1_ratio=0.0`,
  `class_weight=None`, `fit_intercept=True`, `max_iter=1000`, `tol=0.0001`,
  `random_state=42`.
- Undefined metrics: report `0.0` and name each undefined metric explicitly.

The imputer, scaler and model are fitted by one scikit-learn `Pipeline` using
only the eight training Cases. Train and test Case IDs are checked for
disjointness before fitting.

## Recorded result

The deterministic machine-readable result is
`experiments/ai/results/ai_e2_logistic_baseline_v0.1.json`.

| Partition | Cases | Label 0 | Label 1 |
| --- | ---: | ---: | ---: |
| Train | 8 | 5 | 3 |
| Test | 4 | 3 | 1 |

The test confusion matrix uses actual labels as rows and predicted labels as
columns, both ordered `[0, 1]`:

|  | Predicted 0 | Predicted 1 |
| --- | ---: | ---: |
| Actual 0 | 2 | 1 |
| Actual 1 | 1 | 0 |

| Metric | Value |
| --- | ---: |
| Precision | 0.0 |
| Recall | 0.0 |
| F1 | 0.0 |

No recorded metric is mathematically undefined in this run: the test set has
one positive label and the model makes one positive prediction. The zero values
come from no true-positive prediction. Per-Case train/test predictions and the
separate audit metadata are retained in the JSON result.

## Reproducibility and limitations

The stored result and two immediate reruns in the locked environment were
byte-identical. The fixture SHA-256 was unchanged before and after training.
The result intentionally excludes timestamps, UUIDs and absolute paths.

This is a 12-Case synthetic experiment with only four test Cases. One of those
test Cases, `C011`, has partial telemetry. A single prediction change would
materially change every reported metric. The result cannot establish
generalization, real-world malware detection performance or performance on a
final unseen dataset. Research interpretation and any later experimental
decision remain subject to user review and approval.
