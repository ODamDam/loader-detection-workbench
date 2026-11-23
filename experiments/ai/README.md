## AI-E1 Dataset Exploration

From the repository root:

```powershell
uv run python experiments/ai/src/explore_case_summary.py
```

An alternate CSV can be supplied as the first argument. The script prints
structure and quality observations without changing the input file.

## AI-E2 Logistic Regression Baseline

From the repository root, reproduce the frozen synthetic experiment with:

```powershell
uv run --offline --frozen python experiments/ai/src/train_logistic_baseline.py --output experiments/ai/results/ai_e2_logistic_baseline_v0.1.json
```

The script validates the Case Summary v0.1 schema, removes exact duplicate rows,
rejects conflicting Case IDs, creates a deterministic Case-level stratified
split and fits training-only imputation/scaling with one Logistic Regression
model. It never modifies the input fixture. The methodology, recorded metrics
and research limitations are in
[`docs/ai_e2_logistic_baseline.md`](docs/ai_e2_logistic_baseline.md).

Run the focused checks with:

```powershell
uv run --offline --frozen pytest experiments/ai/tests/test_train_logistic_baseline.py
```
