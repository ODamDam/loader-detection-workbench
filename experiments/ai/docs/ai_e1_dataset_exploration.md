# AI-E1 Dataset Exploration — Case Summary v0.1

This report describes the benign synthetic fixture
`case_summary_fixture_v0.1.csv`. AI-E1 is descriptive only: it does not repair
missing values, remove duplicates, normalize values, encode categories, or make
a train/test split.

## Dataset structure

The fixture has 13 CSV rows and 12 columns. A row is intended to summarize one
Case, but `C010` appears twice as an exact duplicate, so there are 12 unique
Case identifiers. The duplicate must be resolved as a data-governance decision
before any model dataset is built.

| Group | Columns |
| --- | --- |
| Identifier | `case_id` |
| Dataset metadata | `pool`, `telemetry_quality` |
| Label | `label` |
| Behavioral/telemetry counts | `process_count`, `child_process_count`, `file_create_count`, `module_load_count`, `registry_modify_count`, `network_connect_count`, `dns_query_count` |
| Behavioral timing | `episode_duration_sec` |

The CSV contains no raw process, file, module, registry, network endpoint, or
domain event records. It contains only aggregate Case-level measurements.

## Label and pool distribution

`label` counts are:

| Label | Count |
| ---: | ---: |
| 0 | 9 |
| 1 | 4 |

The positive class is 4/13 (30.8%) and class 0 is 9/13 (69.2%). This is a
small, moderately imbalanced fixture; it is insufficient for conclusions about
generalization or model quality.

Because `C010` is duplicated, a provisional unique-Case view would count label
0 as 8 and label 1 as 4. AI-E1 does not choose between row-level and
Case-level deduplication; that is an explicit AI-E2 data decision.

`pool` counts are:

| Pool | Count |
| --- | ---: |
| `benign` | 5 |
| `loader_positive` | 4 |
| `hard_negative_malware` | 4 |

The pool is metadata and may encode collection or labeling policy. It should be
kept for audit and stratification analysis, not automatically used as a model
feature.

## Data quality

- Missing values: one missing `dns_query_count` value, in `C003`.
- Exact duplicates: one duplicate row after the first occurrence; both rows are
  `C010`. There are two rows in the duplicate group.
- Partial telemetry: `telemetry_quality=partial` occurs once, for `C011`.
- Numeric outlier candidates from 1.5×IQR screening, with no removal:
  - `module_load_count`: row 7 (`C008`, value 310).
  - `registry_modify_count`: row 4 (`C005`, 19), rows 9 and 12 (`C010`, 17).
  - `network_connect_count`: row 5 (`C006`, 12), row 8 (`C009`, 18).
  - `dns_query_count`: row 5 (`C006`, 16), row 8 (`C009`, 24).
  - `episode_duration_sec`: rows 9 and 12 (`C010`, 115.8).

These are review candidates, not errors. A high count may be legitimate behavior,
and duplicate `C010` rows make its influence appear larger.

## Leakage candidates

The following must not be model features:

- `case_id` and any future internal/display Case ID.
- SHA-256 values, artifact paths, filenames, and source paths.
- `pool`, source dataset identifiers, collection batch identifiers, and split
  markers when they reveal how the label was assigned.
- `label` itself and any direct ground-truth field.
- Analyst verdicts, adjudication outcomes, rule matches, or external detector
  results when they encode the target.
- Post-analysis fields or fields generated using the final verdict.

The current fixture has no SHA-256, path, analyst-verdict, or detector-result
columns, but the exclusion policy should be applied when richer Case exports are
introduced.

## Minimal tabular input for AI-E2

Use only evidence-derived measurements:

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

`telemetry_quality` should initially remain a quality/audit field. If later used
as a feature, its semantics and missingness interaction must be explicitly
approved. `case_id`, `pool`, and `label` stay outside the feature matrix.

## Graph-input readiness for AI-E3

The requested graph vocabulary is:

- Nodes: Process, File, Module, Registry, Network Endpoint, Domain.
- Edges: SPAWN, CREATE, MODIFY, DELETE, LOAD, CONNECT, QUERY, TERMINATE.

The fixture cannot construct this graph. It has no event-level identifiers,
timestamps, parent-child process relations, file/module/registry identities,
network endpoints, domains, or event types. AI-E3 needs raw normalized telemetry
or an approved event-level fixture; aggregate counts must not be expanded into
fabricated nodes or edges.

## Criteria to begin AI-E2

Before feature preparation or training, the project should:

1. Decide how the duplicate `C010` records are resolved or retained as separate
   observations.
2. Define a missing-value policy for `dns_query_count` and a policy for the
   partial `C011` telemetry record.
3. Complete a leakage review and freeze the label definition.
4. Specify a Case-level split policy that prevents duplicate/source leakage.
5. Record feature provenance and a reproducible preprocessing configuration.
6. Expand the benign synthetic fixture enough to make class and pool analyses
   meaningful.

No model training, split, graph construction, or external AI/API call is part of
AI-E1.
