# Sysmon Event ID 1 handoff — 2026-10-06

## Result and approved contract

The approved minimal Event ID 1 slice is implemented and verified:

```text
Synthetic XML -> attached Sysmon Artifact -> verified content bytes
              -> ProcessCreateEvent -> ArtifactId + EventRecordID
```

`SysmonService(root).normalize(case_display_id, artifact_display_id)` reads an
existing Case's attached Sysmon Artifact and returns exactly one event in memory.
No DB migration, event persistence, CLI command or dependency was added.
README contains the calling example; `docs/05-data-model.md` defines the fields,
input restrictions, timestamp precision and error identities.

Investigation found no normalized event class or Artifact-to-record contract.
The user explicitly approved the proposed minimal model after the initial
handoff: timestamp, event_id, process_guid, process_id, image, command_line,
source_artifact_id and source_record_id. ArtifactId and UTC conventions are
reused. This closes the earlier contract blocker.

## Git and preserved baseline

- Repository: `ODamDam/loader-detection-workbench`.
- Branch: `feat/sysmon-normalization-20261006`.
- Tracking: `origin/feat/sysmon-normalization-20261006`.
- M1 checkpoint: `9280606a2c807c51c88bf9d19fca25e758ebf832`, pushed before Sysmon work.
- Initial HEAD and origin/main were both `a27fd4f`; local M1 was uncommitted.
- The checkpoint preserved M1, Sample Intake, existing AI-E1 synthetic fixtures
  and development files, including the pre-existing pandas dev dependency.
- The subsequent `feat: add Sysmon Event ID 1 normalization slice` commit holds
  this implementation. Use `git rev-parse HEAD` after fetching this branch for
  the exact latest commit; do not resume from origin/main.
- `migration-note.txt` remains local/untracked because it contains machine-local
  path information. It must not be uploaded and is not needed for development.

## Changed files

- `src/loader_detection_workbench/domain/events.py`: immutable result.
- `src/loader_detection_workbench/domain/errors.py`: stable validation errors.
- `src/loader_detection_workbench/artifact/store.py`: bounded read that verifies
  hash/size of exactly the returned bytes.
- `src/loader_detection_workbench/sysmon/`: parser and Case application service.
- `tests/fixtures/public/sysmon/process-create.xml`: invented benign XML.
- `tests/unit/test_sysmon_normalizer.py`: mapping, traceability, malformed XML,
  invalid/missing/duplicate fields, unsupported event/provider, DTD and limits.
- `tests/integration/test_sysmon_service.py`: temporary Project/Case/Artifact,
  workspace move, wrong attachment/kind, content integrity errors, malformed
  source with no mutation, and closed Case reads.
- README, data-model documentation, PLANS and this handoff.

## Validation

| Check | Final result |
| --- | --- |
| `uv run pytest tests/unit/test_sysmon_normalizer.py tests/integration/test_sysmon_service.py` | PASS: 30 tests |
| `uv run pytest` | PASS: 347 tests |
| `uv lock --check` | PASS |
| `uv run ruff check .` | PASS |
| `uv run ruff format --check .` | PASS: 70 files |
| `uv run mypy src` | PASS: 41 files; official README/PLANS gate |
| `uv run mypy src tests/unit/test_sysmon_normalizer.py tests/integration/test_sysmon_service.py` | PASS: 43 files |
| `uv run mypy src tests` | FAIL: same 6 pre-existing Artifact-test errors |
| `git diff --check` | PASS |

The initial lint run flagged constant `setattr` in the immutability test; it was
corrected and lint plus targeted tests passed again. The extra mypy errors are
in `test_artifact_domain.py` and `test_artifact_store.py`: an intentional frozen
assignment, an untyped callback and implicit re-exports used by monkeypatch.
No unrelated fixes were included. No required offline check remains unrun.
Real telemetry, VM, Guest Orchestrator and simulator execution were not run.

## Self-review and limitations

- Existing Case/Artifact API, IDs, relative paths, domain errors and UTC rules
  are reused. DB v1 and Bundle v1 remain unchanged.
- Accepts one namespaced Event ID 1 with a 1 MiB cap. Malformed XML, DTD,
  unsupported events and missing/ambiguous fields fail closed.
- Tests follow ArtifactId + EventRecordID back to content in the existing Case,
  including after moving the workspace. No host absolute paths are stored.
- Sub-second time is truncated by the existing UTC convention; original XML
  preserves precision. Parent/User fields are not mapped.
- Results are read-only and in-memory. Later concurrent detach is not prevented;
  durable normalized-event storage is not implemented.
- Fixture data is entirely invented. Image/CommandLine are never executed.
  No raw logs, samples, credentials or runtime workspace were staged.
- No Event ID 11, generic Evidence graph, AI, new CLI or report integration.
- M1 changes are in a separate checkpoint; feature changes are limited to this
  slice. Existing test typing errors remain a separate issue.

## Resume on another device

Inspect that device's working tree and preserve local changes first. With a
clean, non-divergent checkout:

```powershell
git fetch origin
git switch feat/sysmon-normalization-20261006
git pull --ff-only
git rev-parse HEAD
uv sync
uv run pytest tests/unit/test_sysmon_normalizer.py tests/integration/test_sysmon_service.py
```

If commits diverge, stop and report; do not reset, force push or rebase.
Next work, after separate scope approval: Event ID 11 and Case query/Markdown
report integration. This slice's service and source references are the starting
point for that demo work.
