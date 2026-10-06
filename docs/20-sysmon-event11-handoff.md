# Sysmon Event ID 1 + 11 handoff — 2026-10-06

## Current support

- Input: one namespaced Windows Event XML, exercised with invented benign fixtures.
- Event ID 1 -> immutable `ProcessCreateEvent`.
- Event ID 11 -> immutable `FileCreateEvent`.
- Output: a one-element list of memory-only normalized events.
- Provenance: existing ArtifactId (ULID + display ID) and XML EventRecordID.
- Shared entry: `normalize_sysmon_event(xml, source_artifact_id)`.
- `normalize_process_create()` remains Event ID 1 only, with its original result
  type and rejection of other event IDs, including 11.
- `SysmonService.normalize(case_display_id, artifact_display_id)` retains its
  arguments and returns `list[ProcessCreateEvent | FileCreateEvent]`.

The user explicitly approved the FileCreateEvent fields and common dispatch.
The exact contract and error rules are in `docs/05-data-model.md`, with calling
examples in README. Consumers can narrow the union with `isinstance` before
accessing event-specific fields. No base class or generic Evidence schema exists.

## Git baseline and handoff

- Repository: `ODamDam/loader-detection-workbench`.
- Branch: `feat/sysmon-normalization-20261006`.
- Tracking: `origin/feat/sysmon-normalization-20261006`.
- Starting local and remote SHA: `15469c1a168460ac2ffa2b59a6c9a4ba68e59e16`.
- Prior M1 work remains preserved in checkpoint `9280606`.
- Implementation commit: `feat: add Sysmon Event ID 11 normalization`.
  Use the branch HEAD after fetch for its exact SHA.
- Local-only `migration-note.txt` is unchanged and excluded from upload because
  it contains machine-local path information. No other user changes were present.

## Implementation and self-review

- `domain/events.py`: FileCreateEvent with only the nine approved fields and a
  simple `NormalizedSysmonEvent` union. Frozen dataclass/slots, ArtifactId,
  validation conventions and `require_utc` are reused.
- `domain/errors.py`: `INVALID_FILE_CREATE` in the validation category.
- `sysmon/normalizer.py`: single XML parser, shared field/time checks and dispatch.
  No parser/service duplication. Legacy ID 1 error identities remain compatible.
- `sysmon/service.py`: dispatches verified bytes through the common entry point.
  Attachment, kind, hash/size, byte cap and content-store handling are unchanged.
- `tests/fixtures/public/sysmon/file-create.xml`: wholly invented benign data,
  same invented process GUID as the Process Create fixture, separate record ID.
- Existing Sysmon unit/integration files cover both events, failures and regression.
- README, data model, PLANS and handoff documents reflect the current boundary.

Image and TargetFilename are strings, never opened or executed. No real username,
hostname, host path, telemetry, malware, runtime workspace or secret was added.
There is no DB migration, new dependency, CLI, collector, VM operation or report
implementation. All changes are within the approved normalization slice.

## Validation

| Command | Final result |
| --- | --- |
| `uv run pytest tests/unit/test_sysmon_normalizer.py tests/integration/test_sysmon_service.py` | PASS: 54 tests |
| `uv run pytest` | PASS: 371 tests |
| `uv lock --check` | PASS |
| `uv run ruff check .` | PASS |
| `uv run ruff format --check .` | PASS: 70 files |
| `uv run mypy src` | PASS: 41 files |
| `uv run mypy src tests/unit/test_sysmon_normalizer.py tests/integration/test_sysmon_service.py` | PASS: 43 files |
| `uv run mypy src tests` | FAIL: only the same 6 pre-existing Artifact-test errors |
| `git diff --check` | PASS |

Initial formatting/import findings were fixed. The first mypy run found four
new errors caused by inferring a mixed event list as `list[object]`; declaring
`list[NormalizedSysmonEvent]` fixed them. No new type errors remain. The existing
six Artifact-test errors were not changed. One concurrent Ruff check reported
a cache-write warning; the subsequent format check passed without the warning.

Tests verify File Create mapping, both UTC values, required TargetFilename,
invalid PID/GUID/times, malformed XML, duplicate fields, source references,
unsupported event rejection, DTD and size cap. Integration covers both Artifact
types in the same Case, closed Case reads after relocation, time ordering,
provenance and unchanged DB bytes, plus invalid File Create failure.

No required offline verification remains unrun. Actual Sysmon collection,
VMware, Guest Orchestrator and analysis-target execution were not run.

## Limits and next task

- Input remains one Event, max 1 MiB; no multi-event container, EVTX or streaming.
- Both timestamps follow existing second-precision UTC policy; raw XML retains
  sub-second values. Results are not persisted.
- Source attachment is checked during reading; long-term locking against later
  concurrent detach remains out of scope.
- Event IDs other than 1 and 11 fail closed. TargetFilename has no filesystem
  semantics in the normalizer.
- Existing Artifact-test typing errors remain a separate maintenance item.

The next implementation is **Case-level aggregation/query -> CLI Case view ->
Markdown report**, using Event IDs 1 and 11. Do not expand parser event coverage
in the next demo session. Begin by listing Case-attached Sysmon Artifacts,
normalizing each through the service and ordering observations by timestamp with
source references preserved. Aggregation/query/report behavior needs its own scope.

## Resume on another device

Preserve that device's local changes first. In a clean, non-divergent checkout:

```powershell
git fetch origin
git switch feat/sysmon-normalization-20261006
git pull --ff-only
git rev-parse HEAD
git rev-parse origin/feat/sysmon-normalization-20261006
uv sync
uv run pytest tests/unit/test_sysmon_normalizer.py tests/integration/test_sysmon_service.py
```

If history diverges, stop and report instead of resetting, rebasing or force
pushing. The latest local and remote feature HEAD must match for the handoff.
