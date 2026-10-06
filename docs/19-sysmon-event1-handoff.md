# Sysmon Event ID 1 handoff — 2026-10-06

## Current state

- Repository: `ODamDam/loader-detection-workbench`.
- Branch: `feat/sysmon-normalization-20261006`.
- Tracking: `origin/feat/sysmon-normalization-20261006`.
- M1 checkpoint: `9280606a2c807c51c88bf9d19fca25e758ebf832`, pushed.
- Initial HEAD and origin/main were both `a27fd4f`; M1 existed as uncommitted
  source, tests, documentation, configuration and synthetic development data.
- The checkpoint preserves those changes, including pre-existing Sample Intake
  and AI-E1 files. It does not add new experiments or dependencies.
- `migration-note.txt` remains local and untracked because it contains
  machine-local path information. It must not be staged or uploaded.
- Sysmon implementation has not started. Status: `verification_blocked`;
  required Event ID 1 implementation and tests do not yet exist.

## Investigation and decision needed

The local M1 implementation provides `Artifact`, `ArtifactId`, `ArtifactKind`,
Case attachment, project-relative canonical content paths and stable
`DomainError` codes. `ArtifactService.add()` and `list_artifacts()` provide the
existing Case pipeline. Artifact identity combines a ULID and a display ID.

There is no normalized event class, Sysmon parser, event-field schema, or
Artifact-to-event-record reference contract in source or the current documents.
`docs/04-architecture.md` describes an Event Normalizer but does not define its
fields; `docs/05-data-model.md` describes Evidence conceptually only.
Sample Intake's `source_reference` / `source_record_id` fields describe sample
provenance and are not an existing normalized event contract.

The implementation request prioritizes reuse of an existing normalized model
and forbids arbitrary new fields. AGENTS.md requires reporting a missing
implementation decision. The following minimal additive contract has therefore
been proposed to the user and is **pending confirmation**, not approved by this
document:

| Proposed field | Meaning |
| --- | --- |
| `timestamp` | Process creation `UtcTime`, aware UTC using existing time convention |
| `event_id` | Exactly `1` |
| `process_guid` | Sysmon ProcessGuid |
| `process_id` | Non-negative integer ProcessId |
| `image` | Image string from the synthetic record |
| `command_line` | CommandLine string from the synthetic record |
| `source_artifact_id` | Existing ArtifactId, including ULID and display ID |
| `source_record_id` | System/EventRecordID, scoped to that Artifact |

The current UTC helper truncates sub-second precision. Reusing it would make
that limitation explicit; original precision remains in the source Artifact.
No parent/user fields, Evidence graph or generic event schema are proposed.

## Proposed implementation after confirmation

1. Add an immutable Event ID 1 domain result in `domain/events.py` and stable
   validation errors in `domain/errors.py`.
2. Add `sysmon/normalizer.py` for one synthetic, namespaced XML Event ID 1.
   Reject malformed XML, missing required fields and unsupported Event IDs.
   Do not silently skip records or return a success-shaped partial result.
3. Add `sysmon/service.py` to select an attached Sysmon Artifact through the
   existing Case/Artifact API, check content integrity and normalize its bytes.
   Return results in memory; leave DB v1, Bundle v1 and existing interfaces intact.
4. Add `tests/fixtures/public/sysmon/process-create.xml` with wholly invented
   benign data, plus `tests/unit/test_sysmon_normalizer.py` and
   `tests/integration/test_sysmon_service.py`.
5. Verify exactly one result, mapped values and Artifact/record traceability
   through a real temporary Project/Case/Artifact workspace. Cover malformed
   input and attachment/integrity errors. Update README, data model and PLANS.

No new dependency, Event ID 11, EVTX parser, VM, simulator execution, detection
engine, AI integration, report generator or new CLI is part of this proposal.
Success requires the Event ID 1 tests and a further feature commit/push.

## Executed baseline validation

| Check | Result |
| --- | --- |
| `uv lock --check` | PASS |
| `uv run pytest` | PASS: 317 tests |
| `uv run ruff check .` | PASS |
| `uv run ruff format --check .` | PASS: 64 files |
| `uv run mypy src` | PASS: 37 source files; README/PLANS official gate |
| `uv run mypy src tests` | FAIL: 6 pre-existing errors in Artifact tests |
| `git diff --cached --check` | PASS for M1 checkpoint |
| Event ID 1 targeted tests | NOT RUN: implementation awaits contract decision |

The extra mypy failures are in `test_artifact_domain.py` (intentional mutation of
a frozen dataclass) and `test_artifact_store.py` (untyped callback and implicit
module re-exports used by monkeypatch tests). No unrelated fixes were made.

Staged paths, file types, fixture provenance and sensitive-data patterns were
reviewed. No raw logs, malware, runtime workspace or credentials were staged.
No VM, Guest Orchestrator, simulator or external AI was run. The baseline check
is not a claim that the unimplemented Sysmon slice is complete or merge-ready.

## Resume on another device

First inspect that device's working tree and preserve local changes. With a
clean, non-divergent checkout:

```powershell
git fetch origin
git switch feat/sysmon-normalization-20261006
git pull --ff-only
git log -1 --oneline
uv sync
```

If local commits diverge, stop and report; do not reset, force push or rebase.
The next task is to resolve the proposed minimal model (or locate a separately
approved contract), then implement and test Event ID 1 only. Read this branch's
latest commit for the complete handoff, not remote main.
