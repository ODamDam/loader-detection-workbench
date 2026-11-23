# Case timeline and Markdown demo handoff — 2026-10-06

## Supported flow

```text
Case -> attached Sysmon Artifact -> Event 1/11 normalization
     -> deterministic CaseTimeline query result
     -> CLI timeline / Markdown report
```

`CaseTimelineQuery(root).query(case_display_id)` returns an immutable result:
Case, a tuple of existing normalized events, and Sysmon Artifact count. It uses
CaseService, ArtifactService and SysmonService without duplicating parsing or
opening canonical source files itself. Both renderers consume that result;
ReportService queries once before rendering and publishing. An integration test
passes the same query object to both entry points and forbids direct lower-layer
reads during presentation; another exercises both CLI commands without mocks.

Ordering is timestamp, integer event_id, Artifact display ID, EventRecordID,
all ascending. The last two keys are lexicographic strings ("10" precedes "2").
No process correlation or tree is built. A failed source fails the whole query.
An existing Case with no attached Sysmon is an empty success. Closed Cases work.

## Git

- Repository: `ODamDam/loader-detection-workbench`.
- Branch: `feat/case-timeline-report-20261006`.
- Tracking: `origin/feat/case-timeline-report-20261006`.
- Starting SHA: `b23644c1f8a1b61224e50f0fea959e5ec4d93844`.
- Implementation commit: `feat: add case timeline and markdown report`.
  Fetch the feature branch and use `git rev-parse HEAD` for the final SHA.
- `migration-note.txt` remains machine-local/untracked, excluded from upload.
- No main merge, history rewrite, tag, release or branch deletion.

## Changed files

- `src/loader_detection_workbench/case/timeline.py`: shared query/result.
- `src/loader_detection_workbench/case/render.py`: pure text rendering.
- `src/loader_detection_workbench/presentation.py`: single-line and Markdown escaping.
- `src/loader_detection_workbench/report/`: pure Markdown renderer, application
  service and atomic no-overwrite UTF-8 file publication.
- `src/loader_detection_workbench/cli.py`: additive timeline/report commands.
- `src/loader_detection_workbench/domain/errors.py`: two stable output errors.
- `tests/unit/test_case_timeline.py`, `test_report_render.py`, `test_report_output.py`.
- `tests/integration/test_case_timeline_query.py`, `test_report_cli.py`.
- README, PLANS, CLI/report policy docs and this handoff.

## Validation

| Check | Result |
| --- | --- |
| New query/render/output/CLI targeted tests | PASS: 21 |
| Existing Sysmon unit/integration tests | PASS: 54 |
| `uv run pytest` | PASS: 392 |
| `uv lock --check` | PASS |
| `uv run ruff check .` | PASS (non-blocking cache-write warning) |
| `uv run ruff format --check .` | PASS: 81 files |
| `uv run mypy src` | PASS: 47 files |
| mypy src + five new test files | PASS: 52 files |
| `uv run mypy src tests` | FAIL: only the same six pre-existing Artifact-test errors |
| `git diff --check` | PASS |
| Installed `workbench.exe` synthetic demo in a temporary workspace | PASS: timeline and Markdown generated |

Initial test collection found duplicate unit/integration basenames; the new
integration module was renamed without changing pytest configuration. One escaping
expectation was corrected to include the escaped entity semicolon. Final tests pass.
No required offline gate remains unrun. VM, simulator, malware and telemetry
collection were not run. The unchanged Artifact-test typing issue is separate.

## Self-review and limits

- Same query source for CLI and Markdown; source provenance and parser contracts
  are preserved. Tests cover each ordering key, relocation and no DB mutation.
- Invalid/corrupt source: no partial stdout/report. Empty query is distinguishable.
- Existing output and racing writer are protected. Write/fsync/publication errors
  fail safely and normally remove staging; empty parent directories can remain.
- Crash or cleanup failure can leave staging; cleanup failure is reported and may
  leave a fully published report. No hostile filesystem race sandbox is promised.
- Generated At is injectable; event times remain second-precision UTC.
- Case/XML values are escaped as text. This is not automatic privacy redaction or
  authorization to publish a report containing real telemetry.
- Query uses existing service reads, not a global DB snapshot; concurrent changes
  may be observed across reads. No timeline/report metadata is persisted.
- Existing case show/lifecycle, Artifact, Bundle, validator and Sysmon APIs remain.
- No DB/schema/dependency change; no real logs, credentials or host paths added.
- Not supported: VM collection, EVTX, other Sysmon events, multi-event XML, HTML,
  detection verdict, correlation, Evidence graph, AI or full final report.

The full report template remains intact; this is its intermediate demo subset.

## Reproduce the demo on Windows

From this repository root after `uv sync`, use the installed CLI explicitly so
changing directory does not change which environment supplies `workbench`:

```powershell
$demoRepo = (Get-Location).Path
$demoCli = Join-Path $demoRepo '.venv/Scripts/workbench.exe'
$demoRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('workbench-demo-' + [guid]::NewGuid())
& $demoCli project create $demoRoot --name 'Synthetic Demo'
Push-Location -LiteralPath $demoRoot
try {
    & $demoCli case create --name 'Benign Demo' --kind benign
    & $demoCli case artifact add CASE-0001 (Join-Path $demoRepo 'tests/fixtures/public/sysmon/process-create.xml') --kind sysmon
    & $demoCli case artifact add CASE-0001 (Join-Path $demoRepo 'tests/fixtures/public/sysmon/file-create.xml') --kind sysmon
    & $demoCli case show CASE-0001
    & $demoCli case timeline CASE-0001
    & $demoCli report build CASE-0001 demo.md
    Get-Content -Encoding utf8 demo.md
} finally {
    Pop-Location
}
```

This reads synthetic XML as data, never executes its Image or TargetFilename.
The workspace/report is runtime data outside the repository and is not uploaded.
The timeline should show 2 artifacts, 2 observations, Process Create then File
Create, and ART-000001#42 / ART-000002#43. Running report build again with the same
output must fail with REPORT_OUTPUT_EXISTS. Use a new filename to rebuild.

## Next device

Inspect and preserve that device's local changes first:

```powershell
git fetch origin
git switch feat/case-timeline-report-20261006
git pull --ff-only
git rev-parse HEAD
git rev-parse origin/feat/case-timeline-report-20261006
uv sync
uv run pytest tests/unit/test_case_timeline.py tests/integration/test_case_timeline_query.py tests/unit/test_report_render.py tests/unit/test_report_output.py tests/integration/test_report_cli.py
```

If history diverges, report it; do not rebase/reset/force push. Next start point is
rehearsing the synthetic demo and reviewing its rendered Markdown. Further product
scope needs a separate instruction; do not expand parser/VM coverage automatically.
