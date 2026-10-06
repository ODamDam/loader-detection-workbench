# VirtualBox Sysmon demo export helper — 2026-10-06

Status: `verification_blocked` — helper guest execution and ingestion of its actual
output are not yet verified. Host syntax and synthetic/mocked checks are separate.

## Baseline and approved decision

- Repository: `ODamDam/loader-detection-workbench`.
- Branch/tracking: `feat/vm-sysmon-collection-20261006` / same branch on `origin`.
- Starting local/remote SHA: `c9536419173c7edd11f3ac2a6ef9ea62e3cb5aa8`, 0/0.
- Windows host, Oracle VirtualBox, Windows 11 x64, Guest Additions.
- Clean snapshot: `SYSMON-DEMO-CLEAN`; restore/start remain manual.
- ADR-018 supersedes the active VMware choice, retaining adapter abstraction and
  historical records. VirtualBoxAdapter/VBoxManage automation is future work.
- VM images/disks/state and OVA are not source control artifacts. OVA may be
  transported separately if needed. `migration-note.txt` stays local/untracked.

The user confirmed **REAL VM → WORKBENCH MANUAL E2E PASS**: benign PowerShell,
Event 1 and 11 with identical ProcessGuid/PID, single XML export, existing Shared
Folder transfer, Artifact add, timeline and Markdown. No parser change was needed.
This evidence predates the new helper. No direct permitted guest control interface
is available in this session; no credential request or guestcontrol workaround is
used. Do not describe host mock tests as a guest collection success.

## Helper boundary

`scripts/vm/Invoke-SysmonDemoCollection.ps1` runs in the prepared Windows guest.
Requires Windows PowerShell 5.1, a running Sysmon/Sysmon64 service and readable,
enabled `Microsoft-Windows-Sysmon/Operational` log. Before activity it requires
historical Event 1 and 11 records as evidence of prepared coverage. An empty log
therefore fails conservatively with `SYSMON_COVERAGE_UNVERIFIED`.

Historical coverage does **not** prove the current filter accepts this run. The
helper does not parse configuration CLI text or alter filters. Only a newly
correlated pair establishes this run's success; filtering changes can cause a
timeout. Sysmon's event/filter semantics and configuration commands are documented
in [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

- Required: `-OutputDirectory`, a new filesystem directory (local or existing share).
- Optional: `-TimeoutSeconds` 1–120, default 20; polling interval 250 ms.
- Optional: `-DemoRoot`, default system-drive `SysmonDemo`; activity must be local,
  without filesystem links. Each run uses a random GUID and its own subdirectory.
- Baseline: latest EventRecordID and UTC collection start immediately before child.
- Activity: hidden child Windows PowerShell writes one harmless UTF-8 text file.
  The literal command contains `hello-workbench-<run_id>` and the target path.
- Event 1: after baseline, exact child PID, run marker and demo command marker.
- Event 11: after selected Event 1, same ProcessGuid/PID, exact target filename
  (Windows case-insensitive comparison). Ambiguous matching records fail closed.
- No partial success on readiness failure, child failure, ambiguity or timeout.
  Timeout covers child wait/polling; a blocking OS log query or filesystem operation
  is not forcibly interrupted by this timeout.
- No downloads, registry/service changes, credentials or executable payloads.
  Shared-folder output uses only the already available transfer route.

Successful runtime output:

```text
<new-output-directory>/
  process-create.xml
  file-create.xml
  collection-metadata.json
```

XML is the exact `ToXml()` string, one namespaced Event per file, UTF-8 without BOM.
Metadata contains collector/version/run_id/start/completion UTC timestamps and
event IDs, record IDs, relative filenames and SHA-256. It omits machine identity,
usernames and paths. Raw XML itself can contain private telemetry and stays out of
Git along with metadata and generated reports/workspaces.

Both records must be selected before export. A sibling temporary directory is
written and hashes checked before a no-replace directory move publishes the final
directory. Existing outputs are never merged/overwritten. Write failures clean
staging; process termination or cleanup failure can leave a `.sysmon-demo-*.tmp`
directory, which is not a completed collection. Actual Shared Folder rename behavior
still requires guest validation; on failure, use guest-local output and manual copy,
without weakening publication safety. Benign activity files are retained for local
inspection; the helper does not recursively delete the demo root.

## Professor demo commands — guest

1. Manually restore `SYSMON-DEMO-CLEAN` and start the prepared guest with its existing
   network safety settings. No network expansion is needed.
2. Copy the helper through the already approved shared folder or manual route.
3. In guest PowerShell, set the existing output parent below to the permitted shared
   folder or guest-local directory. The placeholder is not a literal path to use.

```powershell
$outputParent = '<existing writable output parent outside the repository>'
$collection = Join-Path $outputParent ('run-' + [guid]::NewGuid().ToString('N'))
.\Invoke-SysmonDemoCollection.ps1 -OutputDirectory $collection -TimeoutSeconds 20
if ($LASTEXITCODE -ne 0) { throw 'Collection failed; do not ingest partial output.' }
Get-ChildItem -LiteralPath $collection
Get-Content -LiteralPath (Join-Path $collection 'collection-metadata.json') -Encoding UTF8
```

Expected helper success: `collection: complete (2 events)`, exactly the three files
above. On readiness/timeout/ambiguity errors, inspect the prepared guest locally;
do not use a lone XML as a complete run. Shared Folder is optional: a successful
guest-local directory can be transferred manually as one unit. Never commit it.

## Professor demo commands — host

Use the existing shared folder or manually transferred complete collection. Run
the following from the source repository after `uv sync`, replacing only the input
placeholder. The runtime Project is created outside the repository.

```powershell
$workbench = (Resolve-Path .\.venv\Scripts\workbench.exe).Path
$hostCollection = '<host-visible complete collection directory>'
$project = Join-Path ([IO.Path]::GetTempPath()) ('workbench-demo-' + [guid]::NewGuid().ToString('N'))
& $workbench project create $project --name 'VM Sysmon Demo'
Push-Location $project
try {
    & $workbench case create --name 'Benign Sysmon Demo' --kind benign
    & $workbench case artifact add CASE-0001 (Join-Path $hostCollection 'process-create.xml') --kind sysmon
    & $workbench case artifact add CASE-0001 (Join-Path $hostCollection 'file-create.xml') --kind sysmon
    & $workbench case timeline CASE-0001
    & $workbench report build CASE-0001 vm-demo.md
    Get-Content .\vm-demo.md -Encoding UTF8
} finally {
    Pop-Location
}
```

Each CLI command must exit 0; stop on errors. Expect two observations, Process
Create then File Create, and ArtifactId + EventRecordID provenance. Verify Case
Overview, Evidence Summary, Timeline and Collection / Analysis Limits. Rebuilding
the same report must fail with `REPORT_OUTPUT_EXISTS`, preserving the original.
Windows PowerShell 5.1 needs explicit `-Encoding UTF8` for display; the report's
UTF-8 no-BOM contract is unchanged. The source-neutral limitation now reads:
“The report does not independently attest how the source telemetry was collected.”

The CLI and renderer still use the existing read-only query. No product parser,
DB/schema, dependency or normalized event persistence changes were introduced.

## Verification record

Host verification:

| Check | Result |
| --- | --- |
| PowerShell 5.1 parser, helper and test script | PASS |
| Dependency-free synthetic/mocked PowerShell checks | 53 PASS |
| Targeted timeline/report/Sysmon pytest | 67 PASS (including 54 Sysmon tests) |
| Full `uv run pytest` | 392 PASS |
| `uv lock --check` | PASS |
| Ruff lint and format | PASS |
| `uv run mypy src` | PASS, 47 files |
| `uv run mypy src tests/unit/test_report_render.py` | PASS, 48 files |
| `uv run mypy src tests` | FAIL, exactly 6 pre-existing Artifact-test errors |
| `git diff --check` | PASS |

The known typing errors remain at `test_artifact_domain.py:51` and
`test_artifact_store.py:151,171,177,236,459`; no new typing errors were added.
An initial Ruff line-length failure in the new wording was corrected; subsequent
lint/format, renderer test and changed-test typing checks passed.

The PowerShell harness mocks process/service/log boundaries and never runs activity
or reads host telemetry. It checks marker/child/correlation selection, baseline,
ambiguity, readiness failures before activity, timeout, quoted command construction,
exact output identities/hashes/BOM/metadata, overwrite refusal and staging cleanup
after injected write-validation failure. Run it with:

```powershell
.\tests\powershell\Test-SysmonDemoCollection.ps1
```

Guest helper run, actual helper-output transfer and its Workbench E2E: **NOT RUN**.
The blocker is unavailable permitted direct guest access, not a known parser defect.
No malware, guest execution, network expansion, credentials, raw telemetry upload
or VM automation was performed. Only safe source, tests and documentation are
included in this checkpoint; the parser and synthetic fixtures are unchanged.

## Handoff / next

```powershell
git fetch origin
git switch feat/vm-sysmon-collection-20261006
git pull --ff-only
git rev-parse HEAD
git rev-parse origin/feat/vm-sysmon-collection-20261006
```

Preserve local work on another device; report divergence without reset/rebase.
Run the helper manually in the prepared guest, ingest its two exported XML files
and record success/failure without copying private XML, GUIDs, hashes or host/user
details into repository documentation. Then rehearse 2–3 times and fix the demo
instructions. Use the frozen synthetic path in `21-case-timeline-report-handoff.md`
as fallback. VBoxManage lifecycle/snapshot automation is a separate future scope.
