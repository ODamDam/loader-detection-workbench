# VirtualBox Sysmon demo export helper — 2026-10-06

Updated: 2026-10-13. Status: `completed` for the tested single-run manual helper
E2E scope, based on user-reported real Windows 11 VirtualBox verification.
The original real-guest `verification_blocked` condition is resolved for that scope.
The second collection passed guest output checks only; a second E2E is not verified.
Host mocked checks remain separate. VM lifecycle automation remains unimplemented.

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
This earlier evidence predates the helper. The 2026-10-13 helper-specific evidence
is recorded below and was supplied by the user, not observed through agent guest
control. No credentials or guestcontrol workaround are needed to record it.

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
directory, which is not a completed collection. Existing Shared Folder transfer
passed; this does not independently establish direct publication/rename behavior
on every share. On publication failure, use a new guest-local output and manual copy,
without weakening publication safety. Benign activity files are retained for local
inspection; the helper does not recursively delete the demo root.

## Professor demo commands — guest

1. Manually restore `SYSMON-DEMO-CLEAN` and start the prepared guest with its existing
   network safety settings. No network expansion is needed.
2. Copy the helper through the already approved shared folder or manual route.
3. Open **Windows PowerShell 5.1 inside the Windows 11 guest**, in the directory
   containing the copied helper. Do not run the collector on the host.
4. Set the existing output parent below to the permitted shared folder or guest-local
   directory. Replace placeholders locally; never record real paths in Git.

Before a new real run, obtain execution approval under `AGENTS.md`. Check
`Get-ExecutionPolicy -List` and `Get-ExecutionPolicy` in the guest. Script loading
can fail before the helper starts (Restricted, signature requirements, or downloaded
file zone markings). Such a failure is not a collection result. Do not change
CurrentUser/LocalMachine policy, automatically unblock files, or use policy bypasses
for the demo. If blocked, stop and use an administrator-approved, policy-compliant
delivery/signing route. Enforced MachinePolicy/UserPolicy Group Policy takes
precedence over process settings; respect it. See
[Microsoft execution-policy documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1).

Paste the entire block as one unit. It uses a separate PowerShell process with
`-File`, resets the exit-code sentinel, and checks invocation, exit status, completion
message, exact nonempty output files and XML hashes. A direct script-load failure
can leave `$LASTEXITCODE` null or stale, so checking that variable alone is unsafe.

```powershell
& {
$ErrorActionPreference = 'Stop'
$outputParent = '<existing writable output parent outside the repository>'
$helper = (Resolve-Path -LiteralPath .\Invoke-SysmonDemoCollection.ps1).ProviderPath
$powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$collection = Join-Path $outputParent ('run-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $collection) { throw 'OUTPUT_EXISTS: choose a new directory.' }
$LASTEXITCODE = $null
$messages = & $powershell -NoProfile -NonInteractive -File $helper -OutputDirectory $collection -TimeoutSeconds 20
$invoked = $?
$collectionExit = $LASTEXITCODE
if (-not $invoked -or $null -eq $collectionExit -or $collectionExit -ne 0 -or
    @($messages) -notcontains 'collection: complete (2 events)') {
    throw 'Collection execution failed; do not ingest output.'
}
$expected = @('collection-metadata.json', 'file-create.xml', 'process-create.xml')
$items = @(Get-ChildItem -LiteralPath $collection -Force)
if ($items.Count -ne 3 -or @($items | Where-Object { $_.PSIsContainer -or $_.Length -eq 0 }).Count -ne 0 -or
    @(Compare-Object $expected @($items.Name)).Count -ne 0) {
    throw 'Unexpected collection output; do not ingest.'
}
$metadata = Get-Content -LiteralPath (Join-Path $collection 'collection-metadata.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$events = @($metadata.events)
if ($metadata.collector -ne 'sysmon-demo' -or $metadata.version -ne 1 -or $events.Count -ne 2) {
    throw 'Invalid collection metadata.'
}
$names = @('process-create.xml', 'file-create.xml')
$ids = @(1, 11)
for ($i = 0; $i -lt 2; $i++) {
    if ($events[$i].file -cne $names[$i] -or $events[$i].event_id -ne $ids[$i] -or
        $events[$i].sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid event metadata.' }
    $hash = (Get-FileHash -LiteralPath (Join-Path $collection $names[$i]) -Algorithm SHA256).Hash
    if ($hash -ne $events[$i].sha256) { throw 'Collection hash mismatch.' }
}
Write-Output 'Guest output checks PASS; continue with local pair review and transfer.'
Get-Item -LiteralPath $collection # Display the fresh directory locally for transfer.
}
```

Expected helper success: `collection: complete (2 events)`, exactly the three files
above. On readiness/timeout/ambiguity errors, inspect the prepared guest locally;
do not use a lone XML as a complete run. Shared Folder is optional: a successful
guest-local directory can be transferred manually as one unit. Never commit it.
Before transfer, locally confirm XML Event IDs 1/11, equal ProcessGuid/PID and
increasing EventRecordID. Record SHA-256 of all three files locally; after transfer,
compare all three host hashes with the guest values, and both XML hashes with
metadata. Stop on any missing file or mismatch. Metadata hashes establish integrity,
not independent authenticity. Keep these values and telemetry out of Git.

## Professor demo commands — host

Return to **PowerShell on the host**, at the source repository root. The guest needs
only the helper and prepared Sysmon; `uv`, Workbench and the repository belong on
the host. After the transfer/hash checks above and host `uv sync` succeeds, paste
the entire block below, replacing the input placeholder with the host-visible
directory (guest and host paths need not match). The runtime Project is outside
the repository. The wrapper stops immediately on failed or unconfirmed CLI exits.

```powershell
& {
$ErrorActionPreference = 'Stop'
$workbench = (Resolve-Path .\.venv\Scripts\workbench.exe).Path
function Invoke-WorkbenchChecked {
    $LASTEXITCODE = $null
    & $workbench @args
    $invoked = $?
    $code = $LASTEXITCODE
    if (-not $invoked -or $null -eq $code -or $code -ne 0) {
        throw 'Workbench command failed; stop the demo.'
    }
}
$hostCollection = '<host-visible complete collection directory>'
$hostCollection = (Resolve-Path -LiteralPath $hostCollection).ProviderPath
$project = Join-Path ([IO.Path]::GetTempPath()) ('workbench-demo-' + [guid]::NewGuid().ToString('N'))
Invoke-WorkbenchChecked project create $project --name 'VM Sysmon Demo'
Push-Location $project
try {
    Invoke-WorkbenchChecked case create --name 'Benign Sysmon Demo' --kind benign
    Invoke-WorkbenchChecked case artifact add CASE-0001 (Join-Path $hostCollection 'process-create.xml') --kind sysmon
    Invoke-WorkbenchChecked case artifact add CASE-0001 (Join-Path $hostCollection 'file-create.xml') --kind sysmon
    Invoke-WorkbenchChecked case timeline CASE-0001
    Invoke-WorkbenchChecked report build CASE-0001 vm-demo.md
    Get-Content .\vm-demo.md -Encoding UTF8
} finally {
    Pop-Location
}
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

### Historical host verification — 2026-10-06

Synthetic/mocked checks, not evidence of guest execution:

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

### Real VirtualBox verification — 2026-10-13

Source: user's manual verification report. Raw XML, metadata, reports, workspaces,
run identifiers, hashes and environment-specific paths are not included in Git.
The agent did not rerun the guest or independently inspect private telemetry.

Historical execution detail: during the first guest collection on 2026-10-13,
the user ran `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`.
This was a temporary process-scoped setting, not a persistent execution-policy
change. This records what occurred; it does not recommend or authorize unapproved
policy bypasses for future demos. The future-demo instructions above continue to
respect enforced Group Policy and require a policy-compliant execution route.

| Scope | Result |
| --- | --- |
| Prepared Windows 11 guest | PASS: Sysmon service running, Operational log enabled |
| First helper collection | PASS: exit 0; exactly `process-create.xml`, `file-create.xml`, `collection-metadata.json` |
| First pair and export integrity | PASS: IDs 1/11, same ProcessGuid/PID, correct EventRecordID order; XML SHA-256 matches metadata |
| First transfer | PASS: existing VirtualBox Shared Folder; host copy SHA-256 checks |
| First Workbench ingestion | PASS: temporary Project and benign Case; both XML files registered as Artifacts |
| First timeline | PASS: exactly two observations with valid provenance; repeated queries identical |
| First Markdown report | PASS: all expected sections and collection/analysis limitations |
| Report no-overwrite | PASS: same output rejected with `REPORT_OUTPUT_EXISTS`; original report hash preserved |
| Second independent helper collection | PASS: exit 0 and exactly three guest output files only |
| Second transfer, ingestion, timeline and report | NOT VERIFIED; do not count as a second E2E |

This resolves the original unavailable-real-guest blocker for **one complete
helper VM-to-Workbench E2E**. It does not verify repeated full E2E reliability,
automated restore/start/stop, snapshot failure recovery or other VM configurations.
Shared Folder transfer success does not prove every direct-share atomic rename
case. No new malware execution, VM/security configuration changes or raw telemetry
upload is part of this documentation update.

## Handoff / next

### Documentation update validation — 2026-10-13

- `uv run --offline --frozen pytest`: 392 PASS.
- `uv lock --check --offline`: PASS; no dependency changes.
- `uv run --offline --frozen ruff check .` and `ruff format --check .`: PASS
  (81 files already formatted).
- `uv run --offline --frozen mypy src`: PASS, 47 source files.
- `uv run --offline --frozen mypy src tests`: FAIL, the same six pre-existing
  errors in the two Artifact test files listed above; no source/test files changed.
- `powershell.exe -NoProfile -NonInteractive -File
  tests/powershell/Test-SysmonDemoCollection.ps1`: 53 mocked checks PASS.
- Windows PowerShell parser: all three documented PowerShell blocks PASS.
- Extracted guest block with in-memory synthetic process/filesystem responses:
  eight checks PASS (success, launch error, unset exit with stale prior zero,
  nonzero exit, missing output, bad hash, extra file, missing completion message).
- Extracted host CLI wrapper: four mocked checks PASS (success, launch error,
  unset exit with stale prior zero, nonzero exit). No guest/host collection activity.
- `git diff --check` and final scope/security review: PASS. Only three Markdown
  files changed; no product code, raw evidence, dependencies or VM settings changed.

The initial ad hoc command-check harness encountered a mock/module-autoload
collision; explicitly loading the existing utility module before defining mocks
resolved it. This was a validation-harness issue, not a collector defect. The
checks above used in-memory mocks and did not change execution policy.

The earlier three-document update was committed/pushed as `d902576`; that approval
does not cover the host automation below. Preserve untracked `migration-note.txt`;
do not stage runtime evidence. No main merge, reset, rebase or history rewrite is authorized.
For a future approved rehearsal, use a fresh output directory, follow the guest
then host steps, and distinguish guest-only success from complete E2E success.
The revised command blocks still need a real-guest rehearsal; prior E2E evidence
does not claim that these revised instructions have already run in the guest.
Use the frozen synthetic path in `21-case-timeline-report-handoff.md` as fallback.
VBoxManage lifecycle/snapshot automation is a separate future scope.

## Host automation — 2026-10-13

`scripts/Invoke-SysmonHostDemo.ps1` automates the host steps for an explicitly
selected, completed benign helper collection. It does not discover telemetry,
run the guest collector, execute captured command lines, or control a VM.
Use Windows PowerShell 5.1 on the host, with the existing Workbench installation.
Execution policy must already permit the script; it does not change policy or
recommend a bypass. The earlier Process-scoped guest Bypass is historical evidence,
not a prerequisite for this host workflow.

```powershell
# Host, repository root. Replace the placeholder locally.
& {
    $ErrorActionPreference = 'Stop'
    $powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $LASTEXITCODE = $null
    $output = & $powershell -NoProfile -NonInteractive -File .\scripts\Invoke-SysmonHostDemo.ps1 -CollectionDirectory '<existing benign collection directory>'
    $invoked = $?
    $code = $LASTEXITCODE
    if (-not $invoked -or $null -eq $code -or $code -ne 0) {
        throw 'Host demo failed; inspect local safe diagnostics and preserve partial output.'
    }
    $result = ($output -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($result.status -cne 'success' -or $result.stage -cne 'complete' -or $result.code -cne 'OK') {
        throw 'Host demo success was not confirmed.'
    }
    $result
}
```

Parameters:

| Parameter | Contract |
| --- | --- |
| `-CollectionDirectory` | Required existing directory; exactly the three helper files, no recursion or private telemetry search |
| `-WorkbenchExecutable` | Optional explicit installed `.exe`; default is the repository's `.venv/Scripts/workbench.exe`; no install/sync performed |
| `-OutputParent` | Optional existing local directory; defaults to the system temporary directory; must be outside the repository and collection |

Runtime data paths reject reparse points, including junctions, symlinks and
cloud-backed placeholders. Use an ordinary local directory for host input/output
if a shared/cloud path is rejected; retain the established manual transfer/hash
checks. An explicitly selected installed executable may reside in the cloud-backed
source repository. Each input file must be nonempty and at most 4 MiB; this is a
bounded single-event demo, not a general log importer.

The script inventories and hashes the original without changing it, creates an
independent `workbench-host-demo-<random-token>` directory, and copies files with
no-replace writes. It compares original membership, sizes, hashes and modification
times before/after copying and compares the copy's sizes/hashes. Copy readers deny
concurrent writes while open. All copied files remain read-locked from validation
through the CLI workflow. Any observed change or file-layout mismatch stops the run
before a Project is created. Metadata must match the helper's version 1 shape,
including unique keys, run ID, UTC start/completion times and two event entries.
XML validation disables DTD/external resolution and checks the Sysmon provider,
single-event identities, required fields, metadata record IDs, Event IDs 1/11,
equal ProcessGuid/PID and increasing EventRecordID.

Only the copied XML files are registered. CLI checks focus on returned IDs, benign
Case kind, Artifact hashes/sizes, two observations and matching per-event provenance.
The report must exist, contain the expected sections/counts and identify the same
Case, Artifacts and records. Additional harmless CLI fields are tolerated; missing,
duplicate or inconsistent required fields fail closed. Existing parser/core CLI
behavior is unchanged and still performs normalization when generating the timeline.

Successful runtime layout (all outside Git):

```text
workbench-host-demo-<random-token>/
  collection/                  # independent three-file copy
  project/                     # CLI-managed Project and stored Artifacts
    vm-demo.md
  timeline.txt
  diagnostic.json
```

The console returns only JSON containing `status`, `stage`, allowlisted `code`,
optional numeric `cli_exit`, generated host `run` directory name, and `diagnostic`
write status. The token is newly generated for the host directory, not the guest's
run ID or ProcessGuid. Locate it under the selected output parent; diagnostics use
no absolute paths, raw CLI output, XML or private identifiers. Timeline/report and
the collection/Project are private runtime evidence, not diagnostic logs; never
commit them or print them into repository/agent logs.

Exit 0 requires every stage and diagnostic write to succeed. Any failure stops
later CLI calls, returns exit 1 and preserves existing output. There is no automatic
cleanup, resume or overwrite. A colliding run directory is rejected without writing
into it. Report existence is checked before build, with the core CLI's no-overwrite
guarantee handling a race. Before run-directory creation only safe console status
is available. If diagnostic writing fails, console status reports that failure;
an earlier workflow failure retains its original stage/code. Review partial runs
locally and start a fresh run after resolving the cause.

Limitations: this is not proof that supplied telemetry is benign/authentic. Hashes
and correlation check consistency only. Pre/post comparisons are not an atomic
snapshot of a hostile filesystem and cannot detect every change-and-restore race.
Use a quiescent, trusted collection directory and local output parent. CLI calls are
synchronous with no forced timeout; terminating PowerShell can leave partial output
without final diagnostics. Future CLI presentation changes may require updating the
required-field extraction. One corrected real-collection host E2E has passed; private
collection repeat runs and VM lifecycle automation are not verified.

### Host automation verification

#### First real host attempt and Native exit-code correction

The first real host automation attempt validated and copied the collection, then
reported `failed / project / CLI_FAILED` with a null `cli_exit`. Its outer PowerShell
invocation reported failure and exit 1. Safe inspection read only the allowlisted
diagnostic fields and checked file existence: the preserved partial run contains a
Project directory, `project.json` and `project.db`. This proves the existing
`project create` completed before the wrapper misclassified the result. No XML,
metadata, raw CLI output, private identifiers or absolute paths were inspected or
reported, and the failed run was not modified or deleted.

Root cause: under Windows PowerShell 5.1, assigning `$LASTEXITCODE = $null` inside
`Invoke-HostDemoCli` created a local variable, while the native executable updated
`$global:LASTEXITCODE`. The wrapper therefore read its unchanged local null even
when Workbench exited 0. It also read `$?` after the surrounding array assignment,
which can replace the native command's status. The wrapper now resets the global
sentinel, captures `$?` immediately after the native call inside the output capture,
and then reads the global native exit code. Required exit-0 and output checks remain
fail-closed. Captured stdout/stderr stays internal and is never serialized into the
safe diagnostic record.

Regression coverage now uses real `cmd.exe` processes for exit 0 and exit 7,
including stale-code replacement and stdout capture. It also verifies a missing
executable is rejected with no stale exit code and runs a read-only native
`workbench.exe --version` smoke test. The existing mocked full workflow remains.

#### First corrected real host E2E — PASS

Source: the user's manual execution and output review after the Native exit-code
correction. The host automation returned `success / complete / OK` and its enclosing
PowerShell process exited 0. The run created the independent collection and Project
directories, `diagnostic.json`, `timeline.txt`, and exactly one Markdown report.
The user confirmed all four required report sections. This resolves the corrected
host workflow's real-E2E verification blocker for one run.

The successful run is distinct from the preserved first failure above. Neither run's
collection, XML, metadata, Project, timeline, report, identifiers, hashes or local
paths are stored in Git or reproduced here. The agent did not independently inspect
the private runtime evidence. A single successful run does not establish repeated-run
reliability; no second corrected host E2E has been performed.

Only the five approved files changed: the host script, its PowerShell test script,
README, PLANS and this handoff. Existing core CLI, parsers, schema, dependencies,
guest helper and public fixtures are unchanged.

| Check | Result |
| --- | --- |
| `powershell.exe -NoProfile -NonInteractive -File tests/powershell/Test-SysmonHostDemo.ps1` | 415 synthetic/mocked/native assertions PASS |
| Existing `Test-SysmonDemoCollection.ps1` | 53 mocked assertions PASS |
| Changed scripts and 11 documented PowerShell blocks, PowerShell 5.1 parser | PASS |
| `uv run --offline --frozen pytest` | 392 PASS |
| `uv lock --check --offline` | PASS |
| `uv run --offline --frozen ruff check .` / `ruff format --check .` | PASS, 81 files already formatted |
| `uv run --offline --frozen mypy src` | PASS, 47 files |
| Additional `uv run --offline --frozen mypy src tests` | Same six pre-existing Artifact-test errors listed above |
| Corrected actual collection → Host automation E2E | 1 PASS, user verified; repeat NOT RUN |
| Diff whitespace, scope and security review | PASS |

The host harness generates metadata around existing benign XML fixtures and mocks
the full workflow's CLI calls. It covers missing/extra/empty/non-file entries, bad
JSON and duplicate keys, incorrect metadata, modified hashes, malformed XML/DTD, wrong providers,
duplicate event fields, wrong IDs/record order, mismatched ProcessGuid/PID, source
and copy mutation, timestamp/layout changes, and data-path rejection. It checks
required CLI fields while tolerating harmless extra fields, rejects invalid hashes,
counts and provenance, and exercises invocation errors, unset/stale exit status,
each CLI stage failure, output collisions, report races and diagnostic write errors.
It verifies original bytes, copied-file write locks, working-directory restoration,
stopping after failure and preservation of partial outputs. The native-call wrapper
uses real `cmd.exe` exits and the installed Workbench launcher's read-only version
command; no Project is created by those wrapper tests and no VM is run.

One corrected full host E2E with a real private collection passed by user verification.
Repeated corrected host E2E, guest execution during this implementation, and VM
lifecycle operation were not tested. The failed first host attempt and earlier manual
VM-to-Workbench E2E evidence remain separate.
`migration-note.txt` was preserved and checked for an unchanged hash. No commit or
push is authorized for this implementation.

### Host repeat validator — implementation and synthetic verification

`scripts/Invoke-SysmonHostDemoRepeat.ps1` accepts one explicit existing collection,
an existing local output parent, the installed Workbench executable and an iteration
count from 2 through 10. It never searches for telemetry. It validates the source,
records its initial snapshot and launches the existing `Invoke-SysmonHostDemo.ps1`
through a separate Windows PowerShell process for every iteration.

```powershell
# Host, repository root. Replace both placeholders locally.
$powershell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$global:LASTEXITCODE = $null
$output = & $powershell -NoProfile -NonInteractive `
    -File .\scripts\Invoke-SysmonHostDemoRepeat.ps1 `
    -CollectionDirectory '<existing validated benign collection>' `
    -OutputParent '<existing local directory outside the repository>' `
    -Iterations 2
$invoked = $?
$code = $global:LASTEXITCODE
if (-not $invoked -or $null -eq $code -or $code -ne 0) {
    throw 'Host repeat validation failed; preserve all local output and inspect safe diagnostics.'
}
$result = ($output -join "`n") | ConvertFrom-Json -ErrorAction Stop
if ($result.status -cne 'success' -or $result.stage -cne 'complete' -or
    $result.code -cne 'OK' -or $result.iterations_completed -ne 2 -or
    @($result.runs).Count -ne 2 -or $result.diagnostic -cne 'written' -or
    -not $result.source_unchanged -or -not $result.copies_match -or
    -not $result.artifacts_valid -or -not $result.projects_valid -or
    -not $result.timelines_consistent -or -not $result.reports_consistent) {
    throw 'Host repeat success was not confirmed.'
}
$result
```

The batch diagnostic directory and Host run directories are siblings under the chosen
output parent. This keeps each Host run at the same path depth as a direct invocation
and avoids adding a long batch-directory component to Windows Artifact Store paths.

```text
<output-parent>/
  workbench-host-repeat-<random-token>/
    repeat-diagnostic.json
  workbench-host-demo-<random-token>/
    collection/
    project/
    timeline.txt
    diagnostic.json
  workbench-host-demo-<different-random-token>/
    ...
```

For every successful iteration the repeat validator verifies:

- a unique run directory and independent Project;
- exact source/copy filename, size and SHA-256 equality;
- Event IDs 1/11, ProcessGuid/PID correlation and increasing EventRecordID;
- Artifact list SHA-256/size mapped back to the two copied XML files;
- `workbench project validate <project> --full` returning exactly `valid`, which
  independently hashes canonical Artifact Store content;
- byte-equivalent stored and newly queried Timeline output after CRLF/LF normalization;
- Timeline event order, PID and ArtifactId/EventRecordID provenance;
- one Markdown report, all four required sections, counts and matching provenance.

Cross-run comparison replaces only Case and Artifact display IDs in Timeline/report,
and the report's single `Generated At` value. Run and Project paths do not enter the
canonical content. All other normalized text participates in an in-memory SHA-256
digest comparison. The digest, raw XML, command line, image, target filename, private
identifiers and absolute paths are never written to the batch diagnostic.

`repeat-diagnostic.json` contains safe status, stage/code, requested/completed counts,
failed iteration, generated run names, source/copy/Artifact/Project/Timeline/report
booleans, the inner safe Host stage/code and diagnostic state. A failed iteration stops
later launches. Existing complete and partial outputs are retained without cleanup,
resume or overwrite. The source snapshot is checked after each completed iteration and again before the final
result; an observed change fails the batch.

#### First private repeat attempt and entry-point correction

The first user-run private-collection repeat attempt exited 1 before analysis and emitted
seven PowerShell error records instead of one JSON result. The first error was
`Split-Path` rejecting an empty `Path`. The repeat script's only direct `Split-Path`
expression was the `WorkbenchExecutable` parameter default, which evaluated
`$PSScriptRoot` before the structured failure boundary. The output parent and child-result
paths never call `Split-Path`, so they were not the source of this error. The previous
`$result` value in the interactive shell was stale and is not evidence from that attempt.

Review also reproduced a second entry-point defect: dot-sourcing the existing Host script
in script scope replaced the repeat script's `CollectionDirectory`, `WorkbenchExecutable`
and `OutputParent` variables with the imported script's parameter values. The earlier
synthetic test called the repeat function directly and therefore did not exercise this
`powershell.exe -File` entry path.

The repeat script now has no computed path parameter default. It validates its script
context before deriving repository paths, imports the unchanged Host helper with explicit
arguments, and restores all caller inputs immediately after import. Required runtime path
values are rejected with `PATH_ARGUMENT_INVALID` before filesystem commands. Initialization
failures map to `SCRIPT_CONTEXT_INVALID` or `SCRIPT_INITIALIZATION_FAILED`; exception text
and paths are not returned. The entry point emits exactly one JSON object on both tested
success and failure paths. The regression test invokes the actual script entry point,
checks exit 0 plus one JSON result for success, and checks exit 1 plus one safe JSON result
for an empty required path.

#### Phase A read-only evidence inspection

A bounded inspection considered only direct `workbench-host-demo-*` children of the
system temporary directory. It found two preserved Host runs: one `success / complete /
OK` run and the earlier `failed / project / CLI_FAILED` run. Both contained valid
three-file collection copies, but the copies had one shared content fingerprint, so
they prove one distinct collection rather than two independent guest collections.

Both preserved Projects passed read-only `project validate --full`. For the successful
run, the stored Timeline matched a new read-only Timeline query, Artifact SHA-256 linked
the copied XML to both provenance references, and the report contained all four sections
with matching Artifact/EventRecordID provenance. The failed run retained its collection
and partial Project and had no Timeline/report, as expected for its failure stage. No
private path, hash, GUID, XML, Timeline or report content was recorded in this document.
These read-only queries do not count as new E2E executions.

#### Repeat verification status

`tests/powershell/Test-SysmonHostDemoRepeat.ps1` generated a collection from the public
harmless Event ID 1/11 fixtures, invoked the repeat script through its real
`powershell.exe -File` entry point and ran the installed Workbench through two independent
Host child processes. Both iterations completed, and all copy, Artifact, full-Project,
Timeline, provenance, report and source-invariance checks passed. The same test covers
second-iteration failure, invalid child output, copy failure, duplicate run identity,
Timeline/report semantic differences, source modification, missing/corrupt input and
an existing batch-directory collision. It verifies immediate stop, safe diagnostics,
partial-output preservation and no write into a colliding directory.

| Check | Result |
| --- | --- |
| New Host repeat PowerShell test | 70 assertions PASS |
| Actual installed CLI over public synthetic collection | 2 independent Host iterations PASS |
| Existing Host PowerShell regression | 415 assertions PASS |
| Existing Artifact Store targeted pytest | 42 PASS |
| Full Workbench pytest | 392 PASS |
| Ruff lint and format check | PASS; 83 files already formatted |
| `mypy src` | PASS; 47 source files |
| Offline frozen lock check | PASS |
| PowerShell parser, `git diff --check` and scoped security scan | PASS |
| First private VM collection repeat attempt | FAIL before analysis; entry-point initialization corrected |
| Private VM collection repeat after correction | PASS: 1 batch, 2/2 independent Host iterations |

The synthetic iterations validate repeat orchestration and the real local CLI boundary;
they are not additional real-VM collection results. After the entry-point correction, the
user reused one existing benign VM collection for one repeat batch. Its result was
`success / complete / OK`, with two requested and two completed independent Host runs,
no failed iteration, and a written safe diagnostic. `source_unchanged`, `copies_match`,
`artifacts_valid`, `projects_valid`, `timelines_consistent` and `reports_consistent` were
all true.

This result verifies repeated Host processing of the same completed collection. It does
not represent two new Guest collections, a new Guest execution or malware execution. The
record therefore remains separated into the earlier single successful Host E2E, the first
failed repeat attempt before analysis, and this corrected repeat batch with two successful
Host iterations. No private path, XML, metadata, hash value, Project, Timeline or report
content is recorded here.
