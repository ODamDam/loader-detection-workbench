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

Commit/push approval is limited to `PLANS.md`, `README.md` and this handoff on
`feat/vm-sysmon-collection-20261006`. Preserve untracked `migration-note.txt`; do not
stage runtime evidence. No main merge, reset, rebase or history rewrite is authorized.
For a future approved rehearsal, use a fresh output directory, follow the guest
then host steps, and distinguish guest-only success from complete E2E success.
The revised command blocks still need a real-guest rehearsal; prior E2E evidence
does not claim that these revised instructions have already run in the guest.
Use the frozen synthetic path in `21-case-timeline-report-handoff.md` as fallback.
VBoxManage lifecycle/snapshot automation is a separate future scope.
