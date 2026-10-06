# Demo freeze and VM Sysmon collection handoff — 2026-10-06

Status: `verification_blocked`. Offline demo frozen; real-VM collection not run.

## Repository and baseline

- Repository: `ODamDam/loader-detection-workbench`.
- Branch: `feat/vm-sysmon-collection-20261006`.
- Tracking destination: `origin/feat/vm-sysmon-collection-20261006`.
- Starting local/remote SHA: `731026b5e6e21c3c8ed5d823f47a900c8b4df4a0`.
- Starting divergence: 0/0. Tracked working tree was clean.
- The known machine-local `migration-note.txt` is preserved untracked and excluded.
- This checkpoint changes only PLANS and this handoff, not product code, tests,
  fixtures, dependencies, parser behavior or DB schema.

## Demo A — guaranteed offline path

**OFFLINE DEMO FROZEN: PASS** on this PC.

Used a new temporary workspace outside the repository and the installed
`workbench.exe`, following the existing handoff's commands:

1. `project create ... --name "Synthetic Demo"`.
2. `case create --name "Benign Demo" --kind benign`.
3. Attach repository `process-create.xml` and `file-create.xml` as Sysmon Artifacts.
4. `case timeline CASE-0001`.
5. `report build CASE-0001 demo.md`.
6. Read the Markdown and check all four required sections and source records.
7. Repeat report build: exit 2 / REPORT_OUTPUT_EXISTS, original report bytes unchanged.

Observed timeline:

```text
case: CASE-0001
sysmon_artifacts: 2
observations: 2
2026-10-06T01:02:03Z  EventID=1  process_create
  source: ART-000001#42
2026-10-06T01:02:05Z  EventID=11  file_create
  source: ART-000002#43
```

Case Overview, Evidence Summary, Timeline and Collection / Analysis Limits were
present. These are synthetic timestamps and record IDs, not actual VM telemetry.
The report stayed in temporary runtime storage and was not staged.

Use the complete portable PowerShell recipe in
`21-case-timeline-report-handoff.md` to recreate Demo A on the next device.
No new demo implementation or simulator was introduced.

## VM readiness evidence

Read repository VM design, security policy and ADR-003/013/015. The repository
contains design records but no concrete ready VM inventory, guest execution
adapter, VM scripts or configured collection/transfer implementation.

Read-only host checks found:

| Check | Result |
| --- | --- |
| vmrun.exe / vmware.exe / vmplayer.exe / vmrest.exe on PATH | Not found |
| Those tools in standard VMware Workstation installation directories | Not found |
| VMware Workstation/Player uninstall registration (machine and current user) | 0 products |
| VMware Workstation product registry keys checked | None found |
| VMware-related services | 0 found |
| VMware / vmware-vmx / vmplayer / vmrest processes | 0 found |
| Current-user VMware inventory.vmls | Not present |

This is evidence that the usable VMware environment has not been identified on
this PC, not proof that no VM exists on another device or in a custom location.
No whole-disk search or sample-location exploration was performed. Actual local
paths, usernames, hostnames, credentials and machine identifiers are omitted.

The user was asked whether VMware is installed elsewhere, available only on
another PC, or not yet prepared. No installation or network change was attempted.

## Demo B — VM manual E2E

**NOT RUN / NOT VERIFIED.** Do not describe this session as real telemetry success.

| Step | State |
| --- | --- |
| Identify usable Windows VM and execution safety | Blocked: environment not located |
| Boot/readiness | NOT RUN |
| Guest Sysmon installed / service running | UNKNOWN; guest not accessed |
| Sysmon config / Event ID 11 enabled | UNKNOWN |
| Microsoft-Windows-Sysmon/Operational access | NOT RUN |
| PowerShell/wevtutil query/export capability | NOT VERIFIED in guest |
| Benign Process Create / File Create | NOT RUN |
| Actual Event ID 1 / 11 confirmation | NOT RUN |
| Single Event XML export | NOT RUN |
| Existing safe Host/Guest transfer path | NOT IDENTIFIED |
| Real XML vs parser contract comparison | NOT RUN |
| Real-VM Artifact add / case timeline / report build | NOT RUN |

No raw XML exists from this session. Automation: **none**. Manual E2E must succeed
before any collector framework. Level 3 omission is not the blocker; Level 1 VM
readiness and all Level 2 steps remain incomplete.

## Validation and security

- Targeted: installed CLI synthetic end-to-end + overwrite protection PASS.
- `git diff --check`: PASS for documentation changes.
- Full pytest, lock, Ruff and mypy: NOT RUN this session because product code,
  tests and dependency files were unchanged. Prior baseline: 392 tests and required
  gates passed; full `mypy src tests` had six known Artifact-test errors.
- Actual malware, suspect samples, simulator or guest activity executed: NO.
- Internet enabled in a VM or network scope expanded: NO.
- Credentials used or committed: NO.
- Raw telemetry/runtime workspaces/reports committed: NO.
- GitHub fetch/checkpoint push is the authorized development handoff only.
- No VM start, snapshot restore or guest operation was attempted; no restore
  success or failure is claimed.

## Resume / next device

Preserve any local changes and fetch the checkpoint:

```powershell
git fetch origin
git switch feat/vm-sysmon-collection-20261006
git pull --ff-only
git rev-parse HEAD
git rev-parse origin/feat/vm-sysmon-collection-20261006
```

If local history diverges, report it; do not reset/rebase/force push.

Next needs a concrete VMware installation/Windows VM location or continuation
on the PC where the analysis VM is prepared. Do not request or record credentials.
Then inspect VM identity, safe network mode and existing transfer route before
booting or executing the authorized benign activity. If Sysmon/config/Event 11
is missing or safety is unclear, stop at that finding as instructed.

Once ready, manually generate benign process/file activity, confirm matching
Event IDs 1 and 11 and their fields, export each selected EventRecordID as single
Event XML, compare structure/timestamps with the current parser, and transfer
through an already available safe local route. Keep real XML and environment
details outside Git. Use a new temporary Workbench project for Artifact add,
timeline and report. Only then mark REAL VM -> WORKBENCH MANUAL E2E PASS.

If Demo B is unavailable during rehearsal, immediately use frozen Demo A.
