# ADR-018: Active VirtualBox Windows 11 analysis VM

## Status

Approved by the user on 2026-10-06. Supersedes ADR-003's active hypervisor choice
and ADR-015's VMware Tools-specific integration choice, preserving the adapter
abstraction and one-shot PowerShell direction.

## Decision

- Current MVP/demo hypervisor: Oracle VirtualBox on Windows.
- Guest: Windows 11 x64; integration: VirtualBox Guest Additions.
- Current clean snapshot: `SYSMON-DEMO-CLEAN`.
- Future automation command surface: `VBoxManage`; no adapter, guestcontrol,
  credentials, VM start/stop or snapshot automation is implemented by this change.
- `HypervisorAdapter` remains replaceable. VirtualBoxAdapter is the active future
  implementation target; VMwareAdapter remains an alternative/future target only.
- VM disks, images, state and credentials are never Git artifacts. OVA may be an
  optional out-of-band transport, not source control data.

## Reason and evidence

The user's current host already has VirtualBox. The user reports successful
Windows 11 benign PowerShell activity, Sysmon Event IDs 1 and 11 with the same
ProcessGuid/PID, single-event XML export, Shared Folder transfer and Workbench
Artifact/timeline/Markdown ingestion. No parser correction was needed.

This is user-confirmed manual E2E evidence, not a claim that Codex ran the newly
added helper in the guest. The earlier VMware-not-found checkpoint remains a
valid historical record of the previous investigation.

## Consequences

Use existing Shared Folder or manual transfer for the approved benign demo.
No network expansion, service exposure or credentials are introduced. The guest
export helper accepts any writable output directory and does not depend on the
hypervisor. Real telemetry stays outside Git; only synthetic structure belongs
in fixtures. Future orchestration and alternate hypervisors need separate scope.
