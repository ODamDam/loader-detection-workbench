"""Execution Run domain: profiles, steps, VM settings and safety lock.

An Execution Run executes either a registered sample Artifact or a fixed benign
scenario in the analysis VM, collects every Sysmon event of the run window and
registers the collection on the Case. VM details stay behind the ``Hypervisor``
interface (``execution.hypervisor``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import require_utc

RUN_PREFIX = "VMR"
DEFAULT_VM_NAME = "WIN11-ANALYSIS"
DEFAULT_SNAPSHOT = "SYSMON-V2-CLEAN"
DEFAULT_TIMEOUT_SECONDS = 180
MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 900
GUEST_ROOT = "C:\\WorkbenchRun"
GUEST_SCRIPT_NAME = "Invoke-WorkbenchGuestRun.ps1"
EVENTS_FILE = "events.xml"
MANIFEST_FILE = "run-manifest.json"
GUEST_COLLECTOR = "workbench-guest-run"
GUEST_COLLECTOR_VERSION = 1

# Fixed benign scenarios. Their guest implementation lives only in the guest
# script; arbitrary commands are never accepted (keep both lists identical).
BENIGN_SCENARIOS: dict[str, str] = {
    "notepad-open-close": "start Notepad, wait, then close it",
    "powershell-inventory": "list processes, services and System32 DLL names",
    "registry-probe": "create and delete an HKCU test key and value",
    "file-write": "create, modify and delete files in the run work directory",
    "dns-invalid": "resolve an example.invalid name (no network required)",
}

_VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", re.ASCII)
_RUN_ID = re.compile(rf"{RUN_PREFIX}-[0-9]{{4,}}", re.ASCII)


class ExecutionProfile(StrEnum):
    SAMPLE = "sample"
    BENIGN_SCENARIO = "benign_scenario"


class RunStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABANDONED = "abandoned"


class StepName(StrEnum):
    APPROVAL = "approval"
    SAFETY_LOCK = "safety_lock"
    PREFLIGHT = "preflight"
    RESTORE_BEFORE = "restore_before"
    NETWORK_CHECK = "network_check"
    START = "start"
    GUEST_READY = "guest_ready"
    TRANSFER_IN = "transfer_in"
    EXECUTE = "execute"
    COLLECT = "collect"
    VERIFY = "verify"
    POWER_OFF = "power_off"
    RESTORE_AFTER = "restore_after"
    REGISTER = "register"


class StepStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.INVALID_EXECUTION_REQUEST, message)


def require_vm_name(value: str, label: str = "VM name") -> str:
    if not isinstance(value, str) or _VM_NAME.fullmatch(value) is None:
        raise _invalid(f"{label} must be 1-64 letters, digits, space, '.', '_' or '-'")
    return value


def require_timeout(value: int) -> int:
    if type(value) is not int or not (
        MIN_TIMEOUT_SECONDS <= value <= MAX_TIMEOUT_SECONDS
    ):
        raise _invalid(
            f"timeout must be {MIN_TIMEOUT_SECONDS}-{MAX_TIMEOUT_SECONDS} seconds"
        )
    return value


def require_scenario(value: str) -> str:
    if value not in BENIGN_SCENARIOS:
        raise _invalid("unknown benign scenario")
    return value


def require_run_id(value: str) -> str:
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        raise DomainError(
            DomainErrorCode.INVALID_DISPLAY_ID,
            f"run ID must use {RUN_PREFIX}-0001 format",
        )
    return value


@dataclass(frozen=True, slots=True)
class VmSettings:
    """Which VM and clean snapshot to use. Names only; no host paths."""

    vm_name: str = DEFAULT_VM_NAME
    snapshot: str = DEFAULT_SNAPSHOT
    guest_ready_timeout_seconds: int = 300
    settle_seconds: int = 5

    def __post_init__(self) -> None:
        require_vm_name(self.vm_name)
        require_vm_name(self.snapshot, "snapshot name")
        if not 10 <= self.guest_ready_timeout_seconds <= 1800:
            raise _invalid("guest ready timeout must be 10-1800 seconds")
        if not 0 <= self.settle_seconds <= 60:
            raise _invalid("settle time must be 0-60 seconds")


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    case_display_id: str
    profile: ExecutionProfile
    timeout_seconds: int
    sample_artifact_id: str | None = None
    scenario: str | None = None

    def __post_init__(self) -> None:
        require_timeout(self.timeout_seconds)
        if self.profile is ExecutionProfile.SAMPLE:
            if self.sample_artifact_id is None or self.scenario is not None:
                raise _invalid("sample runs require exactly one sample Artifact")
        else:
            if self.scenario is None or self.sample_artifact_id is not None:
                raise _invalid("benign runs require exactly one scenario")
            require_scenario(self.scenario)

    @property
    def target(self) -> str:
        value = self.sample_artifact_id or self.scenario
        assert value is not None
        return value


@dataclass(frozen=True, slots=True)
class StepRecord:
    sequence: int
    step: StepName
    status: StepStatus
    at: datetime
    detail: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "at", require_utc(self.at))


@dataclass(frozen=True, slots=True)
class ExecutionRun:
    display_id: str
    case_display_id: str
    profile: ExecutionProfile
    target: str
    target_sha256: str | None
    vm_name: str
    snapshot: str
    timeout_seconds: int
    status: RunStatus
    started_at: datetime
    finished_at: datetime | None
    error_code: str | None
    sysmon_artifact_id: str | None
    metadata_artifact_id: str | None
    event_count: int | None
    steps: tuple[StepRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class SafetyLock:
    """Blocks every further run until a person confirms the VM is clean."""

    run_display_id: str | None
    reason: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class PlannedStep:
    step: StepName
    description: str
    command: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """Dry-run output: what would happen, with no hypervisor command executed."""

    request: ExecutionRequest
    settings: VmSettings
    target_sha256: str | None
    steps: tuple[PlannedStep, ...]
