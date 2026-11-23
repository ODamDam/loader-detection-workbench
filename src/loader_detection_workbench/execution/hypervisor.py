"""Replaceable hypervisor boundary and isolation policy.

``Hypervisor`` is the only way the execution service touches a VM. The
VirtualBox adapter lives in ``execution.vboxmanage``; tests use a simulated
VBoxManage. Guest credentials are read from the environment at call time and
are never persisted, logged or placed on a command line.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.execution.domain import ExecutionProfile

GUEST_USER_ENV = "WORKBENCH_GUEST_USER"
GUEST_PASSWORD_ENV = "WORKBENCH_GUEST_PASSWORD"
POWERED_OFF_STATES = frozenset({"poweroff", "aborted"})
_DISABLED = frozenset({"disabled", ""})


@dataclass(frozen=True, slots=True)
class GuestCredentials:
    user: str
    password: str = field(repr=False)

    @classmethod
    def from_environment(
        cls, environ: Mapping[str, str] | None = None
    ) -> GuestCredentials:
        source = os.environ if environ is None else environ
        user = source.get(GUEST_USER_ENV, "")
        password = source.get(GUEST_PASSWORD_ENV, "")
        if not user.strip() or not password:
            raise DomainError(
                DomainErrorCode.EXECUTION_GUEST_CREDENTIALS_MISSING,
                f"set {GUEST_USER_ENV} and {GUEST_PASSWORD_ENV} for the guest account",
            )
        return cls(user, password)


@dataclass(frozen=True, slots=True)
class NicInfo:
    index: int
    attachment: str
    cable_connected: bool

    @property
    def isolated(self) -> bool:
        return self.attachment in {"none", "null"} or not self.cable_connected


@dataclass(frozen=True, slots=True)
class VmInfo:
    name: str
    state: str
    current_snapshot: str | None
    snapshots: tuple[str, ...]
    nics: tuple[NicInfo, ...]
    shared_folders: tuple[str, ...]
    clipboard_mode: str
    drag_and_drop_mode: str
    guest_additions_run_level: int | None

    @property
    def powered_off(self) -> bool:
        return self.state in POWERED_OFF_STATES


def network_problems(info: VmInfo) -> list[str]:
    return [
        f"nic{nic.index} ({nic.attachment}) cable is connected"
        for nic in info.nics
        if not nic.isolated
    ]


def isolation_problems(info: VmInfo, profile: ExecutionProfile) -> list[str]:
    """Return every reason the VM is not isolated enough for ``profile``."""
    problems = network_problems(info)
    if profile is ExecutionProfile.SAMPLE:
        # A sample could write to the host through these channels (ADR-024 D1).
        if info.shared_folders:
            problems.append(
                f"{len(info.shared_folders)} shared folder(s) configured; "
                "remove them before sample runs"
            )
        if info.clipboard_mode not in _DISABLED:
            problems.append(f"clipboard mode is {info.clipboard_mode}")
        if info.drag_and_drop_mode not in _DISABLED:
            problems.append(f"drag and drop mode is {info.drag_and_drop_mode}")
    return problems


@dataclass(frozen=True, slots=True)
class GuestProcessResult:
    exit_code: int


class Hypervisor(Protocol):
    def vm_info(self, vm_name: str) -> VmInfo: ...

    def restore_snapshot(self, vm_name: str, snapshot: str) -> None: ...

    def start(self, vm_name: str) -> None: ...

    def power_off(self, vm_name: str) -> None: ...

    def guest_make_directory(
        self, vm_name: str, credentials: GuestCredentials, guest_path: str
    ) -> None: ...

    def copy_to_guest(
        self,
        vm_name: str,
        credentials: GuestCredentials,
        host_files: Sequence[Path],
        guest_directory: str,
    ) -> None: ...

    def run_in_guest(
        self,
        vm_name: str,
        credentials: GuestCredentials,
        program: str,
        arguments: Sequence[str],
        timeout_seconds: int,
    ) -> GuestProcessResult: ...

    def copy_from_guest(
        self,
        vm_name: str,
        credentials: GuestCredentials,
        guest_files: Sequence[str],
        host_directory: Path,
    ) -> None: ...
