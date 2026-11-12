"""VirtualBox ``VBoxManage`` adapter for the ``Hypervisor`` interface.

Commands are argument lists (never a shell). The guest password is written to a
short-lived temporary file passed with ``--passwordfile`` and removed right
after the call, so it never appears on a command line, in a record or in an
error message. Errors carry only the operation name and exit status, never
VBoxManage output, which may contain host paths.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.execution.hypervisor import (
    GuestCredentials,
    GuestProcessResult,
    NicInfo,
    VmInfo,
)

DEFAULT_VBOXMANAGE = Path("C:/Program Files/Oracle/VirtualBox/VBoxManage.exe")
VBOXMANAGE_ENV = "WORKBENCH_VBOXMANAGE"
CONTROL_TIMEOUT_SECONDS = 120
RESTORE_TIMEOUT_SECONDS = 600
COPY_TIMEOUT_SECONDS = 600
RUN_MARGIN_SECONDS = 120
PASSWORD_FILE_PLACEHOLDER = "<password-file>"


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str


class CommandRunner(Protocol):
    def run(self, arguments: Sequence[str], timeout_seconds: float) -> CommandResult:
        """Run ``arguments`` (argv[0] is VBoxManage) without a shell."""
        ...


class SubprocessRunner:
    def run(self, arguments: Sequence[str], timeout_seconds: float) -> CommandResult:
        try:
            completed = subprocess.run(
                list(arguments),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise DomainError(
                DomainErrorCode.HYPERVISOR_COMMAND_FAILED,
                "VBoxManage command timed out",
            ) from exc
        except OSError as exc:
            raise DomainError(
                DomainErrorCode.HYPERVISOR_COMMAND_FAILED,
                "VBoxManage could not be started",
            ) from exc
        return CommandResult(completed.returncode, completed.stdout)


def default_executable() -> Path:
    configured = os.environ.get(VBOXMANAGE_ENV)
    return Path(configured) if configured else DEFAULT_VBOXMANAGE


def _unescape(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            result.append(value[index + 1])
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _closing_quote(text: str) -> int:
    """Index of the first unescaped quote in ``text``, or -1."""
    index = 0
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == '"':
            return index
        index += 1
    return -1


def parse_machine_readable(output: str) -> dict[str, str]:
    """Parse ``--machinereadable`` output, including multi-line quoted values.

    Continuation lines of a quoted value (e.g. snapshot descriptions) are
    consumed as part of that value, so description text can never be read as
    a separate key.
    """
    values: dict[str, str] = {}
    lines = output.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if line.startswith('"'):
            end = _closing_quote(line[1:])
            if end < 0 or line[end + 2 : end + 3] != "=":
                continue
            key = _unescape(line[1 : end + 1])
            raw = line[end + 3 :]
        else:
            key, sep, raw = line.partition("=")
            if not sep or not key:
                continue
        if raw.startswith('"'):
            body = raw[1:]
            end = _closing_quote(body)
            while end < 0 and index < len(lines):
                body += "\n" + lines[index]
                index += 1
                end = _closing_quote(body)
            values[key] = _unescape(body if end < 0 else body[:end])
        else:
            values[key] = raw.strip()
    return values


def vm_info_from_machine_readable(vm_name: str, output: str) -> VmInfo:
    values = parse_machine_readable(output)
    if "VMState" not in values:
        raise DomainError(
            DomainErrorCode.HYPERVISOR_COMMAND_FAILED,
            "VM information did not include a state",
        )
    nics: list[NicInfo] = []
    for number in range(1, 37):
        attachment = values.get(f"nic{number}")
        if attachment is None:
            continue
        cable = values.get(f"cableconnected{number}", "on")
        nics.append(NicInfo(number, attachment, cable != "off"))
    snapshots = tuple(
        value
        for key, value in values.items()
        if key == "SnapshotName" or key.startswith("SnapshotName-")
    )
    shared = tuple(
        value for key, value in values.items() if key.startswith("SharedFolderName")
    )
    run_level_text = values.get("GuestAdditionsRunLevel")
    run_level = (
        int(run_level_text) if run_level_text and run_level_text.isdigit() else None
    )
    return VmInfo(
        name=vm_name,
        state=values["VMState"],
        current_snapshot=values.get("CurrentSnapshotName"),
        snapshots=snapshots,
        nics=tuple(nics),
        shared_folders=shared,
        clipboard_mode=values.get("clipboard", values.get("clipboard_mode", "")),
        drag_and_drop_mode=values.get("draganddrop", ""),
        guest_additions_run_level=run_level,
    )


# -- command builders (shared by the adapter and dry-run plans) ---------------


def showvminfo_command(executable: Path, vm_name: str) -> tuple[str, ...]:
    return (str(executable), "showvminfo", vm_name, "--machinereadable")


def restore_command(executable: Path, vm_name: str, snapshot: str) -> tuple[str, ...]:
    return (str(executable), "snapshot", vm_name, "restore", snapshot)


def start_command(executable: Path, vm_name: str) -> tuple[str, ...]:
    return (str(executable), "startvm", vm_name, "--type", "headless")


def poweroff_command(executable: Path, vm_name: str) -> tuple[str, ...]:
    return (str(executable), "controlvm", vm_name, "poweroff")


def _guest_common(user: str, password_file: str) -> tuple[str, ...]:
    return (f"--username={user}", f"--passwordfile={password_file}")


def mkdir_command(
    executable: Path, vm_name: str, user: str, password_file: str, guest_path: str
) -> tuple[str, ...]:
    return (
        str(executable),
        "guestcontrol",
        vm_name,
        "mkdir",
        *_guest_common(user, password_file),
        "--parents",
        guest_path,
    )


def copyto_command(
    executable: Path,
    vm_name: str,
    user: str,
    password_file: str,
    host_files: Sequence[str],
    guest_directory: str,
) -> tuple[str, ...]:
    return (
        str(executable),
        "guestcontrol",
        vm_name,
        "copyto",
        *_guest_common(user, password_file),
        f"--target-directory={guest_directory}",
        *host_files,
    )


def run_command(
    executable: Path,
    vm_name: str,
    user: str,
    password_file: str,
    program: str,
    arguments: Sequence[str],
    timeout_seconds: int,
) -> tuple[str, ...]:
    return (
        str(executable),
        "guestcontrol",
        vm_name,
        "run",
        *_guest_common(user, password_file),
        f"--exe={program}",
        f"--timeout={timeout_seconds * 1000}",
        "--no-wait-stdout",
        "--",
        program,
        *arguments,
    )


def copyfrom_command(
    executable: Path,
    vm_name: str,
    user: str,
    password_file: str,
    guest_files: Sequence[str],
    host_directory: str,
) -> tuple[str, ...]:
    return (
        str(executable),
        "guestcontrol",
        vm_name,
        "copyfrom",
        *_guest_common(user, password_file),
        f"--target-directory={host_directory}",
        *guest_files,
    )


class VBoxManageHypervisor:
    def __init__(
        self, executable: Path | None = None, runner: CommandRunner | None = None
    ) -> None:
        self.executable = executable or default_executable()
        self._runner = runner or SubprocessRunner()

    def _run(
        self, operation: str, arguments: Sequence[str], timeout: float
    ) -> CommandResult:
        result = self._runner.run(arguments, timeout)
        if result.returncode != 0:
            raise DomainError(
                DomainErrorCode.HYPERVISOR_COMMAND_FAILED,
                f"VBoxManage {operation} failed with exit status {result.returncode}",
            )
        return result

    @contextmanager
    def _password_file(self, credentials: GuestCredentials) -> Iterator[str]:
        descriptor, name = tempfile.mkstemp(prefix="wb-guest-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(credentials.password)
            yield name
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name)

    def vm_info(self, vm_name: str) -> VmInfo:
        result = self._run(
            "showvminfo",
            showvminfo_command(self.executable, vm_name),
            CONTROL_TIMEOUT_SECONDS,
        )
        return vm_info_from_machine_readable(vm_name, result.stdout)

    def restore_snapshot(self, vm_name: str, snapshot: str) -> None:
        self._run(
            "snapshot restore",
            restore_command(self.executable, vm_name, snapshot),
            RESTORE_TIMEOUT_SECONDS,
        )

    def start(self, vm_name: str) -> None:
        self._run(
            "startvm", start_command(self.executable, vm_name), CONTROL_TIMEOUT_SECONDS
        )

    def power_off(self, vm_name: str) -> None:
        self._run(
            "poweroff",
            poweroff_command(self.executable, vm_name),
            CONTROL_TIMEOUT_SECONDS,
        )

    def guest_make_directory(
        self, vm_name: str, credentials: GuestCredentials, guest_path: str
    ) -> None:
        with self._password_file(credentials) as password_file:
            self._run(
                "guestcontrol mkdir",
                mkdir_command(
                    self.executable,
                    vm_name,
                    credentials.user,
                    password_file,
                    guest_path,
                ),
                CONTROL_TIMEOUT_SECONDS,
            )

    def copy_to_guest(
        self,
        vm_name: str,
        credentials: GuestCredentials,
        host_files: Sequence[Path],
        guest_directory: str,
    ) -> None:
        with self._password_file(credentials) as password_file:
            self._run(
                "guestcontrol copyto",
                copyto_command(
                    self.executable,
                    vm_name,
                    credentials.user,
                    password_file,
                    [str(item) for item in host_files],
                    guest_directory,
                ),
                COPY_TIMEOUT_SECONDS,
            )

    def run_in_guest(
        self,
        vm_name: str,
        credentials: GuestCredentials,
        program: str,
        arguments: Sequence[str],
        timeout_seconds: int,
    ) -> GuestProcessResult:
        with self._password_file(credentials) as password_file:
            result = self._runner.run(
                run_command(
                    self.executable,
                    vm_name,
                    credentials.user,
                    password_file,
                    program,
                    arguments,
                    timeout_seconds,
                ),
                timeout_seconds + RUN_MARGIN_SECONDS,
            )
        return GuestProcessResult(result.returncode)

    def copy_from_guest(
        self,
        vm_name: str,
        credentials: GuestCredentials,
        guest_files: Sequence[str],
        host_directory: Path,
    ) -> None:
        with self._password_file(credentials) as password_file:
            self._run(
                "guestcontrol copyfrom",
                copyfrom_command(
                    self.executable,
                    vm_name,
                    credentials.user,
                    password_file,
                    guest_files,
                    str(host_directory),
                ),
                COPY_TIMEOUT_SECONDS,
            )
