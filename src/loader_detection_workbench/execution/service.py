"""Approved VM Execution Runs: restore, run, collect, restore, register.

Flow (ADR-024): approval -> safety lock check -> preflight (VM off, snapshot
present, isolation) -> restore clean snapshot -> network re-check -> headless
start -> guest ready -> transfer -> time-limited run -> collect ``<Events>``
XML + manifest -> verify hashes and events -> power off -> restore -> register
Artifacts on the Case.

Every step is recorded in its own transaction so a crash leaves a trace. A
failed or unverifiable restore sets the persistent safety lock; a lock or an
unfinished (``running``) run blocks every later run until ``unlock``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.domain.artifact import Artifact, ArtifactKind
from loader_detection_workbench.domain.case import CaseKind, CaseStatus
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.ids import ArtifactId, CaseId
from loader_detection_workbench.domain.time import format_utc, utc_now
from loader_detection_workbench.execution import vboxmanage as vbox
from loader_detection_workbench.execution.domain import (
    EVENTS_FILE,
    GUEST_COLLECTOR,
    GUEST_COLLECTOR_VERSION,
    GUEST_ROOT,
    GUEST_SCRIPT_NAME,
    MANIFEST_FILE,
    ExecutionPlan,
    ExecutionProfile,
    ExecutionRequest,
    ExecutionRun,
    PlannedStep,
    RunStatus,
    SafetyLock,
    StepName,
    StepStatus,
    VmSettings,
    require_run_id,
)
from loader_detection_workbench.execution.hypervisor import (
    GuestCredentials,
    Hypervisor,
    VmInfo,
    isolation_problems,
    network_problems,
)
from loader_detection_workbench.execution.sqlite_repository import (
    SQLiteExecutionRepository,
)
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.sysmon.records import (
    MAX_RECORD_XML_BYTES,
    parse_sysmon_records,
)

MAX_SAMPLE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
GUEST_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
# Guest-side work outside the run window: Sysmon baseline, process-tree stop,
# settle and export. Real samples (2026-11-18, VMR-0002..0010) needed more than
# 120 s, so the guestcontrol limit cut runs that had finished their window.
GUEST_RUN_OVERHEAD_SECONDS = 360
READY_POLL_SECONDS = 5.0
METADATA_FORMAT = "workbench-execution-run"
_PROCESS_OUTCOMES = frozenset({"exited", "timeout_killed"})
# The guest script appends one "HH:MM:SS phase [number]" line per phase to this
# file next to itself; it is fetched only when the guest run fails.
PROGRESS_FILE = "progress.log"
MAX_PROGRESS_BYTES = 4096
_PROGRESS_LINE = re.compile(
    r"([0-2][0-9]:[0-5][0-9]:[0-5][0-9]) ([a-z][a-z-]{0,31})(?: ([0-9]{1,9}))?",
    re.ASCII,
)


def summarize_progress(data: bytes) -> str:
    """Last guest phase from ``progress.log``; any other content is ignored.

    The file is guest-written, so only lines of the fixed shape are read and
    the summary is built from those parts alone (no guest text is echoed).
    """
    if len(data) > MAX_PROGRESS_BYTES:
        return "guest progress unreadable (too large)"
    phases = [
        match
        for line in data.decode("ascii", errors="replace").splitlines()
        if (match := _PROGRESS_LINE.fullmatch(line.strip())) is not None
    ]
    if not phases:
        return "guest progress empty"
    time_text, phase, number = phases[-1].groups()
    shown = phase if number is None else f"{phase} {number}"
    return f"last guest phase {shown} at {time_text} UTC ({len(phases)} phases)"


# Guest script exit codes -> stable reasons (no guest output is trusted/echoed).
GUEST_EXIT_REASONS: dict[int, str] = {
    1: "guest run failed",
    10: "invalid guest arguments",
    11: "Sysmon is not running in the guest",
    12: "guest Sysmon log is unreadable",
    13: "sample hash mismatch in the guest",
    14: "target could not be started in the guest",
    15: "guest output already exists",
    16: "guest export failed",
}


def _case_selector(display_id: str) -> str:
    CaseId("00000000000000000000000000", display_id)
    return display_id


def _artifact_selector(display_id: str) -> str:
    ArtifactId("00000000000000000000000000", display_id)
    return display_id


@contextmanager
def host_exchange_directory(prefix: str) -> Iterator[Path]:
    """Host directory the hypervisor's VM process reads from or writes into.

    ``guestcontrol copyto``/``copyfrom`` open host files from the VM process,
    not from this process. ``tempfile.mkdtemp`` creates an owner-only directory;
    on Windows that ACL has no entry for the user's normal token, and a real
    VirtualBox 7.2 run failed with ``VERR_ACCESS_DENIED`` on the copy source.
    A plain ``os.mkdir`` inherits the ACL of the user's temporary directory
    instead. The name is random and creation fails if it already exists.
    """
    path = Path(tempfile.gettempdir()) / f"{prefix}{secrets.token_hex(8)}"
    os.mkdir(path)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def guest_script_bytes() -> bytes:
    return (
        resources.files("loader_detection_workbench.execution")
        .joinpath("guest", GUEST_SCRIPT_NAME)
        .read_bytes()
    )


def guest_work_directory(run_display_id: str) -> str:
    return f"{GUEST_ROOT}\\{run_display_id}"


def guest_arguments(
    request: ExecutionRequest,
    run_display_id: str,
    target_sha256: str | None,
    settle_seconds: int,
) -> list[str]:
    work = guest_work_directory(run_display_id)
    arguments = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        f"{work}\\{GUEST_SCRIPT_NAME}",
        "-WorkDirectory",
        work,
        "-RunId",
        run_display_id,
        "-TimeoutSeconds",
        str(request.timeout_seconds),
        "-SettleSeconds",
        str(settle_seconds),
    ]
    if request.profile is ExecutionProfile.SAMPLE:
        assert target_sha256 is not None
        arguments += [
            "-Mode",
            "Sample",
            "-SampleFileName",
            target_sha256,
            "-ExpectedSha256",
            target_sha256,
        ]
    else:
        assert request.scenario is not None
        arguments += ["-Mode", "Scenario", "-Scenario", request.scenario]
    return arguments


@dataclass(frozen=True, slots=True)
class PreflightReport:
    info: VmInfo
    snapshot: str
    snapshot_present: bool
    problems: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.problems


@dataclass(frozen=True, slots=True)
class LockStatus:
    lock: SafetyLock | None
    running_runs: tuple[str, ...]

    @property
    def locked(self) -> bool:
        return self.lock is not None or bool(self.running_runs)


@dataclass(frozen=True, slots=True)
class _Target:
    artifact: Artifact | None
    sha256: str | None


@dataclass(frozen=True, slots=True)
class _Collected:
    events: Path
    manifest: dict[str, Any]
    event_count: int
    events_sha256: str


class _StepFailed(Exception):
    """Internal: a recorded step failure carrying the user-facing error."""

    def __init__(self, error: DomainError) -> None:
        super().__init__(str(error))
        self.error = error


class ExecutionService:
    def __init__(
        self,
        root: Path,
        settings: VmSettings | None = None,
        hypervisor: Hypervisor | None = None,
        *,
        credentials: Callable[[], GuestCredentials] = GuestCredentials.from_environment,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._root = root
        self.settings = settings or VmSettings()
        self._hypervisor = hypervisor
        self._credentials = credentials
        self._sleep = sleep
        self._monotonic = monotonic

    # -- persistence ----------------------------------------------------------

    @contextmanager
    def _repository(
        self, *, write: bool = False
    ) -> Iterator[SQLiteExecutionRepository]:
        repository: SQLiteExecutionRepository | None = None
        try:
            workspace = ProjectService().open(self._root)
            repository = SQLiteExecutionRepository(workspace, write=write)
            with repository.transaction():
                yield repository
        except sqlite3.Error as exc:
            raise DomainError(
                DomainErrorCode.EXECUTION_PERSISTENCE_FAILED,
                "execution database operation failed",
            ) from exc
        finally:
            if repository is not None:
                repository.close()

    def _record(
        self, run_id: str, step: StepName, status: StepStatus, detail: str | None
    ) -> None:
        with self._repository(write=True) as repository:
            repository.append_step(run_id, step, status, detail)

    def _require_hypervisor(self) -> Hypervisor:
        if self._hypervisor is None:
            raise RuntimeError("a hypervisor is required for this operation")
        return self._hypervisor

    # -- queries --------------------------------------------------------------

    def lock_status(self) -> LockStatus:
        with self._repository() as repository:
            return LockStatus(repository.get_lock(), tuple(repository.running_runs()))

    def show_run(self, run_display_id: str) -> ExecutionRun:
        require_run_id(run_display_id)
        with self._repository() as repository:
            return repository.get_run(run_display_id)

    def list_runs(self) -> list[ExecutionRun]:
        with self._repository() as repository:
            return repository.list_runs()

    def unlock(self, note: str) -> LockStatus:
        """Release the lock after a person verified the VM; abandon open runs."""
        if not isinstance(note, str) or not note.strip() or len(note) > 500:
            raise DomainError(
                DomainErrorCode.INVALID_EXECUTION_REQUEST,
                "unlock requires a short note describing the manual verification",
            )
        with self._repository(write=True) as repository:
            before = LockStatus(repository.get_lock(), tuple(repository.running_runs()))
            for run_id in before.running_runs:
                repository.append_step(
                    run_id,
                    StepName.RESTORE_AFTER,
                    StepStatus.SKIPPED,
                    "run abandoned; VM state confirmed manually at unlock",
                )
                repository.finish_run(
                    run_id, RunStatus.ABANDONED, error_code="RUN_ABANDONED"
                )
            if before.lock is not None or before.running_runs:
                if before.lock is None:
                    repository.set_lock(None, "abandoned run")
                repository.release_lock(note.strip())
        return before

    def preflight(self, profile: ExecutionProfile) -> PreflightReport:
        """Read-only VM inspection; never starts, restores or changes the VM."""
        info = self._require_hypervisor().vm_info(self.settings.vm_name)
        return self._evaluate(info, profile)

    def _evaluate(self, info: VmInfo, profile: ExecutionProfile) -> PreflightReport:
        problems: list[str] = []
        present = self.settings.snapshot in info.snapshots
        if not present:
            problems.append("clean snapshot is missing")
        if not info.powered_off:
            problems.append(f"VM state is {info.state}; it must be powered off")
        problems += isolation_problems(info, profile)
        return PreflightReport(info, self.settings.snapshot, present, tuple(problems))

    # -- request validation ---------------------------------------------------

    def _resolve_target(self, request: ExecutionRequest) -> _Target:
        _case_selector(request.case_display_id)
        case = CaseService(self._root).show(request.case_display_id)
        if case.status is not CaseStatus.OPEN:
            raise DomainError(DomainErrorCode.CASE_CLOSED, "closed case is read-only")
        if request.profile is ExecutionProfile.BENIGN_SCENARIO:
            if case.kind is not CaseKind.BENIGN:
                raise DomainError(
                    DomainErrorCode.INVALID_EXECUTION_REQUEST,
                    "benign scenarios must run in a benign Case",
                )
            return _Target(None, None)
        if case.kind is CaseKind.BENIGN:
            raise DomainError(
                DomainErrorCode.INVALID_EXECUTION_REQUEST,
                "sample runs require a malware or simulator Case",
            )
        assert request.sample_artifact_id is not None
        _artifact_selector(request.sample_artifact_id)
        artifact = ArtifactService(self._root).show(
            request.case_display_id, request.sample_artifact_id
        )
        if artifact.kind is not ArtifactKind.SAMPLE:
            raise DomainError(
                DomainErrorCode.INVALID_EXECUTION_REQUEST,
                "the target Artifact must be of kind sample",
            )
        if artifact.size_bytes > MAX_SAMPLE_BYTES:
            raise DomainError(
                DomainErrorCode.INVALID_EXECUTION_REQUEST,
                "sample exceeds the 64 MiB transfer limit",
            )
        return _Target(artifact, artifact.sha256)

    # -- dry run --------------------------------------------------------------

    def plan(self, request: ExecutionRequest) -> ExecutionPlan:
        """Validate and describe a run without executing any VM command."""
        target = self._resolve_target(request)
        executable = Path("VBoxManage")
        vm = self.settings.vm_name
        user = "<guest-user>"
        password = vbox.PASSWORD_FILE_PLACEHOLDER
        run_id = "VMR-NNNN"
        work = guest_work_directory(run_id)
        sources = [f"<workbench>/{GUEST_SCRIPT_NAME}"]
        if target.sha256 is not None:
            sources.append(f"<artifact-store>/{target.sha256}")
        arguments = guest_arguments(
            request, run_id, target.sha256, self.settings.settle_seconds
        )
        steps = (
            PlannedStep(StepName.APPROVAL, "require explicit --approve"),
            PlannedStep(
                StepName.SAFETY_LOCK, "refuse if a safety lock or unfinished run exists"
            ),
            PlannedStep(
                StepName.PREFLIGHT,
                "VM powered off, snapshot present, NICs disconnected"
                + (
                    ", no shared folders, clipboard and drag-and-drop disabled"
                    if request.profile is ExecutionProfile.SAMPLE
                    else ""
                ),
                vbox.showvminfo_command(executable, vm),
            ),
            PlannedStep(
                StepName.RESTORE_BEFORE,
                f"restore {self.settings.snapshot} and verify it is current",
                vbox.restore_command(executable, vm, self.settings.snapshot),
            ),
            PlannedStep(
                StepName.NETWORK_CHECK,
                "re-check isolation of the restored configuration",
                vbox.showvminfo_command(executable, vm),
            ),
            PlannedStep(
                StepName.START, "start headless", vbox.start_command(executable, vm)
            ),
            PlannedStep(
                StepName.GUEST_READY,
                "wait for Guest Additions, create the guest work directory",
                vbox.mkdir_command(executable, vm, user, password, work),
            ),
            PlannedStep(
                StepName.TRANSFER_IN,
                "copy the guest script" + (" and the sample" if target.sha256 else ""),
                vbox.copyto_command(executable, vm, user, password, sources, work),
            ),
            PlannedStep(
                StepName.EXECUTE,
                f"run for {request.timeout_seconds}s, then kill the process tree "
                "and export every Sysmon event of the window",
                vbox.run_command(
                    executable,
                    vm,
                    user,
                    password,
                    GUEST_POWERSHELL,
                    arguments,
                    request.timeout_seconds + GUEST_RUN_OVERHEAD_SECONDS,
                ),
            ),
            PlannedStep(
                StepName.COLLECT,
                "copy events.xml and run-manifest.json to the host",
                vbox.copyfrom_command(
                    executable,
                    vm,
                    user,
                    password,
                    [f"{work}\\out\\{EVENTS_FILE}", f"{work}\\out\\{MANIFEST_FILE}"],
                    "<host-temp>",
                ),
            ),
            PlannedStep(
                StepName.VERIFY, "verify manifest, SHA-256 and parse every event"
            ),
            PlannedStep(
                StepName.POWER_OFF, "power off", vbox.poweroff_command(executable, vm)
            ),
            PlannedStep(
                StepName.RESTORE_AFTER,
                f"restore {self.settings.snapshot}; failure sets the safety lock",
                vbox.restore_command(executable, vm, self.settings.snapshot),
            ),
            PlannedStep(
                StepName.REGISTER,
                "register events.xml as sysmon and the run metadata as other",
            ),
        )
        return ExecutionPlan(request, self.settings, target.sha256, steps)

    @staticmethod
    def credentials_configured() -> bool:
        try:
            GuestCredentials.from_environment()
        except DomainError:
            return False
        return True

    # -- run ------------------------------------------------------------------

    def run(self, request: ExecutionRequest, *, approved: bool) -> ExecutionRun:
        if not approved:
            raise DomainError(
                DomainErrorCode.EXECUTION_NOT_APPROVED,
                "VM execution requires explicit approval (--approve)",
            )
        hypervisor = self._require_hypervisor()
        target = self._resolve_target(request)
        sample_path: Path | None = None
        if target.artifact is not None:
            store = ArtifactStore(self._root)
            sample_path = store.resolve(target.artifact.relative_path)
            store.verify(
                sample_path, (target.artifact.sha256, target.artifact.size_bytes)
            )
        credentials = self._credentials()

        with self._repository(write=True) as repository:
            lock = repository.get_lock()
            running = repository.running_runs()
            if lock is not None or running:
                raise DomainError(
                    DomainErrorCode.EXECUTION_SAFETY_LOCKED,
                    "a safety lock or unfinished run blocks execution; verify the "
                    "VM manually, then run 'workbench vm unlock'",
                )
            run_id = repository.allocate_run_id()
            repository.insert_run(
                ExecutionRun(
                    display_id=run_id,
                    case_display_id=request.case_display_id,
                    profile=request.profile,
                    target=request.target,
                    target_sha256=target.sha256,
                    vm_name=self.settings.vm_name,
                    snapshot=self.settings.snapshot,
                    timeout_seconds=request.timeout_seconds,
                    status=RunStatus.RUNNING,
                    started_at=utc_now(),
                    finished_at=None,
                    error_code=None,
                    sysmon_artifact_id=None,
                    metadata_artifact_id=None,
                    event_count=None,
                )
            )
            repository.append_step(run_id, StepName.APPROVAL, StepStatus.OK, None)
            repository.append_step(run_id, StepName.SAFETY_LOCK, StepStatus.OK, None)

        _Run(self, hypervisor, credentials, request, run_id, target, sample_path).run()
        return self.show_run(run_id)


class _Run:
    """One run's step machine; owns cleanup and safety-lock decisions."""

    def __init__(
        self,
        service: ExecutionService,
        hypervisor: Hypervisor,
        credentials: GuestCredentials,
        request: ExecutionRequest,
        run_id: str,
        target: _Target,
        sample_path: Path | None,
    ) -> None:
        self.service = service
        self.hv = hypervisor
        self.credentials = credentials
        self.request = request
        self.run_id = run_id
        self.target = target
        self.sample_path = sample_path
        self.settings = service.settings
        self.vm = service.settings.vm_name
        self.work = guest_work_directory(run_id)
        self.vm_touched = False  # restore attempted: cleanup must restore again
        self.restored_after = False

    def _ok(self, step: StepName, detail: str | None = None) -> None:
        self.service._record(self.run_id, step, StepStatus.OK, detail)

    def _fail(self, step: StepName, error: DomainError) -> _StepFailed:
        self.service._record(
            self.run_id, step, StepStatus.FAILED, f"{error.code.value}: {error}"
        )
        return _StepFailed(error)

    def _step(self, step: StepName, action: Callable[[], str | None]) -> None:
        try:
            detail = action()
        except DomainError as exc:
            raise self._fail(step, exc) from exc
        self._ok(step, detail)

    def run(self) -> None:
        keep = Path(tempfile.mkdtemp(prefix="wb-events-"))
        try:
            collected = self._execute(keep)
            self._step(StepName.POWER_OFF, self._power_off)
            self._restore_after()
            artifacts = self._register(collected)
        except _StepFailed as failure:
            raise self._cleanup(failure.error) from None
        except BaseException as exc:
            reported = self._cleanup(None)
            if reported.code is DomainErrorCode.SNAPSHOT_RESTORE_FAILED:
                raise reported from exc
            raise
        finally:
            # Collected logs are sensitive runtime data: never leave host copies.
            for path in keep.iterdir():
                path.unlink()
            keep.rmdir()
        with self.service._repository(write=True) as repository:
            repository.finish_run(
                self.run_id,
                RunStatus.SUCCEEDED,
                sysmon_artifact_id=artifacts[0],
                metadata_artifact_id=artifacts[1],
                event_count=collected.event_count,
            )

    # -- steps ----------------------------------------------------------------

    def _execute(self, keep_dir: Path) -> _Collected:
        self._step(StepName.PREFLIGHT, self._preflight)
        self.vm_touched = True
        self._restore(StepName.RESTORE_BEFORE)
        self._step(StepName.NETWORK_CHECK, self._network_check)
        self._step(StepName.START, self._start)
        self._step(StepName.GUEST_READY, self._wait_ready)
        self._step(StepName.TRANSFER_IN, self._transfer)
        self._step(StepName.EXECUTE, self._run_guest)
        with host_exchange_directory("wb-run-") as host_dir:
            self._step(StepName.COLLECT, lambda: self._collect(host_dir))
            collected: list[_Collected] = []

            def verify() -> str:
                collected.append(self._verify(host_dir))
                return f"{collected[0].event_count} events"

            self._step(StepName.VERIFY, verify)
            # Keep the verified bytes outside the temporary directory lifetime.
            data = collected[0].events.read_bytes()
        keep = keep_dir / EVENTS_FILE
        keep.write_bytes(data)
        return _Collected(
            keep,
            collected[0].manifest,
            collected[0].event_count,
            collected[0].events_sha256,
        )

    def _preflight(self) -> str:
        report = self.service._evaluate(self.hv.vm_info(self.vm), self.request.profile)
        if report.problems:
            network = network_problems(report.info)
            code = (
                DomainErrorCode.EXECUTION_NETWORK_NOT_ISOLATED
                if network and len(network) == len(report.problems)
                else DomainErrorCode.EXECUTION_PREFLIGHT_FAILED
            )
            raise DomainError(code, "; ".join(report.problems))
        return "powered off, snapshot present, isolated"

    def _restore(self, step: StepName) -> None:
        try:
            self.hv.restore_snapshot(self.vm, self.settings.snapshot)
            info = self.hv.vm_info(self.vm)
            if info.current_snapshot != self.settings.snapshot or not info.powered_off:
                raise DomainError(
                    DomainErrorCode.SNAPSHOT_RESTORE_FAILED,
                    "restored VM is not powered off at the clean snapshot",
                )
        except DomainError as exc:
            error = DomainError(
                DomainErrorCode.SNAPSHOT_RESTORE_FAILED,
                f"clean snapshot restore could not be verified ({exc.code.value})",
            )
            self._lock(f"{step.value} failed")
            raise self._fail(step, error) from exc
        self._ok(step, f"current snapshot {self.settings.snapshot}")

    def _lock(self, reason: str) -> None:
        with self.service._repository(write=True) as repository:
            repository.set_lock(self.run_id, reason)

    def _network_check(self) -> str:
        problems = isolation_problems(self.hv.vm_info(self.vm), self.request.profile)
        if problems:
            raise DomainError(
                DomainErrorCode.EXECUTION_NETWORK_NOT_ISOLATED,
                "restored snapshot is not isolated: " + "; ".join(problems),
            )
        return "isolated after restore"

    def _start(self) -> None:
        self.hv.start(self.vm)

    def _wait_ready(self) -> str:
        deadline = self.service._monotonic() + self.settings.guest_ready_timeout_seconds
        while True:
            info = self.hv.vm_info(self.vm)
            if info.powered_off:
                raise DomainError(
                    DomainErrorCode.GUEST_NOT_READY, "VM stopped while booting"
                )
            if (info.guest_additions_run_level or 0) >= 2:
                try:
                    self.hv.guest_make_directory(self.vm, self.credentials, self.work)
                    return "guest additions ready"
                except DomainError:
                    pass  # user session not ready yet; retry until deadline
            if self.service._monotonic() >= deadline:
                raise DomainError(
                    DomainErrorCode.GUEST_NOT_READY,
                    "guest did not become ready before the timeout",
                )
            self.service._sleep(READY_POLL_SECONDS)

    def _transfer(self) -> str:
        with host_exchange_directory("wb-guest-script-") as temporary:
            script = temporary / GUEST_SCRIPT_NAME
            script.write_bytes(guest_script_bytes())
            files = [script]
            if self.sample_path is not None:
                files.append(self.sample_path)
            self.hv.copy_to_guest(self.vm, self.credentials, files, self.work)
        return "script" + (" and sample" if self.sample_path is not None else "")

    def _run_guest(self) -> str:
        try:
            result = self.hv.run_in_guest(
                self.vm,
                self.credentials,
                GUEST_POWERSHELL,
                guest_arguments(
                    self.request,
                    self.run_id,
                    self.target.sha256,
                    self.settings.settle_seconds,
                ),
                self.request.timeout_seconds + GUEST_RUN_OVERHEAD_SECONDS,
            )
        except DomainError as exc:  # e.g. the guestcontrol time limit
            raise DomainError(exc.code, f"{exc}; {self._guest_progress()}") from exc
        if result.exit_code != 0:
            reason = GUEST_EXIT_REASONS.get(result.exit_code, "guest run failed")
            raise DomainError(
                DomainErrorCode.GUEST_EXECUTION_FAILED,
                f"{reason} (exit status {result.exit_code}); {self._guest_progress()}",
            )
        return f"time limit {self.request.timeout_seconds}s"

    def _guest_progress(self) -> str:
        """Best effort: where the guest script was when the run failed."""
        with host_exchange_directory("wb-progress-") as host_dir:
            try:
                self.hv.copy_from_guest(
                    self.vm,
                    self.credentials,
                    [f"{self.work}\\{PROGRESS_FILE}"],
                    host_dir,
                )
                path = host_dir / PROGRESS_FILE
                if path.stat().st_size > MAX_PROGRESS_BYTES:
                    return "guest progress unreadable (too large)"
                return summarize_progress(path.read_bytes())
            except (DomainError, OSError):
                return "guest progress unavailable"

    def _collect(self, host_dir: Path) -> str:
        out = f"{self.work}\\out"
        self.hv.copy_from_guest(
            self.vm,
            self.credentials,
            [f"{out}\\{EVENTS_FILE}", f"{out}\\{MANIFEST_FILE}"],
            host_dir,
        )
        return "events.xml and run-manifest.json"

    def _verify(self, host_dir: Path) -> _Collected:
        def invalid(message: str) -> DomainError:
            return DomainError(DomainErrorCode.EXECUTION_COLLECTION_INVALID, message)

        events_path = host_dir / EVENTS_FILE
        manifest_path = host_dir / MANIFEST_FILE
        for path in (events_path, manifest_path):
            if not path.is_file() or path.is_symlink():
                raise invalid(f"{path.name} was not collected")
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise invalid("run manifest is too large")
        if events_path.stat().st_size > MAX_RECORD_XML_BYTES:
            raise invalid("events.xml exceeds the 32 MiB limit")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (UnicodeError, ValueError) as exc:
            raise invalid("run manifest is not valid JSON") from exc
        if not isinstance(manifest, dict):
            raise invalid("run manifest must be a JSON object")
        data = events_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        expected: dict[str, object] = {
            "collector": GUEST_COLLECTOR,
            "version": GUEST_COLLECTOR_VERSION,
            "run_id": self.run_id,
            "mode": "Sample"
            if self.request.profile is ExecutionProfile.SAMPLE
            else "Scenario",
            "events_file": EVENTS_FILE,
            "events_sha256": digest,
        }
        if self.request.profile is ExecutionProfile.SAMPLE:
            expected["target_sha256"] = self.target.sha256
        else:
            expected["scenario"] = self.request.scenario
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise invalid(f"run manifest field {key} does not match")
        if manifest.get("process_outcome") not in _PROCESS_OUTCOMES:
            raise invalid("run manifest process outcome is invalid")
        baseline = manifest.get("baseline_record_id")
        count = manifest.get("event_count")
        if type(baseline) is not int or type(count) is not int or count < 1:
            raise invalid("run manifest counts are invalid or no event was collected")
        try:
            records = parse_sysmon_records(data)
        except DomainError as exc:
            raise invalid(f"events.xml is invalid ({exc})") from exc
        if len(records) != count:
            raise invalid("event count does not match the manifest")
        for record in records:
            if (
                record.record_id is None
                or not record.record_id.isdigit()
                or int(record.record_id) <= baseline
            ):
                raise invalid("an event is outside the run window")
        return _Collected(events_path, manifest, count, digest)

    def _power_off(self) -> None:
        info = self.hv.vm_info(self.vm)
        if not info.powered_off:
            self.hv.power_off(self.vm)
        self.vm_touched = True

    def _restore_after(self) -> None:
        self._restore(StepName.RESTORE_AFTER)
        self.restored_after = True

    def _register(self, collected: _Collected) -> tuple[str, str]:
        artifacts = ArtifactService(self.service._root)
        try:
            sysmon = artifacts.add(
                self.request.case_display_id, collected.events, "sysmon"
            )
            run = self.service.show_run(self.run_id)
            metadata = {
                "format": METADATA_FORMAT,
                "version": 1,
                "run_id": self.run_id,
                "case_id": self.request.case_display_id,
                "profile": self.request.profile.value,
                "target": self.request.target,
                "target_sha256": self.target.sha256,
                "vm_name": self.vm,
                "snapshot": self.settings.snapshot,
                "timeout_seconds": self.request.timeout_seconds,
                "sysmon_artifact_id": sysmon.artifact_id.display_id,
                "events_sha256": collected.events_sha256,
                "event_count": collected.event_count,
                "guest_manifest": {
                    key: collected.manifest.get(key)
                    for key in (
                        "collector",
                        "version",
                        "mode",
                        "scenario",
                        "target_sha256",
                        "baseline_record_id",
                        "event_count",
                        "process_outcome",
                        "started_at",
                        "completed_at",
                    )
                },
                "steps": [
                    {
                        "step": item.step.value,
                        "status": item.status.value,
                        "at": format_utc(item.at),
                        "detail": item.detail,
                    }
                    for item in run.steps
                ],
            }
            meta_path = collected.events.parent / "execution-run.json"
            meta_path.write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            other = artifacts.add(self.request.case_display_id, meta_path, "other")
        except DomainError as exc:
            raise self._fail(StepName.REGISTER, exc) from exc
        self._ok(
            StepName.REGISTER,
            f"sysmon {sysmon.artifact_id.display_id}, "
            f"metadata {other.artifact_id.display_id}",
        )
        return sysmon.artifact_id.display_id, other.artifact_id.display_id

    # -- cleanup --------------------------------------------------------------

    def _cleanup(self, error: DomainError | None) -> DomainError:
        """Power off and restore after a failure; return the error to report.

        A failed cleanup restore outranks the original failure: the safety lock
        is set, so the caller must see ``SNAPSHOT_RESTORE_FAILED``.
        """
        restore_failed = False
        if self.vm_touched and not self.restored_after:
            try:
                info = self.hv.vm_info(self.vm)
                if not info.powered_off:
                    self.hv.power_off(self.vm)
                    self.service._record(
                        self.run_id, StepName.POWER_OFF, StepStatus.OK, "cleanup"
                    )
            except DomainError as exc:
                self.service._record(
                    self.run_id,
                    StepName.POWER_OFF,
                    StepStatus.FAILED,
                    f"cleanup: {exc.code.value}",
                )
            try:
                self._restore(StepName.RESTORE_AFTER)
            except _StepFailed:
                restore_failed = True  # lock already set by _restore
        original = "INTERRUPTED" if error is None else error.code.value
        reported = error
        if restore_failed and (
            error is None or error.code is not DomainErrorCode.SNAPSHOT_RESTORE_FAILED
        ):
            reported = DomainError(
                DomainErrorCode.SNAPSHOT_RESTORE_FAILED,
                f"cleanup restore failed after {original}; the safety lock is set",
            )
        code = original if reported is None else reported.code.value
        with self.service._repository(write=True) as repository:
            repository.finish_run(self.run_id, RunStatus.FAILED, error_code=code)
        return reported or DomainError(
            DomainErrorCode.GUEST_EXECUTION_FAILED, "run was interrupted"
        )
