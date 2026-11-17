"""W4 Execution Runs against a simulated VBoxManage (no real VM is touched).

``FakeVBoxManage`` imitates the VBoxManage commands the adapter issues, keeps
VM state (power, snapshot, NIC cables, guest files) and supports failure
injection. All sample bytes and Sysmon events are invented harmless data.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.artifact.store import ArtifactStore
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.cli import main
from loader_detection_workbench.domain.artifact import ArtifactKind
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.execution.domain import (
    ExecutionProfile,
    ExecutionRequest,
    ExecutionRun,
    RunStatus,
    StepName,
    StepStatus,
    VmSettings,
)
from loader_detection_workbench.execution.hypervisor import GuestCredentials
from loader_detection_workbench.execution.service import ExecutionService
from loader_detection_workbench.execution.sqlite_repository import (
    SQLiteExecutionRepository,
)
from loader_detection_workbench.execution.vboxmanage import (
    CommandResult,
    VBoxManageHypervisor,
)
from loader_detection_workbench.project.service import ProjectService

PASSWORD = "synthetic-guest-password"
CREDENTIALS = GuestCredentials("analyst", PASSWORD)
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SNAPSHOT = "SYSMON-V2-CLEAN"
VM = "WIN11-ANALYSIS"


def _event(record: int, event_id: int, **fields: str) -> str:
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>"
        f"</System><EventData>{data}</EventData></Event>"
    )


def _guest_events(baseline: int) -> str:
    return (
        "<Events>"
        + _event(
            baseline + 1,
            1,
            UtcTime="2026-11-12 01:02:03.456",
            ProcessGuid="{11111111-2222-4333-8444-555555555555}",
            ProcessId="1234",
            Image="synthetic-target.exe",
            CommandLine="synthetic-target.exe",
        )
        + _event(
            baseline + 2,
            13,
            UtcTime="2026-11-12 01:02:04.000",
            EventType="SetValue",
            Image="synthetic-target.exe",
            TargetObject="HKU\\S-1-5-21\\Software\\WorkbenchScenario\\probe",
            Details="DWORD (0x00000001)",
        )
        + _event(
            baseline + 3,
            22,
            UtcTime="2026-11-12 01:02:05.000",
            Image="synthetic-target.exe",
            QueryName="workbench-probe.example.invalid",
            QueryStatus="9003",
        )
        + "</Events>"
    )


@dataclass
class VmConfig:
    cable: str = "off"
    shared_folders: tuple[str, ...] = ()
    clipboard: str = "disabled"
    draganddrop: str = "disabled"


@dataclass
class FakeVBoxManage:
    """Simulated VBoxManage CLI. ``fail`` maps an operation to a failure."""

    state: str = "poweroff"
    current: str = "SYSMON-DEMO-CLEAN"
    snapshots: tuple[str, ...] = ("WIN11-CLEAN-BASE", "SYSMON-DEMO-CLEAN", SNAPSHOT)
    config: VmConfig = field(default_factory=VmConfig)
    snapshot_config: VmConfig = field(default_factory=VmConfig)
    run_level: int = 3
    guest_files: dict[str, bytes] = field(default_factory=dict)
    commands: list[tuple[str, ...]] = field(default_factory=list)
    password_files: list[str] = field(default_factory=list)
    fail: dict[str, int] = field(default_factory=dict)
    restore_keeps_snapshot: bool = False
    guest_exit: int = 0
    tamper: Callable[[dict[str, bytes], str], None] | None = None
    baseline: int = 500

    def _info(self) -> str:
        lines = [
            f'name="{VM}"',
            f'VMState="{self.state}"',
            'nic1="nat"',
            f'cableconnected1="{self.config.cable}"',
            'nic2="none"',
            f'clipboard="{self.config.clipboard}"',
            f'draganddrop="{self.config.draganddrop}"',
        ]
        for index, name in enumerate(self.config.shared_folders, start=1):
            lines.append(f'SharedFolderNameMachineMapping{index}="{name}"')
        for index, name in enumerate(self.snapshots):
            suffix = "" if index == 0 else f"-{index}"
            lines.append(f'SnapshotName{suffix}="{name}"')
            lines.append(f'SnapshotDescription{suffix}="multi\nline"')
        lines.append(f'CurrentSnapshotName="{self.current}"')
        if self.state == "running":
            lines.append(f"GuestAdditionsRunLevel={self.run_level}")
        return "\n".join(lines) + "\n"

    def _option(self, argv: Sequence[str], name: str) -> str:
        for item in argv:
            if item.startswith(f"--{name}="):
                return item.split("=", 1)[1]
        raise AssertionError(f"missing --{name}")

    def run(self, arguments: Sequence[str], timeout_seconds: float) -> CommandResult:
        argv = tuple(arguments)
        self.commands.append(argv)
        assert all(PASSWORD not in part for part in argv)
        op = argv[1] if argv[1] != "guestcontrol" else f"guest-{argv[3]}"
        if argv[1] == "snapshot":
            op = "restore"
        if op.startswith("guest-"):
            password_file = self._option(argv, "passwordfile")
            assert Path(password_file).read_text(encoding="utf-8") == PASSWORD
            self.password_files.append(password_file)
            if self.state != "running":
                return CommandResult(1, "")
        if op in self.fail:
            return CommandResult(self.fail[op], "")
        if op == "showvminfo":
            return CommandResult(0, self._info())
        if op == "restore":
            if self.state != "poweroff":
                return CommandResult(1, "")
            if not self.restore_keeps_snapshot:
                self.current = argv[4]
                self.config = VmConfig(**vars(self.snapshot_config))
            self.guest_files.clear()
            return CommandResult(0, "")
        if op == "startvm":
            self.state = "running"
            return CommandResult(0, "")
        if op == "controlvm":
            self.state = "poweroff"
            return CommandResult(0, "")
        if op == "guest-mkdir":
            return CommandResult(0, "")
        if op == "guest-copyto":
            target = self._option(argv, "target-directory")
            for source in argv[argv.index(f"--target-directory={target}") + 1 :]:
                path = Path(source)
                if not target.endswith("\\"):  # real VBoxManage 7.2 refuses
                    return CommandResult(1, "", "VBOX_E_IPRT_ERROR")
                self.guest_files[f"{target}{path.name}"] = path.read_bytes()
            return CommandResult(0, "")
        if op == "guest-run":
            code = self._guest_run(argv)
            if code == 0:
                return CommandResult(0, "")
            # Real VBoxManage 7.2 collapses every non-zero guest exit to 33.
            return CommandResult(33, f"workbench-exit: {code}\r\n")
        if op == "guest-copyfrom":
            host_dir = self._option(argv, "target-directory")
            for source in argv[argv.index(f"--target-directory={host_dir}") + 1 :]:
                if not host_dir.endswith(("\\", "/")):
                    return CommandResult(1, "", "VBOX_E_IPRT_ERROR")
                if source not in self.guest_files:
                    return CommandResult(1, "")
                name = source.rpartition("\\")[2]
                (Path(host_dir) / name).write_bytes(self.guest_files[source])
            return CommandResult(0, "")
        raise AssertionError(f"unexpected command {argv}")

    def _guest_run(self, argv: tuple[str, ...]) -> int:
        args = list(argv[argv.index("--") + 2 :])
        values = {args[i][1:]: args[i + 1] for i in range(4, len(args) - 1, 2)}
        work = values["WorkDirectory"]
        assert f"{work}\\Invoke-WorkbenchGuestRun.ps1" in self.guest_files
        if self.guest_exit:
            return self.guest_exit
        manifest: dict[str, object] = {
            "collector": "workbench-guest-run",
            "version": 1,
            "run_id": values["RunId"],
            "mode": values["Mode"],
            "scenario": values.get("Scenario"),
            "target_sha256": values.get("ExpectedSha256"),
            "baseline_record_id": self.baseline,
            "process_outcome": "timeout_killed",
            "started_at": "2026-11-12T01:02:00Z",
            "completed_at": "2026-11-12T01:05:00Z",
        }
        if values["Mode"] == "Sample":
            sample = self.guest_files[f"{work}\\{values['SampleFileName']}"]
            if hashlib.sha256(sample).hexdigest() != values["ExpectedSha256"]:
                return 13
        events = _guest_events(self.baseline).encode("utf-8")
        manifest.update(
            event_count=3,
            events_file="events.xml",
            events_sha256=hashlib.sha256(events).hexdigest(),
        )
        self.guest_files[f"{work}\\out\\events.xml"] = events
        self.guest_files[f"{work}\\out\\run-manifest.json"] = json.dumps(
            manifest
        ).encode("utf-8")
        if self.tamper is not None:
            self.tamper(self.guest_files, work)
        return 0

    def ops(self) -> list[str]:
        return [
            c[1] if c[1] != "guestcontrol" else f"guest-{c[3]}" for c in self.commands
        ]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    ProjectService().create(project, "Execution")
    cases = CaseService(project)
    cases.create("benign baseline", "benign")  # CASE-0001
    cases.create("dev sample", "malware")  # CASE-0002
    sample = tmp_path / "synthetic.bin"
    sample.write_bytes(b"MZ" + b"\0" * 62 + b"HARMLESS-SYNTHETIC-SAMPLE")
    ArtifactService(project).add("CASE-0002", sample, "sample")  # ART-000001
    note = tmp_path / "note.txt"
    note.write_text("not a sample", encoding="utf-8")
    ArtifactService(project).add("CASE-0002", note, "other")  # ART-000002
    return project


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


def _service(root: Path, fake: FakeVBoxManage) -> ExecutionService:
    clock = FakeClock()
    return ExecutionService(
        root,
        VmSettings(vm_name=VM, snapshot=SNAPSHOT, guest_ready_timeout_seconds=30),
        VBoxManageHypervisor(Path("VBoxManage"), fake),
        credentials=lambda: CREDENTIALS,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )


SCENARIO = ExecutionRequest(
    "CASE-0001", ExecutionProfile.BENIGN_SCENARIO, 60, scenario="registry-probe"
)
SAMPLE = ExecutionRequest(
    "CASE-0002", ExecutionProfile.SAMPLE, 120, sample_artifact_id="ART-000001"
)


def _steps(run: ExecutionRun) -> list[tuple[str, str]]:
    return [(item.step.value, item.status.value) for item in run.steps]


def _last_run(root: Path) -> ExecutionRun:
    return ExecutionService(root).list_runs()[-1]


def test_benign_scenario_run_registers_full_event_collection(root: Path) -> None:
    fake = FakeVBoxManage()
    run = _service(root, fake).run(SCENARIO, approved=True)

    assert run.status is RunStatus.SUCCEEDED
    assert run.display_id == "VMR-0001"
    assert run.event_count == 3
    assert [step for step, _ in _steps(run)] == [
        "approval",
        "safety_lock",
        "preflight",
        "restore_before",
        "network_check",
        "start",
        "guest_ready",
        "transfer_in",
        "execute",
        "collect",
        "verify",
        "power_off",
        "restore_after",
        "register",
    ]
    assert all(status == "ok" for _, status in _steps(run))
    ops = fake.ops()
    assert ops.count("snapshot") == 2
    assert ops.index("snapshot") < ops.index("startvm")
    assert ops[-2:] == ["snapshot", "showvminfo"]
    assert fake.state == "poweroff" and fake.current == SNAPSHOT
    # Secret handling: password only via short-lived files that are removed.
    assert fake.password_files
    assert not any(Path(item).exists() for item in fake.password_files)

    artifacts = {
        a.artifact_id.display_id: a
        for a in ArtifactService(root).list_artifacts("CASE-0001")
    }
    sysmon = artifacts[run.sysmon_artifact_id or ""]
    metadata = artifacts[run.metadata_artifact_id or ""]
    assert sysmon.kind is ArtifactKind.SYSMON
    assert metadata.kind is ArtifactKind.OTHER
    store = ArtifactStore(root)
    events = store.read_verified(
        sysmon.relative_path, (sysmon.sha256, sysmon.size_bytes), max_bytes=1 << 20
    )
    assert events == _guest_events(500).encode("utf-8")
    meta_bytes = store.read_verified(
        metadata.relative_path,
        (metadata.sha256, metadata.size_bytes),
        max_bytes=1 << 20,
    )
    meta = json.loads(meta_bytes)
    assert meta["format"] == "workbench-execution-run"
    assert meta["events_sha256"] == sysmon.sha256
    assert meta["guest_manifest"]["scenario"] == "registry-probe"
    text = meta_bytes.decode("utf-8")
    assert PASSWORD not in text
    assert str(root) not in text and str(root.parent) not in text
    assert re.search(r"[A-Za-z]:\\\\Users", text) is None

    timeline = CaseTimelineQuery(root).query("CASE-0001")
    assert len(timeline.observations) == 1
    assert {record.event_id for record in timeline.other_records} == {13, 22}
    assert ExecutionService(root).lock_status().locked is False


def test_sample_run_transfers_verified_artifact(root: Path) -> None:
    fake = FakeVBoxManage()
    run = _service(root, fake).run(SAMPLE, approved=True)
    assert run.status is RunStatus.SUCCEEDED
    sample = ArtifactService(root).show("CASE-0002", "ART-000001")
    assert run.target_sha256 == sample.sha256
    copy = next(c for c in fake.commands if c[1] == "guestcontrol" and c[3] == "copyto")
    assert copy[-1].endswith(sample.sha256)
    run_cmd = next(c for c in fake.commands if c[1] == "guestcontrol" and c[3] == "run")
    assert "--timeout=240000" in run_cmd  # 120 s + guest overhead
    assert run_cmd[-6:] == (
        "-Mode",
        "Sample",
        "-SampleFileName",
        sample.sha256,
        "-ExpectedSha256",
        sample.sha256,
    )


def test_unapproved_run_executes_nothing(root: Path) -> None:
    fake = FakeVBoxManage()
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=False)
    assert error.value.code is DomainErrorCode.EXECUTION_NOT_APPROVED
    assert fake.commands == []
    assert ExecutionService(root).list_runs() == []


@pytest.mark.parametrize(
    ("request_", "code"),
    [
        (
            ExecutionRequest(
                "CASE-0002", ExecutionProfile.BENIGN_SCENARIO, 60, scenario="file-write"
            ),
            DomainErrorCode.INVALID_EXECUTION_REQUEST,
        ),
        (
            ExecutionRequest(
                "CASE-0001",
                ExecutionProfile.SAMPLE,
                60,
                sample_artifact_id="ART-000001",
            ),
            DomainErrorCode.INVALID_EXECUTION_REQUEST,
        ),
        (
            ExecutionRequest(
                "CASE-0002",
                ExecutionProfile.SAMPLE,
                60,
                sample_artifact_id="ART-000002",
            ),
            DomainErrorCode.INVALID_EXECUTION_REQUEST,
        ),
        (
            ExecutionRequest(
                "CASE-0009",
                ExecutionProfile.SAMPLE,
                60,
                sample_artifact_id="ART-000001",
            ),
            DomainErrorCode.CASE_NOT_FOUND,
        ),
    ],
)
def test_invalid_targets_are_rejected_before_any_command(
    root: Path, request_: ExecutionRequest, code: DomainErrorCode
) -> None:
    fake = FakeVBoxManage()
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(request_, approved=True)
    assert error.value.code is code
    assert fake.commands == []


def test_connected_cable_stops_before_restore(root: Path) -> None:
    fake = FakeVBoxManage(config=VmConfig(cable="on"))
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.EXECUTION_NETWORK_NOT_ISOLATED
    assert fake.ops() == ["showvminfo"]
    run = _last_run(root)
    assert run.status is RunStatus.FAILED
    assert run.error_code == "EXECUTION_NETWORK_NOT_ISOLATED"
    assert ExecutionService(root).lock_status().locked is False


def test_sample_runs_require_no_host_channels(root: Path) -> None:
    channels = VmConfig(shared_folders=("Exchange",), clipboard="bidirectional")
    fake = FakeVBoxManage(config=channels, snapshot_config=channels)
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SAMPLE, approved=True)
    assert error.value.code is DomainErrorCode.EXECUTION_PREFLIGHT_FAILED
    assert "shared folder" in str(error.value)
    # Benign scenarios only require network isolation.
    benign = FakeVBoxManage(config=channels, snapshot_config=channels)
    assert _service(root, benign).run(SCENARIO, approved=True).status is (
        RunStatus.SUCCEEDED
    )


def test_missing_snapshot_or_running_vm_fails_preflight(root: Path) -> None:
    fake = FakeVBoxManage(snapshots=("WIN11-CLEAN-BASE",))
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.EXECUTION_PREFLIGHT_FAILED
    fake = FakeVBoxManage(state="running")
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert "powered off" in str(error.value)
    assert "snapshot" not in fake.ops()


def test_restore_failure_sets_lock_and_blocks_next_run(root: Path) -> None:
    fake = FakeVBoxManage(fail={"restore": 1})
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.SNAPSHOT_RESTORE_FAILED
    assert "startvm" not in fake.ops()
    status = ExecutionService(root).lock_status()
    assert status.lock is not None and status.lock.run_display_id == "VMR-0001"
    run = _last_run(root)
    assert run.status is RunStatus.FAILED
    assert ("restore_before", "failed") in _steps(run)

    healthy = FakeVBoxManage()
    with pytest.raises(DomainError) as error:
        _service(root, healthy).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.EXECUTION_SAFETY_LOCKED
    assert healthy.commands == []
    assert len(ExecutionService(root).list_runs()) == 1

    with pytest.raises(DomainError):
        ExecutionService(root).unlock("  ")
    released = ExecutionService(root).unlock("restored manually and verified")
    assert released.lock is not None
    assert ExecutionService(root).lock_status().locked is False
    assert _service(root, healthy).run(SCENARIO, approved=True).status is (
        RunStatus.SUCCEEDED
    )


def test_unverifiable_restore_is_treated_as_failure(root: Path) -> None:
    fake = FakeVBoxManage(restore_keeps_snapshot=True)
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.SNAPSHOT_RESTORE_FAILED
    assert ExecutionService(root).lock_status().lock is not None


def test_restored_snapshot_with_network_is_never_started(root: Path) -> None:
    fake = FakeVBoxManage(snapshot_config=VmConfig(cable="on"))
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.EXECUTION_NETWORK_NOT_ISOLATED
    assert "startvm" not in fake.ops()
    assert ("network_check", "failed") in _steps(_last_run(root))


@pytest.mark.parametrize(
    ("setup", "code", "failed_step"),
    [
        (
            lambda f: setattr(f, "guest_exit", 13),
            DomainErrorCode.GUEST_EXECUTION_FAILED,
            "execute",
        ),
        (
            lambda f: f.fail.update({"guest-copyto": 1}),
            DomainErrorCode.HYPERVISOR_COMMAND_FAILED,
            "transfer_in",
        ),
        (
            lambda f: setattr(
                f,
                "tamper",
                lambda files, work: files.__setitem__(
                    f"{work}\\out\\events.xml", b"<Events></Events>"
                ),
            ),
            DomainErrorCode.EXECUTION_COLLECTION_INVALID,
            "verify",
        ),
        (
            lambda f: setattr(
                f,
                "tamper",
                lambda files, work: files.pop(f"{work}\\out\\run-manifest.json"),
            ),
            DomainErrorCode.HYPERVISOR_COMMAND_FAILED,
            "collect",
        ),
        (
            lambda f: setattr(
                f,
                "tamper",
                lambda files, work: files.__setitem__(
                    f"{work}\\out\\run-manifest.json",
                    files[f"{work}\\out\\run-manifest.json"].replace(
                        b'"baseline_record_id": 500', b'"baseline_record_id": 501'
                    ),
                ),
            ),
            DomainErrorCode.EXECUTION_COLLECTION_INVALID,
            "verify",
        ),
    ],
)
def test_guest_failures_power_off_and_restore_without_registering(
    root: Path,
    setup: Callable[[FakeVBoxManage], None],
    code: DomainErrorCode,
    failed_step: str,
) -> None:
    fake = FakeVBoxManage()
    setup(fake)
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is code
    run = _last_run(root)
    assert run.status is RunStatus.FAILED
    assert run.error_code == code.value
    steps = _steps(run)
    assert (failed_step, "failed") in steps
    assert steps[-1] == ("restore_after", "ok")
    assert fake.state == "poweroff" and fake.current == SNAPSHOT
    assert ExecutionService(root).lock_status().locked is False
    kinds = {a.kind for a in ArtifactService(root).list_artifacts("CASE-0001")}
    assert ArtifactKind.SYSMON not in kinds


def test_failed_final_restore_locks_and_registers_nothing(root: Path) -> None:
    fake = FakeVBoxManage()
    real_run = fake.run
    restores = {"count": 0}

    def flaky(arguments: Sequence[str], timeout: float) -> CommandResult:
        if arguments[1] == "snapshot":
            restores["count"] += 1
            if restores["count"] >= 2:
                fake.commands.append(tuple(arguments))
                return CommandResult(1, "")
        return real_run(arguments, timeout)

    service = ExecutionService(
        root,
        VmSettings(vm_name=VM, snapshot=SNAPSHOT),
        VBoxManageHypervisor(
            Path("VBoxManage"), type("R", (), {"run": staticmethod(flaky)})()
        ),
        credentials=lambda: CREDENTIALS,
        sleep=lambda _: None,
    )
    with pytest.raises(DomainError) as error:
        service.run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.SNAPSHOT_RESTORE_FAILED
    assert ExecutionService(root).lock_status().lock is not None
    run = _last_run(root)
    assert run.sysmon_artifact_id is None
    assert ("restore_after", "failed") in _steps(run)
    assert ArtifactService(root).list_artifacts("CASE-0001") == []


def test_guest_never_ready_times_out_and_restores(root: Path) -> None:
    fake = FakeVBoxManage(run_level=0)
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.GUEST_NOT_READY
    assert fake.state == "poweroff" and fake.current == SNAPSHOT
    assert _steps(_last_run(root))[-1] == ("restore_after", "ok")


def test_abandoned_running_run_blocks_until_unlock(root: Path) -> None:
    workspace = ProjectService().open(root)
    repository = SQLiteExecutionRepository(workspace, write=True)
    try:
        with repository.transaction():
            run_id = repository.allocate_run_id()
            repository.insert_run(
                ExecutionRun(
                    run_id,
                    "CASE-0001",
                    ExecutionProfile.BENIGN_SCENARIO,
                    "dns-invalid",
                    None,
                    VM,
                    SNAPSHOT,
                    60,
                    RunStatus.RUNNING,
                    datetime.now(UTC),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            )
            repository.append_step(run_id, StepName.START, StepStatus.OK, None)
    finally:
        repository.close()
    status = ExecutionService(root).lock_status()
    assert status.locked and status.running_runs == ("VMR-0001",)
    fake = FakeVBoxManage()
    with pytest.raises(DomainError) as error:
        _service(root, fake).run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.EXECUTION_SAFETY_LOCKED
    before = ExecutionService(root).unlock("VM inspected and restored by hand")
    assert before.running_runs == ("VMR-0001",)
    abandoned = ExecutionService(root).show_run("VMR-0001")
    assert abandoned.status is RunStatus.ABANDONED
    assert abandoned.steps[-1].status is StepStatus.SKIPPED
    assert _service(root, fake).run(SCENARIO, approved=True).display_id == "VMR-0002"


def test_finished_runs_and_steps_are_immutable(root: Path) -> None:
    _service(root, FakeVBoxManage()).run(SCENARIO, approved=True)
    connection = sqlite3.connect(ProjectService().open(root).database_path)
    try:
        for statement in (
            "UPDATE execution_runs SET status = 'failed'",
            "DELETE FROM execution_runs",
            "UPDATE execution_steps SET status = 'failed'",
            "DELETE FROM execution_steps",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
    finally:
        connection.close()


def test_dry_run_plan_executes_nothing_and_hides_paths(root: Path) -> None:
    fake = FakeVBoxManage()
    plan = _service(root, fake).plan(SAMPLE)
    assert fake.commands == []
    assert [step.step for step in plan.steps][0] is StepName.APPROVAL
    rendered = "\n".join(" ".join(s.command) for s in plan.steps if s.command)
    assert "<password-file>" in rendered and PASSWORD not in rendered
    assert str(root) not in rendered
    assert plan.target_sha256 is not None and plan.target_sha256 in rendered
    assert ExecutionService(root).list_runs() == []


def test_cli_vm_commands(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(root)
    monkeypatch.delenv("WORKBENCH_GUEST_PASSWORD", raising=False)
    assert main(["vm", "scenarios"]) == 0
    assert "registry-probe" in capsys.readouterr().out

    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("dry-run and status must not start VBoxManage")

    monkeypatch.setattr(
        "loader_detection_workbench.execution.vboxmanage.subprocess.run", forbidden
    )
    assert (
        main(["vm", "scenario", "CASE-0001", "--scenario", "dns-invalid", "--dry-run"])
        == 0
    )
    out = capsys.readouterr().out
    assert "dry_run: true" in out and "guest_credentials: missing" in out
    assert main(["vm", "run", "CASE-0002", "--sample", "ART-000001"]) == 2
    assert "EXECUTION_NOT_APPROVED" in capsys.readouterr().err
    assert main(["vm", "status"]) == 0
    assert "safety_lock: none" in capsys.readouterr().out
    assert main(["vm", "list"]) == 0
    assert main(["vm", "unlock", "--note", "nothing to do"]) == 0
    assert "nothing to release" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["vm", "run", "CASE-0002", "--sample", "ART-000001", "--timeout", "5"])
    with pytest.raises(SystemExit):
        main(["vm", "scenario", "CASE-0001", "--scenario", "cmd.exe /c whoami"])
    with pytest.raises(SystemExit):
        main(
            [
                "vm",
                "run",
                "CASE-0002",
                "--sample",
                "ART-000001",
                "--dry-run",
                "--approve",
            ]
        )
    assert main(["vm", "show", "VMR-0001"]) == 2
    assert "EXECUTION_RUN_NOT_FOUND" in capsys.readouterr().err


def test_failed_cleanup_restore_outranks_guest_failure(root: Path) -> None:
    fake = FakeVBoxManage(guest_exit=16)
    real_run = fake.run
    restores = {"count": 0}

    def flaky(arguments: Sequence[str], timeout: float) -> CommandResult:
        if arguments[1] == "snapshot":
            restores["count"] += 1
            if restores["count"] >= 2:
                return CommandResult(1, "")
        return real_run(arguments, timeout)

    runner = type("Runner", (), {"run": staticmethod(flaky)})()
    service = ExecutionService(
        root,
        VmSettings(vm_name=VM, snapshot=SNAPSHOT),
        VBoxManageHypervisor(Path("VBoxManage"), runner),
        credentials=lambda: CREDENTIALS,
        sleep=lambda _: None,
    )
    with pytest.raises(DomainError) as error:
        service.run(SCENARIO, approved=True)
    assert error.value.code is DomainErrorCode.SNAPSHOT_RESTORE_FAILED
    assert "GUEST_EXECUTION_FAILED" in str(error.value)
    run = _last_run(root)
    assert run.error_code == "SNAPSHOT_RESTORE_FAILED"
    assert ("execute", "failed") in _steps(run)
    assert ("restore_after", "failed") in _steps(run)
    assert ExecutionService(root).lock_status().lock is not None


def test_host_exchange_directory_is_readable_by_other_processes() -> None:
    """Regression: a real VirtualBox run could not read an owner-only mkdtemp dir."""
    import os
    import subprocess
    import sys
    import tempfile

    from loader_detection_workbench.execution.service import host_exchange_directory

    with host_exchange_directory("wb-test-") as directory:
        assert directory.is_dir() and directory.parent == Path(tempfile.gettempdir())
        assert directory.name.startswith("wb-test-") and len(directory.name) == 24
        (directory / "probe.txt").write_text("ok", encoding="utf-8")
        if os.name == "nt":
            acl = subprocess.run(
                ["icacls", str(directory)], capture_output=True, text=True, check=True
            ).stdout
            # Inherited entries (I) from the user's temp directory, unlike the
            # explicit owner-only ACL that tempfile.mkdtemp applies.
            assert "(I)" in acl
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; print(open(sys.argv[1]).read())",
                str(directory / "probe.txt"),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert child.stdout.strip() == "ok"
        kept = directory
    assert not kept.exists()
    with (
        host_exchange_directory("wb-test-") as first,
        host_exchange_directory("wb-test-") as second,
    ):
        assert first != second


def test_failed_command_reports_status_identifiers_without_output_text() -> None:
    from loader_detection_workbench.execution.vboxmanage import (
        CommandResult,
        VBoxManageHypervisor,
        status_identifiers,
    )

    stderr = (
        "VBoxManage.exe: error: Unable to query type for source "
        "'C:\\Users\\someone\\AppData\\x.ps1' (VERR_ACCESS_DENIED)\n"
        "VBoxManage.exe: error: Details: code VBOX_E_IPRT_ERROR (0x80bb0005), "
        "VERR_ACCESS_DENIED again\n"
    )
    assert status_identifiers(stderr) == ("VERR_ACCESS_DENIED", "VBOX_E_IPRT_ERROR")
    assert status_identifiers("plain failure text") == ()

    class Runner:
        def run(self, arguments: object, timeout_seconds: float) -> CommandResult:
            return CommandResult(1, "", stderr)

    hypervisor = VBoxManageHypervisor(runner=Runner())
    with pytest.raises(DomainError) as caught:
        hypervisor.power_off("VM")
    message = str(caught.value)
    assert "VERR_ACCESS_DENIED, VBOX_E_IPRT_ERROR" in message
    assert "someone" not in message
    assert "AppData" not in message


def test_copy_commands_mark_the_destination_as_a_directory() -> None:
    import os

    from loader_detection_workbench.execution.vboxmanage import (
        as_directory,
        copyfrom_command,
        copyto_command,
    )

    exe = Path("VBoxManage")
    to_guest = copyto_command(exe, "VM", "u", "pw", ["a.ps1"], "C:\\work\\run")
    assert "--target-directory=C:\\work\\run\\" in to_guest
    from_guest = copyfrom_command(exe, "VM", "u", "pw", ["C:\\g\\e.xml"], "hostdir")
    assert f"--target-directory=hostdir{os.sep}" in from_guest
    assert as_directory("C:/work/", "\\") == "C:/work/"
    assert as_directory("C:\\work\\", "\\") == "C:\\work\\"


def test_guest_exit_code_is_read_from_the_fixed_output_line() -> None:
    from loader_detection_workbench.execution.vboxmanage import (
        CommandResult,
        guest_exit_code,
        run_command,
    )

    assert guest_exit_code(CommandResult(0, "workbench-exit: 12\n")) == 0
    assert guest_exit_code(CommandResult(33, "noise\r\nworkbench-exit: 12\r\n")) == 12
    assert guest_exit_code(CommandResult(33, "")) == 33
    assert guest_exit_code(CommandResult(33, "x workbench-exit: 12")) == 33
    assert guest_exit_code(CommandResult(33, "workbench-exit: 0\n")) == 33
    command = run_command(Path("VBoxManage"), "VM", "u", "pw", "p.exe", ["-a"], 30)
    assert "--wait-stdout" in command
    assert "--no-wait-stdout" not in command
