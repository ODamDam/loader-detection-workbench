"""VBoxManage parsing, isolation policy and request validation (no VM)."""

import re
from collections.abc import Callable
from pathlib import Path

import pytest

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.execution import vboxmanage as vbox
from loader_detection_workbench.execution.domain import (
    BENIGN_SCENARIOS,
    ExecutionProfile,
    ExecutionRequest,
    VmSettings,
)
from loader_detection_workbench.execution.hypervisor import (
    GuestCredentials,
    isolation_problems,
)
from loader_detection_workbench.execution.service import guest_script_bytes

SAMPLE_OUTPUT = r"""name="WIN11-ANALYSIS"
VMState="poweroff"
"SATA-0-0"="E:\\VMs\\disk.vdi"
nic1="nat"
cableconnected1="off"
nic2="none"
nic3="hostonly"
cableconnected3="on"
clipboard="bidirectional"
draganddrop="disabled"
SharedFolderNameMachineMapping1="Exchange"
SharedFolderPathMachineMapping1="C:\\Exchange"
SnapshotName="BASE"
SnapshotDescription="line one
CurrentSnapshotName=\"SPOOFED\"
VMState=running
end of description"
SnapshotName-1="SYSMON-V2-CLEAN"
CurrentSnapshotName="SYSMON-V2-CLEAN"
GuestAdditionsRunLevel=2
"""


def test_machine_readable_parser_keeps_multiline_values_out_of_keys() -> None:
    values = vbox.parse_machine_readable(SAMPLE_OUTPUT)
    assert values["VMState"] == "poweroff"
    assert values["CurrentSnapshotName"] == "SYSMON-V2-CLEAN"
    assert values["SATA-0-0"] == "E:\\VMs\\disk.vdi"
    assert "SPOOFED" in values["SnapshotDescription"]


def test_vm_info_and_isolation_policy() -> None:
    info = vbox.vm_info_from_machine_readable("WIN11-ANALYSIS", SAMPLE_OUTPUT)
    assert info.powered_off
    assert info.snapshots == ("BASE", "SYSMON-V2-CLEAN")
    assert info.current_snapshot == "SYSMON-V2-CLEAN"
    assert [(n.index, n.isolated) for n in info.nics] == [
        (1, True),
        (2, True),
        (3, False),
    ]
    assert info.shared_folders == ("Exchange",)
    assert info.guest_additions_run_level == 2
    sample = isolation_problems(info, ExecutionProfile.SAMPLE)
    benign = isolation_problems(info, ExecutionProfile.BENIGN_SCENARIO)
    assert any("nic3" in item for item in sample)
    assert any("shared folder" in item for item in sample)
    assert any("clipboard" in item for item in sample)
    assert not any("drag" in item for item in sample)
    assert benign == ["nic3 (hostonly) cable is connected"]


def test_vm_info_requires_state() -> None:
    with pytest.raises(DomainError) as error:
        vbox.vm_info_from_machine_readable("vm", 'name="vm"\n')
    assert error.value.code is DomainErrorCode.HYPERVISOR_COMMAND_FAILED


def test_command_builders_never_contain_password() -> None:
    credentials = GuestCredentials("analyst", "s3cret-value")
    assert "s3cret-value" not in repr(credentials)
    command = vbox.run_command(
        Path("VBoxManage"), "vm", credentials.user, "<file>", "prog.exe", ["-x"], 30
    )
    assert "--passwordfile=<file>" in command
    assert all("s3cret" not in part for part in command)
    assert command[command.index("--") + 1 :] == ("prog.exe", "-x")
    assert "--timeout=30000" in command


def test_credentials_come_from_environment_only() -> None:
    with pytest.raises(DomainError) as error:
        GuestCredentials.from_environment({})
    assert error.value.code is DomainErrorCode.EXECUTION_GUEST_CREDENTIALS_MISSING
    loaded = GuestCredentials.from_environment(
        {"WORKBENCH_GUEST_USER": "u", "WORKBENCH_GUEST_PASSWORD": "p"}
    )
    assert loaded == GuestCredentials("u", "p")


def test_request_and_settings_validation() -> None:
    ExecutionRequest("CASE-0001", ExecutionProfile.SAMPLE, 60, "ART-000001")
    ExecutionRequest(
        "CASE-0001", ExecutionProfile.BENIGN_SCENARIO, 60, scenario="dns-invalid"
    )
    invalid: list[Callable[[], object]] = [
        lambda: ExecutionRequest("CASE-0001", ExecutionProfile.SAMPLE, 60),
        lambda: ExecutionRequest("CASE-0001", ExecutionProfile.SAMPLE, 5, "ART-000001"),
        lambda: ExecutionRequest("CASE-0001", ExecutionProfile.SAMPLE, 901, "ART-1"),
        lambda: ExecutionRequest(
            "CASE-0001", ExecutionProfile.BENIGN_SCENARIO, 60, scenario="cmd /c x"
        ),
        lambda: ExecutionRequest(
            "CASE-0001",
            ExecutionProfile.BENIGN_SCENARIO,
            60,
            sample_artifact_id="ART-000001",
            scenario="dns-invalid",
        ),
        lambda: VmSettings(vm_name="bad;name"),
        lambda: VmSettings(snapshot=""),
    ]
    for build in invalid:
        with pytest.raises(DomainError) as error:
            build()
        assert error.value.code is DomainErrorCode.INVALID_EXECUTION_REQUEST


def test_guest_script_scenarios_match_domain_list() -> None:
    script = guest_script_bytes().decode("utf-8")
    block = script.split("$script:WorkbenchScenarios = [ordered]@{", 1)[1]
    block = block.split("\n}", 1)[0]
    names = re.findall(r"^\s+'([a-z-]+)'\s+=", block, re.MULTILINE)
    assert names == list(BENIGN_SCENARIOS)
