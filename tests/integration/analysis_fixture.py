"""Shared synthetic workspace with every analysis record kind (not a test).

All sample bytes, Sysmon events, rules and VM run rows are invented, harmless
data. No VM, hypervisor or guest is touched: the execution run is written
directly through the repository.
"""

from __future__ import annotations

import sys
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.time import utc_now
from loader_detection_workbench.execution.domain import (
    ExecutionProfile,
    ExecutionRun,
    RunStatus,
    StepName,
    StepStatus,
)
from loader_detection_workbench.execution.sqlite_repository import (
    SQLiteExecutionRepository,
)
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.static_analysis.service import StaticAnalysisService

sys.path.insert(0, str(Path(__file__).parents[1] / "unit"))
from test_static_features import (  # type: ignore[import-not-found]  # noqa: E402
    synthetic_pe_with_imports,
)

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
PARENT_GUID = "{aaaaaaaa-0000-4000-8000-000000000001}"
CHILD_GUID = "{aaaaaaaa-0000-4000-8000-000000000002}"
UNTRUSTED = "<script>alert(1)</script> | `tick` [x](javascript:bad)"

YARA_RULE = """
rule synthetic_loader_marker {
  strings:
    $marker = "SYNTHETIC-LOADER-MARKER"
  condition:
    $marker
}
"""
SIGMA_V1 = r"""
title: Synthetic hidden encoded PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\powershell.exe'
  condition: sel
"""
SIGMA_V2 = r"""
title: Synthetic hidden encoded PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all: ['-enc', 'hidden']
  condition: sel
"""


def event(event_id: int, record: int, **fields: str) -> str:
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return (
        f'<Event xmlns="{_NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>"
        f"</System><EventData>{data}</EventData></Event>"
    )


def process(
    record: int,
    guid: str,
    pid: int,
    image: str,
    command_line: str,
    parent: str | None = None,
) -> str:
    fields = {
        "UtcTime": f"2026-11-17 01:00:{record % 60:02d}.000",
        "ProcessGuid": guid,
        "ProcessId": str(pid),
        "Image": image,
        "CommandLine": command_line,
    }
    if parent is not None:
        fields["ParentProcessGuid"] = parent
    return event(1, record, **fields)


POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def _add(root: Path, tmp_path: Path, case: str, name: str, data: bytes, kind: str):  # type: ignore[no-untyped-def]
    path = tmp_path / name
    path.write_bytes(data)
    return ArtifactService(root).add(case, path, kind)


def _sysmon(*events: str) -> bytes:
    return ("<Events>" + "".join(events) + "</Events>").encode()


def build_workspace(tmp_path: Path) -> Path:
    """Create the workspace; display IDs are stable and documented inline."""
    root = tmp_path / "project"
    ProjectService().create(root, "Analysis")
    cases = CaseService(root)
    cases.create("dev sample", "malware", "synthetic dev member")  # CASE-0001
    cases.create("benign admin", "benign")  # CASE-0002
    cases.create("unseen sample", "malware")  # CASE-0003
    cases.create("empty", "benign")  # CASE-0004

    # CASE-0001: ART-000001 sample, ART-000002 sysmon, ART-000003 static result.
    _add(
        root,
        tmp_path,
        "CASE-0001",
        "dev.exe",
        synthetic_pe_with_imports() + b"SYNTHETIC-LOADER-MARKER\0",
        "sample",
    )
    _add(
        root,
        tmp_path,
        "CASE-0001",
        "dev.xml",
        _sysmon(
            process(10, PARENT_GUID, 4000, "C:\\synthetic\\dev.exe", "dev.exe"),
            process(
                11,
                CHILD_GUID,
                4001,
                POWERSHELL,
                "powershell -w hidden -enc AAAA",
                parent=PARENT_GUID,
            ),
            event(
                11,
                12,
                UtcTime="2026-11-17 01:00:12.000",
                ProcessGuid=CHILD_GUID,
                ProcessId="4001",
                Image=POWERSHELL,
                TargetFilename="C:\\synthetic\\stage\\out.bin",
                CreationUtcTime="2026-11-17 01:00:12.000",
            ),
            event(
                22,
                13,
                UtcTime="2026-11-17 01:00:13.000",
                ProcessGuid=CHILD_GUID,
                Image=POWERSHELL,
                QueryName="update.example.invalid",
            ),
        ),
        "sysmon",
    )
    StaticAnalysisService(root).analyze("CASE-0001", "ART-000001")

    # CASE-0002: ART-000004 sysmon (benign PowerShell), ART-000005 sample.
    _add(
        root,
        tmp_path,
        "CASE-0002",
        "admin.xml",
        _sysmon(
            process(
                20,
                "{bbbbbbbb-0000-4000-8000-000000000001}",
                5000,
                POWERSHELL,
                "powershell -File maintenance.ps1",
            )
        ),
        "sysmon",
    )
    _add(root, tmp_path, "CASE-0002", "tool.bin", b"MZ" + b"\0" * 62, "sample")

    # CASE-0003: ART-000006 sysmon only (no sample -> YARA not evaluable).
    _add(
        root,
        tmp_path,
        "CASE-0003",
        "unseen.xml",
        _sysmon(
            process(
                30,
                "{cccccccc-0000-4000-8000-000000000001}",
                6000,
                POWERSHELL,
                "powershell -enc BBBB -w hidden",
            )
        ),
        "sysmon",
    )

    detection = DetectionService(root)
    detection.add_rule("synthetic marker", "yara", YARA_RULE)  # RULE-0001
    detection.add_rule(f"hidden powershell {UNTRUSTED}", "sigma", SIGMA_V1)  # RULE-0002
    hypothesis = detection.add_hypothesis(  # HYP-0001
        "CASE-0001",
        f"Hidden encoded PowerShell {UNTRUSTED}",
        "The sample starts PowerShell with a hidden window and encoded command.",
        evidence=["ART-000002", "ART-000003"],
        expected_benign="Admin scripts run PowerShell without -enc",
    )
    detection.link_rule(hypothesis.display_id, "RULE-0001")
    detection.link_rule(hypothesis.display_id, "RULE-0002")
    detection.set_hypothesis_status(hypothesis.display_id, "supported")

    benchmark = detection.create_benchmark("synthetic-v1", "harmless")  # BMK-0001
    for case, role in (
        ("CASE-0001", "dev"),
        ("CASE-0002", "benign_common"),
        ("CASE-0003", "unseen"),
    ):
        detection.add_member(benchmark.display_id, case, role)

    detection.run_validation("RULE-0001", "BMK-0001")  # RUN-0001 development
    detection.run_validation("RULE-0002", "BMK-0001")  # RUN-0002 dev, v1 has an FP
    detection.revise_rule("RULE-0002", SIGMA_V2, "require -enc and hidden")
    detection.run_validation("RULE-0002", "BMK-0001")  # RUN-0003 dev, v2
    detection.freeze_rule("RULE-0002")
    detection.freeze_benchmark("BMK-0001")
    all_roles = ["dev", "unseen", "benign_common"]
    detection.run_validation("RULE-0002", "BMK-0001", roles=all_roles)  # RUN-0004
    detection.run_validation("RULE-0002", "BMK-0001", roles=all_roles)  # RUN-0005

    add_execution_run(root, "CASE-0001", sysmon_artifact="ART-000002")  # VMR-0001
    return root


def add_execution_run(
    root: Path,
    case: str,
    *,
    sysmon_artifact: str | None = None,
    status: RunStatus = RunStatus.SUCCEEDED,
    error_code: str | None = None,
) -> str:
    """Record a benign-scenario run row without touching any VM."""
    repository = SQLiteExecutionRepository(ProjectService().open(root), write=True)
    try:
        with repository.transaction():
            run_id = repository.allocate_run_id()
            repository.insert_run(
                ExecutionRun(
                    run_id,
                    case,
                    ExecutionProfile.BENIGN_SCENARIO,
                    "file-write",
                    None,
                    "WIN11-ANALYSIS",
                    "SYSMON-V2-CLEAN",
                    60,
                    RunStatus.RUNNING,
                    utc_now(),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            )
            for step in (
                StepName.APPROVAL,
                StepName.PREFLIGHT,
                StepName.RESTORE_BEFORE,
            ):
                repository.append_step(run_id, step, StepStatus.OK, "C:\\host\\secret")
            if status is not RunStatus.RUNNING:
                repository.finish_run(
                    run_id,
                    status,
                    error_code=error_code,
                    sysmon_artifact_id=sysmon_artifact,
                    event_count=None if sysmon_artifact is None else 4,
                )
            return run_id
    finally:
        repository.close()
