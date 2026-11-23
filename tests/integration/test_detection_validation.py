"""Detection rules, hypotheses, benchmarks and validation over benign fixtures.

All sample bytes and Sysmon events below are invented harmless test data.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.cli import main
from loader_detection_workbench.detection.domain import Outcome, RunKind
from loader_detection_workbench.detection.service import DetectionService
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
YARA_RULE = """
rule synthetic_loader_marker {
  strings:
    $marker = "SYNTHETIC-LOADER-MARKER"
  condition:
    $marker
}
"""
SIGMA_RULE = r"""
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


def _event(event_id: int, record: int, **fields: str) -> str:
    data = "".join(
        f'<Data Name="{key}">{value}</Data>' for key, value in fields.items()
    )
    return (
        f'<Event xmlns="{_NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID><EventRecordID>{record}</EventRecordID>"
        f"</System><EventData>{data}</EventData></Event>"
    )


def _sysmon(tmp_path: Path, name: str, *events: str) -> Path:
    path = tmp_path / f"{name}.xml"
    path.write_text("<Events>" + "".join(events) + "</Events>", encoding="utf-8")
    return path


def _sample(tmp_path: Path, name: str, payload: bytes) -> Path:
    path = tmp_path / f"{name}.bin"
    path.write_bytes(b"MZ" + b"\0" * 62 + payload)
    return path


def _attach(root: Path, case: str, source: Path, kind: str) -> str:
    return ArtifactService(root).add(case, source, kind).artifact_id.display_id


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    ProjectService().create(root, "Detection")
    cases = CaseService(root)
    cases.create("dev loader", "malware")  # CASE-0001
    cases.create("benign common", "benign")  # CASE-0002
    cases.create("unseen loader", "malware")  # CASE-0003
    cases.create("benign admin script", "benign")  # CASE-0004
    cases.create("unseen no telemetry", "malware")  # CASE-0005
    hidden = _event(
        1,
        10,
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine="powershell -w hidden -enc AAAA",
    )
    admin = _event(
        1,
        11,
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine="powershell -File maintenance.ps1",
    )
    dns = _event(22, 12, QueryName="updates.example.invalid")
    _attach(
        root,
        "CASE-0001",
        _sample(tmp_path, "dev", b"SYNTHETIC-LOADER-MARKER"),
        "sample",
    )
    _attach(root, "CASE-0001", _sysmon(tmp_path, "dev", hidden, dns), "sysmon")
    _attach(root, "CASE-0002", _sample(tmp_path, "benign", b"ordinary bytes"), "sample")
    _attach(root, "CASE-0002", _sysmon(tmp_path, "benign", dns), "sysmon")
    _attach(root, "CASE-0003", _sample(tmp_path, "unseen", b"no marker here"), "sample")
    _attach(root, "CASE-0003", _sysmon(tmp_path, "unseen", hidden), "sysmon")
    _attach(root, "CASE-0004", _sysmon(tmp_path, "admin", admin), "sysmon")
    _attach(
        root,
        "CASE-0005",
        _sample(tmp_path, "unseen2", b"SYNTHETIC-LOADER-MARKER"),
        "sample",
    )
    return root


def _benchmark(service: DetectionService) -> str:
    benchmark = service.create_benchmark("synthetic-v1", "harmless fixtures")
    for case, role in (
        ("CASE-0001", "dev"),
        ("CASE-0002", "benign_common"),
        ("CASE-0003", "unseen"),
        ("CASE-0004", "benign_matched"),
        ("CASE-0005", "unseen"),
    ):
        service.add_member(benchmark.display_id, case, role)
    return benchmark.display_id


def test_development_and_unseen_validation_lifecycle(workspace: Path) -> None:
    service = DetectionService(workspace)
    yara = service.add_rule("synthetic marker", "yara", YARA_RULE)
    sigma = service.add_rule("hidden encoded powershell", "sigma", SIGMA_RULE)
    benchmark = _benchmark(service)

    hypothesis = service.add_hypothesis(
        "CASE-0001",
        "Hidden encoded PowerShell launched early",
        "The sample starts PowerShell with hidden window and encoded command.",
        evidence=["ART-000002"],
        expected_benign="Admin maintenance scripts run PowerShell without -enc",
    )
    hypothesis = service.link_rule(hypothesis.display_id, sigma.display_id)
    assert hypothesis.evidence_artifact_ids == ("ART-000002",)
    assert hypothesis.rule_display_ids == (sigma.display_id,)

    dev_yara = service.run_validation(yara.display_id, benchmark)
    assert dev_yara.kind is RunKind.DEVELOPMENT
    outcomes = {r.case_display_id: r.outcome for r in dev_yara.results}
    assert outcomes == {
        "CASE-0001": Outcome.TP,
        "CASE-0002": Outcome.TN,
        "CASE-0004": Outcome.NOT_EVALUABLE,
    }
    detail = json.loads(dev_yara.results[0].detail)
    assert detail["matches"][0]["strings"][0]["id"] == "$marker"

    dev_sigma = service.run_validation(sigma.display_id, benchmark)
    metrics = dev_sigma.metrics
    assert (metrics.tp, metrics.fp, metrics.tn, metrics.fn) == (1, 0, 2, 0)
    assert (
        json.loads(dev_sigma.results[0].detail)["matched_records"][0]["record_id"]
        == "10"
    )

    with pytest.raises(DomainError) as error:
        service.run_validation(sigma.display_id, benchmark, roles=["unseen"])
    assert error.value.code is DomainErrorCode.DETECTION_RULE_NOT_FROZEN

    service.freeze_rule(sigma.display_id)
    with pytest.raises(DomainError) as error:
        service.run_validation(sigma.display_id, benchmark, roles=["unseen"])
    assert error.value.code is DomainErrorCode.BENCHMARK_NOT_FROZEN

    service.freeze_benchmark(benchmark)
    unseen = service.run_validation(sigma.display_id, benchmark, roles=["unseen"])
    assert unseen.kind is RunKind.EVALUATION
    assert {r.case_display_id: r.outcome for r in unseen.results} == {
        "CASE-0003": Outcome.TP,
        "CASE-0005": Outcome.NOT_EVALUABLE,
    }

    revised = service.revise_rule(
        sigma.display_id, SIGMA_RULE.replace("hidden'", "hidden', '-nop'")
    )
    assert revised.latest.version == 2
    service.freeze_rule(sigma.display_id)
    tuned = service.run_validation(sigma.display_id, benchmark, roles=["unseen"])
    assert tuned.kind is RunKind.TUNING
    assert [run.display_id for run in service.list_runs(sigma.display_id)] == [
        dev_sigma.display_id,
        unseen.display_id,
        tuned.display_id,
    ]


def test_frozen_records_are_immutable(workspace: Path) -> None:
    service = DetectionService(workspace)
    rule = service.add_rule("marker", "yara", YARA_RULE)
    benchmark = _benchmark(service)
    service.freeze_rule(rule.display_id)
    service.freeze_benchmark(benchmark)

    with pytest.raises(DomainError) as error:
        service.add_member(benchmark, "CASE-0002", "benign_common")
    assert error.value.code is DomainErrorCode.BENCHMARK_FROZEN
    with pytest.raises(DomainError) as error:
        service.revise_rule(rule.display_id, YARA_RULE)
    assert error.value.code is DomainErrorCode.INVALID_DETECTION_RULE

    connection = sqlite3.connect(workspace / "project.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE detection_rule_versions SET content = 'x' WHERE version = 1"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE detection_benchmarks SET frozen_at = NULL")
    finally:
        connection.close()
    assert ProjectService().validate(workspace).is_valid


def test_membership_and_rule_input_validation(workspace: Path) -> None:
    service = DetectionService(workspace)
    benchmark = service.create_benchmark("roles")

    for case, role, code in (
        ("CASE-0002", "dev", DomainErrorCode.INVALID_BENCHMARK),
        ("CASE-0001", "benign_common", DomainErrorCode.INVALID_BENCHMARK),
        ("CASE-0009", "dev", DomainErrorCode.CASE_NOT_FOUND),
    ):
        with pytest.raises(DomainError) as error:
            service.add_member(benchmark.display_id, case, role)
        assert error.value.code is code
    with pytest.raises(DomainError) as error:
        service.freeze_benchmark(benchmark.display_id)
    assert error.value.code is DomainErrorCode.INVALID_BENCHMARK
    with pytest.raises(DomainError) as error:
        service.add_rule("broken", "yara", "rule x { condition: }")
    assert error.value.code is DomainErrorCode.DETECTION_RULE_COMPILE_FAILED
    with pytest.raises(DomainError) as error:
        service.add_hypothesis("CASE-0002", "t", "s", evidence=["ART-000001"])
    assert error.value.code is DomainErrorCode.ARTIFACT_NOT_ATTACHED
    assert service.list_rules() == []


def test_read_only_queries_before_detection_tables_exist(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    ProjectService().create(root, "Empty")
    service = DetectionService(root)

    assert service.list_rules() == []
    assert service.list_benchmarks() == []
    with pytest.raises(DomainError) as error:
        service.show_rule("RULE-0001")
    assert error.value.code is DomainErrorCode.DETECTION_RULE_NOT_FOUND


def test_cli_end_to_end(
    workspace: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text(SIGMA_RULE, encoding="utf-8")
    monkeypatch.chdir(workspace)

    assert main(["rule", "check", str(rule_file), "--format", "sigma"]) == 0
    assert "sysmon:1" in capsys.readouterr().out
    assert (
        main(["rule", "add", str(rule_file), "--format", "sigma", "--name", "ps"]) == 0
    )
    assert main(["benchmark", "create", "--name", "cli"]) == 0
    assert main(["benchmark", "add", "BMK-0001", "CASE-0001", "--role", "dev"]) == 0
    assert (
        main(["benchmark", "add", "BMK-0001", "CASE-0004", "--role", "benign_matched"])
        == 0
    )
    assert (
        main(["hypothesis", "add", "CASE-0001", "--title", "t", "--statement", "s"])
        == 0
    )
    assert main(["hypothesis", "link", "HYP-0001", "RULE-0001"]) == 0
    capsys.readouterr()
    assert main(["validate", "run", "RULE-0001", "BMK-0001"]) == 0
    output = capsys.readouterr().out
    assert "TP=1 FN=0 (malicious n=1) FP=0 TN=1 (benign n=1)" in output
    assert "recall=1.000" in output
    assert main(["validate", "run", "RULE-0001", "BMK-0001", "--role", "unseen"]) == 2
    assert "DETECTION_RULE_NOT_FROZEN" in capsys.readouterr().err
    assert main(["validate", "list"]) == 0
    assert "RUN-0001\tRULE-0001:v1\tBMK-0001\tdevelopment" in capsys.readouterr().out
