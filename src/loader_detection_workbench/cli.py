"""Command-line entry point for the local workbench."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import asdict
from enum import Enum
from functools import partial
from importlib.metadata import version
from pathlib import Path
from typing import Any

from loader_detection_workbench.ai.compare import Comparison, OpinionGroup
from loader_detection_workbench.ai.domain import AiAnalysis
from loader_detection_workbench.ai.service import (
    DEFAULT_PROVIDER,
    AiAnalysisService,
)
from loader_detection_workbench.artifact.archive import DEFAULT_PASSWORD, read_member
from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.bundle.service import BundleService
from loader_detection_workbench.case.render import render_timeline
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.case.timeline import CaseTimelineQuery
from loader_detection_workbench.collection.domain import CollectionIngestionResult
from loader_detection_workbench.collection.service import CollectionIngestionService
from loader_detection_workbench.config import (
    ConfigError,
    ConfigValueError,
    load_config,
    normalize_log_level,
)
from loader_detection_workbench.detection.benign_files import (
    SYSTEM_BINARY_SET,
    BenignFileService,
)
from loader_detection_workbench.detection.domain import (
    Benchmark,
    DetectionRule,
    Hypothesis,
    HypothesisStatus,
    MemberRole,
    RuleFormat,
    ValidationRun,
)
from loader_detection_workbench.detection.service import DetectionService, check_rule
from loader_detection_workbench.domain.case import Case
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.domain.time import format_utc
from loader_detection_workbench.evidence.domain import EvidenceType, ManualEvidence
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.execution.domain import (
    BENIGN_SCENARIOS,
    DEFAULT_SNAPSHOT,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_VM_NAME,
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    ExecutionPlan,
    ExecutionProfile,
    ExecutionRequest,
    ExecutionRun,
    VmSettings,
    require_timeout,
)
from loader_detection_workbench.execution.service import (
    ExecutionService,
    LockStatus,
    PreflightReport,
)
from loader_detection_workbench.execution.vboxmanage import VBoxManageHypervisor
from loader_detection_workbench.findings.domain import (
    AnalystFinding,
    FindingKind,
    FindingState,
    Verdict,
)
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.logging_config import configure_console_logging
from loader_detection_workbench.presentation import single_line
from loader_detection_workbench.project.migration import ProjectMigrationService
from loader_detection_workbench.project.service import ProjectService, ProjectWorkspace
from loader_detection_workbench.report.service import ReportFormat, ReportService
from loader_detection_workbench.report.site import SiteService
from loader_detection_workbench.sample.domain import (
    SCREENING_FIELDS,
    AssignmentReason,
    Confidence,
    ContractViolation,
    CriterionStatus,
    DatasetRole,
    DuplicateSampleError,
    ExclusionReason,
    ManifestStatus,
    NotFoundError,
    ReportedRole,
    SampleError,
)
from loader_detection_workbench.sample.service import SampleService
from loader_detection_workbench.sample.sqlite_repository import SQLiteSampleRepository
from loader_detection_workbench.static_analysis.domain import StaticAnalysis
from loader_detection_workbench.static_analysis.service import StaticAnalysisService


def _log_level_argument(value: str) -> str:
    try:
        return normalize_log_level(value)
    except ConfigValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _enum(enum_type: type[Enum]) -> Any:
    def parse(value: str) -> Enum:
        return enum_type(value)

    return parse


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workbench", description="Local Detection-as-Code Workbench"
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="load optional configuration from FILE",
    )
    parser.add_argument(
        "--log-level",
        type=_log_level_argument,
        metavar="LEVEL",
        help="set console logging level (default: INFO)",
    )
    parser.add_argument("--database", type=Path, metavar="FILE", help=argparse.SUPPRESS)
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('loader-detection-workbench')}",
    )
    groups = parser.add_subparsers(dest="group")
    project = groups.add_parser("project", help="manage a Project workspace")
    project_commands = project.add_subparsers(dest="project_command", required=True)
    project_create = project_commands.add_parser("create")
    project_create.add_argument("root", type=Path)
    project_create.add_argument("--name", required=True)
    project_show = project_commands.add_parser("show")
    project_show.add_argument("root", type=Path, nargs="?", default=Path("."))
    project_validate = project_commands.add_parser("validate")
    project_validate.add_argument("root", type=Path, nargs="?", default=Path("."))
    project_validate.add_argument("--full", action="store_true")
    project_migrate = project_commands.add_parser("migrate")
    project_migrate.add_argument("root", type=Path, nargs="?", default=Path("."))
    project_migrate.add_argument("--to", type=int, choices=(2,), default=2)
    case = groups.add_parser("case", help="manage Cases in the current Project")
    case_commands = case.add_subparsers(dest="case_command", required=True)
    case_create = case_commands.add_parser("create", help="create an empty open Case")
    case_create.add_argument("--name", required=True)
    case_create.add_argument(
        "--kind", required=True, metavar="malware|simulator|benign"
    )
    case_create.add_argument("--description")
    case_commands.add_parser("list", help="list Cases in numeric display-ID order")
    for command in ("show", "rename", "close", "reopen", "timeline"):
        case_command = case_commands.add_parser(command)
        case_command.add_argument("display_id", metavar="CASE-NNNN")
        if command == "rename":
            case_command.add_argument("--name", required=True)
    artifact = case_commands.add_parser(
        "artifact", help="add, list or detach Artifacts"
    )
    artifact_commands = artifact.add_subparsers(dest="artifact_command", required=True)
    for command in ("add", "list", "detach"):
        artifact_command = artifact_commands.add_parser(command)
        artifact_command.add_argument("case_display_id", metavar="CASE-NNNN")
        if command == "add":
            artifact_command.add_argument("source", type=Path, metavar="SOURCE")
            artifact_command.add_argument("--kind", required=True)
        elif command == "detach":
            artifact_command.add_argument("artifact_display_id", metavar="ART-NNNNNN")
    import_zip = artifact_commands.add_parser(
        "import-zip",
        help="add a sample from a password-protected ZIP without extracting it; "
        "stored sealed (ADR-030)",
    )
    import_zip.add_argument("case_display_id", metavar="CASE-NNNN")
    import_zip.add_argument("archive", type=Path, metavar="ARCHIVE")
    _archive_options(import_zip)
    benign_files = case_commands.add_parser(
        "benign-files",
        help="add the fixed Windows system binary set to a benign Case "
        "(YARA comparison files)",
    )
    benign_files.add_argument("case_display_id", metavar="CASE-NNNN")
    benign_files.add_argument(
        "--list", action="store_true", help="show the set and exit; adds nothing"
    )
    evidence = case_commands.add_parser(
        "evidence", help="add, list or show analyst-supplied evidence"
    )
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_add = evidence_commands.add_parser("add")
    evidence_add.add_argument("case_display_id", metavar="CASE-NNNN")
    evidence_add.add_argument("file", type=Path, metavar="FILE")
    evidence_add.add_argument("--origin", required=True)
    evidence_add.add_argument(
        "--type", required=True, choices=tuple(item.value for item in EvidenceType)
    )
    evidence_add.add_argument("--description")
    evidence_list = evidence_commands.add_parser("list")
    evidence_list.add_argument("case_display_id", metavar="CASE-NNNN")
    evidence_show = evidence_commands.add_parser("show")
    evidence_show.add_argument("case_display_id", metavar="CASE-NNNN")
    evidence_show.add_argument("artifact_display_id", metavar="ART-NNNNNN")
    collection = case_commands.add_parser(
        "collection", help="import a validated Sysmon Collection"
    )
    collection_commands = collection.add_subparsers(
        dest="collection_command", required=True
    )
    collection_import = collection_commands.add_parser("import")
    collection_import.add_argument("case_display_id", metavar="CASE-NNNN")
    collection_import.add_argument("directory", type=Path, metavar="DIRECTORY")
    static = case_commands.add_parser(
        "static", help="collect bounded static PE evidence"
    )
    static_commands = static.add_subparsers(dest="static_command", required=True)
    static_analyze = static_commands.add_parser("analyze")
    static_analyze.add_argument("case_display_id", metavar="CASE-NNNN")
    static_analyze.add_argument("artifact_display_id", metavar="ART-NNNNNN")
    sample = groups.add_parser("sample", help="manage pre-Case candidate samples")
    commands = sample.add_subparsers(dest="sample_command", required=True)
    add = commands.add_parser("add")
    add.add_argument("file", type=Path)
    add.add_argument(
        "--zip",
        action="store_true",
        help="FILE is a password-protected archive; hash its member in memory",
    )
    _archive_options(add)
    add.add_argument("--source", required=True)
    add.add_argument("--source-reference", required=True)
    add.add_argument("--source-record-id")
    add.add_argument(
        "--reported-role",
        type=_enum(ReportedRole),
        choices=list(ReportedRole),
        default=ReportedRole.UNKNOWN,
    )
    add.add_argument("--role-label-source")
    add.add_argument(
        "--role-label-confidence",
        type=_enum(Confidence),
        choices=list(Confidence),
        default=Confidence.UNKNOWN,
    )
    add.add_argument("--reported-family")
    add.add_argument("--family-label-source")
    add.add_argument(
        "--family-label-confidence",
        type=_enum(Confidence),
        choices=list(Confidence),
        default=Confidence.UNKNOWN,
    )
    show = commands.add_parser("show")
    show.add_argument("sample_id")
    show.add_argument("--format", choices=("text", "json"), default="text")
    listing = commands.add_parser("list")
    listing.add_argument(
        "--status", type=_enum(ManifestStatus), choices=list(ManifestStatus)
    )
    listing.add_argument("--role", type=_enum(DatasetRole), choices=list(DatasetRole))
    listing.add_argument("--format", choices=("text", "json"), default="text")
    screen = commands.add_parser("screen")
    screen.add_argument("sample_id")
    for field in SCREENING_FIELDS:
        screen.add_argument(
            f"--{field.replace('_', '-')}",
            required=True,
            type=_enum(CriterionStatus),
            choices=list(CriterionStatus),
        )
    eligible = commands.add_parser("eligible")
    eligible.add_argument("sample_id")
    exclude = commands.add_parser("exclude")
    exclude.add_argument("sample_id")
    exclude.add_argument(
        "--reason",
        required=True,
        type=_enum(ExclusionReason),
        choices=list(ExclusionReason),
    )
    exclude.add_argument("--detail")
    validate = commands.add_parser("validate")
    validate.add_argument("sample_id", nargs="?")
    validate.add_argument(
        "--gate", choices=("intake", "eligibility", "freeze", "eval-open")
    )
    assign = commands.add_parser("assign")
    assign.add_argument("sample_id")
    assign.add_argument(
        "--role",
        required=True,
        type=_enum(DatasetRole),
        choices=[DatasetRole.MALWARE_DEV, DatasetRole.MALWARE_EVAL],
    )
    assign.add_argument(
        "--reason",
        required=True,
        type=_enum(AssignmentReason),
        choices=list(AssignmentReason),
    )
    assign.add_argument("--detail")
    split = commands.add_parser("split")
    split.add_argument("--dev-count", required=True, type=int)
    split.add_argument("--eval-count", required=True, type=int)
    split.add_argument("--seed", required=True, type=int)
    split.add_argument("--split-id", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("--benchmark-id", required=True)
    freeze.add_argument("--benchmark-version", required=True, type=int)
    opened = commands.add_parser("eval-open")
    opened.add_argument("sample_id")
    bundle = groups.add_parser("bundle", help="export, validate or import Case Bundles")
    bundle_commands = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_export = bundle_commands.add_parser("export")
    bundle_export.add_argument("case_display_id", metavar="CASE-NNNN")
    bundle_export.add_argument("output", type=Path, metavar="OUTPUT.zip")
    bundle_validate = bundle_commands.add_parser("validate")
    bundle_validate.add_argument("bundle", type=Path, metavar="BUNDLE.zip")
    bundle_import = bundle_commands.add_parser("import")
    bundle_import.add_argument("bundle", type=Path, metavar="BUNDLE.zip")
    report = groups.add_parser("report", help="build a Case Markdown or HTML report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    report_build = report_commands.add_parser("build")
    report_build.add_argument("case_display_id", metavar="CASE-NNNN")
    report_build.add_argument("output", type=Path, metavar="OUTPUT")
    report_build.add_argument(
        "--format",
        choices=[item.value for item in ReportFormat],
        help="default: html for .html/.htm output names, otherwise markdown",
    )
    report_site = report_commands.add_parser(
        "site",
        help="build a de-identified static HTML site of every Case into a new "
        "directory; publishes nothing",
    )
    report_site.add_argument("output", type=Path, metavar="OUTPUT_DIR")
    ui = groups.add_parser("ui", help="serve the local Case platform UI")
    ui_commands = ui.add_subparsers(dest="ui_command", required=True)
    ui_serve = ui_commands.add_parser("serve")
    ui_serve.add_argument("root", type=Path, nargs="?", default=Path("."))
    ui_serve.add_argument("--port", type=_port, default=8080)
    _add_detection_parsers(groups)
    _add_ai_parsers(groups)
    _add_finding_parsers(groups)
    _add_vm_parsers(groups)
    return parser


def _timeout_argument(value: str) -> int:
    try:
        return require_timeout(int(value))
    except (ValueError, DomainError) as exc:
        raise argparse.ArgumentTypeError(
            f"timeout must be {MIN_TIMEOUT_SECONDS}-{MAX_TIMEOUT_SECONDS} seconds"
        ) from exc


def _add_vm_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vm", default=DEFAULT_VM_NAME, help="VirtualBox VM name")
    parser.add_argument(
        "--snapshot", default=DEFAULT_SNAPSHOT, help="clean snapshot name"
    )


def _add_vm_run_options(parser: argparse.ArgumentParser) -> None:
    _add_vm_target_options(parser)
    parser.add_argument(
        "--timeout",
        type=_timeout_argument,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"execution time limit (default {DEFAULT_TIMEOUT_SECONDS})",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print the plan; no VM command is executed",
    )
    mode.add_argument(
        "--approve",
        action="store_true",
        help="explicitly approve restoring, starting and running the analysis VM",
    )


def _add_vm_parsers(groups: Any) -> None:
    vm = groups.add_parser(
        "vm", help="isolated VM execution runs with clean snapshot restore"
    )
    commands = vm.add_subparsers(dest="vm_command", required=True)
    commands.add_parser("scenarios", help="list fixed benign scenarios")
    preflight = commands.add_parser(
        "preflight", help="read-only VM state and isolation check"
    )
    _add_vm_target_options(preflight)
    preflight.add_argument(
        "--profile",
        choices=tuple(item.value for item in ExecutionProfile),
        default=ExecutionProfile.SAMPLE.value,
    )
    run = commands.add_parser("run", help="execute a sample Artifact in the VM")
    run.add_argument("case_display_id", metavar="CASE-NNNN")
    run.add_argument("--sample", required=True, metavar="ART-NNNNNN")
    run.add_argument(
        "--collect-dropped",
        action="store_true",
        help="also collect, sealed, the files the sample tree wrote (ADR-032)",
    )
    _add_vm_run_options(run)
    scenario = commands.add_parser(
        "scenario", help="execute a fixed benign scenario in the VM"
    )
    scenario.add_argument("case_display_id", metavar="CASE-NNNN")
    scenario.add_argument("--scenario", required=True, choices=tuple(BENIGN_SCENARIOS))
    _add_vm_run_options(scenario)
    commands.add_parser("status", help="show the safety lock and unfinished runs")
    show = commands.add_parser("show", help="show one execution run and its steps")
    show.add_argument("run_id", metavar="VMR-NNNN")
    commands.add_parser("list", help="list execution runs")
    unlock = commands.add_parser(
        "unlock",
        help="release the safety lock after manually verifying the VM is clean",
    )
    unlock.add_argument(
        "--note", required=True, help="what was verified (stored with the release)"
    )


def _add_finding_parsers(groups: Any) -> None:
    finding = groups.add_parser(
        "finding",
        help="analyst-confirmed findings that a report is built from (ADR-031)",
    )
    commands = finding.add_subparsers(dest="finding_command", required=True)
    kinds = tuple(item.value for item in FindingKind)
    verdicts = tuple(item.value for item in Verdict)

    def content_options(parser: argparse.ArgumentParser, *, editing: bool) -> None:
        parser.add_argument("--text", required=not editing)
        parser.add_argument("--title")
        parser.add_argument("--verdict", choices=verdicts)
        parser.add_argument(
            "--evidence",
            action="append",
            metavar="ART-NNNNNN[:RECORD]",
            help="cited Artifact, optionally one event (evidence findings)",
        )
        parser.add_argument("--hypothesis", metavar="HYP-NNNN")
        parser.add_argument(
            "--ref",
            action="append",
            metavar="FND-NNNN",
            help="cited finding (link and mechanism findings)",
        )
        parser.add_argument("--note")

    add = commands.add_parser("add", help="create a draft finding")
    add.add_argument("case_display_id", metavar="CASE-NNNN")
    add.add_argument("--kind", required=True, choices=kinds)
    content_options(add, editing=False)
    edit = commands.add_parser("edit", help="change a finding; it becomes a draft")
    edit.add_argument("finding_id", metavar="FND-NNNN")
    content_options(edit, editing=True)
    edit.add_argument(
        "--clear",
        action="append",
        choices=("title", "verdict", "hypothesis"),
        default=[],
    )
    confirm = commands.add_parser("confirm", help="confirm a draft")
    confirm.add_argument("finding_id", metavar="FND-NNNN")
    confirm.add_argument("--note")
    withdraw = commands.add_parser("withdraw", help="withdraw a finding for good")
    withdraw.add_argument("finding_id", metavar="FND-NNNN")
    withdraw.add_argument("--note", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("case_display_id", metavar="CASE-NNNN")
    listing.add_argument("--state", choices=tuple(item.value for item in FindingState))
    show = commands.add_parser("show", help="show a finding and its revisions")
    show.add_argument("finding_id", metavar="FND-NNNN")
    adopt = commands.add_parser(
        "adopt", help="start a draft from an AI hypothesis suggestion"
    )
    adopt.add_argument("analysis_id", metavar="AIA-NNNN")
    adopt.add_argument("sequence", type=int)
    adopt.add_argument("--note")


def _add_ai_parsers(groups: Any) -> None:
    ai = groups.add_parser(
        "ai", help="optional AI-assisted analysis (offline providers only)"
    )
    commands = ai.add_subparsers(dest="ai_command", required=True)
    commands.add_parser("providers", help="list analysis providers")
    preview = commands.add_parser(
        "preview", help="print the exact provider input; calls no provider"
    )
    preview.add_argument("case_display_id", metavar="CASE-NNNN")
    stage_help = (
        "collection: hypothesis candidates, evidence links, next steps; "
        "synthesis: key hypotheses and mechanism over confirmed findings "
        "(ADR-031). Without it the ADR-026 summary/hypothesis/review kinds."
    )
    preview.add_argument(
        "--stage", choices=("collection", "synthesis"), help=stage_help
    )
    analyze = commands.add_parser("analyze", help="store suggestions for review")
    analyze.add_argument("case_display_id", metavar="CASE-NNNN")
    analyze.add_argument(
        "--provider",
        default=DEFAULT_PROVIDER,
        help="provider name, or several separated by commas (same input each)",
    )
    analyze.add_argument(
        "--stage", choices=("collection", "synthesis"), help=stage_help
    )
    analyze.add_argument(
        "--allow-network",
        action="store_true",
        help="allow sending the previewed input to an external provider; "
        "also needs [ai] allow_network = true in --config (ADR-031)",
    )
    listing = commands.add_parser("list")
    listing.add_argument("--case", dest="case_display_id", metavar="CASE-NNNN")
    show = commands.add_parser("show")
    show.add_argument("analysis_id", metavar="AIA-NNNN")
    compare = commands.add_parser(
        "compare",
        help="split stored analyses of one input into shared and "
        "single-provider opinions; calls no provider",
    )
    compare.add_argument("case_display_id", metavar="CASE-NNNN")
    compare.add_argument(
        "--analysis",
        dest="analysis_ids",
        nargs="+",
        metavar="AIA-NNNN",
        help="default: newest analysis per provider of the newest input",
    )
    for name, text in (
        ("accept", "accept a suggestion; a hypothesis candidate becomes a Hypothesis"),
        ("reject", "reject a suggestion"),
    ):
        review = commands.add_parser(name, help=text)
        review.add_argument("analysis_id", metavar="AIA-NNNN")
        review.add_argument("number", type=int, metavar="N")
        review.add_argument("--note")


def _add_detection_parsers(groups: Any) -> None:
    formats = tuple(item.value for item in RuleFormat)
    rule = groups.add_parser("rule", help="manage versioned YARA/Sigma rules")
    rule_commands = rule.add_subparsers(dest="rule_command", required=True)
    rule_check = rule_commands.add_parser("check", help="compile a rule file only")
    rule_check.add_argument("file", type=Path, metavar="FILE")
    rule_check.add_argument("--format", required=True, choices=formats)
    rule_add = rule_commands.add_parser("add", help="register a new draft rule")
    rule_add.add_argument("file", type=Path, metavar="FILE")
    rule_add.add_argument("--format", required=True, choices=formats)
    rule_add.add_argument("--name", required=True)
    rule_add.add_argument("--note")
    rule_revise = rule_commands.add_parser("revise", help="add a new draft version")
    rule_revise.add_argument("rule_id", metavar="RULE-NNNN")
    rule_revise.add_argument("file", type=Path, metavar="FILE")
    rule_revise.add_argument("--note")
    rule_freeze = rule_commands.add_parser("freeze", help="freeze a rule version")
    rule_freeze.add_argument("rule_id", metavar="RULE-NNNN")
    rule_freeze.add_argument("--version", type=int)
    rule_show = rule_commands.add_parser("show")
    rule_show.add_argument("rule_id", metavar="RULE-NNNN")
    rule_show.add_argument("--content", action="store_true")
    rule_commands.add_parser("list")

    hypothesis = groups.add_parser(
        "hypothesis", help="manage evidence-backed Detection Hypotheses"
    )
    hypothesis_commands = hypothesis.add_subparsers(
        dest="hypothesis_command", required=True
    )
    hypothesis_add = hypothesis_commands.add_parser("add")
    hypothesis_add.add_argument("case_display_id", metavar="CASE-NNNN")
    hypothesis_add.add_argument("--title", required=True)
    hypothesis_add.add_argument("--statement", required=True)
    hypothesis_add.add_argument(
        "--evidence", nargs="+", default=[], metavar="ART-NNNNNN"
    )
    hypothesis_add.add_argument("--expected-benign")
    hypothesis_evidence = hypothesis_commands.add_parser(
        "evidence", help="link supporting evidence Artifacts"
    )
    hypothesis_evidence.add_argument("hypothesis_id", metavar="HYP-NNNN")
    hypothesis_evidence.add_argument("artifacts", nargs="+", metavar="ART-NNNNNN")
    hypothesis_link = hypothesis_commands.add_parser("link", help="link a rule")
    hypothesis_link.add_argument("hypothesis_id", metavar="HYP-NNNN")
    hypothesis_link.add_argument("rule_id", metavar="RULE-NNNN")
    hypothesis_status = hypothesis_commands.add_parser("status")
    hypothesis_status.add_argument("hypothesis_id", metavar="HYP-NNNN")
    hypothesis_status.add_argument(
        "status", choices=tuple(item.value for item in HypothesisStatus)
    )
    hypothesis_show = hypothesis_commands.add_parser("show")
    hypothesis_show.add_argument("hypothesis_id", metavar="HYP-NNNN")
    hypothesis_list = hypothesis_commands.add_parser("list")
    hypothesis_list.add_argument("--case", metavar="CASE-NNNN")

    benchmark = groups.add_parser(
        "benchmark", help="manage dev/unseen/benign Case benchmarks"
    )
    benchmark_commands = benchmark.add_subparsers(
        dest="benchmark_command", required=True
    )
    benchmark_create = benchmark_commands.add_parser("create")
    benchmark_create.add_argument("--name", required=True)
    benchmark_create.add_argument("--description")
    benchmark_add = benchmark_commands.add_parser("add", help="add a member Case")
    benchmark_add.add_argument("benchmark_id", metavar="BMK-NNNN")
    benchmark_add.add_argument("case_display_id", metavar="CASE-NNNN")
    benchmark_add.add_argument(
        "--role", required=True, choices=tuple(item.value for item in MemberRole)
    )
    benchmark_freeze = benchmark_commands.add_parser("freeze")
    benchmark_freeze.add_argument("benchmark_id", metavar="BMK-NNNN")
    benchmark_show = benchmark_commands.add_parser("show")
    benchmark_show.add_argument("benchmark_id", metavar="BMK-NNNN")
    benchmark_commands.add_parser("list")

    validate = groups.add_parser("validate", help="run and inspect rule validation")
    validate_commands = validate.add_subparsers(dest="validate_command", required=True)
    validate_run = validate_commands.add_parser("run")
    validate_run.add_argument("rule_id", metavar="RULE-NNNN")
    validate_run.add_argument("benchmark_id", metavar="BMK-NNNN")
    validate_run.add_argument("--version", type=int)
    validate_run.add_argument(
        "--role",
        action="append",
        choices=tuple(item.value for item in MemberRole),
        help="member role to evaluate (repeatable; default: dev and benign roles)",
    )
    validate_show = validate_commands.add_parser("show")
    validate_show.add_argument("run_id", metavar="RUN-NNNN")
    validate_list = validate_commands.add_parser("list")
    validate_list.add_argument("--rule", metavar="RULE-NNNN")


def _value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _value(item) for key, item in value.items()}
    return value


def _data(sample: Any) -> dict[str, Any]:
    data = {key: _value(value) for key, value in asdict(sample).items()}
    data["evaluation_integrity"] = sample.evaluation_integrity.value
    return data


def _print(samples: list[Any], output_format: str = "text") -> None:
    if output_format == "json":
        payload: Any = (
            _data(samples[0])
            if len(samples) == 1
            else [_data(item) for item in samples]
        )
        print(json.dumps(payload, sort_keys=True, indent=2))
        return
    for item in samples:
        print(
            f"{item.sample_id}\t{item.manifest_status.value}\t{item.assigned_dataset_role.value}\t{item.sha256}"
        )


def _archive_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--password",
        default=DEFAULT_PASSWORD,
        help=f"archive password (default: {DEFAULT_PASSWORD})",
    )
    parser.add_argument(
        "--member", help="file inside the archive (required if it holds several)"
    )


def _run_sample(a: argparse.Namespace, service: SampleService) -> int:
    command = a.sample_command
    if command == "add":
        if a.zip:
            data = read_member(a.file, password=a.password, member=a.member).data
            register = partial(service.register, hashlib.sha256(data).hexdigest())
        else:
            if a.member is not None:
                raise ContractViolation("--member requires --zip")
            register = partial(service.add, a.file)
        _print(
            [
                register(
                    source=a.source,
                    source_reference=a.source_reference,
                    source_record_id=a.source_record_id,
                    reported_role=a.reported_role,
                    role_label_source=a.role_label_source,
                    role_label_confidence=a.role_label_confidence,
                    reported_family=a.reported_family,
                    family_label_source=a.family_label_source,
                    family_label_confidence=a.family_label_confidence,
                )
            ]
        )
    elif command == "show":
        _print([service.show(a.sample_id)], a.format)
    elif command == "list":
        _print(service.list_samples(a.status, a.role), a.format)
    elif command == "screen":
        _print(
            [
                service.screen(
                    a.sample_id, {key: getattr(a, key) for key in SCREENING_FIELDS}
                )
            ]
        )
    elif command == "eligible":
        _print([service.eligible(a.sample_id)])
    elif command == "exclude":
        _print([service.exclude(a.sample_id, a.reason, a.detail)])
    elif command == "assign":
        _print([service.assign(a.sample_id, a.role, a.reason, a.detail)])
    elif command == "split":
        assigned, warnings = service.split(
            a.dev_count, a.eval_count, a.seed, a.split_id
        )
        _print(assigned)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
    elif command == "freeze":
        _print(service.freeze(a.benchmark_id, a.benchmark_version))
    elif command == "eval-open":
        _print([service.eval_open(a.sample_id)])
    elif command == "validate":
        errors = service.validate(a.sample_id, a.gate)
        for error in errors:
            print(error, file=sys.stderr)
        return int(bool(errors))
    return 0


def _print_project(workspace: ProjectWorkspace) -> None:
    manifest = workspace.manifest
    print(f"schema_version: {manifest.schema_version}")
    print(f"display_id: {manifest.project_id.display_id}")
    print(f"internal_id: {manifest.project_id.ulid}")
    print(f"name: {manifest.name}")
    print(f"created_at: {format_utc(manifest.created_at)}")
    print(f"database.path: {manifest.database_path.as_posix()}")
    print(f"sqlite_schema_version: {workspace.sqlite_schema_version}")


def _run_project(arguments: argparse.Namespace, service: ProjectService) -> int:
    command = arguments.project_command
    if command == "create":
        _print_project(service.create(arguments.root, arguments.name))
    elif command == "show":
        _print_project(service.show(arguments.root))
    elif command == "validate":
        result = service.validate_report(arguments.root, full=arguments.full)
        if not result.findings:
            print("valid")
            return 0
        for finding in result.findings:
            subject = f"/{finding.subject}" if finding.subject is not None else ""
            print(
                f"{finding.severity.value} {finding.code} "
                f"[{finding.scope.value}{subject}]: {finding.message}",
                file=sys.stderr,
            )
        return 0 if result.is_valid else 1
    elif command == "migrate":
        migration = ProjectMigrationService().migrate(
            arguments.root, target=arguments.to
        )
        print(
            f"migration: {migration.status} "
            f"{migration.previous_version} -> {migration.current_version}"
        )
    return 0


def _run_bundle(arguments: argparse.Namespace, service: BundleService) -> int:
    if arguments.bundle_command == "export":
        print(service.export(arguments.case_display_id, arguments.output))
        return 0
    if arguments.bundle_command == "validate":
        report = service.validate(arguments.bundle)
        if not report.findings:
            print("valid")
            return 0
        for finding in report.findings:
            print(
                f"{finding.severity.value} {finding.code} "
                f"[{finding.scope.value}]: {finding.message}",
                file=sys.stderr,
            )
        return 0 if report.is_valid else 1
    result = service.import_bundle(arguments.bundle)
    print(f"imported_case: {result['case_display_id']}")
    return 0


def _print_case(case: Case) -> None:
    print(f"internal_id: {case.case_id.ulid}")
    print(f"project_id: {case.project_id}")
    print(f"display_id: {case.case_id.display_id}")
    print(f"kind: {case.kind.value}")
    print(f"status: {case.status.value}")
    print(f"name: {case.name}")
    print(f"description: {'NULL' if case.description is None else case.description}")
    print(f"created_at: {format_utc(case.created_at)}")
    print(f"updated_at: {format_utc(case.updated_at)}")
    print(
        f"closed_at: {'NULL' if case.closed_at is None else format_utc(case.closed_at)}"
    )


def _run_case(arguments: argparse.Namespace, service: CaseService) -> int:
    command = arguments.case_command
    if command == "list":
        for case in service.list_cases():
            print(
                f"{case.case_id.display_id}\t{case.kind.value}\t{case.status.value}\t{case.name}"
            )
        return 0
    if command == "create":
        result = service.create(arguments.name, arguments.kind, arguments.description)
    elif command == "rename":
        result = service.rename(arguments.display_id, arguments.name)
    elif command == "close":
        result = service.close(arguments.display_id)
    elif command == "reopen":
        result = service.reopen(arguments.display_id)
    else:
        result = service.show(arguments.display_id)
    _print_case(result)
    return 0


def _run_benign_files(arguments: argparse.Namespace, service: BenignFileService) -> int:
    print(f"set: {SYSTEM_BINARY_SET}")
    if arguments.list:
        for name, available in service.plan():
            print(f"{name}	{'available' if available else 'missing'}")
        return 0
    results = service.add_system_binaries(arguments.case_display_id)
    for result in results:
        print(
            f"{result.name}	{result.status}	{result.artifact_display_id or '-'}	"
            f"{result.sha256 or '-'}"
        )
    added = sum(1 for result in results if result.status == "added")
    missing = sum(1 for result in results if result.status == "missing")
    print(
        f"added: {added}, already present: {len(results) - added - missing}, "
        f"missing: {missing}"
    )
    return 0


def _run_artifact(arguments: argparse.Namespace, service: ArtifactService) -> int:
    if arguments.artifact_command == "add":
        artifacts = [
            service.add(arguments.case_display_id, arguments.source, arguments.kind)
        ]
    elif arguments.artifact_command == "import-zip":
        member = read_member(
            arguments.archive, password=arguments.password, member=arguments.member
        )
        artifacts = [
            service.add_content(arguments.case_display_id, member.data, "sample")
        ]
    elif arguments.artifact_command == "detach":
        artifacts = [
            service.detach(arguments.case_display_id, arguments.artifact_display_id)
        ]
    else:
        artifacts = service.list_artifacts(arguments.case_display_id)
    for artifact in artifacts:
        print(
            f"{artifact.artifact_id.display_id}\t{artifact.kind.value}\t"
            f"{artifact.sha256}\t{artifact.size_bytes}\t{artifact.relative_path.as_posix()}"
        )
    return 0


def _print_evidence(evidence: ManualEvidence, *, detailed: bool = False) -> None:
    artifact = evidence.artifact
    provenance = evidence.provenance
    if not detailed:
        print(
            f"{artifact.artifact_id.display_id}\t{provenance.evidence_type.value}\t"
            f"{provenance.original_filename}\t{artifact.sha256}\t{artifact.size_bytes}"
        )
        return
    print(f"artifact_id: {artifact.artifact_id.display_id}")
    print(f"internal_id: {artifact.artifact_id.ulid}")
    print(f"case_id: {artifact.case_id}")
    print(f"kind: {artifact.kind.value}")
    print(f"sha256: {artifact.sha256}")
    print(f"size_bytes: {artifact.size_bytes}")
    print(f"relative_path: {artifact.relative_path.as_posix()}")
    print(f"created_at: {format_utc(artifact.created_at)}")
    print(f"original_filename: {provenance.original_filename}")
    print(f"origin: {provenance.source}")
    print(f"evidence_type: {provenance.evidence_type.value}")
    description = "NULL" if provenance.description is None else provenance.description
    print(f"description: {description}")


def _run_evidence(arguments: argparse.Namespace, service: ManualEvidenceService) -> int:
    if arguments.evidence_command == "add":
        result = service.register(
            arguments.case_display_id,
            arguments.file,
            source=arguments.origin,
            evidence_type=arguments.type,
            description=arguments.description,
        )
        _print_evidence(result, detailed=True)
    elif arguments.evidence_command == "show":
        result = service.show(arguments.case_display_id, arguments.artifact_display_id)
        _print_evidence(result, detailed=True)
    else:
        for result in service.list_evidence(arguments.case_display_id):
            _print_evidence(result)
    return 0


def _print_collection(result: CollectionIngestionResult) -> None:
    print(f"status: {result.status}")
    print(f"case_id: {result.case_display_id}")
    print(f"process_artifact: {result.process_artifact.artifact_id.display_id}")
    print(f"file_artifact: {result.file_artifact.artifact_id.display_id}")
    print(f"metadata_artifact: {result.metadata_artifact.artifact_id.display_id}")
    print(f"created: {result.created_count}")
    print(f"reused: {result.reused_count}")


def _print_static(result: StaticAnalysis) -> None:
    print(f"result_artifact: {result.artifact.artifact_id.display_id}")
    print(f"source_artifact: {result.source_artifact_id}")
    print(f"source_sha256: {result.source_sha256}")
    print(f"source_size_bytes: {result.source_size_bytes}")
    print(f"status: {result.status}")
    print(f"is_pe: {str(result.is_pe).lower()}")
    print(f"architecture: {result.architecture or 'NULL'}")
    print(f"sections: {len(result.sections)}")
    if result.schema_version < 2:
        return
    print(f"file_entropy: {result.file_entropy}")
    print(f"imphash: {result.imphash or 'NULL'}")
    print(
        f"imports: {len(result.imports)} dlls / "
        f"{result.import_function_count} functions"
        + (" (truncated)" if result.imports_truncated else "")
    )
    print(f"exports: {result.export_count}")
    print(f"signature: {result.signature or 'NULL'}")
    print(f"compile_timestamp: {result.compile_timestamp or 'NULL'}")
    print(f"strings: {len(result.strings)} kept / {result.strings_total} found")
    for kind, values in sorted(result.indicators.items()):
        print(f"indicator.{kind}: {len(values)}")
    for flag in result.flags:
        print(f"flag: {flag}")
    if result.parser_warning:
        print(f"parser_warning: {result.parser_warning}")


def _run_collection(
    arguments: argparse.Namespace, service: CollectionIngestionService
) -> int:
    result = service.import_collection(arguments.case_display_id, arguments.directory)
    _print_collection(result)
    return 0


def _ratio(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _print_rule(rule: DetectionRule, *, content: bool = False) -> None:
    print(f"rule_id: {rule.display_id}")
    print(f"name: {rule.name}")
    print(f"format: {rule.format.value}")
    print(f"created_at: {format_utc(rule.created_at)}")
    for item in rule.versions:
        frozen = "" if item.frozen_at is None else f" {format_utc(item.frozen_at)}"
        note = "" if item.note is None else f" note={item.note}"
        print(f"v{item.version}\t{item.status.value}{frozen}\t{item.sha256}{note}")
    if content:
        print("--- latest content ---")
        print(
            rule.latest.content, end="" if rule.latest.content.endswith("\n") else "\n"
        )


def _print_hypothesis(hypothesis: Hypothesis) -> None:
    print(f"hypothesis_id: {hypothesis.display_id}")
    print(f"case_id: {hypothesis.case_display_id or 'NULL'}")
    print(f"status: {hypothesis.status.value}")
    print(f"title: {hypothesis.title}")
    print(f"statement: {hypothesis.statement}")
    print(f"expected_benign: {hypothesis.expected_benign or 'NULL'}")
    print(f"evidence: {', '.join(hypothesis.evidence_artifact_ids) or 'none'}")
    print(f"rules: {', '.join(hypothesis.rule_display_ids) or 'none'}")


def _print_benchmark(benchmark: Benchmark) -> None:
    print(f"benchmark_id: {benchmark.display_id}")
    print(f"name: {benchmark.name}")
    frozen = "NULL" if benchmark.frozen_at is None else format_utc(benchmark.frozen_at)
    print(f"frozen_at: {frozen}")
    for member in benchmark.members:
        print(f"{member.case_display_id}\t{member.role.value}")


def _print_run(run: ValidationRun) -> None:
    metrics = run.metrics
    print(f"run_id: {run.display_id}")
    print(f"rule: {run.rule_display_id} v{run.rule_version} ({run.rule_sha256[:12]})")
    print(f"benchmark: {run.benchmark_display_id}")
    print(f"kind: {run.kind.value}")
    print(f"roles: {','.join(role.value for role in run.roles)}")
    print(f"engine: {run.engine}")
    print(f"created_at: {format_utc(run.created_at)}")
    print(
        f"TP={metrics.tp} FN={metrics.fn} (malicious n={metrics.malicious_total}) "
        f"FP={metrics.fp} TN={metrics.tn} (benign n={metrics.benign_total}) "
        f"not_evaluable={metrics.not_evaluable}"
    )
    print(
        f"recall={_ratio(metrics.recall)} precision={_ratio(metrics.precision)} "
        f"fp_rate={_ratio(metrics.false_positive_rate)}"
    )
    for result in run.results:
        print(f"{result.case_display_id}\t{result.role.value}\t{result.outcome.value}")


def _run_detection(arguments: argparse.Namespace, service: DetectionService) -> int:
    group = arguments.group
    if group == "rule":
        command = arguments.rule_command
        if command == "check":
            text = arguments.file.read_text(encoding="utf-8")
            print(check_rule(RuleFormat(arguments.format), text).summary)
        elif command == "add":
            text = arguments.file.read_text(encoding="utf-8")
            _print_rule(
                service.add_rule(arguments.name, arguments.format, text, arguments.note)
            )
        elif command == "revise":
            text = arguments.file.read_text(encoding="utf-8")
            _print_rule(service.revise_rule(arguments.rule_id, text, arguments.note))
        elif command == "freeze":
            _print_rule(service.freeze_rule(arguments.rule_id, arguments.version))
        elif command == "show":
            _print_rule(service.show_rule(arguments.rule_id), content=arguments.content)
        else:
            for rule in service.list_rules():
                print(
                    f"{rule.display_id}\t{rule.format.value}\t"
                    f"v{rule.latest.version}:{rule.latest.status.value}\t{rule.name}"
                )
    elif group == "hypothesis":
        command = arguments.hypothesis_command
        if command == "add":
            _print_hypothesis(
                service.add_hypothesis(
                    arguments.case_display_id,
                    arguments.title,
                    arguments.statement,
                    evidence=arguments.evidence,
                    expected_benign=arguments.expected_benign,
                )
            )
        elif command == "evidence":
            _print_hypothesis(
                service.link_evidence(arguments.hypothesis_id, arguments.artifacts)
            )
        elif command == "link":
            _print_hypothesis(
                service.link_rule(arguments.hypothesis_id, arguments.rule_id)
            )
        elif command == "status":
            _print_hypothesis(
                service.set_hypothesis_status(arguments.hypothesis_id, arguments.status)
            )
        elif command == "show":
            _print_hypothesis(service.show_hypothesis(arguments.hypothesis_id))
        else:
            for hypothesis in service.list_hypotheses(arguments.case):
                print(
                    f"{hypothesis.display_id}\t{hypothesis.case_display_id or '-'}\t"
                    f"{hypothesis.status.value}\t{hypothesis.title}"
                )
    elif group == "benchmark":
        command = arguments.benchmark_command
        if command == "create":
            _print_benchmark(
                service.create_benchmark(arguments.name, arguments.description)
            )
        elif command == "add":
            _print_benchmark(
                service.add_member(
                    arguments.benchmark_id, arguments.case_display_id, arguments.role
                )
            )
        elif command == "freeze":
            _print_benchmark(service.freeze_benchmark(arguments.benchmark_id))
        elif command == "show":
            _print_benchmark(service.show_benchmark(arguments.benchmark_id))
        else:
            for benchmark in service.list_benchmarks():
                state = "frozen" if benchmark.is_frozen else "open"
                print(
                    f"{benchmark.display_id}\t{state}\t"
                    f"{len(benchmark.members)}\t{benchmark.name}"
                )
    else:
        command = arguments.validate_command
        if command == "run":
            _print_run(
                service.run_validation(
                    arguments.rule_id,
                    arguments.benchmark_id,
                    version=arguments.version,
                    roles=arguments.role,
                )
            )
        elif command == "show":
            _print_run(service.show_run(arguments.run_id))
        else:
            for run in service.list_runs(arguments.rule):
                metrics = run.metrics
                print(
                    f"{run.display_id}\t{run.rule_display_id}:v{run.rule_version}\t"
                    f"{run.benchmark_display_id}\t{run.kind.value}\t"
                    f"TP={metrics.tp} FP={metrics.fp} FN={metrics.fn} TN={metrics.tn}"
                )
    return 0


def _print_ai_analysis(analysis: AiAnalysis) -> None:
    print(f"analysis: {analysis.display_id}")
    print(f"case: {analysis.case_display_id}")
    print(f"stage: {analysis.stage.value}")
    print(f"provider: {analysis.provider}")
    print(f"model: {analysis.model}")
    print(f"input_scope: {analysis.input_scope}")
    print(f"input_sha256: {analysis.input_sha256}")
    print(f"created_at: {format_utc(analysis.created_at)}")
    print("note: suggestions are inferences, not observed evidence")
    for suggestion in analysis.suggestions:
        title = "" if suggestion.title is None else f"{suggestion.title}: "
        print(
            f"[{suggestion.sequence}] {suggestion.kind.value} "
            f"({suggestion.state.value}) {single_line(title + suggestion.text)}"
        )
        if suggestion.evidence_artifact_ids:
            print(f"    evidence: {', '.join(suggestion.evidence_artifact_ids)}")
        if suggestion.expected_benign:
            print(f"    expected_benign: {single_line(suggestion.expected_benign)}")
        if suggestion.hypothesis_display_id:
            print(f"    hypothesis: {suggestion.hypothesis_display_id}")
        if suggestion.review_note:
            print(f"    review_note: {single_line(suggestion.review_note)}")


def _print_opinion_group(group: OpinionGroup, *, with_provider: bool) -> None:
    first = group.opinions[0]
    label = first.title if first.title is not None else first.text
    who = f" [{', '.join(group.providers)}]" if with_provider else ""
    print(f"- {group.kind.value}{who} {single_line(label)}")
    if group.evidence_artifact_ids:
        print(f"    evidence: {', '.join(group.evidence_artifact_ids)}")
    for opinion in group.opinions:
        print(
            f"    {opinion.analysis_display_id}#{opinion.sequence} "
            f"{opinion.provider}: {single_line(opinion.text)}"
        )


def _print_comparison(comparison: Comparison) -> None:
    print(f"case: {comparison.case_display_id}")
    print(f"input_sha256: {comparison.input_sha256}")
    for analysis in comparison.analyses:
        print(f"analysis: {analysis.display_id}\t{analysis.provider}\t{analysis.model}")
    print(
        "note: suggestions are inferences, not observed evidence; "
        "grouping is a citation and behavior-theme heuristic"
    )
    print(f"shared opinions: {len(comparison.common)}")
    for group in comparison.common:
        _print_opinion_group(group, with_provider=True)
    print(f"single-provider opinions: {len(comparison.individual)}")
    for group in comparison.individual:
        _print_opinion_group(group, with_provider=True)
    print("summaries:")
    for summary in comparison.summaries:
        print(f"- {summary.provider}: {single_line(summary.text)}")


def _finding_line(finding: AnalystFinding) -> str:
    content = finding.content
    label = content.title or content.text
    return (
        f"{finding.display_id}\t{finding.kind.value}\t{finding.state.value}\t"
        f"r{finding.revision}\t{single_line(label)[:80]}"
    )


def _print_finding(finding: AnalystFinding) -> None:
    content = finding.content
    print(f"finding: {finding.display_id}")
    print(f"case: {finding.case_display_id}")
    print(f"kind: {finding.kind.value}")
    print(f"state: {finding.state.value}")
    print(f"revision: {finding.revision}")
    print(f"source: {finding.source}")
    if content.title is not None:
        print(f"title: {single_line(content.title)}")
    if content.verdict is not None:
        print(f"verdict: {content.verdict.value}")
    if content.evidence:
        print("evidence: " + ", ".join(str(ref) for ref in content.evidence))
    if content.hypothesis_display_id is not None:
        print(f"hypothesis: {content.hypothesis_display_id}")
    if content.finding_refs:
        print("references: " + ", ".join(content.finding_refs))
    confirmed = finding.confirmed_at
    print(f"confirmed_at: {'NULL' if confirmed is None else format_utc(confirmed)}")
    print("text:")
    for line in content.text.splitlines():
        print(f"  {single_line(line)}")
    for revision in finding.history:
        note = "" if revision.note is None else f" note={single_line(revision.note)}"
        print(
            f"r{revision.revision}\t{revision.action.value}\t{revision.state.value}\t"
            f"{format_utc(revision.at)}{note}"
        )


def _run_finding(arguments: argparse.Namespace, service: FindingService) -> int:
    command = arguments.finding_command
    if command == "list":
        state = None if arguments.state is None else FindingState(arguments.state)
        for item in service.list_findings(arguments.case_display_id, state):
            print(_finding_line(item))
        return 0
    if command == "show":
        _print_finding(service.show(arguments.finding_id))
        return 0
    if command == "add":
        finding = service.create(
            arguments.case_display_id,
            arguments.kind,
            arguments.text,
            title=arguments.title,
            verdict=arguments.verdict,
            evidence=arguments.evidence or (),
            hypothesis=arguments.hypothesis,
            findings=arguments.ref or (),
            note=arguments.note,
        )
    elif command == "edit":
        finding = service.edit(
            arguments.finding_id,
            text=arguments.text,
            title=arguments.title,
            verdict=arguments.verdict,
            evidence=arguments.evidence,
            hypothesis=arguments.hypothesis,
            findings=arguments.ref,
            clear=arguments.clear,
            note=arguments.note,
        )
    elif command == "confirm":
        finding = service.confirm(arguments.finding_id, arguments.note)
    elif command == "withdraw":
        finding = service.withdraw(arguments.finding_id, arguments.note)
    else:
        finding = service.adopt(
            arguments.analysis_id, arguments.sequence, arguments.note
        )
    print(_finding_line(finding))
    return 0


def _run_ai(arguments: argparse.Namespace, service: AiAnalysisService) -> int:
    command = arguments.ai_command
    if command == "providers":
        for provider in service.providers():
            if not provider.enabled:
                state = f"disabled: {provider.blocked_by}"
            elif provider.requires_network:
                state = "enabled (external: needs --allow-network)"
            else:
                state = "enabled"
            print(f"{provider.name}\t{provider.model}\t{state}")
    elif command == "preview":
        preview = service.preview(arguments.case_display_id, arguments.stage)
        print(f"case: {preview.case_display_id}")
        print(f"input_scope: {preview.scope}")
        print(f"input_sha256: {preview.sha256}")
        print(f"input_bytes: {preview.size_bytes}")
        print(json.dumps(preview.digest, indent=2, sort_keys=True))
    elif command == "analyze":
        names = [name.strip() for name in arguments.provider.split(",")]
        if not all(names) or len(set(names)) != len(names):
            raise DomainError(
                DomainErrorCode.INVALID_AI_REQUEST,
                "--provider must list distinct provider names",
            )
        for name in names:
            _print_ai_analysis(
                service.analyze(
                    arguments.case_display_id,
                    name,
                    arguments.stage,
                    allow_network=arguments.allow_network,
                )
            )
    elif command == "list":
        for analysis in service.list_analyses(arguments.case_display_id):
            pending = sum(1 for s in analysis.suggestions if s.state.value == "pending")
            print(
                f"{analysis.display_id}\t{analysis.case_display_id}\t"
                f"{analysis.stage.value}\t{analysis.provider}\t"
                f"{len(analysis.suggestions)} suggestions\t"
                f"{pending} pending"
            )
    elif command == "show":
        _print_ai_analysis(service.show(arguments.analysis_id))
    elif command == "compare":
        _print_comparison(
            service.compare(arguments.case_display_id, arguments.analysis_ids)
        )
    elif command == "accept":
        _print_ai_analysis(
            service.accept(arguments.analysis_id, arguments.number, arguments.note)
        )
    else:
        _print_ai_analysis(
            service.reject(arguments.analysis_id, arguments.number, arguments.note)
        )
    return 0


def _print_execution_run(run: ExecutionRun) -> None:
    print(f"run_id: {run.display_id}")
    print(f"case_id: {run.case_display_id}")
    print(f"profile: {run.profile.value}")
    print(f"target: {run.target}")
    print(f"target_sha256: {run.target_sha256 or 'NULL'}")
    print(f"vm: {run.vm_name}")
    print(f"snapshot: {run.snapshot}")
    print(f"timeout_seconds: {run.timeout_seconds}")
    print(f"status: {run.status.value}")
    print(f"started_at: {format_utc(run.started_at)}")
    finished = "NULL" if run.finished_at is None else format_utc(run.finished_at)
    print(f"finished_at: {finished}")
    print(f"error_code: {run.error_code or 'NULL'}")
    print(f"sysmon_artifact: {run.sysmon_artifact_id or 'NULL'}")
    print(f"metadata_artifact: {run.metadata_artifact_id or 'NULL'}")
    print(f"event_count: {'NULL' if run.event_count is None else run.event_count}")
    for step in run.steps:
        detail = "" if step.detail is None else f"\t{step.detail}"
        print(
            f"{step.sequence:02d}\t{step.step.value}\t{step.status.value}\t"
            f"{format_utc(step.at)}{detail}"
        )


def _print_plan(plan: ExecutionPlan, credentials_configured: bool) -> None:
    request = plan.request
    print("dry_run: true (no VM command was executed)")
    print(f"case_id: {request.case_display_id}")
    print(f"profile: {request.profile.value}")
    print(f"target: {request.target}")
    print(f"target_sha256: {plan.target_sha256 or 'NULL'}")
    print(f"vm: {plan.settings.vm_name}")
    print(f"snapshot: {plan.settings.snapshot}")
    print(f"timeout_seconds: {request.timeout_seconds}")
    print(f"guest_credentials: {'set' if credentials_configured else 'missing'}")
    for index, step in enumerate(plan.steps, start=1):
        print(f"{index:02d}\t{step.step.value}\t{step.description}")
        if step.command is not None:
            print("\t$ " + " ".join(step.command))


def _print_lock(status: LockStatus) -> None:
    if status.lock is None:
        print("safety_lock: none")
    else:
        print("safety_lock: SET")
        print(f"lock_run: {status.lock.run_display_id or 'NULL'}")
        print(f"lock_reason: {status.lock.reason}")
        print(f"lock_created_at: {format_utc(status.lock.created_at)}")
    print(f"unfinished_runs: {', '.join(status.running_runs) or 'none'}")


def _print_preflight(report: PreflightReport) -> None:
    info = report.info
    print(f"vm: {info.name}")
    print(f"state: {info.state}")
    print(f"current_snapshot: {info.current_snapshot or 'NULL'}")
    presence = "present" if report.snapshot_present else "MISSING"
    print(f"clean_snapshot: {report.snapshot} ({presence})")
    for nic in info.nics:
        cable = "connected" if nic.cable_connected else "disconnected"
        print(f"nic{nic.index}: {nic.attachment} cable={cable}")
    print(f"shared_folders: {len(info.shared_folders)}")
    print(f"clipboard: {info.clipboard_mode or 'unknown'}")
    print(f"drag_and_drop: {info.drag_and_drop_mode or 'unknown'}")
    print(f"ready: {'yes' if report.ready else 'no'}")
    for problem in report.problems:
        print(f"problem: {problem}")


def _run_vm(arguments: argparse.Namespace) -> int:
    command = arguments.vm_command
    root = Path.cwd()
    if command == "scenarios":
        for name, description in BENIGN_SCENARIOS.items():
            print(f"{name}\t{description}")
        return 0
    if command in {"status", "show", "list", "unlock"}:
        service = ExecutionService(root)
        if command == "status":
            _print_lock(service.lock_status())
        elif command == "show":
            _print_execution_run(service.show_run(arguments.run_id))
        elif command == "list":
            for run in service.list_runs():
                print(
                    f"{run.display_id}\t{run.case_display_id}\t{run.profile.value}\t"
                    f"{run.target}\t{run.status.value}\t{run.error_code or '-'}"
                )
        else:
            before = service.unlock(arguments.note)
            if not before.locked:
                print("safety_lock: none (nothing to release)")
            else:
                print("safety_lock: released")
                for run_id in before.running_runs:
                    print(f"abandoned_run: {run_id}")
        return 0
    settings = VmSettings(vm_name=arguments.vm, snapshot=arguments.snapshot)
    hypervisor = VBoxManageHypervisor()
    service = ExecutionService(root, settings, hypervisor)
    if command == "preflight":
        report = service.preflight(ExecutionProfile(arguments.profile))
        _print_preflight(report)
        return 0 if report.ready else 1
    if command == "run":
        request = ExecutionRequest(
            arguments.case_display_id,
            ExecutionProfile.SAMPLE,
            arguments.timeout,
            sample_artifact_id=arguments.sample,
            collect_dropped=arguments.collect_dropped,
        )
    else:
        request = ExecutionRequest(
            arguments.case_display_id,
            ExecutionProfile.BENIGN_SCENARIO,
            arguments.timeout,
            scenario=arguments.scenario,
        )
    if arguments.dry_run:
        _print_plan(service.plan(request), service.credentials_configured())
        return 0
    _print_execution_run(service.run(request, approved=arguments.approve))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        config = load_config(arguments.config)
    except ConfigError as exc:
        parser.error(str(exc))
    configure_console_logging(arguments.log_level or config.log_level)
    if arguments.group == "ui":
        try:
            from loader_detection_workbench.web.server import serve

            serve(arguments.root, port=arguments.port)
            return 0
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
        except OSError:
            print("error: UI_SERVER_FAILED: local server failed", file=sys.stderr)
            return 2
    if arguments.group == "case":
        try:
            if arguments.case_command == "timeline":
                timeline = CaseTimelineQuery(Path.cwd()).query(arguments.display_id)
                print(render_timeline(timeline), end="")
                return 0
            if arguments.case_command == "benign-files":
                return _run_benign_files(arguments, BenignFileService(Path.cwd()))
            if arguments.case_command == "artifact":
                return _run_artifact(arguments, ArtifactService(Path.cwd()))
            if arguments.case_command == "evidence":
                return _run_evidence(arguments, ManualEvidenceService(Path.cwd()))
            if arguments.case_command == "collection":
                return _run_collection(
                    arguments, CollectionIngestionService(Path.cwd())
                )
            if arguments.case_command == "static":
                result = StaticAnalysisService(Path.cwd()).analyze(
                    arguments.case_display_id, arguments.artifact_display_id
                )
                _print_static(result)
                return 0
            return _run_case(arguments, CaseService(Path.cwd()))
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
    if arguments.group == "report":
        try:
            if arguments.report_command == "site":
                summary = SiteService(Path.cwd()).build(arguments.output)
                print(f"site: created ({summary.pages} pages, {summary.cases} Cases)")
                print(f"redactions: {summary.redactions}")
                print("note: review the pages before sharing; nothing was published")
                return 0
            ReportService(Path.cwd()).build(
                arguments.case_display_id,
                arguments.output,
                None if arguments.format is None else ReportFormat(arguments.format),
            )
            print("report: created")
            return 0
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
    if arguments.group == "project":
        try:
            return _run_project(arguments, ProjectService())
        except (DomainError, OSError, sqlite3.Error) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if arguments.group == "bundle":
        try:
            return _run_bundle(arguments, BundleService(Path.cwd()))
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
        except (OSError, sqlite3.Error, zipfile.BadZipFile) as exc:
            print(
                f"error: {DomainErrorCode.BUNDLE_IMPORT_FAILED.value}: {exc}",
                file=sys.stderr,
            )
            return 2
    if arguments.group == "vm":
        try:
            return _run_vm(arguments)
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            if exc.code is DomainErrorCode.SNAPSHOT_RESTORE_FAILED:
                print(
                    "error: SAFETY: the safety lock is set; no further run is "
                    "possible until the VM is verified and 'workbench vm unlock' "
                    "is used",
                    file=sys.stderr,
                )
            return 2
    if arguments.group == "finding":
        try:
            return _run_finding(arguments, FindingService(Path.cwd()))
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
    if arguments.group == "ai":
        try:
            return _run_ai(
                arguments, AiAnalysisService(Path.cwd(), ai_config=config.ai)
            )
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
    if arguments.group in {"rule", "hypothesis", "benchmark", "validate"}:
        try:
            return _run_detection(arguments, DetectionService(Path.cwd()))
        except DomainError as exc:
            print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
            return 2
        except (OSError, UnicodeDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if arguments.group != "sample":
        return 0
    repository: SQLiteSampleRepository | None = None
    try:
        database_path = arguments.database
        if database_path is None:
            database_path = ProjectService().open(Path.cwd()).database_path
        repository = SQLiteSampleRepository(database_path)
        return _run_sample(arguments, SampleService(repository))
    except (ContractViolation, DuplicateSampleError) as exc:
        print(f"contract violation: {exc}", file=sys.stderr)
        return 1
    except DomainError as exc:
        print(f"error: {exc.code.value}: {exc}", file=sys.stderr)
        return 2
    except (NotFoundError, SampleError, OSError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if repository is not None:
            repository.close()
