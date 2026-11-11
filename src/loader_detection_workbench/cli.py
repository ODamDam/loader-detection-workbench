"""Command-line entry point for the local workbench."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import asdict
from enum import Enum
from importlib.metadata import version
from pathlib import Path
from typing import Any

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
from loader_detection_workbench.logging_config import configure_console_logging
from loader_detection_workbench.project.migration import ProjectMigrationService
from loader_detection_workbench.project.service import ProjectService, ProjectWorkspace
from loader_detection_workbench.report.service import ReportService
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
    report = groups.add_parser("report", help="build a minimal Case Markdown report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    report_build = report_commands.add_parser("build")
    report_build.add_argument("case_display_id", metavar="CASE-NNNN")
    report_build.add_argument("output", type=Path, metavar="OUTPUT.md")
    ui = groups.add_parser("ui", help="serve the local Case platform UI")
    ui_commands = ui.add_subparsers(dest="ui_command", required=True)
    ui_serve = ui_commands.add_parser("serve")
    ui_serve.add_argument("root", type=Path, nargs="?", default=Path("."))
    ui_serve.add_argument("--port", type=_port, default=8080)
    _add_detection_parsers(groups)
    return parser


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


def _run_sample(a: argparse.Namespace, service: SampleService) -> int:
    command = a.sample_command
    if command == "add":
        _print(
            [
                service.add(
                    a.file,
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


def _run_artifact(arguments: argparse.Namespace, service: ArtifactService) -> int:
    if arguments.artifact_command == "add":
        artifacts = [
            service.add(arguments.case_display_id, arguments.source, arguments.kind)
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
            ReportService(Path.cwd()).build(arguments.case_display_id, arguments.output)
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
    except (NotFoundError, SampleError, DomainError, OSError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if repository is not None:
            repository.close()
