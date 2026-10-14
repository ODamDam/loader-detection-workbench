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
from loader_detection_workbench.config import (
    ConfigError,
    ConfigValueError,
    load_config,
    normalize_log_level,
)
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


def _log_level_argument(value: str) -> str:
    try:
        return normalize_log_level(value)
    except ConfigValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _enum(enum_type: type[Enum]) -> Any:
    def parse(value: str) -> Enum:
        return enum_type(value)

    return parse


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
    return parser


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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        config = load_config(arguments.config)
    except ConfigError as exc:
        parser.error(str(exc))
    configure_console_logging(arguments.log_level or config.log_level)
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
