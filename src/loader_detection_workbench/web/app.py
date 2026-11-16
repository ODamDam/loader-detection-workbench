"""Flask application factory and local-browser security boundary."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from flask import Flask, Response, render_template, request
from flask.typing import ResponseReturnValue
from flask_wtf.csrf import CSRFError, CSRFProtect  # type: ignore[import-untyped]

from loader_detection_workbench.domain.errors import (
    DomainError,
    DomainErrorCategory,
    DomainErrorCode,
)
from loader_detection_workbench.evidence.domain import MANUAL_EVIDENCE_MAX_BYTES
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.web.routes import web

_REQUEST_OVERHEAD_BYTES = 1024 * 1024
_SAFE_MESSAGES = {
    DomainErrorCode.CASE_NOT_FOUND: "The requested Case was not found.",
    DomainErrorCode.ARTIFACT_NOT_FOUND: "The requested Artifact was not found.",
    DomainErrorCode.CASE_CLOSED: "Manual evidence can only be added to an Open Case.",
    DomainErrorCode.PROJECT_MIGRATION_REQUIRED: (
        "Manual evidence registration requires an explicit Project migration to v2."
    ),
    DomainErrorCode.INVALID_EVIDENCE_TYPE: "The evidence type is not supported.",
    DomainErrorCode.INVALID_ARTIFACT_PROVENANCE: (
        "The evidence metadata or original filename is invalid."
    ),
    DomainErrorCode.EVIDENCE_EXTENSION_NOT_ALLOWED: (
        "The uploaded filename extension is not allowed."
    ),
    DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED: (
        "The uploaded evidence exceeds the 4 MiB limit."
    ),
    DomainErrorCode.ARTIFACT_INTEGRITY_MISMATCH: (
        "Stored evidence failed its integrity check."
    ),
    DomainErrorCode.DETECTION_RULE_NOT_FOUND: "The requested Rule was not found.",
    DomainErrorCode.VALIDATION_RUN_NOT_FOUND: (
        "The requested Validation run was not found."
    ),
    DomainErrorCode.INVALID_ARTIFACT_RECORD: "A stored analysis result is invalid.",
    DomainErrorCode.INVALID_DETECTION_RECORD: "A stored detection record is invalid.",
    DomainErrorCode.INVALID_SYSMON_XML: "Stored Sysmon XML is invalid.",
    DomainErrorCode.INVALID_PROCESS_CREATE: "A Process Create event is invalid.",
    DomainErrorCode.INVALID_FILE_CREATE: "A File Create event is invalid.",
    DomainErrorCode.UNSUPPORTED_SYSMON_EVENT: "A Sysmon event is not supported.",
}


def _domain_status(error: DomainError) -> int:
    if error.category is DomainErrorCategory.IDENTITY:
        return 404
    if error.code in {
        DomainErrorCode.CASE_CLOSED,
        DomainErrorCode.PROJECT_MIGRATION_REQUIRED,
    }:
        return 409
    if error.category in {
        DomainErrorCategory.VALIDATION,
        DomainErrorCategory.PATH,
        DomainErrorCategory.CONTRACT,
    }:
        return 400 if request.method == "POST" else 422
    return 500


def create_app(
    project_root: Path,
    *,
    port: int = 8080,
    secret_key: bytes | None = None,
    test_config: dict[str, Any] | None = None,
) -> Flask:
    """Create a UI bound to one already-selected Project workspace."""
    workspace = ProjectService().open(project_root)
    app = Flask(__name__)
    app.config.from_mapping(
        DEBUG=False,
        SECRET_KEY=secret_key or secrets.token_bytes(32),
        MAX_CONTENT_LENGTH=MANUAL_EVIDENCE_MAX_BYTES + _REQUEST_OVERHEAD_BYTES,
        MAX_FORM_MEMORY_SIZE=64 * 1024,
        MAX_FORM_PARTS=10,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        TRUSTED_HOSTS=["127.0.0.1"],
        WORKBENCH_ORIGIN=f"http://127.0.0.1:{port}",
        WORKBENCH_PROJECT_ROOT=workspace.root,
        WORKBENCH_SCHEMA_VERSION=workspace.sqlite_schema_version,
        UPLOAD_TEMP_ROOT=None,
    )
    if test_config is not None:
        app.config.update(test_config)

    csrf = CSRFProtect()
    app.register_blueprint(web)

    @app.before_request
    def enforce_origin() -> ResponseReturnValue | None:
        if (
            request.method not in {"GET", "HEAD", "OPTIONS"}
            and request.headers.get("Origin") != app.config["WORKBENCH_ORIGIN"]
        ):
            return render_template(
                "error.html",
                status=403,
                code="ORIGIN_REJECTED",
                message="The request origin was rejected.",
            ), 403
        return None

    # Reject cross-origin writes before CSRF needs to parse a multipart body.
    csrf.init_app(app)

    @app.after_request
    def secure_response(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(DomainError)
    def handle_domain_error(error: DomainError) -> tuple[str, int]:
        status = _domain_status(error)
        return (
            render_template(
                "error.html",
                status=status,
                code=error.code.value,
                message=_SAFE_MESSAGES.get(
                    error.code, "The request could not be completed safely."
                ),
            ),
            status,
        )

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error: CSRFError) -> tuple[str, int]:
        del error
        return (
            render_template(
                "error.html",
                status=400,
                code="CSRF_REJECTED",
                message="The form security token was rejected.",
            ),
            400,
        )

    @app.errorhandler(413)
    def handle_too_large(error: Exception) -> tuple[str, int]:
        del error
        return (
            render_template(
                "error.html",
                status=413,
                code=DomainErrorCode.ARTIFACT_SIZE_LIMIT_EXCEEDED.value,
                message="The upload request is too large.",
            ),
            413,
        )

    @app.errorhandler(500)
    def handle_internal_error(error: Exception) -> tuple[str, int]:
        del error
        return (
            render_template(
                "error.html",
                status=500,
                code="INTERNAL_ERROR",
                message="The request could not be completed safely.",
            ),
            500,
        )

    return app
