import io
import re
import shutil
import sqlite3
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.case.service import CaseService
from loader_detection_workbench.collection.service import CollectionIngestionService
from loader_detection_workbench.evidence.domain import MANUAL_EVIDENCE_MAX_BYTES
from loader_detection_workbench.evidence.service import ManualEvidenceService
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.web import create_app

BASE_URL = "http://127.0.0.1:8080"
ORIGIN = {"Origin": BASE_URL}
FIXTURES = Path(__file__).parents[1] / "fixtures/public/sysmon"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "project"
    ProjectService().create(path, "Web")
    CaseService(path).create("Open", "benign")
    CaseService(path).create("Closed", "benign")
    CaseService(path).close("CASE-0002")
    return path


@pytest.fixture
def app(root: Path, tmp_path: Path) -> Flask:
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    return create_app(
        root,
        secret_key=b"test-secret-key",
        test_config={"TESTING": True, "UPLOAD_TEMP_ROOT": upload_root},
    )


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def _get(client: FlaskClient, path: str):  # type: ignore[no-untyped-def]
    return client.get(path, base_url=BASE_URL)


def _csrf(client: FlaskClient) -> str:
    response = _get(client, "/cases/CASE-0001/evidence/new")
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def _upload(
    client: FlaskClient,
    *,
    case_id: str = "CASE-0001",
    filename: str = "note.txt",
    content: bytes = b"benign evidence",
    source: str = "analyst",
    csrf_token: str | None = None,
):
    return client.post(
        f"/cases/{case_id}/evidence",
        base_url=BASE_URL,
        headers=ORIGIN,
        data={
            "csrf_token": csrf_token or _csrf(client),
            "file": (io.BytesIO(content), filename),
            "source": source,
            "evidence_type": "analyst_note",
            "description": "sanitized fixture",
        },
        content_type="multipart/form-data",
    )


def test_case_list_empty_state_and_security_headers(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    ProjectService().create(root, "Empty")
    client = create_app(root, secret_key=b"test").test_client()

    response = _get(client, "/cases")

    assert response.status_code == 200
    assert "No Cases are registered" in response.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_case_detail_escapes_text_and_hides_internal_paths(root: Path) -> None:
    CaseService(root).rename("CASE-0001", '<script>alert("x")</script>')
    source = root.parent / "generic.txt"
    source.write_text("private body", encoding="utf-8")
    artifact = ArtifactService(root).add("CASE-0001", source, "evidence")
    case = CaseService(root).show("CASE-0001")
    client = create_app(root, secret_key=b"test").test_client()

    response = _get(client, "/cases/CASE-0001")

    assert response.status_code == 200
    assert "&lt;script&gt;" in response.text
    assert "<script>" not in response.text
    assert case.case_id.ulid not in response.text
    assert artifact.artifact_id.ulid not in response.text
    assert artifact.relative_path.as_posix() not in response.text
    assert str(root) not in response.text
    assert "Evidence (provenance unavailable)" in response.text


def test_manual_upload_is_visible_to_existing_service_and_duplicate_policy(
    root: Path, client: FlaskClient
) -> None:
    first = _upload(client, filename="note.txt")
    second = _upload(client, filename="copy.log")

    assert first.status_code == 303
    assert second.status_code == 303
    evidence = ManualEvidenceService(root).list_evidence("CASE-0001")
    assert len(evidence) == 2
    assert evidence[0].artifact.artifact_id != evidence[1].artifact.artifact_id
    assert evidence[0].artifact.sha256 == evidence[1].artifact.sha256
    response = _get(client, "/cases/CASE-0001")
    assert "note.txt" in response.text
    assert "copy.log" in response.text
    assert "analyst_note" in response.text


def test_manual_upload_escapes_provenance_and_never_returns_content(
    client: FlaskClient,
) -> None:
    marker = b"PRIVATE-CONTENT-MARKER"
    response = _upload(
        client,
        content=marker,
        source='<img src=x onerror="alert(1)">',
    )
    assert response.status_code == 303

    detail = _get(client, response.headers["Location"])
    assert "&lt;img" in detail.text
    assert "<img src=x" not in detail.text
    assert marker.decode() not in detail.text


def test_closed_missing_and_v1_registration_are_blocked(
    root: Path, client: FlaskClient
) -> None:
    closed = _upload(client, case_id="CASE-0002")
    missing = _upload(client, case_id="CASE-9999")
    assert closed.status_code == 409
    assert "CASE_CLOSED" in closed.text
    assert missing.status_code == 404
    assert "CASE_NOT_FOUND" in missing.text

    token = _csrf(client)
    with sqlite3.connect(root / "project.db") as connection:
        connection.execute("DROP TABLE artifact_provenance")
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    detail = _get(client, "/cases/CASE-0001")
    blocked = _upload(client, csrf_token=token)
    assert detail.status_code == 200
    assert "v1 Project is readable" in detail.text
    assert blocked.status_code == 409
    assert "PROJECT_MIGRATION_REQUIRED" in blocked.text


def test_extension_service_size_and_request_size_limits(
    client: FlaskClient,
) -> None:
    invalid = _upload(client, filename="evidence.exe")
    service_limit = _upload(
        client,
        content=b"x" * (MANUAL_EVIDENCE_MAX_BYTES + 1),
    )
    request_limit = _upload(client, content=b"x" * (5 * 1024 * 1024 + 1))

    assert invalid.status_code == 400
    assert "EVIDENCE_EXTENSION_NOT_ALLOWED" in invalid.text
    assert service_limit.status_code == 400
    assert "ARTIFACT_SIZE_LIMIT_EXCEEDED" in service_limit.text
    assert request_limit.status_code == 413


def test_temporary_uploads_are_removed_after_success_and_failure(
    app: Flask, client: FlaskClient
) -> None:
    upload_root = Path(app.config["UPLOAD_TEMP_ROOT"])
    assert _upload(client).status_code == 303
    assert list(upload_root.iterdir()) == []
    assert _upload(client, filename="blocked.exe").status_code == 400
    assert _upload(client, filename="../escape.txt").status_code == 400
    assert _upload(client, source=" ").status_code == 400
    assert list(upload_root.iterdir()) == []


def test_csrf_host_and_origin_are_enforced(client: FlaskClient) -> None:
    no_csrf = client.post(
        "/cases/CASE-0001/evidence",
        base_url=BASE_URL,
        headers=ORIGIN,
        data={},
    )
    bad_origin = client.post(
        "/cases/CASE-0001/evidence",
        base_url=BASE_URL,
        headers={"Origin": "http://evil.invalid"},
        data={"csrf_token": _csrf(client)},
    )
    bad_host = client.get("/cases", base_url="http://evil.invalid")

    assert no_csrf.status_code == 400
    assert "CSRF_REJECTED" in no_csrf.text
    assert bad_origin.status_code == 403
    assert "ORIGIN_REJECTED" in bad_origin.text
    assert bad_host.status_code == 400


def test_collection_and_manual_evidence_share_case_with_safe_timeline(
    root: Path, client: FlaskClient, tmp_path: Path
) -> None:
    collection = tmp_path / "collection"
    shutil.copytree(FIXTURES, collection)
    CollectionIngestionService(root).import_collection("CASE-0001", collection)
    assert _upload(client).status_code == 303

    detail = _get(client, "/cases/CASE-0001")
    timeline = _get(client, "/cases/CASE-0001/timeline")

    assert "Manual evidence" in detail.text
    assert detail.text.count("Sysmon telemetry") == 2
    assert "Other artifact" in detail.text
    assert "Collection metadata" not in detail.text
    assert "1 · Process Create" in timeline.text
    assert "11 · File Create" in timeline.text
    assert (
        "ART-" in timeline.text and ">42<" in timeline.text and ">43<" in timeline.text
    )
    assert "benign-demo.exe" not in timeline.text
    assert "--message" not in timeline.text
    assert "synthetic-demo/output.txt" not in timeline.text
    assert "11111111-2222-4333-8444-555555555555" not in timeline.text
