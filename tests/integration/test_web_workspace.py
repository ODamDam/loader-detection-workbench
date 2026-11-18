"""Case workspace: evidence, hypotheses, AI opinions, findings, report (ADR-031)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from analysis_fixture import UNTRUSTED, build_workspace
from flask.testing import FlaskClient

from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.findings.domain import FindingState
from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.web import create_app

BASE_URL = "http://127.0.0.1:8080"
WS = "/cases/CASE-0001/workspace"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return build_workspace(tmp_path)


@pytest.fixture
def client(root: Path) -> FlaskClient:
    return create_app(
        root, secret_key=b"test-secret-key", test_config={"TESTING": True}
    ).test_client()


def _get(client: FlaskClient, path: str):  # type: ignore[no-untyped-def]
    return client.get(path, base_url=BASE_URL)


def _post(client: FlaskClient, path: str, data: dict[str, str]):  # type: ignore[no-untyped-def]
    page = _get(client, WS + "?tab=findings")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert token is not None
    return client.post(
        path,
        base_url=BASE_URL,
        headers={"Origin": BASE_URL},
        data={"csrf_token": token.group(1), **data},
    )


def test_every_tab_renders_escaped(client: FlaskClient) -> None:
    for tab in ("evidence", "hypotheses", "ai", "findings", "report"):
        response = _get(client, f"{WS}?tab={tab}")
        assert response.status_code == 200, tab
        assert "Case workspace" in response.text
        assert UNTRUSTED not in response.text
    assert _get(client, f"{WS}?tab=unknown").status_code == 200  # falls back
    assert _get(client, f"{WS}?tab=ai&stage=legacy").status_code == 422
    assert _get(client, "/cases/CASE-0001").text.count("Case workspace") == 1


def test_finding_lifecycle_through_forms(client: FlaskClient, root: Path) -> None:
    response = _post(
        client,
        "/cases/CASE-0001/findings",
        {
            "kind": "evidence",
            "evidence": "ART-000002:11",
            "text": "PowerShell wrote out.bin",
        },
    )
    assert response.status_code == 303
    service = FindingService(root)
    (draft,) = service.list_findings("CASE-0001")
    assert draft.state is FindingState.DRAFT
    path = f"/cases/CASE-0001/findings/{draft.display_id}"
    assert _post(client, f"{path}/confirm", {}).status_code == 303
    assert service.show(draft.display_id).state is FindingState.CONFIRMED

    edited = _post(
        client, f"{path}/edit", {"text": "PowerShell staged out.bin", "note": "wording"}
    )
    assert edited.status_code == 303
    again = service.show(draft.display_id)
    assert again.state is FindingState.DRAFT and "staged" in again.content.text
    page = _get(client, WS + "?tab=findings").text
    assert draft.display_id in page and "History" in page

    assert _post(client, f"{path}/withdraw", {"note": ""}).status_code == 400
    assert _post(client, f"{path}/withdraw", {"note": "duplicate"}).status_code == 303
    assert service.show(draft.display_id).state is FindingState.WITHDRAWN
    assert _post(client, f"{path}/explode", {}).status_code == 400
    other = _post(client, f"/cases/CASE-0002/findings/{draft.display_id}/confirm", {})
    assert other.status_code == 404


def test_invalid_reference_is_refused(client: FlaskClient, root: Path) -> None:
    response = _post(
        client,
        "/cases/CASE-0001/findings",
        {"kind": "evidence", "evidence": "ART-999999", "text": "missing"},
    )
    assert response.status_code in (400, 404)
    assert FindingService(root).list_findings("CASE-0001") == []


def test_ai_tab_shows_providers_and_adopts(client: FlaskClient, root: Path) -> None:
    analysis = AiAnalysisService(root).analyze("CASE-0001", stage="collection")
    page = _get(client, WS + "?tab=ai&stage=collection").text
    assert "offline-template" in page and "hypothesis_candidate" in page
    assert "Adopt as draft" in page
    candidate = next(
        s for s in analysis.suggestions if s.kind.value == "hypothesis_candidate"
    )
    url = f"/cases/CASE-0001/ai/{analysis.display_id}/{candidate.sequence}/adopt"
    assert _post(client, url, {}).status_code == 303
    (draft,) = FindingService(root).list_findings("CASE-0001")
    assert draft.source == f"ai:{analysis.display_id}#{candidate.sequence}"
    assert (
        _post(client, url.replace("CASE-0001", "CASE-0002", 1), {}).status_code == 404
    )
    synthesis = _get(client, WS + "?tab=ai&stage=synthesis").text
    assert "No synthesis analysis" in synthesis


def test_report_tab_serves_confirmed_report(client: FlaskClient, root: Path) -> None:
    html = _get(client, WS + "/report.html")
    assert html.status_code == 200
    assert "default-src 'none'" in html.text
    markdown = _get(client, WS + "/report.md")
    assert markdown.status_code == 200
    assert "attachment" in markdown.headers["Content-Disposition"]
    assert _get(client, WS + "/report.pdf").status_code == 404
