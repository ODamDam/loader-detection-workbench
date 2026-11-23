"""Redesigned overview pages, ID search and the workspace detail panel."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from analysis_fixture import UNTRUSTED, build_workspace
from flask.testing import FlaskClient
from markupsafe import Markup

from loader_detection_workbench.findings.service import FindingService
from loader_detection_workbench.web import create_app

BASE_URL = "http://127.0.0.1:8080"


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


PAGES = (
    "/",
    "/samples",
    "/samples?filter=dev",
    "/samples?filter=unknown",
    "/rules",
    "/rules?format=sigma",
    "/validation",
    "/validation?benchmark=BMK-0001",
    "/outputs",
    "/environment",
)


@pytest.mark.parametrize("path", PAGES)
def test_overview_pages_render_without_inline_style_or_script(
    client: FlaskClient, root: Path, path: str
) -> None:
    before = (root / "project.db").read_bytes()
    response = _get(client, path)
    assert response.status_code == 200
    text = response.text
    assert 'lang="ko"' in text and "주요 메뉴" in text
    assert "style=" not in text  # blocked by the CSP
    assert text.count("<script") == 1  # only the same-origin UI script
    assert UNTRUSTED not in text
    assert str(root) not in text
    assert (root / "project.db").read_bytes() == before  # read-only


def test_dashboard_and_rules_show_project_numbers(client: FlaskClient) -> None:
    dashboard = _get(client, "/").text
    assert "VMR-0001" in dashboard  # recent activity
    assert "룰 v2 동결" in dashboard
    rules = _get(client, "/rules").text
    assert "/rules/RULE-0001" in rules and "/rules/RULE-0002" in rules
    assert "동결" in rules and "초안" in rules
    matrix = _get(client, "/validation?benchmark=BMK-0001").text
    assert 'class="c TP"' in matrix or 'class="c FN"' in matrix
    assert 'href="/validation/RUN-' in matrix


def test_frozen_ruleset_zip_has_only_frozen_versions(client: FlaskClient) -> None:
    response = _get(client, "/outputs/frozen-rules.zip")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
    assert [item["rule"] for item in manifest["rules"]] == ["RULE-0002"]
    assert manifest["rules"][0]["version"] == 2
    assert "sigma/RULE-0002-v2.yml" in names


@pytest.mark.parametrize(
    ("query", "target"),
    [
        ("case-0001", "/cases/CASE-0001/workspace"),
        ("RULE-0001", "/rules/RULE-0001"),
        ("RUN-0002", "/validation/RUN-0002"),
        ("BMK-0001", "/validation?benchmark=BMK-0001"),
        ("ART-000005", "/cases/CASE-0002/artifacts/ART-000005"),
        ("ART-000002#12", "/cases/CASE-0001/artifacts/ART-000002"),
        ("VMR-0001", "/cases/CASE-0001/workspace"),
    ],
)
def test_id_search_redirects(client: FlaskClient, query: str, target: str) -> None:
    response = _get(client, f"/go?q={query.replace('#', '%23')}")
    assert response.status_code == 302
    assert response.headers["Location"].endswith(target)


@pytest.mark.parametrize("query", ["", "ART-999999", "nonsense", "CASE-0099"])
def test_id_search_unknown_is_404(client: FlaskClient, query: str) -> None:
    response = _get(client, f"/go?q={query}")
    assert response.status_code == 404
    assert "찾을 수 없습니다" in response.text


def test_detail_panel_fragments(client: FlaskClient, root: Path) -> None:
    finding = FindingService(root).create(
        "CASE-0001", "evidence", "dev.exe wrote out.bin", evidence=["ART-000002:12"]
    )
    event = _get(client, "/cases/CASE-0001/detail?ref=ART-000002%2312")
    assert event.status_code == 200
    assert "<html" not in event.text  # a fragment, not a page
    assert "File Create" in event.text or "Sysmon" in event.text
    assert finding.display_id in event.text  # cited by
    # UI contract: file names only, never command lines or directories.
    assert ":\\" not in event.text and "명령줄" not in event.text
    artifact = _get(client, "/cases/CASE-0001/detail?ref=ART-000001").text
    assert "Artifact 상세 열기" in artifact
    detail = _get(client, f"/cases/CASE-0001/detail?ref={finding.display_id}").text
    assert "dev.exe wrote out.bin" in detail
    rule = _get(client, "/cases/CASE-0001/detail?ref=RULE-0002").text
    assert UNTRUSTED not in rule and "&lt;script&gt;" in rule
    run = _get(client, "/cases/CASE-0001/detail?ref=VMR-0001").text
    assert "VM 실행" in run
    assert _get(client, "/cases/CASE-0001/detail?ref=bad").status_code == 404
    assert _get(client, "/cases/CASE-0001/detail?ref=ART-999999").status_code == 404


def test_workspace_sections_link_ids_to_the_panel(
    client: FlaskClient, root: Path
) -> None:
    FindingService(root).create(
        "CASE-0001", "evidence", "see ART-000002 and RULE-0001", evidence=["ART-000002"]
    )
    page = _get(client, "/cases/CASE-0001/workspace?tab=findings").text
    assert 'data-detail="/cases/CASE-0001/detail?ref=ART-000002"' in page
    assert 'href="/rules/RULE-0001"' in page
    assert 'id="detail-panel"' in page
    evidence = _get(client, "/cases/CASE-0001/workspace?tab=evidence").text
    assert "VM 실행 (Sysmon)" in evidence and "VMR-0001" in evidence
    process = _get(client, "/cases/CASE-0001/workspace?tab=process").text
    assert "<svg" in process
    overview = _get(client, "/cases/CASE-0001/workspace").text
    assert "진행 단계" in overview


def test_link_ids_escapes_before_linking(root: Path) -> None:
    from loader_detection_workbench.web.detail import link_ids

    app = create_app(root, secret_key=b"k", test_config={"TESTING": True})
    with app.test_request_context(base_url=BASE_URL):
        html = link_ids('<b>x</b> ART-000001 "q"', "CASE-0001")
    assert isinstance(html, Markup)
    assert "&lt;b&gt;x&lt;/b&gt;" in html and "&#34;q&#34;" in html
    assert '<a class="id" href="/cases/CASE-0001/artifacts/ART-000001"' in html
