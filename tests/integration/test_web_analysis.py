"""Read-only analysis, rule comparison and validation views (W6)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from analysis_fixture import CHILD_GUID, PARENT_GUID, UNTRUSTED, build_workspace
from flask.testing import FlaskClient

from loader_detection_workbench.artifact.service import ArtifactService
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


def get(client: FlaskClient, path: str):  # type: ignore[no-untyped-def]
    return client.get(path, base_url=BASE_URL)


def assert_path_safe(text: str, root: Path) -> None:
    for forbidden in (
        str(root),
        "C:\\",
        "synthetic\\",
        "System32",
        "-enc AAAA",
        "maintenance.ps1",
        PARENT_GUID,
        CHILD_GUID.strip("{}"),
        "secret",
        UNTRUSTED,
        "<script>alert",
    ):
        assert forbidden not in text


def test_case_analysis_page_shows_both_graphs(client: FlaskClient, root: Path) -> None:
    before = (root / "project.db").read_bytes()
    detail = get(client, "/cases/CASE-0001")
    assert 'href="/cases/CASE-0001/analysis"' in detail.text
    response = get(client, "/cases/CASE-0001/analysis")
    text = response.text
    assert response.status_code == 200
    assert text.count("<svg") == 2
    # Evidence -> Hypothesis -> Rule -> Validation graph.
    for label in ("ART-000002", "HYP-0001", "RULE-0002", "RUN-0004"):
        assert '<text class="graph-label"' in text and f">{label}</text>" in text
    assert "static of ART-000001" in text
    assert "sysmon from VMR-0001" in text
    assert 'class="graph-node run outcome-tp"' in text
    assert 'class="graph-edge edge-supports"' in text
    assert 'class="graph-edge edge-implements"' in text
    assert text.count('class="graph-edge edge-validated"') == 5
    assert '<a href="/rules/RULE-0002">' in text
    assert '<a href="/validation/RUN-0004">' in text
    assert '<a href="/cases/CASE-0001/artifacts/ART-000002">' in text
    # Hypothesis and validation tables.
    assert "supported</span> (set by the analyst)" in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert text.index("<h3>Development</h3>") < text.index(
        "<h3>Evaluation (Unseen)</h3>"
    )
    assert text.index("<h3>Evaluation (Unseen)</h3>") < text.index(
        "<h3>Tuning (after Unseen)</h3>"
    )
    assert "<td>2/2</td>" in text and "<td>dev: TP</td>" in text
    assert "Member of BMK-0001 as <strong>dev</strong> (frozen)" in text
    # Process tree: file names only.
    for name in ("dev.exe", "powershell.exe", "out.bin"):
        assert f">{name}</text>" in text
    assert "PID 4001 · dns 1" in text
    assert 'class="graph-edge edge-spawned"' in text
    assert 'class="graph-edge edge-wrote"' in text
    assert "file · ART-000002#12" in text
    # VM run: step names but never step detail.
    assert "VMR-0001" in text and "approval ok, preflight ok" in text
    assert_path_safe(text, root)
    assert "style=" not in text
    # Only the same-origin UI script; never inline script (CSP).
    assert text.count("<script") == 1
    assert '<script src="/static/workbench.js" defer></script>' in text
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert (root / "project.db").read_bytes() == before


def test_empty_case_analysis_and_non_member(client: FlaskClient) -> None:
    text = get(client, "/cases/CASE-0004/analysis").text
    assert "<svg" not in text
    assert "이 Case의 가설, 룰, 검증 런이 없습니다." in text
    assert "프로세스 관계를 만들 수 없습니다" in text
    assert "이 Case의 VM 실행 기록이 없습니다." in text

    benign = get(client, "/cases/CASE-0002/analysis").text
    assert "<td>benign_common: FP</td>" in benign  # RUN-0002, Sigma v1
    assert "<td>benign_common: TN</td>" in benign
    assert 'class="graph-node run outcome-fp"' in benign
    assert "이 Case의 탐지 가설이 없습니다." in benign


def test_detection_overview(client: FlaskClient, root: Path) -> None:
    text = get(client, "/detection").text
    assert '<a href="/rules" class="on" aria-current="page">탐지 룰</a>' in text
    assert '<a href="/rules/RULE-0001">RULE-0001</a>' in text
    assert "BMK-0001 · synthetic-v1" in text and "frozen</span>" in text
    assert "<td>unseen</td>" in text and "<td>malicious</td>" in text
    assert text.count('href="/validation/RUN-') == 5
    assert_path_safe(text, root)


def test_rule_version_comparison(client: FlaskClient, root: Path) -> None:
    response = get(client, "/rules/RULE-0002")
    text = response.text
    assert response.status_code == 200
    assert "Content of v2 (frozen)" in text and "Content of v1 (draft)" in text
    assert "CommandLine|contains|all: [&#39;-enc&#39;, &#39;hidden&#39;]" in text
    assert "require -enc and hidden" in text
    # Version rows: v1 has a development FP, v2 removes it and is evaluated.
    rows = re.findall(r"<tr>\s*<td>v(\d) <span.*?</tr>", text, re.S)
    assert rows == ["1", "2"]
    v1 = re.search(r"<td>v1 <span.*?</tr>", text, re.S)
    v2 = re.search(r"<td>v2 <span.*?</tr>", text, re.S)
    assert v1 is not None and v2 is not None
    assert '<a href="/validation/RUN-0002">1/1</a>' in v1.group(0)
    assert "<td>1/1</td>" in v1.group(0)  # FP 1/1 benign
    assert v1.group(0).count("<td>—</td>") == 6  # no evaluation or tuning for v1
    assert '<a href="/validation/RUN-0003">1/1</a>' in v2.group(0)
    assert '<a href="/validation/RUN-0004">2/2</a>' in v2.group(0)
    assert '<a href="/validation/RUN-0005">2/2</a>' in v2.group(0)
    assert "<td>0/1</td>" in v2.group(0)
    # Per-Case matrix highlights the benign Case whose outcome changed.
    changed = re.search(r'<tr class="changed">.*?</tr>', text, re.S)
    assert changed is not None
    assert "CASE-0002" in changed.group(0)
    assert changed.group(0).index(">FP<") < changed.group(0).index(">TN<")
    assert "HYP-0001" in text and 'href="/cases/CASE-0001/analysis"' in text
    assert_path_safe(text, root)

    single = get(client, "/rules/RULE-0001").text
    assert "Content of v1 (draft)" in single
    assert "SYNTHETIC-LOADER-MARKER" in single


def test_validation_run_detail(client: FlaskClient, root: Path) -> None:
    evaluation = get(client, "/validation/RUN-0004").text
    assert "RUN-0004 · Evaluation (Unseen)" in evaluation
    assert "<strong>2/2</strong><span>탐지 (TP / 악성)</span>" in evaluation
    assert "<strong>0/1</strong><span>오탐 (FP / 정상)</span>" in evaluation
    assert "동결된 룰 버전과 동결된 벤치마크" in evaluation
    assert "ART-000006#30 (EventID 1)" in evaluation
    assert_path_safe(evaluation, root)

    tuning = get(client, "/validation/RUN-0005").text
    assert "Unseen 평가 결과가 아닙니다" in tuning

    yara = get(client, "/validation/RUN-0001").text
    assert "ART-000001 rule synthetic_loader_marker" in yara
    assert "SYNTHETIC-LOADER-MARKER" not in yara  # matched content is not shown


@pytest.mark.parametrize(
    "path",
    [
        "/rules/RULE-9999",
        "/rules/not-an-id",
        "/validation/RUN-9999",
        "/validation/bad",
        "/cases/CASE-9999/analysis",
    ],
)
def test_unknown_records_return_404(client: FlaskClient, path: str) -> None:
    response = get(client, path)
    assert response.status_code == 404
    assert "Traceback" not in response.text and "sqlite" not in response.text.lower()


def test_views_are_read_only(client: FlaskClient) -> None:
    for path in (
        "/cases/CASE-0001/analysis",
        "/detection",
        "/rules/RULE-0001",
        "/validation/RUN-0001",
    ):
        response = client.post(path, base_url=BASE_URL, headers={"Origin": BASE_URL})
        assert response.status_code in {400, 405}


def test_analysis_fails_closed_on_invalid_static_result(
    client: FlaskClient, root: Path
) -> None:
    bad = root.parent / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    ArtifactService(root).add("CASE-0004", bad, "static")
    response = get(client, "/cases/CASE-0004/analysis")
    assert response.status_code == 422
    assert "INVALID_ARTIFACT_RECORD" in response.text
    assert "A stored analysis result is invalid." in response.text
    assert str(root) not in response.text


def test_project_without_detection_records(tmp_path: Path) -> None:
    from loader_detection_workbench.case.service import CaseService
    from loader_detection_workbench.project.service import ProjectService

    plain = tmp_path / "plain"
    ProjectService().create(plain, "Plain")
    CaseService(plain).create("only", "benign")
    client = create_app(plain, test_config={"TESTING": True}).test_client()
    overview = get(client, "/detection")
    assert overview.status_code == 200
    assert "등록된 룰이 없습니다." in overview.text
    assert "기록된 검증 런이 없습니다." in overview.text
    assert get(client, "/cases/CASE-0001/analysis").status_code == 200
    assert get(client, "/rules/RULE-0001").status_code == 404
