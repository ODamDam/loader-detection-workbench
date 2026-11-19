"""Korean reading translations of AI suggestions (ADR-033), fake transport only."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from analysis_fixture import build_workspace

from loader_detection_workbench.ai.domain import (
    ReviewState,
    Suggestion,
    SuggestionKind,
)
from loader_detection_workbench.ai.external import external_providers
from loader_detection_workbench.ai.provider import default_providers
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.ai.translate import (
    parse_translation,
    translation_request,
)
from loader_detection_workbench.cli import main
from loader_detection_workbench.config import DEFAULT_AI_MODELS, AiConfig
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.project.service import ProjectService
from loader_detection_workbench.web import create_app

SECRET = "sk-test-not-a-real-key-0123456789"
BASE_URL = "http://127.0.0.1:8080"


def _suggestion(sequence: int, title: str | None, text: str) -> Suggestion:
    return Suggestion(
        sequence,
        SuggestionKind.HYPOTHESIS_CANDIDATE if title else SuggestionKind.NEXT_STEP,
        title,
        text,
        ("ART-000002",),
        None,
        ReviewState.PENDING,
        None,
        None,
        None,
    )


ITEMS = (
    _suggestion(1, "Script host started", "ART-000002 starts powershell.exe."),
    _suggestion(2, None, "Compare with FND-0001 and RULE-0005."),
)


def _answer(items: list[dict[str, Any]]) -> str:
    return json.dumps({"items": items}, ensure_ascii=False)


GOOD = [
    {
        "sequence": 1,
        "title": "스크립트 호스트 실행",
        "text": "ART-000002가 powershell.exe를 실행한다.",
    },
    {"sequence": 2, "title": None, "text": "FND-0001, RULE-0005와 비교한다."},
]


def test_request_carries_only_sequence_title_and_text() -> None:
    request = translation_request(ITEMS)
    assert json.loads(request.json) == {
        "items": [
            {"sequence": 1, "title": "Script host started", "text": ITEMS[0].text},
            {"sequence": 2, "title": None, "text": ITEMS[1].text},
        ]
    }
    assert re.fullmatch(r"[0-9a-f]{64}", request.sha256)


def test_valid_answer_is_parsed_in_sequence_order() -> None:
    parsed = parse_translation(_answer(list(reversed(GOOD))), ITEMS)
    assert parsed == (
        (1, "스크립트 호스트 실행", "ART-000002가 powershell.exe를 실행한다."),
        (2, None, "FND-0001, RULE-0005와 비교한다."),
    )


@pytest.mark.parametrize(
    "items",
    [
        [GOOD[0]],  # one missing
        [GOOD[0], GOOD[1], GOOD[1]],  # repeated
        [GOOD[0], {**GOOD[1], "sequence": 9}],  # unknown sequence
        [{**GOOD[0], "text": "ART-000003가 실행한다."}, GOOD[1]],  # ID changed
        [GOOD[0], {**GOOD[1], "text": "FND-0001과 비교한다."}],  # ID dropped
        [{**GOOD[0], "title": None}, GOOD[1]],  # title dropped
        [{**GOOD[0], "text": "자세히는 https://example.invalid 참고"}, GOOD[1]],
        [{**GOOD[0], "text": "powershell.exe -enc AAAA 실행"}, GOOD[1]],
        [{**GOOD[0], "text": "제어\x07문자"}, GOOD[1]],
        [{**GOOD[0], "text": "  "}, GOOD[1]],
        [{**GOOD[0], "text": "가" * 4001}, GOOD[1]],
    ],
)
def test_bad_answers_fail_closed(items: list[dict[str, Any]]) -> None:
    with pytest.raises(DomainError) as error:
        parse_translation(_answer(items), ITEMS)
    assert error.value.code is DomainErrorCode.AI_OUTPUT_INVALID


@pytest.mark.parametrize("answer", ["not json", "[]", '{"items": 3}', 5])
def test_malformed_answers_fail_closed(answer: object) -> None:
    with pytest.raises(DomainError):
        parse_translation(answer, ITEMS)


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = False

    def __call__(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Any:
        self.calls.append(dict(body))
        request = json.loads(body["messages"][1]["content"])
        items = [
            {
                "sequence": item["sequence"],
                "title": None if item["title"] is None else f"[ko] {item['title']}",
                "text": f"[ko] {item['text']}",
            }
            for item in request["items"]
        ]
        if self.fail:
            items = items[:-1]
        content = json.dumps({"items": items}, ensure_ascii=False)
        return {"choices": [{"message": {"content": content}}]}


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    monkeypatch.setenv("DEEPSEEK_API_KEY", SECRET)
    return path


def _service(
    root: Path, transport: FakeTransport, allow: bool = True
) -> AiAnalysisService:
    providers = {
        **default_providers(),
        **external_providers(DEFAULT_AI_MODELS, transport),
    }
    return AiAnalysisService(root, providers, ai_config=AiConfig(allow_network=allow))


def test_translate_stores_once_and_needs_both_gates(root: Path) -> None:
    transport = FakeTransport()
    service = _service(root, transport)
    analysis = service.analyze("CASE-0001", stage="collection")
    with pytest.raises(DomainError) as error:
        service.translate(analysis.display_id)  # no --allow-network
    assert "--allow-network" in str(error.value)
    with pytest.raises(DomainError):
        _service(root, transport, allow=False).translate(
            analysis.display_id, allow_network=True
        )
    with pytest.raises(DomainError) as error:
        service.translate(analysis.display_id, "offline-template", allow_network=True)
    assert "cannot translate" in str(error.value)
    assert transport.calls == []

    result = service.translate(analysis.display_id, allow_network=True)
    assert result.stored == result.total == len(analysis.suggestions)
    (body,) = transport.calls
    assert body["response_format"] == {"type": "json_object"}
    sent = json.loads(body["messages"][1]["content"])
    assert {tuple(sorted(item)) for item in sent["items"]} == {
        ("sequence", "text", "title")
    }
    assert analysis.input_json not in body["messages"][1]["content"]
    stored = service.translations(analysis.display_id)
    first = analysis.suggestions[0]
    assert stored[first.sequence][1] == f"[ko] {first.text}"
    # The English record is unchanged and a second call sends nothing.
    assert service.show(analysis.display_id).suggestions == analysis.suggestions
    again = service.translate(analysis.display_id, allow_network=True)
    assert (again.stored, len(transport.calls)) == (0, 1)


def test_rejected_answer_stores_nothing(root: Path) -> None:
    transport = FakeTransport()
    transport.fail = True
    service = _service(root, transport)
    analysis = service.analyze("CASE-0001", stage="collection")
    with pytest.raises(DomainError) as error:
        service.translate(analysis.display_id, allow_network=True)
    assert error.value.code is DomainErrorCode.AI_OUTPUT_INVALID
    assert service.translations(analysis.display_id) == {}


def test_translations_are_append_only(root: Path) -> None:
    service = _service(root, FakeTransport())
    analysis = service.analyze("CASE-0001", stage="collection")
    service.translate(analysis.display_id, allow_network=True)
    database = ProjectService().open(root).database_path
    with sqlite3.connect(database) as connection:
        for statement in (
            "UPDATE ai_translations SET text = 'x'",
            "DELETE FROM ai_translations",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                connection.execute(statement)


def test_v2_database_is_read_then_upgraded(root: Path) -> None:
    service = _service(root, FakeTransport())
    analysis = service.analyze("CASE-0001", stage="collection")
    database = ProjectService().open(root).database_path
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER ai_translations_immutable")
        connection.execute("DROP TRIGGER ai_translations_no_delete")
        connection.execute("DROP TABLE ai_translations")
        connection.execute("UPDATE ai_schema SET version = 2")
    assert service.translations(analysis.display_id) == {}  # read-only, v2
    service.translate(analysis.display_id, allow_network=True)  # upgrades
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version FROM ai_schema").fetchall() == [(3,)]
    assert main(["project", "validate"]) == 0


def test_cli_translates_a_case_and_the_hover_text_renders(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    transport = FakeTransport()
    monkeypatch.setattr(
        "loader_detection_workbench.ai.service.external_providers",
        lambda models: external_providers(models, transport),
    )
    analysis = AiAnalysisService(root).analyze("CASE-0001", stage="collection")
    config = root / "ai.toml"
    config.write_text("[ai]\nallow_network = true\n", encoding="utf-8")
    # Without --allow-network nothing is sent.
    assert main(["--config", str(config), "ai", "translate", "CASE-0001"]) != 0
    assert "--allow-network" in capsys.readouterr().err
    assert transport.calls == []
    code = main(
        [
            "--config",
            str(config),
            "ai",
            "translate",
            analysis.display_id,
            "--allow-network",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0 and f"{analysis.display_id}\tdeepseek\t" in out
    assert SECRET not in out
    client = create_app(
        root, secret_key=b"test-secret-key", test_config={"TESTING": True}
    ).test_client()
    page = client.get(
        "/cases/CASE-0001/workspace?tab=ai&stage=collection", base_url=BASE_URL
    ).text
    assert 'class="ko-text"' in page and 'lang="ko"' in page
    assert "[ko] " in page and "Machine translation for reading only" in page
