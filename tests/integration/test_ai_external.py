"""External providers behind two gates, with a fake transport (ADR-031).

No test touches the network: providers get an in-memory transport, and the
HTTPS transport itself is exercised with a patched ``urlopen``.
"""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
from analysis_fixture import build_workspace

from loader_detection_workbench.ai.external import (
    external_providers,
    https_post_json,
    parse_answer,
)
from loader_detection_workbench.ai.provider import default_providers
from loader_detection_workbench.ai.service import AiAnalysisService
from loader_detection_workbench.cli import main
from loader_detection_workbench.config import (
    DEFAULT_AI_MODELS,
    AiConfig,
    ConfigValueError,
    load_config,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

SECRET = "sk-test-not-a-real-key-0123456789"
OPINIONS: dict[str, Any] = {
    "opinions": [
        {
            "kind": "hypothesis_candidate",
            "title": "Script host started by the sample",
            "text": "dev.exe starts powershell.exe, which could stage a later step.",
            "citations": ["ART-000002"],
            "expected_benign": "Installers also start PowerShell.",
        },
        {
            "kind": "next_step",
            "title": "ignored for this kind",
            "text": "Compare the child process timing with a benign installer run.",
            "citations": ["ART-000002"],
            "expected_benign": None,
        },
    ]
}


class FakeTransport:
    def __init__(self, reply: Any) -> None:
        self.reply = reply
        self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def __call__(
        self, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Any:
        self.calls.append((url, dict(headers), dict(body)))
        return self.reply


def _openai_reply(document: object) -> dict[str, Any]:
    return {"choices": [{"message": {"content": json.dumps(document)}}]}


def _gemini_reply(document: object) -> dict[str, Any]:
    text = json.dumps(document)
    return {
        "candidates": [
            {"content": {"parts": [{"text": text[:20]}, {"text": text[20:]}]}}
        ]
    }


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = build_workspace(tmp_path)
    monkeypatch.chdir(path)
    for name in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    return path


def _service(
    root: Path, transport: FakeTransport, *, allow: bool = True
) -> AiAnalysisService:
    providers = {
        **default_providers(),
        **external_providers(DEFAULT_AI_MODELS, transport),
    }
    return AiAnalysisService(root, providers, ai_config=AiConfig(allow_network=allow))


def test_config_parsing(tmp_path: Path) -> None:
    assert load_config(None).ai.allow_network is False
    good = tmp_path / "good.toml"
    good.write_text(
        '[ai]\nallow_network = true\n[ai.models]\nopenai = "gpt-5-nano"\n',
        encoding="utf-8",
    )
    config = load_config(good).ai
    assert config.allow_network is True
    assert config.models["openai"] == "gpt-5-nano"
    assert config.models["gemini"] == DEFAULT_AI_MODELS["gemini"]
    for body in (
        '[ai]\nallow_network = "yes"\n',
        "[ai]\nendpoint = 1\n",
        '[ai.models]\nclaude = "x"\n',
        '[ai.models]\nopenai = "gpt 5; rm"\n',
    ):
        bad = tmp_path / "bad.toml"
        bad.write_text(body, encoding="utf-8")
        with pytest.raises(ConfigValueError):
            load_config(bad)


def test_both_gates_and_the_key_are_required(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = FakeTransport(_openai_reply(OPINIONS))
    closed = _service(root, transport, allow=False)
    with pytest.raises(DomainError) as error:
        closed.analyze("CASE-0001", "openai", "collection", allow_network=True)
    assert error.value.code is DomainErrorCode.AI_PROVIDER_UNAVAILABLE
    assert "allow_network" in str(error.value)

    service = _service(root, transport)
    with pytest.raises(DomainError) as error:
        service.analyze("CASE-0001", "openai", "collection", allow_network=True)
    assert "OPENAI_API_KEY is not set" in str(error.value)

    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    with pytest.raises(DomainError) as error:
        service.analyze("CASE-0001", "openai", "collection")
    assert "--allow-network" in str(error.value)
    assert transport.calls == []  # nothing left the machine
    assert service.list_analyses("CASE-0001") == []
    states = {p.name: p.blocked_by for p in closed.providers()}
    assert states["offline-template"] is None and "allow_network" in str(
        states["openai"]
    )


def test_openai_call_sends_the_previewed_digest(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    transport = FakeTransport(_openai_reply(OPINIONS))
    service = _service(root, transport)
    preview = service.preview("CASE-0001", "collection")
    analysis = service.analyze("CASE-0001", "openai", "collection", allow_network=True)
    ((url, headers, body),) = transport.calls
    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers == {"Authorization": f"Bearer {SECRET}"}
    assert body["model"] == DEFAULT_AI_MODELS["openai"]
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    user = body["messages"][1]["content"]
    assert preview.serialized in user  # exactly the stored input, nothing more
    assert analysis.input_sha256 == preview.sha256
    assert (analysis.provider, analysis.model) == (
        "openai",
        DEFAULT_AI_MODELS["openai"],
    )
    kinds = [s.kind.value for s in analysis.suggestions]
    assert kinds == ["hypothesis_candidate", "next_step"]
    assert analysis.suggestions[1].title is None  # dropped for that kind
    assert SECRET not in analysis.input_json


def test_deepseek_and_gemini_wire_formats(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", SECRET)
    monkeypatch.setenv("GEMINI_API_KEY", SECRET)
    deepseek = FakeTransport(_openai_reply(OPINIONS))
    _service(root, deepseek).analyze(
        "CASE-0001", "deepseek", "collection", allow_network=True
    )
    ((url, _, body),) = deepseek.calls
    assert url == "https://api.deepseek.com/chat/completions"
    assert body["response_format"] == {"type": "json_object"}
    assert "JSON schema" in body["messages"][0]["content"]

    gemini = FakeTransport(_gemini_reply(OPINIONS))
    analysis = _service(root, gemini).analyze(
        "CASE-0001", "gemini", "collection", allow_network=True
    )
    ((url, headers, body),) = gemini.calls
    assert url.startswith("https://generativelanguage.googleapis.com/v1beta/models/")
    assert url.endswith(f"{DEFAULT_AI_MODELS['gemini']}:generateContent")
    assert headers == {"x-goog-api-key": SECRET}
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["responseSchema"]["type"] == "OBJECT"
    assert len(analysis.suggestions) == 2


@pytest.mark.parametrize(
    "reply",
    [
        _openai_reply(
            {"opinions": [{**OPINIONS["opinions"][0], "citations": ["ART-999999"]}]}
        ),
        _openai_reply({"opinions": [{**OPINIONS["opinions"][0], "kind": "mechanism"}]}),
        _openai_reply({"opinions": []}),
        _openai_reply(["not", "an", "object"]),
        {"choices": [{"message": {"content": "not json"}}]},
        {"choices": []},
        {"error": {"message": "quota"}},
    ],
)
def test_bad_answers_store_nothing(
    root: Path, monkeypatch: pytest.MonkeyPatch, reply: object
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    service = _service(root, FakeTransport(reply))
    with pytest.raises(DomainError) as error:
        service.analyze("CASE-0001", "openai", "collection", allow_network=True)
    assert error.value.code is DomainErrorCode.AI_OUTPUT_INVALID
    assert service.list_analyses("CASE-0001") == []


def test_external_providers_need_a_stage(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    transport = FakeTransport(_openai_reply(OPINIONS))
    with pytest.raises(DomainError) as error:
        _service(root, transport).analyze("CASE-0001", "openai", allow_network=True)
    assert error.value.code is DomainErrorCode.INVALID_AI_REQUEST
    assert transport.calls == []


def test_parse_answer_rejects_bad_shapes() -> None:
    for text in (None, "[]", '{"opinions": [1]}', '{"opinions": [{"kind": "x"}]}'):
        with pytest.raises(DomainError):
            parse_answer(text)
    with pytest.raises(DomainError):
        parse_answer(
            '{"opinions": [{"kind": "next_step", "text": "t", "citations": [1]}]}'
        )


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def test_https_transport_hosts_errors_and_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for url in ("http://api.openai.com/x", "https://example.invalid/x"):
        with pytest.raises(DomainError) as error:
            https_post_json(url, {}, {})
        assert error.value.code is DomainErrorCode.AI_PROVIDER_UNAVAILABLE

    seen: list[str] = []

    def ok(request: Any, timeout: float) -> _Response:
        seen.append(request.full_url)
        return _Response(b'{"ok": true}')

    monkeypatch.setattr("urllib.request.urlopen", ok)
    assert https_post_json(
        "https://api.openai.com/v1/x", {"Authorization": SECRET}, {}
    ) == {"ok": True}

    def denied(request: Any, timeout: float) -> _Response:
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            SECRET,
            Message(),
            io.BytesIO(SECRET.encode()),
        )

    monkeypatch.setattr("urllib.request.urlopen", denied)
    with pytest.raises(DomainError) as error:
        https_post_json("https://api.openai.com/v1/x", {"Authorization": SECRET}, {})
    assert str(error.value) == "provider returned HTTP 401"
    assert error.value.__cause__ is None and SECRET not in str(error.value)

    monkeypatch.setattr(
        "urllib.request.urlopen", lambda r, timeout: _Response(b"x" * (2 << 20))
    )
    with pytest.raises(DomainError) as error:
        https_post_json("https://api.openai.com/v1/x", {}, {})
    assert "too large" in str(error.value)


def test_cli_end_to_end_with_patched_urlopen(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = root / "workbench.toml"
    config.write_text("[ai]\nallow_network = true\n", encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    hosts: list[str] = []

    def fake(request: Any, timeout: float) -> _Response:
        hosts.append(request.host)
        return _Response(json.dumps(_openai_reply(OPINIONS)).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake)
    args = [
        "--config",
        str(config),
        "ai",
        "analyze",
        "CASE-0001",
        "--stage",
        "collection",
    ]
    assert main([*args, "--provider", "openai"]) == 2
    assert "--allow-network" in capsys.readouterr().err and hosts == []
    assert main([*args, "--provider", "openai", "--allow-network"]) == 0
    out = capsys.readouterr().out
    assert "provider: openai" in out and SECRET not in out
    assert hosts == ["api.openai.com"]
    assert main(["--config", str(config), "ai", "providers"]) == 0
    listing = capsys.readouterr().out
    assert "openai\tgpt-5-mini\tenabled (external: needs --allow-network)" in listing
    assert "DEEPSEEK_API_KEY is not set" in listing
