"""External language-model providers for the staged opinions (ADR-031).

OpenAI and DeepSeek share the Chat Completions wire format; Gemini uses
``generateContent``. All three are called with the standard library over
HTTPS, only to fixed hosts, with an API key read from the environment at call
time. Nothing here decides *whether* a call may happen: the service allows it
only when the configuration and the command both permit network use.

The provider receives exactly the stored digest (scope ``structural`` or
``structural+findings``) and must answer with JSON that matches the stage's
schema. Its answer is untrusted: it is parsed here and then validated fail
closed by ``ai.domain.validate_output`` like every other provider's output.
Keys, request bodies and response bodies never appear in error messages.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from loader_detection_workbench.ai.digest import serialize_digest
from loader_detection_workbench.ai.domain import (
    STAGE_KINDS,
    TITLED_KINDS,
    AnalysisStage,
    ProviderOutput,
    ProviderSuggestion,
    SuggestionKind,
)
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

ALLOWED_HOSTS = frozenset(
    {"api.openai.com", "api.deepseek.com", "generativelanguage.googleapis.com"}
)
KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "gemini": "GEMINI_API_KEY",
}
TIMEOUT_SECONDS = 120
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_OPINIONS = 12

# A transport posts JSON to an HTTPS URL and returns the decoded JSON reply.
Transport = Callable[[str, Mapping[str, str], Mapping[str, Any]], Any]

SYSTEM_PROMPT = """\
You assist a malware analyst who works in a local detection workbench. You get a
JSON digest of one analysis Case: structural facts only (process image names and
activity counts, file extensions, PE structure and import names, Sysmon event
counts) and, in the synthesis stage, the analyst's own confirmed findings.

Rules:
- Use only the digest. Do not assume facts it does not contain.
- Every opinion must cite Workbench IDs that appear in the digest: Artifact IDs
  (ART-NNNNNN) and, in the synthesis stage, finding IDs (FND-NNNN).
- You give opinions for a person to check. Do not state that something is or is
  not malicious as a fact, and do not name a malware family unless the digest
  shows it.
- Never include URLs, links, commands to run or instructions to execute code.
- Write plain English. Keep each text under 1200 characters and each title under
  150 characters. Return at most 12 opinions.
- Answer only with JSON matching the given schema.
"""

STAGE_INSTRUCTIONS = {
    AnalysisStage.COLLECTION: """\
Stage: collection (evidence is still being gathered). Return opinions of these kinds:
- hypothesis_candidate: a hypothesis the evidence could support. Needs a title,
  a text and at least 1 citation. expected_benign may name benign software that
  shows the same behavior.
- evidence_link: why two or more cited items belong together. At least 2
  citations. title is null.
- next_step: one more analysis that would confirm or weaken something, and why.
  At least 1 citation. title is null.
""",
    AnalysisStage.SYNTHESIS: """\
Stage: synthesis (the analyst has confirmed findings). Return opinions of these kinds:
- key_hypothesis: a main hypothesis with the confirmed findings that support it.
  Needs a title, a text and at least 1 citation (prefer FND IDs).
- mechanism: how the observed behavior fits together, step by step, as far as
  the confirmed findings show it. At least 1 citation. title is null.
""",
}


def _kinds(stage: AnalysisStage) -> list[str]:
    return sorted(kind.value for kind in STAGE_KINDS[stage])


def json_schema(stage: AnalysisStage) -> dict[str, Any]:
    """JSON Schema of the answer (OpenAI strict structured outputs)."""
    nullable = {"type": ["string", "null"]}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["opinions"],
        "properties": {
            "opinions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "kind",
                        "title",
                        "text",
                        "citations",
                        "expected_benign",
                    ],
                    "properties": {
                        "kind": {"type": "string", "enum": _kinds(stage)},
                        "title": nullable,
                        "text": {"type": "string"},
                        "citations": {"type": "array", "items": {"type": "string"}},
                        "expected_benign": nullable,
                    },
                },
            }
        },
    }


def gemini_schema(stage: AnalysisStage) -> dict[str, Any]:
    """The same shape in Gemini's OpenAPI subset."""
    text = {"type": "STRING"}
    nullable = {"type": "STRING", "nullable": True}
    return {
        "type": "OBJECT",
        "required": ["opinions"],
        "properties": {
            "opinions": {
                "type": "ARRAY",
                "items": {
                    "type": "OBJECT",
                    "required": ["kind", "text", "citations"],
                    "properties": {
                        "kind": {"type": "STRING", "enum": _kinds(stage)},
                        "title": nullable,
                        "text": text,
                        "citations": {"type": "ARRAY", "items": text},
                        "expected_benign": nullable,
                    },
                },
            }
        },
    }


def stage_of(digest: Mapping[str, Any]) -> AnalysisStage:
    value = digest.get("stage")
    if value not in (AnalysisStage.COLLECTION.value, AnalysisStage.SYNTHESIS.value):
        raise DomainError(
            DomainErrorCode.INVALID_AI_REQUEST,
            "external providers answer staged requests only; use --stage",
        )
    return AnalysisStage(value)


def user_prompt(digest: Mapping[str, Any]) -> str:
    stage = stage_of(digest)
    return (
        STAGE_INSTRUCTIONS[stage]
        + "\nDigest (JSON):\n"
        + serialize_digest(dict(digest))
    )


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.AI_OUTPUT_INVALID, message)


def _optional(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid("provider answer has a non-text field")
    return value.strip() or None


def parse_answer(text: object) -> ProviderOutput:
    """Turn the provider's JSON text into suggestions; shape errors fail closed."""
    if not isinstance(text, str):
        raise _invalid("provider answer is not text")
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise _invalid("provider answer is not valid JSON") from exc
    opinions = document.get("opinions") if isinstance(document, dict) else None
    if not isinstance(opinions, list) or not opinions:
        raise _invalid("provider answer has no opinions")
    suggestions: list[ProviderSuggestion] = []
    for item in opinions[:MAX_OPINIONS]:
        if not isinstance(item, dict):
            raise _invalid("provider opinion is not an object")
        try:
            kind = SuggestionKind(str(item.get("kind")))
        except ValueError as exc:
            raise _invalid("provider opinion has an unknown kind") from exc
        citations = item.get("citations")
        if not isinstance(citations, list) or not all(
            isinstance(value, str) for value in citations
        ):
            raise _invalid("provider opinion citations must be a list of IDs")
        titled = kind in TITLED_KINDS
        suggestions.append(
            ProviderSuggestion(
                kind,
                str(item.get("text", "")),
                # Optional fields a kind does not use are dropped, not trusted.
                _optional(item.get("title")) if titled else None,
                tuple(value.strip() for value in citations),
                _optional(item.get("expected_benign")) if titled else None,
            )
        )
    return ProviderOutput(tuple(suggestions))


def https_post_json(
    url: str, headers: Mapping[str, str], body: Mapping[str, Any]
) -> Any:
    """POST JSON to an allowed HTTPS host; errors never carry key or payload."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise DomainError(
            DomainErrorCode.AI_PROVIDER_UNAVAILABLE, "provider host is not allowed"
        )
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise DomainError(
            DomainErrorCode.AI_PROVIDER_FAILED,
            f"provider returned HTTP {exc.code}",
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise DomainError(
            DomainErrorCode.AI_PROVIDER_FAILED, "provider could not be reached"
        ) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise DomainError(
            DomainErrorCode.AI_PROVIDER_FAILED, "provider response is too large"
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise DomainError(
            DomainErrorCode.AI_PROVIDER_FAILED, "provider response is not JSON"
        ) from None


def api_key(provider: str) -> str | None:
    value = os.environ.get(KEY_ENV[provider], "").strip()
    return value or None


def _require_key(provider: str) -> str:
    key = api_key(provider)
    if key is None:
        raise DomainError(
            DomainErrorCode.AI_PROVIDER_UNAVAILABLE,
            f"{KEY_ENV[provider]} is not set",
        )
    return key


class ChatCompletionsProvider:
    """OpenAI and DeepSeek (OpenAI-compatible) Chat Completions."""

    requires_network = True

    def __init__(
        self,
        name: str,
        model: str,
        url: str,
        *,
        strict_schema: bool,
        transport: Transport = https_post_json,
    ) -> None:
        self.name = name
        self.model = model
        self._url = url
        self._strict = strict_schema
        self._transport = transport

    def analyze(self, digest: Mapping[str, Any]) -> ProviderOutput:
        stage = stage_of(digest)
        prompt = user_prompt(digest)
        key = _require_key(self.name)
        response_format: dict[str, Any] = (
            {
                "type": "json_schema",
                "json_schema": {
                    "name": f"workbench_{stage.value}",
                    "strict": True,
                    "schema": json_schema(stage),
                },
            }
            if self._strict
            # DeepSeek JSON mode: the schema travels in the prompt instead.
            else {"type": "json_object"}
        )
        system = SYSTEM_PROMPT
        if not self._strict:
            system += "\nJSON schema:\n" + json.dumps(json_schema(stage))
        reply = self._transport(
            self._url,
            {"Authorization": f"Bearer {key}"},
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "response_format": response_format,
            },
        )
        try:
            content = reply["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise _invalid("provider reply has no message content") from exc
        return parse_answer(content)


class GeminiProvider:
    """Google Gemini ``generateContent`` with a response schema."""

    name = "gemini"
    requires_network = True

    def __init__(self, model: str, *, transport: Transport = https_post_json) -> None:
        self.model = model
        self._transport = transport

    def analyze(self, digest: Mapping[str, Any]) -> ProviderOutput:
        stage = stage_of(digest)
        prompt = user_prompt(digest)
        key = _require_key(self.name)
        reply = self._transport(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent",
            {"x-goog-api-key": key},
            {
                "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "responseSchema": gemini_schema(stage),
                    "temperature": 0.2,
                },
            },
        )
        try:
            parts = reply["candidates"][0]["content"]["parts"]
            content = "".join(str(part.get("text", "")) for part in parts)
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise _invalid("provider reply has no candidate content") from exc
        return parse_answer(content)


def external_providers(
    models: Mapping[str, str], transport: Transport = https_post_json
) -> dict[str, Any]:
    """The three approved providers, keyed by name (ADR-031)."""
    return {
        "openai": ChatCompletionsProvider(
            "openai",
            models["openai"],
            "https://api.openai.com/v1/chat/completions",
            strict_schema=True,
            transport=transport,
        ),
        "deepseek": ChatCompletionsProvider(
            "deepseek",
            models["deepseek"],
            "https://api.deepseek.com/chat/completions",
            strict_schema=False,
            transport=transport,
        ),
        "gemini": GeminiProvider(models["gemini"], transport=transport),
    }
