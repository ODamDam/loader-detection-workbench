"""Korean reading aids for stored AI suggestions (ADR-033).

A translation is a convenience for the analyst, not evidence: the stored
English suggestion stays the source for comparison, adoption and reports.
The only text sent is the suggestion's own title and text (model output that
was produced from the approved structural digest), keyed by sequence number.

The provider's answer is untrusted and checked fail closed: every requested
sequence must come back exactly once, every Workbench ID of the original must
survive, and links, executable instructions and control characters are
refused. Nothing in a translation is ever parsed as an ID or a reference.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from loader_detection_workbench.ai.domain import Suggestion
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

LANGUAGE = "ko"
MAX_TRANSLATED_TEXT = 4000
MAX_TRANSLATED_TITLE = 400
# Workbench display IDs that must appear unchanged in a translation.
_IDS = re.compile(
    r"\b(?:ART-[0-9]{6,}|FND-[0-9]{4,}|SMP-[0-9]{6,}|RULE-[0-9]{4,}"
    r"|CASE-[0-9]{4,}|HYP-[0-9]{4,}|AIA-[0-9]{4,}|VMR-[0-9]{4,}|BMK-[0-9]{4,})\b",
    re.ASCII,
)
_LINK = re.compile(r"(?i)\b(?:https?|ftp|file)://|\bwww\.[a-z0-9-]+\.")
_INSTRUCTION = re.compile(
    r"(?i)\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-(?:c|e|enc|command)\b)"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SYSTEM_PROMPT = """\
You translate short English analysis notes into natural Korean for a malware
analyst. Translate meaning faithfully; do not add, drop or soften claims.
Keep unchanged: Workbench IDs (ART-000001, FND-0001, RULE-0001 and similar),
file names, API names, registry and file paths, hashes and numbers. Do not add
links or instructions. Answer only with JSON:
{"items": [{"sequence": <int>, "title": <string or null>, "text": <string>}]}
with exactly one item per input item and the same sequence numbers.
"""


@dataclass(frozen=True, slots=True)
class TranslationRequest:
    items: tuple[dict[str, Any], ...]

    @property
    def json(self) -> str:
        return json.dumps(
            {"items": list(self.items)}, ensure_ascii=False, sort_keys=True
        )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.json.encode("utf-8")).hexdigest()


def translation_request(suggestions: Sequence[Suggestion]) -> TranslationRequest:
    """Only sequence, title and text of each suggestion; nothing else is sent."""
    return TranslationRequest(
        tuple(
            {"sequence": item.sequence, "title": item.title, "text": item.text}
            for item in suggestions
        )
    )


def _invalid(message: str) -> DomainError:
    return DomainError(DomainErrorCode.AI_OUTPUT_INVALID, message)


def _clean(value: object, limit: int, label: str) -> str:
    if not isinstance(value, str):
        raise _invalid(f"translated {label} is not text")
    text = value.strip()
    if not text or len(text) > limit:
        raise _invalid(f"translated {label} is empty or too long")
    if _CONTROL.search(text) or _LINK.search(text) or _INSTRUCTION.search(text):
        raise _invalid(f"translated {label} has refused content")
    return text


def parse_translation(
    answer: object, suggestions: Sequence[Suggestion]
) -> tuple[tuple[int, str | None, str], ...]:
    """Validate a provider answer against the suggestions it translates."""
    if not isinstance(answer, str):
        raise _invalid("translation answer is not text")
    try:
        document = json.loads(answer)
    except ValueError as exc:
        raise _invalid("translation answer is not valid JSON") from exc
    items = document.get("items") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise _invalid("translation answer has no items")
    by_sequence = {item.sequence: item for item in suggestions}
    seen: dict[int, tuple[int, str | None, str]] = {}
    for item in items:
        if not isinstance(item, dict) or type(item.get("sequence")) is not int:
            raise _invalid("translation item has no sequence")
        sequence = int(item["sequence"])
        original = by_sequence.get(sequence)
        if original is None or sequence in seen:
            raise _invalid("translation item sequence is unknown or repeated")
        text = _clean(item.get("text"), MAX_TRANSLATED_TEXT, "text")
        title: str | None = None
        if original.title is not None:
            title = _clean(item.get("title"), MAX_TRANSLATED_TITLE, "title")
        for source, translated in ((original.text, text), (original.title, title)):
            missing = set(_IDS.findall(source or "")) - set(
                _IDS.findall(translated or "")
            )
            if missing:
                raise _invalid("translation dropped or changed a Workbench ID")
        seen[sequence] = (sequence, title, text)
    if set(seen) != set(by_sequence):
        raise _invalid("translation answer does not cover every suggestion")
    return tuple(seen[key] for key in sorted(seen))
