"""Offline YARA compilation and in-memory scanning of verified Artifact bytes.

Scanning never executes or writes the scanned content. ``include`` directives
are disabled so a rule cannot read arbitrary files from the host.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import version
from typing import Any

import yara

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode

MAX_STRING_HITS = 20
SCAN_TIMEOUT_SECONDS = 60


def engine_label() -> str:
    return f"yara-python {version('yara-python')}"


@dataclass(frozen=True, slots=True)
class YaraStringHit:
    identifier: str
    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class YaraMatch:
    rule: str
    tags: tuple[str, ...]
    strings: tuple[YaraStringHit, ...]


def compile_rule(content: str) -> Any:
    try:
        return yara.compile(source=content, includes=False)
    except yara.SyntaxError as exc:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED, f"YARA syntax error: {exc}"
        ) from exc
    except yara.Error as exc:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED, f"YARA compile error: {exc}"
        ) from exc


def check_rule(content: str) -> list[str]:
    """Compile and return the rule names declared by the source."""
    compiled = compile_rule(content)
    names = [rule.identifier for rule in compiled]
    if not names:
        raise DomainError(
            DomainErrorCode.INVALID_DETECTION_RULE, "YARA source declares no rule"
        )
    return names


def scan(compiled: Any, data: bytes) -> list[YaraMatch]:
    try:
        matches = compiled.match(data=data, timeout=SCAN_TIMEOUT_SECONDS)
    except yara.TimeoutError as exc:
        raise DomainError(
            DomainErrorCode.INVALID_VALIDATION_REQUEST, "YARA scan timed out"
        ) from exc
    except yara.Error as exc:
        raise DomainError(
            DomainErrorCode.INVALID_VALIDATION_REQUEST, f"YARA scan failed: {exc}"
        ) from exc
    result: list[YaraMatch] = []
    for match in matches:
        hits: list[YaraStringHit] = []
        for string in match.strings:
            for instance in string.instances:
                if len(hits) >= MAX_STRING_HITS:
                    break
                hits.append(
                    YaraStringHit(
                        string.identifier,
                        int(instance.offset),
                        int(instance.matched_length),
                    )
                )
        result.append(YaraMatch(str(match.rule), tuple(match.tags), tuple(hits)))
    return result
