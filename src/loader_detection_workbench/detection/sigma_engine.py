"""Offline Sigma evaluation over field-level Sysmon records.

pySigma parses the rule and resolves the condition (selectors such as
``1 of sel_*`` and value modifiers) into a tree of field/value expressions.
This module evaluates that tree directly against each Sysmon record, so no
SIEM or backend conversion is involved. Unsupported constructs raise
``UNSUPPORTED_SIGMA_FEATURE`` instead of silently evaluating to ``False``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import version
from typing import Any

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.sysmon.records import SysmonRecord

# Sysmon Event IDs for the Sigma ``windows`` log source categories.
CATEGORY_EVENT_IDS: dict[str, frozenset[int]] = {
    "process_creation": frozenset({1}),
    "file_change": frozenset({2}),
    "network_connection": frozenset({3}),
    "sysmon_status": frozenset({4, 16}),
    "process_termination": frozenset({5}),
    "driver_load": frozenset({6}),
    "image_load": frozenset({7}),
    "create_remote_thread": frozenset({8}),
    "raw_access_thread": frozenset({9}),
    "process_access": frozenset({10}),
    "file_event": frozenset({11}),
    "registry_add": frozenset({12}),
    "registry_delete": frozenset({12}),
    "registry_set": frozenset({13}),
    "registry_rename": frozenset({14}),
    "registry_event": frozenset({12, 13, 14}),
    "create_stream_hash": frozenset({15}),
    "pipe_created": frozenset({17, 18}),
    "wmi_event": frozenset({19, 20, 21}),
    "dns_query": frozenset({22}),
    "file_delete": frozenset({23, 26}),
    "clipboard_capture": frozenset({24}),
    "process_tampering": frozenset({25}),
    "file_block": frozenset({27, 28}),
}
MAX_MATCHED_RECORDS = 20


def engine_label() -> str:
    return f"workbench-sigma-offline 1 (pySigma {version('pysigma')})"


def _unsupported(message: str) -> DomainError:
    return DomainError(DomainErrorCode.UNSUPPORTED_SIGMA_FEATURE, message)


@dataclass(frozen=True, slots=True)
class CompiledSigmaRule:
    title: str
    rule_id: str | None
    event_ids: frozenset[int] | None
    conditions: tuple[Any, ...]


def compile_rule(content: str) -> CompiledSigmaRule:
    try:
        collection = SigmaCollection.from_yaml(content)
    except SigmaError as exc:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED, f"Sigma parse error: {exc}"
        ) from exc
    except Exception as exc:  # YAML and pySigma raise several error types.
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED, "Sigma rule is malformed"
        ) from exc
    if collection.errors:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED,
            f"Sigma parse error: {collection.errors[0]}",
        )
    rules = [rule for rule in collection.rules if isinstance(rule, SigmaRule)]
    if len(rules) != 1 or len(collection.rules) != 1:
        raise DomainError(
            DomainErrorCode.INVALID_DETECTION_RULE,
            "a Sigma rule version must contain exactly one detection rule",
        )
    rule = rules[0]
    if rule.errors:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED,
            f"Sigma parse error: {rule.errors[0]}",
        )
    logsource = rule.logsource
    if logsource.product not in (None, "windows"):
        raise _unsupported("only the windows Sigma log source is supported")
    event_ids: frozenset[int] | None
    if logsource.category is not None:
        if logsource.category not in CATEGORY_EVENT_IDS:
            raise _unsupported(
                f"Sigma category is not mapped to Sysmon: {logsource.category}"
            )
        event_ids = CATEGORY_EVENT_IDS[logsource.category]
    elif logsource.service == "sysmon":
        event_ids = None
    else:
        raise _unsupported("Sigma log source must name a category or service: sysmon")
    try:
        conditions = tuple(
            condition.parse() for condition in rule.detection.parsed_condition
        )
    except SigmaError as exc:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED,
            f"Sigma condition error: {exc}",
        ) from exc
    for condition in conditions:
        _validate(condition)
    return CompiledSigmaRule(
        rule.title, None if rule.id is None else str(rule.id), event_ids, conditions
    )


def _validate(node: Any) -> None:
    if isinstance(node, ConditionAND | ConditionOR | ConditionNOT):
        for argument in node.args:
            _validate(argument)
    elif isinstance(node, ConditionFieldEqualsValueExpression):
        _validate_value(node.value)
    elif isinstance(node, ConditionValueExpression):
        if not isinstance(node.value, SigmaString | SigmaNumber):
            raise _unsupported("keyword detections must be strings or numbers")
        _validate_value(node.value)
    else:
        raise _unsupported(f"unsupported Sigma condition node: {type(node).__name__}")


_SUPPORTED_VALUES = (
    SigmaString,
    SigmaNumber,
    SigmaBool,
    SigmaNull,
    SigmaRegularExpression,
    SigmaCompareExpression,
    SigmaCIDRExpression,
    SigmaExists,
)


def _validate_value(value: Any) -> None:
    if not isinstance(value, _SUPPORTED_VALUES):
        raise _unsupported(f"unsupported Sigma value type: {type(value).__name__}")
    if isinstance(value, SigmaString):
        for part in value.s:
            if isinstance(part, SpecialChars) and part not in (
                SpecialChars.WILDCARD_MULTI,
                SpecialChars.WILDCARD_SINGLE,
            ):
                raise _unsupported("Sigma placeholders and references are unsupported")
    if isinstance(value, SigmaRegularExpression):
        _regex(value)


@lru_cache(maxsize=4096)
def _string_pattern(parts: tuple[Any, ...], cased: bool) -> re.Pattern[str]:
    text = "".join(
        ".*"
        if part is SpecialChars.WILDCARD_MULTI
        else "."
        if part is SpecialChars.WILDCARD_SINGLE
        else re.escape(str(part))
        for part in parts
    )
    return re.compile(f"\\A{text}\\Z", re.DOTALL | (0 if cased else re.IGNORECASE))


def _regex(value: SigmaRegularExpression) -> re.Pattern[str]:
    source = value.regexp
    text = (
        source.original
        if isinstance(source, SigmaString) and source.original
        else str(source)
    )
    flags = 0
    mapping = {
        SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
        SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
        SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
    }
    for flag in value.flags:
        flags |= mapping.get(flag, 0)
    try:
        return _compile_regex(text, flags)
    except re.error as exc:
        raise DomainError(
            DomainErrorCode.DETECTION_RULE_COMPILE_FAILED, f"invalid Sigma regex: {exc}"
        ) from exc


@lru_cache(maxsize=1024)
def _compile_regex(text: str, flags: int) -> re.Pattern[str]:
    return re.compile(text, flags)


def _number(text: str) -> float | None:
    try:
        return float(text.strip())
    except ValueError:
        return None


def _matches_value(value: Any, field: str | None) -> bool:
    if isinstance(value, SigmaNull):
        return field is None or field == ""
    if isinstance(value, SigmaExists):
        return (field is not None) == bool(value.exists)
    if field is None:
        return False
    if isinstance(value, SigmaString):
        return (
            _string_pattern(tuple(value.s), isinstance(value, SigmaCasedString)).match(
                field
            )
            is not None
        )
    if isinstance(value, SigmaNumber):
        number = _number(field)
        return number is not None and number == float(value.number)
    if isinstance(value, SigmaBool):
        return field.strip().lower() == str(bool(value.boolean)).lower()
    if isinstance(value, SigmaRegularExpression):
        return _regex(value).search(field) is not None
    if isinstance(value, SigmaCompareExpression):
        number = _number(field)
        if number is None:
            return False
        threshold = float(value.number.number)
        operator = value.op
        return {
            CompareOperators.LT: number < threshold,
            CompareOperators.LTE: number <= threshold,
            CompareOperators.GT: number > threshold,
            CompareOperators.GTE: number >= threshold,
        }[operator]
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(field.strip()) in value.network
        except ValueError:
            return False
    raise _unsupported(f"unsupported Sigma value type: {type(value).__name__}")


def _evaluate(node: Any, record: SysmonRecord) -> bool:
    if isinstance(node, ConditionAND):
        return all(_evaluate(argument, record) for argument in node.args)
    if isinstance(node, ConditionOR):
        return any(_evaluate(argument, record) for argument in node.args)
    if isinstance(node, ConditionNOT):
        return not _evaluate(node.args[0], record)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _matches_value(node.value, record.value(node.field))
    if isinstance(node, ConditionValueExpression):
        return any(
            _matches_value(_keyword(node.value), field)
            for field in record.all_fields().values()
        )
    raise _unsupported(f"unsupported Sigma condition node: {type(node).__name__}")


def _keyword(value: Any) -> Any:
    # Keywords match anywhere inside a field value.
    if isinstance(value, SigmaString):
        parts = list(value.s)
        if not parts or parts[0] is not SpecialChars.WILDCARD_MULTI:
            parts.insert(0, SpecialChars.WILDCARD_MULTI)
        if parts[-1] is not SpecialChars.WILDCARD_MULTI:
            parts.append(SpecialChars.WILDCARD_MULTI)
        copy = SigmaString("")
        copy.s = parts
        return copy
    return value


def matches(rule: CompiledSigmaRule, record: SysmonRecord) -> bool:
    if rule.event_ids is not None and record.event_id not in rule.event_ids:
        return False
    return any(_evaluate(condition, record) for condition in rule.conditions)


def evaluate(
    rule: CompiledSigmaRule, records: Iterable[SysmonRecord]
) -> list[SysmonRecord]:
    return [record for record in records if matches(rule, record)]
