from types import MappingProxyType

import pytest

import loader_detection_workbench.detection.sigma_engine as sigma_engine
from loader_detection_workbench.domain.errors import DomainError, DomainErrorCode
from loader_detection_workbench.sysmon.records import SysmonRecord


def _record(event_id: int, **fields: str) -> SysmonRecord:
    return SysmonRecord(event_id, "1", None, MappingProxyType(fields))


def _rule(detection: str, logsource: str = "category: process_creation") -> str:
    return (
        "title: synthetic test rule\n"
        f"logsource:\n  product: windows\n  {logsource}\n"
        f"detection:\n{detection}"
    )


def test_modifiers_selectors_and_negation() -> None:
    rule = sigma_engine.compile_rule(
        _rule(
            "  sel_img:\n"
            "    Image|endswith: '\\powershell.exe'\n"
            "    CommandLine|contains|all: ['-enc', 'hidden']\n"
            "  sel_parent:\n"
            "    ParentImage|re: '(?i)winword\\.exe$'\n"
            "  filter:\n"
            "    User: 'NT AUTHORITY\\SYSTEM'\n"
            "  condition: 1 of sel_* and not filter\n"
        )
    )
    hit = _record(
        1,
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE",
        CommandLine="powershell -w hidden -enc AAAA",
        User="LAB\\analyst",
    )
    parent_only = _record(1, Image="x.exe", ParentImage="C:\\Office\\WINWORD.EXE")
    filtered = _record(
        1,
        Image="C:\\a\\powershell.exe",
        CommandLine="-enc x hidden",
        User="NT AUTHORITY\\SYSTEM",
    )
    partial = _record(1, Image="C:\\a\\powershell.exe", CommandLine="-enc only")
    wrong_event = _record(11, Image="C:\\a\\powershell.exe", CommandLine="-enc hidden")

    assert sigma_engine.matches(rule, hit)
    assert sigma_engine.matches(rule, parent_only)
    assert not sigma_engine.matches(rule, filtered)
    assert not sigma_engine.matches(rule, partial)
    assert not sigma_engine.matches(rule, wrong_event)
    assert sigma_engine.evaluate(rule, [hit, partial]) == [hit]


def test_keywords_numbers_cidr_null_and_exists() -> None:
    rule = sigma_engine.compile_rule(
        _rule(
            "  keywords:\n"
            "    - 'mimikatz'\n"
            "  net:\n"
            "    DestinationIp|cidr: 10.0.0.0/8\n"
            "    DestinationPort|gte: 4444\n"
            "  empty:\n"
            "    QueryResults: null\n"
            "  hashes:\n"
            "    Hashes|exists: true\n"
            "  condition: keywords or net or (empty and hashes)\n",
            logsource="service: sysmon",
        )
    )

    assert rule.event_ids is None
    assert sigma_engine.matches(rule, _record(1, CommandLine="run MimiKatz now"))
    assert sigma_engine.matches(
        rule, _record(3, DestinationIp="10.1.2.3", DestinationPort="4444")
    )
    assert not sigma_engine.matches(
        rule, _record(3, DestinationIp="192.0.2.1", DestinationPort="4444")
    )
    assert not sigma_engine.matches(
        rule, _record(3, DestinationIp="10.1.2.3", DestinationPort="80")
    )
    assert sigma_engine.matches(rule, _record(22, Hashes="SHA256=AA"))
    assert not sigma_engine.matches(rule, _record(22, QueryResults="x", Hashes="y"))


def test_event_id_field_and_cased_strings() -> None:
    rule = sigma_engine.compile_rule(
        _rule(
            "  sel:\n    EventID: 13\n    TargetObject|cased|contains: 'Run'\n"
            "  condition: sel\n",
            logsource="category: registry_event",
        )
    )

    assert sigma_engine.matches(rule, _record(13, TargetObject="HKCU\\...\\Run\\x"))
    assert not sigma_engine.matches(rule, _record(13, TargetObject="hkcu\\run\\x"))
    assert not sigma_engine.matches(rule, _record(12, TargetObject="\\Run\\"))


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("not: [valid", DomainErrorCode.DETECTION_RULE_COMPILE_FAILED),
        (
            _rule("  sel:\n    Image: x\n  condition: sel\n", "category: webserver"),
            DomainErrorCode.UNSUPPORTED_SIGMA_FEATURE,
        ),
        (
            "title: t\nlogsource:\n  product: linux\n  category: process_creation\n"
            "detection:\n  sel:\n    Image: x\n  condition: sel\n",
            DomainErrorCode.UNSUPPORTED_SIGMA_FEATURE,
        ),
        (
            _rule("  sel:\n    Image|fieldref: CommandLine\n  condition: sel\n"),
            DomainErrorCode.UNSUPPORTED_SIGMA_FEATURE,
        ),
    ],
)
def test_invalid_or_unsupported_rules_fail_closed(
    text: str, code: DomainErrorCode
) -> None:
    with pytest.raises(DomainError) as error:
        sigma_engine.compile_rule(text)
    assert error.value.code is code
