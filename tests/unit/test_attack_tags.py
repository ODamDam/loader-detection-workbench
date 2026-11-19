"""ATT&CK tags of Sigma rules are shown in reports (normalised, filtered)."""

from __future__ import annotations

from datetime import UTC, datetime

from loader_detection_workbench.detection.domain import (
    DetectionRule,
    RuleFormat,
    RuleVersion,
    RuleVersionStatus,
)
from loader_detection_workbench.detection.sigma_engine import attack_tags
from loader_detection_workbench.report.render import attack_summary

SIGMA = """title: Demo
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\demo.exe'
  condition: selection
tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.persistence
  - attack.T1053.005
  - attack.not_a_tactic
  - attack.t12
  - cve.2024-0001
  - attack.defense_evasion
"""


def _rule(fmt: RuleFormat, content: str) -> tuple[DetectionRule, RuleVersion]:
    now = datetime(2026, 11, 19, tzinfo=UTC)
    version = RuleVersion(
        "RULE-0001", 1, content, "0" * 64, RuleVersionStatus.FROZEN, now, now, None
    )
    return DetectionRule("RULE-0001", "demo", fmt, now, (version,)), version


def test_known_tactics_and_technique_ids_only() -> None:
    tags = attack_tags(SIGMA)
    assert tags.tactics == ("defense-evasion", "persistence")
    assert tags.techniques == ("T1574.002", "T1053.005")


def test_unparseable_or_untagged_content_gives_no_tags() -> None:
    assert attack_tags("::: not yaml [").is_empty
    assert attack_tags(SIGMA.split("tags:")[0]).is_empty


def test_report_summary_for_sigma_and_none_for_yara() -> None:
    assert attack_summary(*_rule(RuleFormat.SIGMA, SIGMA)) == (
        "tactics defense-evasion, persistence; techniques T1574.002, T1053.005"
    )
    assert attack_summary(*_rule(RuleFormat.SIGMA, SIGMA.split("tags:")[0])) == (
        "none tagged"
    )
    assert attack_summary(*_rule(RuleFormat.YARA, "rule x { condition: true }")) is None
