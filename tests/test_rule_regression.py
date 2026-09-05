from __future__ import annotations

import json
from pathlib import Path

import pytest

from quantumguard import audit
from quantumguard.policy import load_rules

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads(
    (ROOT / "tests" / "fixtures" / "rule-regression.json").read_text(encoding="utf-8")
)["cases"]


def _case_id(case: dict[str, str]) -> str:
    return case["rule_id"]


def test_rule_fixture_manifest_covers_every_stable_rule_exactly_once() -> None:
    stable_rules = {
        rule["id"]: rule
        for rule in load_rules(ROOT)["rules"]
        if rule["status"] == "stable" and not rule["deprecated"]
    }
    fixture_ids = [case["rule_id"] for case in FIXTURES]
    assert len(fixture_ids) == len(set(fixture_ids))
    assert set(fixture_ids) == set(stable_rules)
    for case in FIXTURES:
        assert case["expected_severity"] == stable_rules[case["rule_id"]]["default_severity"]
        assert case["positive"].strip()
        assert case["negative"].strip()


@pytest.mark.parametrize("case", FIXTURES, ids=_case_id)
def test_each_rule_has_positive_detection_and_expected_severity(
    tmp_path: Path, case: dict[str, str]
) -> None:
    path = tmp_path / case["path"]
    path.write_text(case["positive"], encoding="utf-8")
    result = audit(tmp_path)
    matches = [finding for finding in result.findings if finding.rule_id == case["rule_id"]]
    assert matches, f"positive fixture did not trigger {case['rule_id']}"
    assert {finding.severity.value for finding in matches} == {case["expected_severity"]}


@pytest.mark.parametrize("case", FIXTURES, ids=_case_id)
def test_each_rule_has_negative_fixture_that_does_not_trigger(
    tmp_path: Path, case: dict[str, str]
) -> None:
    path = tmp_path / case["path"]
    path.write_text(case["negative"], encoding="utf-8")
    result = audit(tmp_path)
    assert case["rule_id"] not in {finding.rule_id for finding in result.findings}
