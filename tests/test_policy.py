from __future__ import annotations

from pathlib import Path

from quantumguard.models import Purpose, Severity
from quantumguard.policy import (
    algorithm_status,
    default_severity,
    explain_rule,
    load_rules,
    matching_rule,
    references_for,
    rule_index,
    targets_for,
)

ROOT = Path(__file__).resolve().parents[1]


def test_rule_index_has_unique_stable_ids() -> None:
    rules = load_rules(ROOT)["rules"]
    index = rule_index(ROOT)
    assert len(index) == len(rules)
    assert set(index) == {item["id"] for item in rules}
    assert all(item["status"] == "stable" for item in rules)
    assert all(item["effective_version"] == "0.1.0" for item in rules)


def test_algorithm_aliases_resolve_to_purpose_specific_rules() -> None:
    assert matching_rule("RS256", Purpose.SIGNATURE, ROOT)["id"] == "QG-RSA-SIGNATURE"
    assert matching_rule("PS512", Purpose.SIGNATURE, ROOT)["id"] == "QG-RSA-SIGNATURE"
    assert matching_rule("ES256", Purpose.SIGNATURE, ROOT)["id"] == "QG-ECDSA-SIGNATURE"
    assert matching_rule("Ed25519", Purpose.SIGNATURE, ROOT)["id"] == "QG-EDDSA-SIGNATURE"
    assert matching_rule("DH", Purpose.KEY_ESTABLISHMENT, ROOT)["id"] == "QG-DH-KEY-ESTABLISHMENT"
    assert matching_rule("X448", Purpose.KEY_ESTABLISHMENT, ROOT)["id"] == (
        "QG-X448-KEY-ESTABLISHMENT"
    )
    assert matching_rule("sha256", Purpose.HASHING, ROOT)["id"] == "QG-SYMMETRIC-HASH"


def test_unknown_purpose_uses_abstention_rule_and_never_gets_target() -> None:
    rule = matching_rule("RSA", Purpose.UNKNOWN, ROOT)
    assert rule is not None
    assert rule["id"] == "QG-UNKNOWN-CRYPTO"
    assert targets_for("RSA", Purpose.UNKNOWN, ROOT) == []
    assert references_for("RSA", Purpose.UNKNOWN, ROOT) == ["QG.ENGINEERING"]


def test_algorithm_status_and_default_severity_are_conservative() -> None:
    assert algorithm_status("RSA") == "shor-vulnerable"
    assert algorithm_status("X448") == "shor-vulnerable"
    assert algorithm_status("ML-KEM") == "pqc-standard"
    assert algorithm_status("HMAC") == "not-shor-target"
    assert algorithm_status("custom-crypto") == "unknown"
    assert default_severity("RSA", Purpose.KEY_ESTABLISHMENT) is Severity.CRITICAL
    assert default_severity("RSA", Purpose.SIGNATURE) is Severity.HIGH
    assert default_severity("RSA", Purpose.SIGNATURE, test_only=True) is Severity.MEDIUM
    assert default_severity("ML-KEM", Purpose.KEY_ESTABLISHMENT) is Severity.INFO
    assert default_severity("custom-crypto", Purpose.UNKNOWN) is Severity.LOW


def test_explain_rule_returns_none_for_unknown_id() -> None:
    assert explain_rule("QG-RSA-SIGNATURE", ROOT)["algorithm_family"] == "RSA"
    assert explain_rule("QG-NOT-A-RULE", ROOT) is None
