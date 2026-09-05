from __future__ import annotations

from pathlib import Path

from quantumguard import Purpose, audit

ROOT = Path(__file__).resolve().parents[1]


def test_vulnerable_demo_has_required_workflow() -> None:
    result = audit(ROOT / "examples" / "vulnerable-app")
    observed = {(item.algorithm, item.purpose) for item in result.findings}
    assert ("RSA", Purpose.SIGNATURE) in observed
    assert ("X25519", Purpose.KEY_ESTABLISHMENT) in observed
    assert any(item.algorithm == "TLS" for item in result.findings)
    assert result.migration_plans
    assert result.agility["overall_score"] < 60


def test_pqc_demo_is_partial_and_keeps_legacy_visible() -> None:
    result = audit(ROOT / "examples" / "pqc-aware")
    observed = {(item.algorithm, item.purpose) for item in result.findings}
    assert ("ML-KEM", Purpose.KEY_ESTABLISHMENT) in observed
    assert ("ML-DSA", Purpose.SIGNATURE) in observed
    assert ("X25519", Purpose.KEY_ESTABLISHMENT) in observed
