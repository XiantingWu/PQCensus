from __future__ import annotations

from quantumguard.models import Confidence, Evidence, Finding, Purpose, Severity, SourceSpan
from quantumguard.risk import RiskContext, assess_finding


def _finding(
    *,
    algorithm: str = "RSA",
    purpose: Purpose = Purpose.SIGNATURE,
    confidence: Confidence = Confidence.HIGH,
    environment: str = "production",
) -> Finding:
    return Finding(
        finding_id="QG-test",
        rule_id="QG-RSA-SIGNATURE",
        category="cryptographic-use",
        algorithm=algorithm,
        purpose=purpose,
        source_path="app.py",
        span=SourceSpan(1, 0, 1, 10),
        symbol="example",
        evidence=[Evidence("ast_call", "algorithm RSA")],
        confidence=confidence,
        quantum_risk="shor-vulnerable",
        severity=Severity.HIGH,
        rationale="initial",
        migration_target=["ML-DSA"],
        migration_confidence=Confidence.HIGH,
        references=[],
        suppressible=True,
        analyzer="python-ast",
        environment=environment,
    )


def test_non_shor_finding_is_not_rescored() -> None:
    finding = _finding(algorithm="HMAC", purpose=Purpose.MAC)
    original = (finding.severity, finding.rationale)
    assert assess_finding(finding) is finding
    assert (finding.severity, finding.rationale) == original


def test_public_long_lived_confidentiality_can_be_critical() -> None:
    finding = _finding(purpose=Purpose.KEY_ESTABLISHMENT)
    assessed = assess_finding(
        finding,
        RiskContext(
            exposure="public",
            data_lifetime_years=10,
            public_reachability="public",
            hndl_relevant=True,
        ),
    )
    assert assessed.severity is Severity.CRITICAL
    assert "harvest-now-decrypt-later" in assessed.rationale
    assert "at least 10 years" in assessed.rationale


def test_unknown_low_confidence_test_code_is_conservatively_lowered() -> None:
    finding = _finding(
        purpose=Purpose.UNKNOWN,
        confidence=Confidence.LOW,
        environment="test",
    )
    assessed = assess_finding(finding)
    assert assessed.severity is Severity.LOW
    assert "downstream purpose is not verified" in assessed.rationale
    assert "test or fixture code" in assessed.rationale
    assert "low evidence confidence" in assessed.rationale


def test_signature_context_is_high_without_extra_exposure() -> None:
    finding = assess_finding(_finding(purpose=Purpose.SIGNATURE), RiskContext())
    assert finding.severity is Severity.HIGH
    assert "anchors authenticity or signatures" in finding.rationale
