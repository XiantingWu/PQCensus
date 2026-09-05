from __future__ import annotations

from quantumguard.models import (
    AuditResult,
    Confidence,
    CryptoAsset,
    Dependency,
    Evidence,
    Finding,
    MigrationPlan,
    Purpose,
    Severity,
    SourceSpan,
)
from quantumguard.reporting import (
    COMPAT_NAMESPACE,
    cbom_document,
    cyclonedx_cbom_document,
    inventory_document,
    markdown_report,
    migration_document,
    sarif_document,
)


def _result(*, active: bool = True) -> AuditResult:
    span = SourceSpan(3, 4, 3, 20)
    finding = Finding(
        finding_id="QG-reporting-test",
        rule_id="QG-RSA-SIGNATURE",
        category="cryptographic-use",
        algorithm="RSA",
        purpose=Purpose.SIGNATURE,
        source_path="app.py",
        span=span,
        symbol="sign",
        evidence=[Evidence("ast_call", "RSA signing call")],
        confidence=Confidence.HIGH,
        quantum_risk="shor-vulnerable",
        severity=Severity.HIGH,
        rationale="RSA signature migration signal.",
        migration_target=["ML-DSA"],
        migration_confidence=Confidence.HIGH,
        references=["NIST.FIPS.204"],
        suppressible=True,
        analyzer="python-ast",
        status="active" if active else "suppressed",
    )
    asset = CryptoAsset(
        asset_id="asset-1",
        asset_type="algorithm",
        name="RSA signature",
        algorithm="RSA",
        purpose=Purpose.SIGNATURE,
        source_path="app.py",
        span=span,
        dependency="cryptography",
        quantum_status="shor-vulnerable",
        provenance=["python-ast"],
        confidence=Confidence.HIGH,
    )
    plan = MigrationPlan(
        plan_id="plan-1",
        finding_id=finding.finding_id,
        source_path="app.py",
        purpose=Purpose.SIGNATURE,
        current_primitive="RSA",
        recommended_targets=["ML-DSA"],
        target_class="signature",
        compatibility_constraints=[],
        required_abstraction_changes=[],
        deployment_ordering=[],
        rollback_considerations=[],
        verification_steps=[],
        urgency="high",
        confidence=Confidence.HIGH,
        unresolved_unknowns=[],
        references=["NIST.FIPS.204"],
    )
    return AuditResult(
        repository="example",
        files_analyzed=1,
        bytes_analyzed=42,
        parser_errors=[],
        findings=[finding],
        assets=[asset],
        dependencies=[Dependency("cryptography", "45.0.0", "pyproject.toml", "python")],
        migration_plans=[plan],
        agility={"overall_score": 50},
        hndl={"status": "UNKNOWN"},
        suppressions=[],
        limits={},
        generated_by="0.1.0",
    )


def test_inventory_and_migration_documents_are_content_addressed() -> None:
    result = _result()
    inventory = inventory_document(result)
    migration = migration_document(result)
    assert inventory["tool"] == {"name": "PQCensus", "version": "0.1.0"}
    assert len(inventory["content_sha256"]) == 64
    assert len(migration["content_sha256"]) == 64
    assert migration["plans"][0]["recommended_targets"] == ["ML-DSA"]


def test_legacy_cbom_namespace_is_an_explicit_0_1_x_contract() -> None:
    document = cbom_document(_result())
    assert document["format"] == "QuantumGuard-CBOM"
    assert document["producer"]["name"] == "PQCensus"
    assert COMPAT_NAMESPACE == "quantumguard"


def test_cyclonedx_document_uses_public_producer_with_legacy_machine_namespace() -> None:
    document = cyclonedx_cbom_document(_result())
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert document["metadata"]["properties"][0] == {
        "name": "pqcensus:producer",
        "value": "PQCensus",
    }
    refs = {component["bom-ref"] for component in document["components"]}
    assert any(ref.startswith("urn:quantumguard:dependency:") for ref in refs)
    assert any(ref.startswith("urn:quantumguard:crypto-asset:") for ref in refs)


def test_sarif_uses_public_identity_and_filters_suppressed_findings() -> None:
    active = sarif_document(_result(active=True))
    driver = active["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PQCensus"
    assert driver["informationUri"] == "https://github.com/XiantingWu/PQCensus"
    assert active["runs"][0]["results"][0]["level"] == "error"
    assert active["runs"][0]["results"][0]["partialFingerprints"] == {
        "quantumguardFindingId": "QG-reporting-test"
    }

    suppressed = sarif_document(_result(active=False))
    assert suppressed["runs"][0]["results"] == []
    assert suppressed["runs"][0]["tool"]["driver"]["rules"] == []


def test_markdown_report_handles_active_and_empty_finding_sets() -> None:
    active = markdown_report(_result(active=True))
    assert "# PQCensus audit: example" in active
    assert "HIGH: RSA / SIGNATURE" in active
    assert "app.py:3" in active

    suppressed = markdown_report(_result(active=False))
    assert "No active findings were verified" in suppressed
