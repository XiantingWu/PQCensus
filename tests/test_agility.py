from __future__ import annotations

from quantumguard.agility import evaluate_agility
from quantumguard.models import (
    Confidence,
    Dependency,
    Evidence,
    Finding,
    Purpose,
    Severity,
    SourceSpan,
)


def _finding(*, analyzer: str, detail: str) -> Finding:
    return Finding(
        finding_id=f"QG-{analyzer}",
        rule_id="QG-RSA-SIGNATURE",
        category="cryptographic-use",
        algorithm="RSA",
        purpose=Purpose.SIGNATURE,
        source_path="app.py",
        span=SourceSpan(1, 0, 1, 1),
        symbol=None,
        evidence=[
            Evidence("ast_call" if analyzer == "python-ast" else "structured_config", detail)
        ],
        confidence=Confidence.HIGH,
        quantum_risk="shor-vulnerable",
        severity=Severity.HIGH,
        rationale="test",
        migration_target=["ML-DSA"],
        migration_confidence=Confidence.HIGH,
        references=[],
        suppressible=True,
        analyzer=analyzer,
    )


def test_agility_scores_observable_controls_without_claiming_absence() -> None:
    result = evaluate_agility(
        [
            _finding(analyzer="python-ast", detail="algorithm RSA"),
            _finding(analyzer="structured-config", detail="structured config algorithm=RSA"),
        ],
        [Dependency("cryptography", "45.0.0", "pyproject.toml", "python")],
        [
            (
                "security/crypto_provider.py",
                "hybrid negotiate supported_algorithms dual_verify rotate_key rotate_certificate",
            ),
            ("quantumguard.toml", "algorithm_preference = ['ML-KEM', 'X25519']"),
        ],
    )
    components = result["components"]
    assert result["schema_version"] == 1
    assert result["scale"] == "0-100"
    assert components["provider_centralization"]["score"] == 85
    assert components["negotiation"]["score"] == 80
    assert components["dual_algorithm_support"]["score"] == 80
    assert components["key_rotation"]["score"] == 75
    assert components["certificate_rotation"]["score"] == 75
    assert components["dependency_constraints"]["score"] == 70
    assert components["policy_centralization"]["score"] == 80
    assert "absence of a static signal is not proof" in result["method"]
    assert "declared engineering scale" in result["method"]
    assert "not a normalized population percentile" in result["method"]
    assert "not an externally calibrated maturity score" in result["method"]


def test_agility_baseline_is_neutral_when_no_crypto_signals_exist() -> None:
    result = evaluate_agility([], [], [("main.py", "print('hello')")])
    components = result["components"]
    assert components["algorithm_selection"]["score"] == 50
    assert components["dependency_constraints"]["score"] == 50
    assert components["provider_centralization"]["score"] == 30
    assert components["negotiation"]["score"] == 25
    assert components["dual_algorithm_support"]["score"] == 20


def test_unpinned_crypto_dependency_reduces_constraint_score() -> None:
    result = evaluate_agility(
        [],
        [Dependency("pyjwt", "latest", "requirements.txt", "python")],
        [],
    )
    component = result["components"]["dependency_constraints"]
    assert component["score"] == 40
    assert component["evidence"] == ["crypto_dependencies=1", "version_constrained=0"]


def test_java_framework_names_do_not_count_as_crypto_dependencies() -> None:
    result = evaluate_agility(
        [],
        [Dependency("spring-core", "6.1.0", "pom.xml", "maven")],
        [],
    )
    component = result["components"]["dependency_constraints"]
    assert component["score"] == 50
    assert component["evidence"] == ["crypto_dependencies=0", "version_constrained=0"]


def test_prose_signals_outside_code_and_config_paths_are_ignored() -> None:
    result = evaluate_agility(
        [],
        [],
        [
            ("README.md", "we will negotiate hybrid support in a future roadmap"),
            ("docs/design.md", "dual_sign and rotate_key are planned"),
        ],
    )
    assert result["components"]["negotiation"]["score"] == 25
    assert result["components"]["dual_algorithm_support"]["score"] == 20
    assert result["components"]["key_rotation"]["score"] == 30


def test_algorithm_selection_scoring_paths_are_pinned() -> None:
    configured = evaluate_agility(
        [_finding(analyzer="structured-config", detail="structured config algorithm=RSA")],
        [],
        [],
    )["components"]["algorithm_selection"]
    assert configured["score"] == 70

    mixed = evaluate_agility(
        [
            _finding(analyzer="python-ast", detail="RSA signing call"),
            _finding(analyzer="structured-config", detail="structured config algorithm=RSA"),
        ],
        [],
        [],
    )["components"]["algorithm_selection"]
    assert mixed["score"] == 45

    hard_coded = evaluate_agility(
        [_finding(analyzer="python-ast", detail="RSA signing call")],
        [],
        [],
    )["components"]["algorithm_selection"]
    assert hard_coded["score"] == 20


def test_hard_coded_evidence_no_longer_depends_on_prose_wording() -> None:
    result = evaluate_agility(
        [_finding(analyzer="python-ast", detail="RSA signature context")],
        [],
        [],
    )["components"]["algorithm_selection"]
    assert result["score"] == 20
    assert result["evidence"] == ["hard_coded_evidence=1", "configured_evidence=0"]


def test_overall_score_snapshot_is_stable() -> None:
    result = evaluate_agility(
        [_finding(analyzer="python-ast", detail="RSA signing call")],
        [Dependency("cryptography", "45.0.0", "pyproject.toml", "python")],
        [("app.py", "rotate_key dual_sign negotiate hybrid")],
    )
    assert result["overall_score"] == 51


def test_declared_scale_bounds_hold_for_observed_scoring_paths() -> None:
    cases = [
        evaluate_agility([], [], []),
        evaluate_agility(
            [_finding(analyzer="python-ast", detail="RSA signing call")],
            [Dependency("cryptography", "45.0.0", "pyproject.toml", "python")],
            [("security/crypto_provider.py", "hybrid negotiate rotate_key")],
        ),
        evaluate_agility(
            [
                _finding(analyzer="python-ast", detail="RSA signing call"),
                _finding(analyzer="structured-config", detail="algorithm=RSA"),
            ],
            [Dependency("pyjwt", "latest", "requirements.txt", "python")],
            [("app.py", "legacy_fallback")],
        ),
    ]
    for result in cases:
        assert 0 <= result["overall_score"] <= 100
        assert all(0 <= component["score"] <= 100 for component in result["components"].values())
