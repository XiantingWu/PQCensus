from __future__ import annotations

from pathlib import Path

from quantumguard.analyzers.base import AnalyzerContext
from quantumguard.analyzers.textual import ExperimentalTextAnalyzer
from quantumguard.models import Confidence, Purpose

ROOT = Path(__file__).resolve().parents[1]


def _scan(tmp_path: Path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return ExperimentalTextAnalyzer().analyze(
        path,
        source,
        AnalyzerContext(root=tmp_path, rules_root=ROOT),
    )


def test_unsupported_extension_is_not_claimed(tmp_path: Path) -> None:
    assert _scan(tmp_path, "notes.txt", "RSA X25519 ML-KEM") == []


def test_line_comments_are_removed_before_token_matching(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "app.go",
        "// RSA.Encrypt should not count\nvar group = X25519\n",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.algorithm == "X25519"
    assert finding.purpose is Purpose.KEY_ESTABLISHMENT
    assert finding.confidence is Confidence.LOW
    assert finding.analyzer == "experimental-text"
    assert finding.span.start_line == 2


def test_experimental_analyzer_reports_at_most_one_pattern_per_line(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "app.ts", "const choice = 'ES256 X25519';\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "ECDSA"
    assert findings[0].purpose is Purpose.SIGNATURE


def test_pqc_tokens_are_low_confidence_observations_not_deployment_claims(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "crypto.rs", "let kem = ML_KEM;\nlet sig = ML-DSA;\n")
    assert [(item.algorithm, item.purpose) for item in findings] == [
        ("ML-KEM", Purpose.KEY_ESTABLISHMENT),
        ("ML-DSA", Purpose.SIGNATURE),
    ]
    assert all(item.confidence is Confidence.LOW for item in findings)
    assert all("semantic resolution is not yet claimed" in item.rationale for item in findings)
