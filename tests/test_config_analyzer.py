from __future__ import annotations

from pathlib import Path

from quantumguard.analyzers.base import AnalyzerContext
from quantumguard.analyzers.config import ConfigAnalyzer
from quantumguard.models import Purpose, Severity

ROOT = Path(__file__).resolve().parents[1]


def _analyze(tmp_path: Path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return ConfigAnalyzer().analyze(
        path,
        source,
        AnalyzerContext(root=tmp_path, rules_root=ROOT),
    )


def test_json_flattens_nested_values_and_ignores_uninteresting_keys(tmp_path: Path) -> None:
    findings = _analyze(
        tmp_path,
        "security.json",
        '{"auth":{"signature_algorithm":"RS256"},"key_exchange":"X25519","note":"RSA"}',
    )
    observed = {(item.algorithm, item.purpose, item.symbol) for item in findings}
    assert observed == {
        ("RSA", Purpose.SIGNATURE, "signature_algorithm"),
        ("X25519", Purpose.KEY_ESTABLISHMENT, "key_exchange"),
    }
    assert all(item.analyzer == "structured-config" for item in findings)


def test_toml_list_and_yaml_scalar_are_supported(tmp_path: Path) -> None:
    toml = _analyze(
        tmp_path,
        "crypto.toml",
        'algorithms = ["ML-KEM-768", "ML-DSA-65"]\n',
    )
    yaml = _analyze(tmp_path, "crypto.yaml", "signature_algorithm: ES256\n")
    assert [(item.algorithm, item.purpose) for item in toml] == [
        ("ML-KEM", Purpose.KEY_ESTABLISHMENT),
        ("ML-DSA", Purpose.SIGNATURE),
    ]
    assert [(item.algorithm, item.purpose) for item in yaml] == [("ECDSA", Purpose.SIGNATURE)]


def test_invalid_structured_data_fails_closed_without_parser_noise(tmp_path: Path) -> None:
    assert _analyze(tmp_path, "broken.json", "{not json") == []
    assert _analyze(tmp_path, "broken.toml", "value = [") == []


def test_unknown_rsa_context_abstains_from_migration_target(tmp_path: Path) -> None:
    finding = _analyze(tmp_path, "crypto.json", '{"algorithm":"RSA"}')[0]
    assert finding.purpose is Purpose.UNKNOWN
    assert finding.rule_id == "QG-UNKNOWN-CRYPTO"
    assert finding.migration_target == []


def test_test_config_is_downgraded_and_line_number_is_preserved(tmp_path: Path) -> None:
    finding = _analyze(
        tmp_path,
        "tests/security.yaml",
        "other: value\nkey_exchange: RSA\n",
    )[0]
    assert finding.environment == "test"
    assert finding.severity is Severity.MEDIUM
    assert finding.span.start_line == 2
