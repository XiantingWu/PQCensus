from __future__ import annotations

from pathlib import Path

from quantumguard import Purpose, audit


def _scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return audit(tmp_path)


def test_alias_jwt_x25519_and_wrapper_context(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        """
import jwt as tokens
from cryptography.hazmat.primitives.asymmetric import x25519 as x

def sign(payload, key):
    return tokens.encode(payload, key, algorithm="RS256")

def exchange():
    return x.X25519PrivateKey.generate()
""",
    )
    observed = {(item.algorithm, item.purpose, item.symbol) for item in result.findings}
    assert ("RSA", Purpose.SIGNATURE, "sign") in observed
    assert ("X25519", Purpose.KEY_ESTABLISHMENT, "exchange") in observed


def test_oaep_is_encryption_not_signature(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        """
from Crypto.Cipher import PKCS1_OAEP

def encrypt(key):
    return PKCS1_OAEP.new(key)
""",
    )
    assert [(item.algorithm, item.purpose) for item in result.findings] == [
        ("RSA", Purpose.ENCRYPTION)
    ]


def test_unused_import_comment_string_and_shadowed_alias_do_not_find(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        """
from cryptography.hazmat.primitives.asymmetric import rsa as r

# r.generate_private_key(public_exponent=65537, key_size=2048)
message = "RSA.generate and jwt.encode algorithm RS256"
r = object()
r.generate_private_key()
""",
    )
    assert result.findings == []


def test_test_path_is_classified_and_lowered(tmp_path: Path) -> None:
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_signing.py").write_text(
        """
import jwt
jwt.encode({"sub": "test"}, "key", algorithm="RS256")
""",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].environment == "test"
    assert result.findings[0].severity.value == "MEDIUM"


def test_unknown_purpose_uses_a_provenanced_abstention_rule(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
    )
    assert result.findings[0].rule_id == "QG-UNKNOWN-CRYPTO"
    assert result.findings[0].migration_target == []


def test_ecdsa_helper_conversion_is_not_a_signature(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from ecdsa.ecdsa import int_to_string\n"
        "def convert(value):\n"
        "    return int_to_string(value)\n",
    )
    assert result.findings == []


def test_negative_confidentiality_lifetime_is_rejected(tmp_path: Path) -> None:
    try:
        audit(tmp_path, confidentiality_lifetime_years=-1)
    except ValueError as exc:
        assert "zero or greater" in str(exc)
    else:
        raise AssertionError("negative lifetime was accepted")


def test_local_function_shadowing_does_not_find_hash_use(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from hashlib import sha256\ndef sha256(value):\n    return value\nsha256(b'not a hash')\n",
    )
    assert result.findings == []


def test_import_aliases_are_resolved_for_hash_constructors(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import hashlib as h\n"
        "from hashlib import sha256 as digest\n"
        "h.sha256(b'data')\n"
        "digest(b'data')\n",
    )
    assert len([item for item in result.findings if item.algorithm == "SHA-2/SHA-3"]) == 2


def test_shadowed_ssl_module_does_not_infer_a_tls_context(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "ssl = object()\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n",
    )
    assert result.findings == []


def test_dead_code_and_docstrings_do_not_create_crypto_findings(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        '"""hashlib.sha256 and jwt.encode are documentation only."""\n'
        "if False:\n"
        "    import hashlib\n"
        "    hashlib.sha256(b'dead')\n"
        "while False:\n"
        "    import jwt\n"
        "    jwt.encode({}, 'key', algorithm='RS256')\n",
    )
    assert result.findings == []


def test_ambiguous_wrapper_is_not_promoted_to_a_crypto_finding(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "def encode(payload, key, algorithm):\n"
        "    return (payload, key, algorithm)\n"
        "encode({}, 'key', algorithm='RS256')\n",
    )
    assert result.findings == []


def test_jwt_decode_headers_and_algorithm_aliases_preserve_purpose(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from jwt import decode as verify\n"
        "import jwt as tokens\n"
        "tokens.encode({}, 'key', headers={'alg': 'ES256'})\n"
        "verify('token', 'key', algorithms=['RS256'])\n",
    )
    observed = {(item.algorithm, item.purpose) for item in result.findings}
    assert observed == {
        ("ECDSA", Purpose.SIGNATURE),
        ("RSA", Purpose.SIGNATURE),
    }


def test_rsa_signature_and_oaep_encryption_are_separate(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from cryptography.hazmat.primitives.asymmetric import padding, rsa\n"
        "from cryptography.hazmat.primitives import hashes\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "key.sign(b'data', padding.PKCS1v15(), hashes.SHA256())\n"
        "key.public_key().encrypt(b'data', padding.OAEP(mgf=object(), algorithm=object(), label=None))\n",
    )
    assert ("RSA", Purpose.SIGNATURE) in {
        (item.algorithm, item.purpose) for item in result.findings
    }
    assert ("RSA", Purpose.ENCRYPTION) in {
        (item.algorithm, item.purpose) for item in result.findings
    }


def test_nested_literal_helper_does_not_duplicate_cipher_findings(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "def cipher_string(name):\n"
        "    return name\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.set_ciphers(cipher_string('TLS_RSA_WITH_AES_128_GCM_SHA256'))\n",
    )
    assert len(result.findings) == 1
    assert result.findings[0].algorithm == "TLS"


def test_ecdhe_cipher_suite_is_generic_ecdh_not_x25519_or_rsa(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.set_ciphers('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')\n",
    )
    transport = [item for item in result.findings if item.algorithm == "RSA"]
    assert transport == []
    agreement = [item for item in result.findings if item.rule_id == "QG-ECDH-KEY-ESTABLISHMENT"]
    assert len(agreement) == 1
    assert agreement[0].algorithm == "ECDH"
    assert agreement[0].purpose == Purpose.KEY_ESTABLISHMENT
    assert agreement[0].confidence.value == "MEDIUM"
    assert "concrete curve/group is not proven" in agreement[0].evidence[0].detail
    assert all(item.algorithm != "X25519" for item in result.findings)


def test_ecdhe_ciphersuites_configuration_is_also_generic_ecdh(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.set_ciphersuites('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')\n",
    )
    agreement = [item for item in result.findings if item.rule_id == "QG-ECDH-KEY-ESTABLISHMENT"]
    assert len(agreement) == 1
    assert agreement[0].algorithm == "ECDH"
    assert not any(item.algorithm == "X25519" for item in result.findings)


def test_x448_maps_to_its_distinct_key_establishment_rule(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from cryptography.hazmat.primitives.asymmetric import x448\n"
        "x448.X448PrivateKey.generate()\n",
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.algorithm == "X448"
    assert finding.rule_id == "QG-X448-KEY-ESTABLISHMENT"


def test_slh_dsa_is_detectable_in_python_source(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from pqcrypto import slhdsa\nslhdsa.sign(b'data', object())\n",
    )
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "QG-SLH-DSA"


def test_legacy_tls_protocol_constants_are_high_severity(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n",
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "QG-TLS-LEGACY-PROTOCOL"
    assert finding.severity.value == "HIGH"


def test_wrap_socket_is_legacy_and_user_defined_wrap_socket_is_not(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "sock = ssl.wrap_socket(object())\n"
        "class Client:\n"
        "    def wrap_socket(self, raw):\n"
        "        return raw\n"
        "    def connect(self):\n"
        "        return self.wrap_socket(None)\n",
    )
    rules = {item.rule_id for item in result.findings}
    assert rules == {"QG-TLS-LEGACY-PROTOCOL"}


def test_check_hostname_assignment_is_insecure_tls_finding(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\n",
    )
    insecure = [item for item in result.findings if item.rule_id == "QG-TLS-INSECURE-CONFIG"]
    assert len(insecure) == 1
    assert insecure[0].severity.value == "HIGH"
    assert insecure[0].evidence[0].evidence_type == "ast_assignment"
    assert "disables hostname verification" in insecure[0].evidence[0].detail


def test_verify_mode_cert_none_assignment_is_insecure_tls_finding(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_NONE\n",
    )
    insecure = [item for item in result.findings if item.rule_id == "QG-TLS-INSECURE-CONFIG"]
    assert len(insecure) == 1
    assert insecure[0].evidence[0].evidence_type == "ast_assignment"
    assert "disables certificate validation" in insecure[0].evidence[0].detail


def test_tls_insecure_assignments_are_independent_and_unverified_context_is_detected(
    tmp_path: Path,
) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "other = ssl._create_unverified_context()\n",
    )
    insecure = [item for item in result.findings if item.rule_id == "QG-TLS-INSECURE-CONFIG"]
    assert len(insecure) == 3
    assert sum(item.evidence[0].evidence_type == "ast_assignment" for item in insecure) == 2
    assert sum(item.evidence[0].evidence_type == "ast_call" for item in insecure) == 1


def test_safe_tls_validation_assignments_and_unrelated_object_are_not_insecure(
    tmp_path: Path,
) -> None:
    result = _scan(
        tmp_path,
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = True\n"
        "ctx.verify_mode = ssl.CERT_REQUIRED\n"
        "random_object = object()\n"
        "random_object.check_hostname = False\n"
        "random_object.verify_mode = ssl.CERT_NONE\n",
    )
    assert [item for item in result.findings if item.rule_id == "QG-TLS-INSECURE-CONFIG"] == []


def test_tls_assignment_alias_and_annotation_are_context_sensitive(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl as tls\n"
        "from ssl import SSLContext\n"
        "ctx: SSLContext = tls.SSLContext(tls.PROTOCOL_TLS_CLIENT)\n"
        "ctx.check_hostname = False\n",
    )
    insecure = [item for item in result.findings if item.rule_id == "QG-TLS-INSECURE-CONFIG"]
    assert len(insecure) == 1
    assert insecure[0].evidence[0].evidence_type == "ast_assignment"


def test_modern_version_negotiation_stays_low_severity(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import ssl\nctx = ssl.create_default_context(minimum_version=ssl.TLSVersion.TLSv1_2)\n",
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "QG-UNKNOWN-CRYPTO"
    assert finding.severity.value == "LOW"
    assert "modern version negotiation" in finding.evidence[0].detail
