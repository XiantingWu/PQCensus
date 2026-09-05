from __future__ import annotations

from pathlib import Path

from quantumguard import Purpose, audit


def test_signature_and_key_establishment_never_cross_map(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import jwt
from cryptography.hazmat.primitives.asymmetric import x25519

jwt.encode({"sub": "1"}, "key", algorithm="RS256")
x25519.X25519PrivateKey.generate()
""",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    by_purpose = {plan.purpose: plan for plan in result.migration_plans}
    assert by_purpose[Purpose.SIGNATURE].recommended_targets == ["ML-DSA", "SLH-DSA"]
    assert "ML-KEM" not in by_purpose[Purpose.SIGNATURE].recommended_targets
    assert by_purpose[Purpose.KEY_ESTABLISHMENT].recommended_targets == ["ML-KEM"]
    assert "ML-DSA" not in by_purpose[Purpose.KEY_ESTABLISHMENT].recommended_targets


def test_unknown_purpose_abstains(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
""",
        encoding="utf-8",
    )
    plan = audit(tmp_path).migration_plans[0]
    assert plan.purpose == Purpose.UNKNOWN
    assert plan.recommended_targets == []
    assert plan.confidence.value == "UNKNOWN"
    assert plan.unresolved_unknowns


def test_finite_field_dh_maps_to_ml_kem(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from cryptography.hazmat.primitives.asymmetric import dh
dh.generate_parameters(generator=2, key_size=2048)
""",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    assert result.findings[0].severity.value == "HIGH"
    assert result.migration_plans[0].recommended_targets == ["ML-KEM"]
