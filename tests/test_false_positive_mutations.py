from __future__ import annotations

from pathlib import Path

import pytest

from quantumguard import Purpose, audit


@pytest.mark.parametrize(
    "source",
    [
        "# import jwt\n# jwt.encode({}, 'key', algorithm='RS256')\n",
        "message = \"jwt.encode({}, 'key', algorithm='RS256')\"\n",
        ("import jwt as tokens\ntokens = object()\ntokens.encode({}, 'key', algorithm='RS256')\n"),
        (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "if False:\n"
            "    rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        ),
        ("import hashlib\nwhile False:\n    hashlib.sha256(b'dead')\n"),
        (
            "import jwt\n"
            "if True:\n"
            "    value = 1\n"
            "else:\n"
            "    jwt.encode({}, 'key', algorithm='RS256')\n"
        ),
    ],
)
def test_mutations_that_remove_runtime_crypto_use_do_not_create_findings(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    assert audit(tmp_path).findings == []


def test_import_alias_and_wrapper_mutations_preserve_real_detection(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import jwt as tokens\n"
        "def wrapper(payload, key):\n"
        "    return tokens.encode(payload, key, algorithm='PS256')\n",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.algorithm == "RSA"
    assert finding.purpose is Purpose.SIGNATURE
    assert finding.symbol == "wrapper"
