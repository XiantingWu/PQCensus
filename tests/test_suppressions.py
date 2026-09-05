from __future__ import annotations

from pathlib import Path

from quantumguard import audit


def test_inline_suppression_requires_reason_and_is_audited(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import jwt
# quantumguard: ignore QG-RSA-SIGNATURE reason=legacy test vector expires=2099-01-01
jwt.encode({"sub": "1"}, "key", algorithm="RS256")
""",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    assert result.findings[0].status == "suppressed"
    assert result.suppressions[0]["reason"] == "legacy test vector"


def test_config_suppression_is_path_scoped(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'import jwt\njwt.encode({"sub": "1"}, "key", algorithm="RS256")\n',
        encoding="utf-8",
    )
    (tmp_path / "quantumguard.toml").write_text(
        """
[[suppressions]]
rule_id = "QG-RSA-SIGNATURE"
path = "app.py"
reason = "tracked migration exception"
""",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    assert result.findings[0].status == "suppressed"


def test_config_suppression_accepts_documented_rule_alias(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'import jwt\njwt.encode({"sub": "1"}, "key", algorithm="RS256")\n',
        encoding="utf-8",
    )
    (tmp_path / "quantumguard.toml").write_text(
        """
[[suppressions]]
rule = "QG-RSA-SIGNATURE"
path = "app.py"
reason = "documented compatibility key"
""",
        encoding="utf-8",
    )
    result = audit(tmp_path)
    assert result.findings[0].status == "suppressed"
    assert result.suppressions[0]["rule_id"] == "QG-RSA-SIGNATURE"
