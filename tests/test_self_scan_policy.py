from __future__ import annotations

from pathlib import Path

from quantumguard.api import audit
from quantumguard.suppression import load_config_suppressions

REPO_ROOT = Path(__file__).resolve().parents[1]
SELF_SCAN_ROOT = REPO_ROOT / "src"


def test_self_scan_suppression_policy_is_narrow_and_reviewable() -> None:
    suppressions = load_config_suppressions(SELF_SCAN_ROOT)

    assert len(suppressions) == 9
    for item in suppressions:
        assert item.rule_id.startswith("QG-")
        assert item.rule_id != "ALL"
        assert item.reason.strip()
        assert item.expires == "2027-08-31"
        assert item.path is not None
        assert item.path.startswith("quantumguard/")
        assert "*" not in item.path
        assert "?" not in item.path


def test_repository_production_self_scan_has_no_active_findings() -> None:
    result = audit(SELF_SCAN_ROOT)

    active = [finding for finding in result.findings if finding.status == "active"]
    assert active == []
    assert len(result.suppressions) == 12
    assert all(item["reason"] for item in result.suppressions)
