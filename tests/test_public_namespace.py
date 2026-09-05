from __future__ import annotations

import pqcensus
import quantumguard


def test_public_namespace_matches_compatibility_api() -> None:
    assert pqcensus.__version__ == quantumguard.__version__ == "0.1.0"
    assert pqcensus.audit is quantumguard.audit
    assert pqcensus.inventory is quantumguard.inventory
    assert pqcensus.plan is quantumguard.plan
    assert pqcensus.AuditResult is quantumguard.AuditResult
    assert pqcensus.Finding is quantumguard.Finding


def test_public_namespace_exports_versioned_api() -> None:
    expected = {
        "AuditResult",
        "Confidence",
        "Finding",
        "MigrationPlan",
        "Purpose",
        "Severity",
        "__version__",
        "audit",
        "inventory",
        "plan",
    }
    assert set(pqcensus.__all__) == expected
