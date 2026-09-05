from __future__ import annotations

from pathlib import Path

import pqcensus


def _typed_consumer(root: Path) -> pqcensus.AuditResult:
    result: pqcensus.AuditResult = pqcensus.audit(root)
    return result


def test_public_namespace_exposes_typed_audit_result(tmp_path: Path) -> None:
    result = _typed_consumer(tmp_path)
    assert isinstance(result, pqcensus.AuditResult)
