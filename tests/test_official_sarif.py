from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from quantumguard import audit
from quantumguard.reporting import sarif_document

ROOT = Path(__file__).resolve().parents[1]


def _validator():
    path = ROOT / "scripts" / "validate_sarif.py"
    spec = importlib.util.spec_from_file_location("validate_sarif", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pinned_official_sarif_schema_validates_real_output() -> None:
    if os.environ.get("QUANTUMGUARD_NETWORK_TESTS") != "1":
        pytest.skip("set QUANTUMGUARD_NETWORK_TESTS=1 for pinned official SARIF validation")
    validator = _validator()
    schema = validator.fetch_schema()
    payload = sarif_document(audit(ROOT / "examples" / "vulnerable-app"))
    assert validator.validation_errors(payload, schema) == []
