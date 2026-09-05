from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from quantumguard.policy import load_rules

ROOT = Path(__file__).resolve().parents[1]


def test_rule_schema_and_authority_provenance() -> None:
    rules = load_rules(ROOT)
    schema = json.loads((ROOT / "rules" / "schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(rules)
    authorities = rules["authorities"]
    for rule in rules["rules"]:
        assert rule["interpretation"]
        assert rule["profiles"]
        assert all(authority_id in authorities for authority_id in rule["authority_ids"])
    assert authorities["NIST.IR.8547.IPD"]["status"] == "draft"
    assert authorities["NIST.FIPS.203"]["status"] == "final"
    assert authorities["NIST.SP.800-227"]["status"] == "final"
    assert authorities["QG.ENGINEERING"]["kind"] == "engineering-interpretation"
    unknown = next(rule for rule in rules["rules"] if rule["id"] == "QG-UNKNOWN-CRYPTO")
    assert unknown["migration_targets"] == []
