from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from quantumguard import audit
from quantumguard.models import canonical_json
from quantumguard.reporting import (
    cbom_document,
    cyclonedx_cbom_document,
    inventory_document,
    migration_document,
    sarif_document,
)

ROOT = Path(__file__).resolve().parents[1]


def test_outputs_are_deterministic_and_schema_valid(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'import jwt\njwt.encode({"sub": "1"}, "key", algorithm="RS256")\n',
        encoding="utf-8",
    )
    first = audit(tmp_path)
    second = audit(tmp_path)
    assert canonical_json(first.to_dict()) == canonical_json(second.to_dict())

    documents = (
        (first.to_dict(), "audit.schema.json"),
        (inventory_document(first), "inventory.schema.json"),
        (cbom_document(first), "cbom.schema.json"),
    )
    for payload, schema_name in documents:
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(payload)

    migration_schema = json.loads(
        (ROOT / "schemas" / "migration-plan.schema.json").read_text(encoding="utf-8")
    )
    for plan in migration_document(first)["plans"]:
        jsonschema.Draft202012Validator(migration_schema).validate(plan)

    sarif = sarif_document(first)
    assert sarif["version"] == "2.1.0"
    assert (
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
        == 2
    )

    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    cyclonedx = cyclonedx_cbom_document(first)
    assert (
        JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(cyclonedx, sort_keys=True))
        is None
    )
    assert canonical_json(cyclonedx) == canonical_json(cyclonedx_cbom_document(second))
