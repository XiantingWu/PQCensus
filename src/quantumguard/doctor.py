from __future__ import annotations

import ast
import json
import platform
import shutil
import ssl
import sys
from pathlib import Path
from typing import Any

from ._version import __version__
from .policy import load_rules

PRODUCT_NAME = "PQCensus"


def run_doctor(*, strict: bool = False) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(
        _check("python", sys.version_info >= (3, 11), platform.python_version(), required=True)
    )
    checks.append(_check("python_ast", hasattr(ast, "parse"), "stdlib ast", required=True))
    rules_ok, rules_detail = _rules_check()
    checks.append(_check("rule_database", rules_ok, rules_detail, required=True))
    schemas_ok, schemas_detail = _schema_resource_check()
    checks.append(_check("schema_resources", schemas_ok, schemas_detail, required=True))
    git = shutil.which("git")
    checks.append(_check("git", bool(git), git or "not found", required=False))
    checks.append(
        _check(
            "network_tls",
            hasattr(ssl, "create_default_context"),
            "stdlib bounded TLS inspector",
            required=False,
            strict_required=False,
        )
    )
    checks.append(_optional_module_check("jsonschema"))
    checks.append(_optional_module_check("cyclonedx"))
    failed_required = [item for item in checks if item["required"] and not item["ok"]]
    failed_strict = [item for item in checks if item["strict_required"] and not item["ok"]]
    ok = not failed_required and (not strict or not failed_strict)
    return {
        "schema_version": 1,
        "tool": {"name": PRODUCT_NAME, "version": __version__},
        "strict": strict,
        "ok": ok,
        "checks": checks,
    }


def _check(
    name: str,
    ok: bool,
    detail: str,
    *,
    required: bool,
    strict_required: bool | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "ok": ok,
        "required": required,
        "strict_required": required if strict_required is None else strict_required,
        "detail": detail,
    }


def _optional_module_check(name: str) -> dict[str, Any]:
    try:
        __import__(name)
    except ImportError:
        return _check(
            name,
            False,
            "optional development validator is not installed",
            required=False,
            strict_required=False,
        )
    return _check(
        name,
        True,
        "optional development validator available",
        required=False,
        strict_required=False,
    )


def _rules_check() -> tuple[bool, str]:
    try:
        payload = load_rules()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return False, str(exc)
    required = {"schema_version", "policy_version", "profiles", "authorities", "rules"}
    if payload.get("schema_version") != 1 or not required.issubset(payload):
        return False, "rule database has an unsupported shape"
    rule_ids = [item.get("id") for item in payload.get("rules", []) if isinstance(item, dict)]
    if not rule_ids or len(rule_ids) != len(set(rule_ids)):
        return False, "rule IDs are empty or duplicated"
    authorities = payload.get("authorities", {})
    for rule in payload.get("rules", []):
        if any(item not in authorities for item in rule.get("authority_ids", [])):
            return False, f"rule {rule.get('id')} references an unknown authority"
        if not all(
            field in rule
            for field in ("effective_version", "deprecated", "profiles", "interpretation")
        ):
            return False, f"rule {rule.get('id')} lacks required provenance fields"
    for authority_id, authority in authorities.items():
        if not all(
            field in authority
            for field in ("publisher", "status", "kind", "url", "version", "publication_date")
        ):
            return False, f"authority {authority_id} lacks required provenance fields"
    return True, f"{len(rule_ids)} rules; {len(authorities)} authorities"


def _schema_resource_check() -> tuple[bool, str]:
    root = Path(__file__).resolve().parents[2]
    schema_root = root / "schemas"
    if schema_root.is_dir():
        count = len(list(schema_root.glob("*.schema.json")))
        return (count >= 5, f"{count} source schemas")
    try:
        from importlib.resources import files

        resource = files("quantumguard").joinpath("data", "schemas")
        names = [item.name for item in resource.iterdir() if item.name.endswith(".schema.json")]
        return (len(names) >= 5, f"{len(names)} packaged schemas")
    except (FileNotFoundError, TypeError):
        return False, "schema resources not found"
