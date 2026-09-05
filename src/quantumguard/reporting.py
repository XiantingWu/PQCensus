from __future__ import annotations

import hashlib
import uuid
from typing import Any

from .models import PRODUCT_NAME, AuditResult, canonical_sha256
from .policy import load_rules

# Machine-readable 0.1.x compatibility namespaces intentionally retain the
# historical `quantumguard` prefix. Human-facing producer identity is PQCensus.
COMPAT_NAMESPACE = "quantumguard"
PROJECT_URL = "https://github.com/XiantingWu/PQCensus"


def inventory_document(result: AuditResult) -> dict[str, Any]:
    assets = [item.to_dict() for item in result.assets]
    dependencies = [item.to_dict() for item in result.dependencies]
    return {
        "schema_version": 1,
        "tool": {"name": PRODUCT_NAME, "version": result.generated_by},
        "repository": result.repository,
        "assets": assets,
        "dependencies": dependencies,
        "content_sha256": canonical_sha256({"assets": assets, "dependencies": dependencies}),
    }


def migration_document(result: AuditResult) -> dict[str, Any]:
    plans = [item.to_dict() for item in result.migration_plans]
    return {
        "schema_version": 1,
        "tool": {"name": PRODUCT_NAME, "version": result.generated_by},
        "repository": result.repository,
        "plans": plans,
        "content_sha256": canonical_sha256(plans),
    }


def cbom_document(result: AuditResult) -> dict[str, Any]:
    components = []
    for asset in result.assets:
        components.append(
            {
                "type": asset.asset_type,
                "name": asset.name,
                "algorithm": asset.algorithm,
                "purpose": asset.purpose.value,
                "quantum_status": asset.quantum_status,
                "source": asset.to_dict()["source"],
                "provenance": asset.provenance,
                "confidence": asset.confidence.value,
            }
        )
    components.sort(key=lambda item: (str(item["type"]), str(item["name"]), str(item["source"])))
    return {
        "schema_version": 1,
        "format": "QuantumGuard-CBOM",  # 0.1.x compatibility contract
        "producer": {"name": PRODUCT_NAME, "version": result.generated_by},
        "cyclonedx_compatibility": "not-claimed",
        "application": {"name": result.repository, "type": "application"},
        "components": components,
        "dependencies": [item.to_dict() for item in result.dependencies],
        "content_sha256": canonical_sha256(components),
    }


def cyclonedx_cbom_document(result: AuditResult) -> dict[str, Any]:
    inventory_hash = inventory_document(result)["content_sha256"]
    application_ref = (
        f"urn:{COMPAT_NAMESPACE}:application:"
        + hashlib.sha256(result.repository.encode("utf-8")).hexdigest()[:20]
    )
    components: list[dict[str, Any]] = []
    component_refs: list[str] = []
    dependency_refs: dict[str, str] = {}
    for dependency in result.dependencies:
        material = (
            f"{dependency.ecosystem}|{dependency.name}|{dependency.version}|{dependency.manifest}"
        )
        bom_ref = (
            f"urn:{COMPAT_NAMESPACE}:dependency:"
            + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        )
        dependency_refs[dependency.name.lower()] = bom_ref
        component = {
            "bom-ref": bom_ref,
            "type": "library",
            "name": dependency.name,
            "properties": [
                {"name": f"{COMPAT_NAMESPACE}:ecosystem", "value": dependency.ecosystem},
                {"name": f"{COMPAT_NAMESPACE}:manifest", "value": dependency.manifest},
                {"name": f"{COMPAT_NAMESPACE}:direct", "value": str(dependency.direct).lower()},
            ],
        }
        if dependency.version:
            component["version"] = dependency.version
        components.append(component)
        component_refs.append(bom_ref)

    asset_dependencies: dict[str, list[str]] = {}
    for asset in result.assets:
        if not asset.algorithm:
            continue
        bom_ref = f"urn:{COMPAT_NAMESPACE}:crypto-asset:" + asset.asset_id
        component_refs.append(bom_ref)
        properties = [
            {"name": f"{COMPAT_NAMESPACE}:asset-id", "value": asset.asset_id},
            {"name": f"{COMPAT_NAMESPACE}:purpose", "value": asset.purpose.value},
            {"name": f"{COMPAT_NAMESPACE}:quantum-status", "value": asset.quantum_status},
            {"name": f"{COMPAT_NAMESPACE}:confidence", "value": asset.confidence.value},
            {"name": f"{COMPAT_NAMESPACE}:provenance", "value": ",".join(asset.provenance)},
        ]
        if asset.source_path:
            properties.append(
                {"name": f"{COMPAT_NAMESPACE}:source-path", "value": asset.source_path}
            )
        if asset.span:
            properties.append(
                {"name": f"{COMPAT_NAMESPACE}:source-line", "value": str(asset.span.start_line)}
            )
        components.append(
            {
                "bom-ref": bom_ref,
                "type": "cryptographic-asset",
                "name": asset.name,
                "cryptoProperties": _cyclonedx_crypto_properties(
                    asset.algorithm, asset.purpose.value
                ),
                "properties": properties,
            }
        )
        if asset.dependency and asset.dependency.lower() in dependency_refs:
            asset_dependencies.setdefault(dependency_refs[asset.dependency.lower()], []).append(
                bom_ref
            )

    components.sort(key=lambda item: item["bom-ref"])
    dependencies = [{"ref": application_ref, "dependsOn": sorted(component_refs)}]
    dependencies.extend(
        {"ref": ref, "dependsOn": sorted(children)}
        for ref, children in sorted(asset_dependencies.items())
    )
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL, f"{COMPAT_NAMESPACE}:{result.repository}:{inventory_hash}"
    )
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": application_ref,
                "type": "application",
                "name": result.repository,
                "version": result.generated_by,
            },
            "properties": [
                {"name": "pqcensus:producer", "value": PRODUCT_NAME},
                {"name": f"{COMPAT_NAMESPACE}:inventory-sha256", "value": str(inventory_hash)},
                {"name": f"{COMPAT_NAMESPACE}:source-stays-local", "value": "true"},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }


def sarif_document(result: AuditResult) -> dict[str, Any]:
    rules = load_rules()
    rule_map = {item["id"]: item for item in rules["rules"]}
    used = sorted({item.rule_id for item in result.findings if item.status == "active"})
    sarif_rules = []
    for rule_id in used:
        rule = rule_map.get(rule_id, {})
        sarif_rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {
                    "text": str(rule.get("recommendation") or "Cryptographic finding")
                },
                "helpUri": _first_authority_url(rule, rules),
                "properties": {
                    "tags": ["security", "post-quantum", str(rule.get("category") or "crypto")]
                },
            }
        )
    results = []
    for finding in result.findings:
        if finding.status != "active":
            continue
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity.value),
                "message": {
                    "text": f"{finding.rationale} Next action: "
                    + (
                        f"assess {', '.join(finding.migration_target)}"
                        if finding.migration_target
                        else "resolve the unknown usage context before selecting a migration target"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.source_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.span.start_line,
                                "startColumn": finding.span.start_column + 1,
                                **(
                                    {"endLine": finding.span.end_line}
                                    if finding.span.end_line
                                    else {}
                                ),
                                **(
                                    {"endColumn": finding.span.end_column + 1}
                                    if finding.span.end_column is not None
                                    else {}
                                ),
                            },
                        },
                        "logicalLocations": ([{"name": finding.symbol}] if finding.symbol else []),
                    }
                ],
                # Keep the key stable so existing code-scanning baselines do not churn.
                "partialFingerprints": {"quantumguardFindingId": finding.finding_id},
                "properties": {
                    "algorithm": finding.algorithm,
                    "purpose": finding.purpose.value,
                    "confidence": finding.confidence.value,
                    "quantumRisk": finding.quantum_risk,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": PRODUCT_NAME,
                        "version": result.generated_by,
                        "informationUri": PROJECT_URL,
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def markdown_report(result: AuditResult) -> str:
    active = [item for item in result.findings if item.status == "active"]
    lines = [
        f"# {PRODUCT_NAME} audit: {result.repository}",
        "",
        f"- Files analyzed: {result.files_analyzed}",
        f"- Crypto assets: {len(result.assets)}",
        f"- Active findings: {len(active)}",
        f"- Suppressed findings: {len(result.findings) - len(active)}",
        f"- Crypto agility: {result.agility['overall_score']}/100",
        f"- HNDL: {result.hndl['status']}",
        "",
        "## Findings",
        "",
    ]
    if not active:
        lines.append("No active findings were verified by the supported analyzers.")
    for finding in active:
        lines.extend(
            [
                f"### {finding.severity.value}: {finding.algorithm} / {finding.purpose.value}",
                "",
                f"{finding.source_path}:{finding.span.start_line} · {finding.rule_id} · confidence {finding.confidence.value}",
                "",
                finding.rationale,
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }[severity]


def _cyclonedx_crypto_properties(algorithm: str, purpose: str) -> dict[str, Any]:
    if algorithm == "TLS":
        return {"assetType": "protocol", "protocolProperties": {"type": "tls"}}
    primitive = {
        "SIGNATURE": "signature",
        "HASHING": "hash",
        "MAC": "mac",
        "KDF": "kdf",
    }.get(purpose)
    if primitive is None:
        if algorithm == "ML-KEM":
            primitive = "kem"
        elif algorithm == "RSA" and purpose in {"ENCRYPTION", "KEY_ESTABLISHMENT"}:
            primitive = "pke"
        elif purpose == "KEY_ESTABLISHMENT":
            primitive = "key-agree"
        else:
            primitive = "unknown"
    family = {
        "RSA": None,
        "ECDSA": "ECDSA",
        "ECDH": "ECDH",
        "X25519": "ECDH",
        "X448": "ECDH",
        "EdDSA": "EdDSA",
        "finite-field DH": "FFDH",
        "ML-KEM": "ML-KEM",
        "ML-DSA": "ML-DSA",
        "SLH-DSA": "SLH-DSA",
        "SHA-2/SHA-3": "SHA-2",
        "HMAC": "HMAC",
    }.get(algorithm)
    functions = {
        "SIGNATURE": ["sign", "verify"],
        "ENCRYPTION": ["encrypt", "decrypt"],
        "HASHING": ["digest"],
        "MAC": ["tag"],
        "KDF": ["keyderive"],
    }.get(purpose)
    if functions is None:
        functions = ["encapsulate", "decapsulate"] if algorithm == "ML-KEM" else ["other"]
    algorithm_properties: dict[str, Any] = {
        "primitive": primitive,
        "cryptoFunctions": functions,
    }
    if family:
        algorithm_properties["algorithmFamily"] = family
    if algorithm == "X25519":
        algorithm_properties["ellipticCurve"] = "other/Curve25519"
    elif algorithm == "X448":
        algorithm_properties["ellipticCurve"] = "other/Curve448"
    return {"assetType": "algorithm", "algorithmProperties": algorithm_properties}


def _first_authority_url(rule: dict[str, Any], rules: dict[str, Any]) -> str:
    for authority_id in rule.get("authority_ids", []):
        authority = rules.get("authorities", {}).get(authority_id, {})
        if authority.get("url"):
            return str(authority["url"])
    return f"{PROJECT_URL}/tree/main/docs"
