from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

FINDING_SCHEMA_VERSION = 1
INVENTORY_SCHEMA_VERSION = 1
CBOM_SCHEMA_VERSION = 1
MIGRATION_SCHEMA_VERSION = 1
PRODUCT_NAME = "PQCensus"


class Purpose(StrEnum):
    SIGNATURE = "SIGNATURE"
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    ENCRYPTION = "ENCRYPTION"
    HASHING = "HASHING"
    MAC = "MAC"
    KDF = "KDF"
    CERTIFICATE = "CERTIFICATE"
    UNKNOWN = "UNKNOWN"


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SourceSpan:
    start_line: int
    start_column: int
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, int]:
        result: dict[str, int] = {
            "start_line": self.start_line,
            "start_column": self.start_column,
        }
        if self.end_line is not None:
            result["end_line"] = self.end_line
        if self.end_column is not None:
            result["end_column"] = self.end_column
        return result


@dataclass(frozen=True)
class Evidence:
    evidence_type: str
    detail: str
    snippet_sha256: str | None = None
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.evidence_type,
            "detail": self.detail,
        }
        if self.snippet_sha256:
            result["snippet_sha256"] = self.snippet_sha256
        if self.references:
            result["references"] = list(self.references)
        return result


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    category: str
    algorithm: str
    purpose: Purpose
    source_path: str
    span: SourceSpan
    symbol: str | None
    evidence: list[Evidence]
    confidence: Confidence
    quantum_risk: str
    severity: Severity
    rationale: str
    migration_target: list[str]
    migration_confidence: Confidence
    references: list[str]
    suppressible: bool
    analyzer: str
    environment: str = "production"
    status: str = "active"
    suppression: dict[str, Any] | None = None

    @staticmethod
    def stable_id(
        rule_id: str,
        source_path: str,
        span: SourceSpan,
        algorithm: str,
        purpose: Purpose,
        evidence_detail: str,
    ) -> str:
        material = "|".join(
            (
                rule_id,
                source_path,
                str(span.start_line),
                str(span.start_column),
                algorithm,
                purpose.value,
                evidence_detail,
            )
        )
        return "QG-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "category": self.category,
            "algorithm": self.algorithm,
            "purpose": self.purpose.value,
            "source": {
                "path": self.source_path,
                "span": self.span.to_dict(),
                "symbol": self.symbol,
            },
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence.value,
            "quantum_risk": self.quantum_risk,
            "severity": self.severity.value,
            "rationale": self.rationale,
            "migration_target": self.migration_target,
            "migration_confidence": self.migration_confidence.value,
            "references": self.references,
            "suppressible": self.suppressible,
            "analyzer": self.analyzer,
            "environment": self.environment,
            "status": self.status,
            "suppression": self.suppression,
        }


@dataclass
class CryptoAsset:
    asset_id: str
    asset_type: str
    name: str
    algorithm: str | None
    purpose: Purpose
    source_path: str | None
    span: SourceSpan | None
    dependency: str | None
    quantum_status: str
    provenance: list[str]
    confidence: Confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "name": self.name,
            "algorithm": self.algorithm,
            "purpose": self.purpose.value,
            "source": (
                {"path": self.source_path, "span": self.span.to_dict()}
                if self.source_path and self.span
                else {"path": self.source_path}
            ),
            "dependency": self.dependency,
            "quantum_status": self.quantum_status,
            "provenance": self.provenance,
            "confidence": self.confidence.value,
        }


@dataclass
class MigrationPlan:
    plan_id: str
    finding_id: str
    source_path: str
    purpose: Purpose
    current_primitive: str
    recommended_targets: list[str]
    target_class: str
    compatibility_constraints: list[str]
    required_abstraction_changes: list[str]
    deployment_ordering: list[str]
    rollback_considerations: list[str]
    verification_steps: list[str]
    urgency: str
    confidence: Confidence
    unresolved_unknowns: list[str]
    references: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MIGRATION_SCHEMA_VERSION,
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "affected_call_sites": [{"path": self.source_path}],
            "purpose": self.purpose.value,
            "current_primitive": self.current_primitive,
            "recommended_targets": self.recommended_targets,
            "target_class": self.target_class,
            "compatibility_constraints": self.compatibility_constraints,
            "required_abstraction_changes": self.required_abstraction_changes,
            "deployment_ordering": self.deployment_ordering,
            "rollback_considerations": self.rollback_considerations,
            "verification_steps": self.verification_steps,
            "urgency": self.urgency,
            "confidence": self.confidence.value,
            "unresolved_unknowns": self.unresolved_unknowns,
            "references": self.references,
        }


@dataclass
class Dependency:
    name: str
    version: str | None
    manifest: str
    ecosystem: str
    direct: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "manifest": self.manifest,
            "ecosystem": self.ecosystem,
            "direct": self.direct,
        }


@dataclass
class AuditResult:
    repository: str
    files_analyzed: int
    bytes_analyzed: int
    parser_errors: list[dict[str, str]]
    findings: list[Finding]
    assets: list[CryptoAsset]
    dependencies: list[Dependency]
    migration_plans: list[MigrationPlan]
    agility: dict[str, Any]
    hndl: dict[str, Any]
    suppressions: list[dict[str, Any]]
    limits: dict[str, Any]
    generated_by: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "tool": {"name": PRODUCT_NAME, "version": self.generated_by},
            "repository": self.repository,
            "summary": {
                "files_analyzed": self.files_analyzed,
                "bytes_analyzed": self.bytes_analyzed,
                "findings": len(self.findings),
                "active_findings": sum(item.status == "active" for item in self.findings),
                "suppressed_findings": sum(item.status == "suppressed" for item in self.findings),
                "crypto_assets": len(self.assets),
                "dependencies": len(self.dependencies),
            },
            "parser_errors": self.parser_errors,
            "findings": [item.to_dict() for item in self.findings],
            "inventory": [item.to_dict() for item in self.assets],
            "dependencies": [item.to_dict() for item in self.dependencies],
            "migration_plans": [item.to_dict() for item in self.migration_plans],
            "crypto_agility": self.agility,
            "hndl": self.hndl,
            "suppressions": self.suppressions,
            "limits": self.limits,
        }


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
