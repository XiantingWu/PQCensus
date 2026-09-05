from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from .models import Purpose, Severity
from .util import normalize_algorithm


def _resource_path() -> Any:
    return files("quantumguard").joinpath("data", "quantumguard-rules.json")


def load_rules(root: Path | None = None) -> dict[str, Any]:
    candidates: list[Path] = []
    if root is not None:
        candidates.append(root / "rules" / "quantumguard-rules.json")
    candidates.append(Path(__file__).resolve().parents[2] / "rules" / "quantumguard-rules.json")
    for path in candidates:
        if path.is_file() and not path.is_symlink():
            return json.loads(path.read_text(encoding="utf-8"))
    return json.loads(_resource_path().read_text(encoding="utf-8"))


def rule_index(root: Path | None = None) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in load_rules(root).get("rules", [])}


def matching_rule(
    algorithm: str, purpose: Purpose, root: Path | None = None
) -> dict[str, Any] | None:
    normalized = normalize_algorithm(algorithm)
    fallback = None
    for rule in rule_index(root).values():
        family = normalize_algorithm(str(rule.get("algorithm_family", "")))
        if family == "*" and purpose.value in rule.get("purposes", []):
            fallback = rule
            continue
        aliases = {family}
        if family == "RSA":
            aliases.update({"RS256", "PS256", "RS384", "RS512", "PS384", "PS512"})
        elif family == "ECDSA":
            aliases.update({"EC", "ES256", "ES384", "ES512"})
        elif family == "EDDSA":
            aliases.update({"ED25519", "ED448"})
        elif family == "ECDH":
            aliases.update({"EC", "ECDH"})
        elif family == "FINITEFIELDDH":
            aliases.update({"DH", "DIFFIEHELLMAN"})
        elif family == "SHA2/SHA3":
            aliases.update({"SHA256", "SHA384", "SHA512", "SHA3"})
        if normalized in aliases and purpose.value in rule.get("purposes", []):
            return rule
    return fallback


def algorithm_status(algorithm: str) -> str:
    normalized = normalize_algorithm(algorithm)
    if normalized in {
        "RSA",
        "ECDSA",
        "ECDH",
        "X25519",
        "X448",
        "DH",
        "FINITEFIELDDH",
        "DIFFIEHELLMAN",
        "EDDSA",
        "ED25519",
        "ED448",
    }:
        return "shor-vulnerable"
    if normalized in {"MLKEM", "MLDSA", "SLHDSA"}:
        return "pqc-standard"
    if normalized in {"TLSLEGACY", "TLSINSECURE"}:
        return "insecure-config"
    if normalized in {
        "AES",
        "AESGCM",
        "CHACHA20",
        "CHACHA20POLY1305",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA3",
        "SHA2/SHA3",
        "HMAC",
    }:
        return "not-shor-target"
    return "unknown"


def default_severity(algorithm: str, purpose: Purpose, *, test_only: bool = False) -> Severity:
    status = algorithm_status(algorithm)
    if status == "insecure-config":
        level = Severity.HIGH
    elif status == "shor-vulnerable":
        level = (
            Severity.CRITICAL
            if purpose in {Purpose.KEY_ESTABLISHMENT, Purpose.ENCRYPTION}
            else Severity.HIGH
            if purpose in {Purpose.SIGNATURE, Purpose.CERTIFICATE}
            else Severity.MEDIUM
        )
    elif status == "pqc-standard":
        level = Severity.INFO
    elif status == "not-shor-target":
        level = Severity.INFO
    else:
        level = Severity.LOW
    if test_only and level in {Severity.CRITICAL, Severity.HIGH}:
        return Severity.MEDIUM
    return level


def references_for(algorithm: str, purpose: Purpose, root: Path | None = None) -> list[str]:
    rule = matching_rule(algorithm, purpose, root)
    return list(rule.get("authority_ids", [])) if rule else []


def targets_for(algorithm: str, purpose: Purpose, root: Path | None = None) -> list[str]:
    rule = matching_rule(algorithm, purpose, root)
    return list(rule.get("migration_targets", [])) if rule else []


def explain_rule(rule_id: str, root: Path | None = None) -> dict[str, Any] | None:
    return rule_index(root).get(rule_id)
