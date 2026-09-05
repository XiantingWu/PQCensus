from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from ..models import Confidence, Evidence, Finding, Purpose, SourceSpan
from ..policy import algorithm_status, default_severity, references_for, targets_for
from ..util import algorithm_display, sha256_text, test_only_path
from .base import AnalyzerContext


class ConfigAnalyzer:
    name = "structured-config"
    extensions = {".json", ".toml", ".yaml", ".yml"}
    _interesting_keys = {
        "algorithm",
        "algorithms",
        "cipher",
        "ciphers",
        "curve",
        "key_exchange",
        "key_establishment",
        "signature",
        "signature_algorithm",
        "tls_cipher",
    }

    def analyze(self, path: Path, source: str, context: AnalyzerContext) -> list[Finding]:
        rel = path.relative_to(context.root).as_posix()
        pairs = self._pairs(path.suffix.lower(), source)
        findings: list[Finding] = []
        for key, value in pairs:
            if key.lower().replace("-", "_") not in self._interesting_keys:
                continue
            classified = self._classify(key, value)
            if not classified:
                continue
            algorithm, purpose = classified
            display = algorithm_display(algorithm)
            lines = source.splitlines()
            line = self._line_number(source, value)
            span = SourceSpan(line, 0, line, len(lines[line - 1]) if lines else 0)
            refs = references_for(display, purpose, context.rules_root)
            targets = targets_for(display, purpose, context.rules_root)
            detail = f"structured config {key}={value}"
            from ..policy import matching_rule

            rule = matching_rule(display, purpose, context.rules_root)
            rule_id = str(rule["id"]) if rule else "QG-UNKNOWN-CRYPTO"
            test_only = test_only_path(rel)
            findings.append(
                Finding(
                    finding_id=Finding.stable_id(rule_id, rel, span, display, purpose, detail),
                    rule_id=rule_id,
                    category="protocol-configuration",
                    algorithm=display,
                    purpose=purpose,
                    source_path=rel,
                    span=span,
                    symbol=key,
                    evidence=[
                        Evidence("structured_config", detail, sha256_text(value), tuple(refs))
                    ],
                    confidence=Confidence.MEDIUM,
                    quantum_risk=algorithm_status(display),
                    severity=default_severity(display, purpose, test_only=test_only),
                    rationale=f"A cryptographic primitive is selected by the structured configuration key {key!r}.",
                    migration_target=targets,
                    migration_confidence=Confidence.MEDIUM if targets else Confidence.UNKNOWN,
                    references=refs,
                    suppressible=True,
                    analyzer=self.name,
                    environment="test" if test_only else "production",
                )
            )
        return findings

    def _pairs(self, suffix: str, source: str) -> list[tuple[str, str]]:
        if suffix == ".json":
            try:
                return list(self._flatten(json.loads(source)))
            except json.JSONDecodeError:
                return []
        if suffix == ".toml":
            try:
                return list(self._flatten(tomllib.loads(source)))
            except tomllib.TOMLDecodeError:
                return []
        result = []
        for line in source.splitlines():
            match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*:\s*['\"]?([^#'\"]+)", line)
            if match:
                result.append((match.group(1), match.group(2).strip()))
        return result

    def _flatten(self, value: Any) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, (str, int, float)):
                    result.append((str(key), str(child)))
                elif isinstance(child, list) and all(isinstance(item, str) for item in child):
                    result.extend((str(key), str(item)) for item in child)
                else:
                    result.extend(self._flatten(child))
        elif isinstance(value, list):
            for child in value:
                result.extend(self._flatten(child))
        return result

    def _classify(self, key: str, value: str) -> tuple[str, Purpose] | None:
        upper = value.upper().replace("_", "-")
        key_lower = key.lower()
        rsa_token_signature = re.fullmatch(r"(?:RS|PS)\d+", upper) is not None
        if rsa_token_signature or "RSA" in upper:
            if "SIGN" in key_lower or rsa_token_signature:
                return "RSA", Purpose.SIGNATURE
            if "CIPHER" in key_lower or "EXCHANGE" in key_lower or "ESTABLISH" in key_lower:
                return "RSA", Purpose.KEY_ESTABLISHMENT
            return "RSA", Purpose.UNKNOWN
        if re.fullmatch(r"ES\d+", upper) or "ECDSA" in upper:
            return "ECDSA", Purpose.SIGNATURE
        if "X25519" in upper or "X448" in upper:
            return ("X448" if "X448" in upper else "X25519"), Purpose.KEY_ESTABLISHMENT
        if "ECDH" in upper:
            return "ECDH", Purpose.KEY_ESTABLISHMENT
        if "ED25519" in upper or "EDDSA" in upper:
            return "EdDSA", Purpose.SIGNATURE
        if "ML-KEM" in upper or "MLKEM" in upper:
            return "ML-KEM", Purpose.KEY_ESTABLISHMENT
        if "ML-DSA" in upper or "MLDSA" in upper:
            return "ML-DSA", Purpose.SIGNATURE
        if "SLH-DSA" in upper or "SLHDSA" in upper:
            return "SLH-DSA", Purpose.SIGNATURE
        return None

    def _line_number(self, source: str, value: str) -> int:
        for index, line in enumerate(source.splitlines(), 1):
            if value in line:
                return index
        return 1
