from __future__ import annotations

import re
from pathlib import Path

from ..models import Confidence, Evidence, Finding, Purpose, SourceSpan
from ..policy import algorithm_status, default_severity, references_for, targets_for
from ..util import algorithm_display, sha256_text, test_only_path
from .base import AnalyzerContext


class ExperimentalTextAnalyzer:
    """Constrained line analyzer for non-Python languages.

    It intentionally reports MEDIUM/LOW confidence and is not part of the stable
    precision claim until language-specific parser fixtures are promoted.
    """

    name = "experimental-text"
    extensions = {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".java",
        ".rs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
    }

    _patterns = (
        (
            re.compile(r"\b(?:RS256|PS256|rsa\.|RSA\.|RSA/)\b", re.I),
            "RSA",
            Purpose.UNKNOWN,
            "public-key RSA token or API",
        ),
        (
            re.compile(r"\b(?:ES256|ES384|ES512|ECDSA|ecdsa)\b", re.I),
            "ECDSA",
            Purpose.SIGNATURE,
            "ECDSA/signature token or API",
        ),
        (
            re.compile(r"\b(?:ECDH|X25519|X448|ecdh|x25519|x448)\b", re.I),
            "X25519",
            Purpose.KEY_ESTABLISHMENT,
            "classical key-agreement token or API",
        ),
        (
            re.compile(r"\b(?:Ed25519|Ed448|EdDSA)\b", re.I),
            "EdDSA",
            Purpose.SIGNATURE,
            "EdDSA/signature token or API",
        ),
        (
            re.compile(r"\b(?:ML[-_]?KEM|Kyber)\b", re.I),
            "ML-KEM",
            Purpose.KEY_ESTABLISHMENT,
            "PQC KEM token or API",
        ),
        (
            re.compile(r"\b(?:ML[-_]?DSA|Dilithium)\b", re.I),
            "ML-DSA",
            Purpose.SIGNATURE,
            "PQC signature token or API",
        ),
    )

    def analyze(self, path: Path, source: str, context: AnalyzerContext) -> list[Finding]:
        if path.suffix.lower() not in self.extensions:
            return []
        rel = path.relative_to(context.root).as_posix()
        findings: list[Finding] = []
        for line_number, line in enumerate(source.splitlines(), 1):
            code = self._strip_comments(line, path.suffix.lower())
            if not code.strip():
                continue
            for pattern, algorithm, purpose, detail in self._patterns:
                match = pattern.search(code)
                if not match:
                    continue
                display = algorithm_display(algorithm)
                test_only = test_only_path(rel)
                severity = default_severity(display, purpose, test_only=test_only)
                refs = references_for(display, purpose, context.rules_root)
                targets = targets_for(display, purpose, context.rules_root)
                span = SourceSpan(line_number, match.start(), line_number, match.end())
                rule_id = self._rule_id(display, purpose, context)
                evidence_detail = f"line token: {detail}"
                findings.append(
                    Finding(
                        finding_id=Finding.stable_id(
                            rule_id, rel, span, display, purpose, evidence_detail
                        ),
                        rule_id=rule_id,
                        category="cryptographic-use",
                        algorithm=display,
                        purpose=purpose,
                        source_path=rel,
                        span=span,
                        symbol=None,
                        evidence=[
                            Evidence(
                                "token", evidence_detail, sha256_text(line.strip()), tuple(refs)
                            )
                        ],
                        confidence=Confidence.LOW,
                        quantum_risk=algorithm_status(display),
                        severity=severity,
                        rationale=(
                            f"Experimental {path.suffix.lower()} text evidence found {display}; "
                            "semantic resolution is not yet claimed."
                        ),
                        migration_target=targets,
                        migration_confidence=Confidence.LOW if targets else Confidence.UNKNOWN,
                        references=refs,
                        suppressible=True,
                        analyzer=self.name,
                        environment="test" if test_only else "production",
                    )
                )
                break
        return findings

    def _strip_comments(self, line: str, suffix: str) -> str:
        if suffix in {".go", ".java", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}:
            return line.split("//", 1)[0]
        return line.split("//", 1)[0].split("#", 1)[0]

    def _rule_id(self, algorithm: str, purpose: Purpose, context: AnalyzerContext) -> str:
        from ..policy import matching_rule

        rule = matching_rule(algorithm, purpose, context.rules_root)
        return str(rule["id"]) if rule else "QG-UNKNOWN-CRYPTO"
