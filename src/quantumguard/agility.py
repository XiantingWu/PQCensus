from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, cast

from .models import Dependency, Finding

_SIGNAL_EXTENSIONS = {
    ".py",
    ".pyw",
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
    ".toml",
    ".yaml",
    ".yml",
}
_CRYPTO_DEP_TOKENS = (
    "crypto",
    "ssl",
    "tls",
    "jwt",
    "jose",
    "openssl",
    "bouncycastle",
    "cryptography",
    "libsodium",
    "nacl",
)


def _crypto_dependency(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in _CRYPTO_DEP_TOKENS)


def evaluate_agility(
    findings: list[Finding],
    dependencies: list[Dependency],
    source_texts: Iterable[tuple[str, str]],
) -> dict[str, object]:
    source_texts = list(source_texts)
    signal_texts = "\n".join(
        text.lower()
        for path, text in source_texts
        if Path(path).suffix.lower() in _SIGNAL_EXTENSIONS
    )
    hard_coded = sum(
        evidence.evidence_type in {"ast_call", "token"}
        for finding in findings
        for evidence in finding.evidence
    )
    configured = sum(finding.analyzer == "structured-config" for finding in findings)
    centralized_paths = sorted(
        path
        for path, _ in source_texts
        if any(
            signal in path.lower()
            for signal in ("crypto_provider", "cryptopolicy", "crypto_policy", "security/crypto")
        )
    )
    negotiation = any(
        word in signal_texts
        for word in ("hybrid", "negotiate", "algorithm_preference", "supported_algorithms")
    )
    dual_support = any(
        word in signal_texts for word in ("dual_sign", "dual_verify", "hybrid", "legacy_fallback")
    )
    key_rotation = any(
        word in signal_texts for word in ("rotate_key", "key_rotation", "key_version")
    )
    certificate_rotation = any(
        word in signal_texts
        for word in ("rotate_certificate", "certificate_rotation", "renew_certificate")
    )
    policy_centralization = bool(centralized_paths) or any(
        path.endswith("quantumguard.toml") for path, _ in source_texts
    )
    crypto_deps = [dep for dep in dependencies if _crypto_dependency(dep.name)]
    pinned = sum(bool(dep.version and dep.version not in {"*", "latest"}) for dep in crypto_deps)

    components = {
        "algorithm_selection": {
            "score": 70
            if configured and not hard_coded
            else 45
            if configured
            else 20
            if hard_coded
            else 50,
            "evidence": [f"hard_coded_evidence={hard_coded}", f"configured_evidence={configured}"],
        },
        "provider_centralization": {
            "score": 85 if centralized_paths else 30,
            "evidence": centralized_paths or ["no centralized crypto provider path observed"],
        },
        "negotiation": {
            "score": 80 if negotiation else 25,
            "evidence": [
                "negotiation signal observed" if negotiation else "no negotiation signal observed"
            ],
        },
        "dual_algorithm_support": {
            "score": 80 if dual_support else 20,
            "evidence": [
                "dual/hybrid signal observed" if dual_support else "no dual/hybrid signal observed"
            ],
        },
        "key_rotation": {
            "score": 75 if key_rotation else 30,
            "evidence": [
                "rotation signal observed" if key_rotation else "no key rotation signal observed"
            ],
        },
        "certificate_rotation": {
            "score": 75 if certificate_rotation else 30,
            "evidence": [
                "certificate rotation signal observed"
                if certificate_rotation
                else "no certificate rotation signal observed"
            ],
        },
        "dependency_constraints": {
            "score": 70
            if crypto_deps and pinned == len(crypto_deps)
            else 40
            if crypto_deps
            else 50,
            "evidence": [
                f"crypto_dependencies={len(crypto_deps)}",
                f"version_constrained={pinned}",
            ],
        },
        "policy_centralization": {
            "score": 80 if policy_centralization else 25,
            "evidence": [
                "central policy signal observed"
                if policy_centralization
                else "no central policy signal observed"
            ],
        },
    }
    overall = round(
        sum(int(cast(dict[str, Any], item)["score"]) for item in components.values())
        / len(components)
    )
    return {
        "schema_version": 1,
        "overall_score": overall,
        "scale": "0-100",
        "components": components,
        "method": (
            "Transparent deterministic signals; absence of a static signal is not proof "
            "that a capability does not exist. The 0-100 value is a declared engineering "
            "scale, not a normalized population percentile and not an externally calibrated "
            "maturity score. Scores are equal-weight component averages, and a mixed hard-coded plus "
            "configured signal can score below a no-signal baseline because ambiguity is "
            "penalized."
        ),
    }
