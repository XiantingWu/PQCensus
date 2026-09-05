from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence, Finding, Purpose, Severity
from .policy import algorithm_status


@dataclass(frozen=True)
class RiskContext:
    exposure: str = "unknown"
    data_lifetime_years: int | None = None
    trust_lifetime_years: int | None = None
    public_reachability: str = "unknown"
    migration_complexity: str = "unknown"
    production: bool = True
    hndl_relevant: bool | None = None


def assess_finding(finding: Finding, context: RiskContext | None = None) -> Finding:
    context = context or RiskContext(production=finding.environment != "test")
    status = algorithm_status(finding.algorithm)
    if status != "shor-vulnerable":
        return finding

    score = 2
    reasons = [f"{finding.algorithm} is Shor-relevant"]
    if finding.purpose in {Purpose.KEY_ESTABLISHMENT, Purpose.ENCRYPTION}:
        score += 2
        reasons.append("the observed purpose protects confidentiality or establishes keys")
    elif finding.purpose in {Purpose.SIGNATURE, Purpose.CERTIFICATE}:
        score += 1
        reasons.append("the observed purpose anchors authenticity or signatures")
    else:
        reasons.append(
            "the downstream purpose is not verified, so the tool abstains from a purpose-specific critical rating"
        )
    if context.exposure == "public" or context.public_reachability == "public":
        score += 1
        reasons.append("public exposure increases capture or attack opportunity")
    if context.data_lifetime_years is not None and context.data_lifetime_years >= 10:
        score += 1
        reasons.append("the stated confidentiality lifetime is at least 10 years")
    if context.hndl_relevant is True:
        score += 1
        reasons.append("the supplied context makes harvest-now-decrypt-later relevant")
    if not context.production:
        score -= 2
        reasons.append("the call site is classified as test or fixture code")
    if finding.confidence in {Confidence.LOW, Confidence.UNKNOWN}:
        score -= 1
        reasons.append("low evidence confidence limits authoritative severity")

    finding.severity = (
        Severity.CRITICAL
        if score >= 5
        else Severity.HIGH
        if score >= 3
        else Severity.MEDIUM
        if score >= 1
        else Severity.LOW
    )
    finding.rationale = "; ".join(reasons) + "."
    return finding
