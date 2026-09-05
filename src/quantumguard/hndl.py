from __future__ import annotations

from .models import Finding, Purpose


def assess_hndl(
    findings: list[Finding],
    *,
    data_sensitivity: str | None = None,
    confidentiality_lifetime_years: int | None = None,
    system_context: str | None = None,
    exposure: str | None = None,
) -> dict[str, object]:
    confidentiality_findings = [
        item
        for item in findings
        if item.status == "active"
        and item.purpose in {Purpose.ENCRYPTION, Purpose.KEY_ESTABLISHMENT}
        and item.quantum_risk == "shor-vulnerable"
    ]
    missing = [
        name
        for name, value in (
            ("data_sensitivity", data_sensitivity),
            ("confidentiality_lifetime_years", confidentiality_lifetime_years),
            ("system_context", system_context),
            ("exposure", exposure),
        )
        if value is None
    ]
    if not confidentiality_findings:
        status = "NO_STATIC_CONFIDENTIALITY_SIGNAL"
    elif missing:
        status = "UNKNOWN"
    elif (
        confidentiality_lifetime_years
        and confidentiality_lifetime_years >= 10
        and exposure in {"public", "internet", "external"}
    ):
        status = "HIGH"
    else:
        status = "REVIEW"
    return {
        "schema_version": 1,
        "status": status,
        "rationale": (
            "Captured ciphertext protected by Shor-vulnerable key establishment could be retained and decrypted after a future cryptographically relevant quantum computer exists."
            if confidentiality_findings
            else "No Shor-vulnerable confidentiality or key-establishment call site was verified by the current static scan."
        ),
        "affected_finding_ids": [item.finding_id for item in confidentiality_findings],
        "inputs": {
            "data_sensitivity": data_sensitivity,
            "confidentiality_lifetime_years": confidentiality_lifetime_years,
            "system_context": system_context,
            "exposure": exposure,
        },
        "unknown_inputs": missing,
        "default_policy": "No enterprise data lifecycle is invented; missing context remains UNKNOWN.",
    }
