from __future__ import annotations

import hashlib

from ..models import Confidence, Finding, MigrationPlan, Purpose
from ..policy import algorithm_status


def build_migration_plan(finding: Finding, *, protocol: str | None = None) -> MigrationPlan | None:
    if finding.status == "suppressed" or algorithm_status(finding.algorithm) != "shor-vulnerable":
        return None

    if finding.purpose in {Purpose.KEY_ESTABLISHMENT, Purpose.ENCRYPTION}:
        targets = ["ML-KEM"]
        target_class = "key-establishment"
        compatibility = [
            "Confirm the application protocol or library supports ML-KEM or an approved hybrid construction.",
            "Do not replace encryption or key establishment with a signature primitive.",
        ]
        unknowns = (
            [] if protocol else ["Protocol negotiation and peer compatibility are not visible."]
        )
    elif finding.purpose in {Purpose.SIGNATURE, Purpose.CERTIFICATE}:
        targets = ["ML-DSA", "SLH-DSA"]
        target_class = "digital-signature"
        compatibility = [
            "Confirm verifier, certificate, token, and message-format support before changing signers.",
            "Do not replace a signature primitive with ML-KEM.",
        ]
        unknowns = (
            []
            if protocol
            else ["Verifier and certificate ecosystem compatibility are not visible."]
        )
    else:
        targets = []
        target_class = "unknown"
        compatibility = [
            "Determine whether this primitive signs, encrypts, establishes keys, authenticates, or appears only in dead/test code before selecting a PQC target."
        ]
        unknowns = [
            "Cryptographic purpose is UNKNOWN; QuantumGuard intentionally abstains from an algorithm recommendation."
        ]

    confidence = (
        Confidence.HIGH
        if targets and finding.confidence == Confidence.HIGH
        else Confidence.MEDIUM
        if targets
        else Confidence.UNKNOWN
    )
    material = (
        f"{finding.finding_id}|{finding.purpose.value}|{'/'.join(targets)}|{protocol or 'unknown'}"
    )
    return MigrationPlan(
        plan_id="QGP-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20],
        finding_id=finding.finding_id,
        source_path=finding.source_path,
        purpose=finding.purpose,
        current_primitive=finding.algorithm,
        recommended_targets=targets,
        target_class=target_class,
        compatibility_constraints=compatibility,
        required_abstraction_changes=[
            "Centralize primitive selection behind a tested crypto policy/provider boundary.",
            "Represent legacy, hybrid/dual, PQ-preferred, and legacy-retired states explicitly.",
        ],
        deployment_ordering=[
            "Inventory consumers, peers, certificates, keys, and stored artifacts.",
            "Add negotiation or dual-read/verify support.",
            "Deploy hybrid or dual support where the protocol permits it.",
            "Prefer the PQ-capable path and monitor compatibility.",
            "Retire legacy keys and algorithms only after rollback criteria are satisfied.",
        ],
        rollback_considerations=[
            "Keep a bounded compatibility rollback while validating interoperability.",
            "Do not silently downgrade after the legacy-retirement gate.",
        ],
        verification_steps=[
            "Run known-answer and negative cryptographic tests.",
            "Verify cross-version and cross-provider interoperability.",
            "Rescan and confirm the original finding is fixed or intentionally retained.",
            "Review protocol traces or configuration evidence without exposing secrets.",
        ],
        urgency=finding.severity.value,
        confidence=confidence,
        unresolved_unknowns=unknowns,
        references=finding.references,
    )


def build_migration_plans(findings: list[Finding]) -> list[MigrationPlan]:
    plans = [plan for finding in findings if (plan := build_migration_plan(finding)) is not None]
    return sorted(plans, key=lambda item: (item.source_path, item.finding_id, item.plan_id))
