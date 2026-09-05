# Prior art and differentiation

PQCensus is not positioned as the first or only post-quantum code scanner. The 2026 ecosystem already contains multiple developer scanners, posture tools, CBOM generators, protocol scanners, and general static-analysis platforms. A credible public repository should state exactly what it adds rather than relying on category novelty.

## Adjacent tool categories

| Area | Representative projects | What they do well | PQCensus boundary / distinction |
| --- | --- | --- | --- |
| semantic code analysis | GitHub CodeQL | repository-scale semantic queries, data flow, mature security ecosystem | PQCensus is narrower and purpose-built for cryptographic inventory/PQC migration; it does not claim CodeQL language breadth or data-flow depth |
| configurable pattern/AST scanning | Semgrep-style analyzers | broad rule ecosystems and customizable source matching | PQCensus ships a small versioned crypto policy, stable Python semantic analyzer, explicit evidence/confidence, and abstention on unknown purpose |
| developer PQC scanners | [pqc-scan](https://pypi.org/project/pqc-scan/), [pqc-audit](https://pypi.org/project/pqc-audit/), [postquant](https://github.com/postquantdev/postquant) | source/config/dependency scanning, migration suggestions, SARIF/CBOM, broader language coverage in some projects | PQCensus does not compete on language count in 0.1.0; it emphasizes evidence provenance, purpose-aware migration-class safety, deterministic release evidence, and explicit benchmark boundaries |
| posture scoring | [qsafe](https://pypi.org/project/qsafe/) / related PQC posture tools | broad pattern coverage, repository grades, easy executive posture summaries | PQCensus avoids presenting a clean/graded scan as proof that unobservable runtime/KMS/HSM crypto is safe; context and uncertainty remain explicit |
| package/SBOM/SCA | Syft, Grype, Trivy | package cataloging, SBOM generation, vulnerability workflows | PQCensus inventories crypto-bearing dependencies/assets but is not a general vulnerability database or SCA replacement |
| CBOM interchange | CycloneDX | standardized cryptographic component representation and interchange | PQCensus emits schema-validated CycloneDX 1.7 and preserves its own evidence/purpose/risk model alongside the interchange output |
| PQC implementations | Open Quantum Safe | implementations, algorithm ecosystem, interoperability experimentation | algorithm/library availability is policy context only; PQCensus does not infer validation, protocol support, side-channel posture, or production readiness from a name |
| protocol/edge scanners | endpoint TLS/SSH scanners and PQ/T TLS analyzers | observe negotiated/public endpoint behavior unavailable to source-only scanners | PQCensus has a bounded TLS probe but does not pretend a source scan can prove remote certificate, key-share, fleet, or middlebox state |
| migration guidance | NIST/NCCoE material | discovery, inventory, transition, interoperability, crypto-agility guidance | PQCensus implements a local repository/developer slice and keeps internal engineering policy explicitly separate from NIST/IETF authority |

## What PQCensus is trying to prove

The differentiating unit is not “we found the text RSA.” It is the evidence-to-decision chain:

```text
observable source/config/dependency evidence
                |
                v
       algorithm + purpose
                |
                v
    confidence + risk context
                |
        +-------+-------+
        |               |
        v               v
  justified class   UNKNOWN purpose
  migration target      |
        |                v
        v              abstain
 staged engineering
 migration plan
```

A useful scanner should make it possible to review *why* a recommendation exists and should refuse to fabricate a migration target when the cryptographic purpose is not established.

## Concrete 0.1.0 differentiators

### Evidence-preserving findings

Findings retain exact source span, symbol/call information where available, evidence type, safe snippet hash, confidence, rule/authority references, analyzer provenance, suppression state, and a stable identifier.

### Purpose-aware migration classes

Signature/certificate observations and key-establishment/encryption observations are kept in separate migration classes. The benchmark explicitly fails dangerous cross-class suggestions such as mapping X25519 key establishment to a signature primitive.

### Explicit abstention

`UNKNOWN` purpose never receives an automatic PQC target. This is a tested policy, not just documentation.

### Deterministic, version-bound release evidence

The release process binds runtime code, tests, rules, schemas, benchmark inputs/corpus, release scripts, package metadata, composite Action, rule hash, corpus identities, and result hashes. A stale result file cannot satisfy the exact-source evidence gate after release-relevant source changes.

### Three-layer benchmark claims

PQCensus separates controlled semantic labels, curated real-code call-site labels, and repository-scale selected-observation smoke evidence. It deliberately does not turn 12 selected end-to-end observations into an “overall 100% precision” claim.

### Local/no-execution security boundary

Normal repository scanning does not import target modules, install target dependencies, run lifecycle scripts, execute repository binaries, or upload source to a hosted service.

## Where competitors may be stronger

PQCensus 0.1.0 should not hide the areas where other tools can be better choices:

- several competing scanners support more stable languages today;
- CodeQL and mature general static analyzers have substantially deeper interprocedural/data-flow capabilities;
- endpoint scanners can observe live protocol behavior that source analysis cannot;
- general SCA/SBOM tools have broader dependency ecosystems and vulnerability feeds;
- enterprise inventory/control-plane products can aggregate fleets and organizations in ways this OSS repository does not implement.

The public claim is therefore intentionally narrow: **high-evidence, reproducible single-repository cryptographic inventory and purpose-aware PQC migration planning, with explicit uncertainty and verifiable release evidence.**

## Naming note

The public project identity is PQCensus. Existing `QG-*` schema IDs, the compatibility `quantumguard` Python package, the 0.1.x compatibility CLI alias, and legacy output filenames remain stable technical identifiers. They are compatibility artifacts, not a claim that the project is the unrelated tools or packages that use the “QuantumGuard” name elsewhere.
