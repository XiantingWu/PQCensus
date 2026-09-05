# PQC migration

Migration is purpose-aware:

| Verified current purpose | Candidate class | Explicit rejection |
|---|---|---|
| signature/certificate | ML-DSA or SLH-DSA | ML-KEM |
| key establishment/encryption | ML-KEM, with protocol-supported hybrid transition | ML-DSA and SLH-DSA |
| unknown | no target | all automatic replacement |

Candidates are based on final FIPS 203, 204, and 205 primitives. A primitive being standardized or available does not prove protocol support, validated implementation, certificate support, peer interoperability, or production readiness.

Plans model `legacy -> abstraction -> negotiation -> hybrid/dual -> PQ-preferred -> legacy retirement`. They include affected path, compatibility constraints, abstraction changes, deployment ordering, rollback limits, verification steps, confidence, and unresolved unknowns. Verifiers/readers are deployed before signer/writer cutover. Legacy fallback is bounded and must not silently reappear after retirement.

RFC 10024 defines specific TLS 1.3 PQ/traditional hybrid groups, but the current stdlib TLS inspector cannot observe the negotiated key-share group. It therefore reports that dimension as `UNKNOWN` instead of asserting hybrid adoption.
