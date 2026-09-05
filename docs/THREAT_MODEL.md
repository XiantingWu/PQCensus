# Threat model

PQCensus addresses migration risk from cryptographically relevant quantum computers, not compromise by an already available machine.

- Shor-relevant risk: RSA, finite-field DH, ECDH, ECDSA, EdDSA, X25519, and X448 are migration signals whose severity depends on purpose and context.
- Grover-related implications: symmetric keys and hash output lengths can require lifecycle review, but ordinary AES or SHA-256 use is not treated as equivalent to broken public-key cryptography.
- Harvest Now, Decrypt Later: captured ciphertext protected by vulnerable key establishment can expose long-lived confidentiality later. Missing lifetime, sensitivity, exposure, or system context remains `UNKNOWN`.
- Signature longevity: JWT, software-signing, certificates, and durable signed artifacts need verifier-first transition planning. A signature is never mapped to ML-KEM.
- PKI and protocols: TLS authentication, key establishment, and bulk encryption are separate assets. The same separation applies to SSH and application protocols.
- Data at rest and in transit: static code can observe calls and configuration, not the actual data classification or every runtime route.
- Indirect boundaries: dependencies, KMS/HSM calls, managed services, external endpoints, and dynamically selected providers can hide cryptography.

False positives arise from ambiguous wrappers, test code, generated code, and weak textual signals. False negatives arise from reflection, runtime configuration, native extensions, framework indirection, generated code excluded by limits, and external services. High-risk uncertainty is represented as `UNKNOWN`, `AMBIGUOUS`, or `PARTIAL`; it is not promoted to certainty.
