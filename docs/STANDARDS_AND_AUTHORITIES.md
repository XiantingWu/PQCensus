# Standards and authorities

This file separates external authority from PQCensus interpretation. URLs and status notes were checked on 2026-08-23. Release evidence records the rule-file hash and must be regenerated when authority metadata that affects policy changes.

## NIST final standards and guidance

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), final 2024-08-13: ML-KEM, the standardized KEM family. NIST's 2025-11-17 planning note identifies an issue that is expected to be corrected in a future update/revision; PQCensus therefore treats the standard as final while keeping errata status distinct from algorithm availability.
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), final 2024-08-13: ML-DSA, the standardized lattice-based signature family. NIST's 2026-07-31 planning note points to several minor issues in the errata/potential-updates spreadsheet that are expected to be corrected in a future update/revision.
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), final 2024-08-13: SLH-DSA, the standardized stateless hash-based signature family.
- [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final), final 2025-09-18: recommendations for implementing and using KEMs.
- [SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final), key-management guidance. It is not a purpose-specific PQC replacement table.
- [CSWP 39 update 1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final), final 2026-06-29: strategies and practices for crypto agility. It informs the project's agility dimensions; the PQCensus numeric score is an internal engineering score, not a NIST score.

## NIST draft and migration material

- [IR 8547 Initial Public Draft](https://csrc.nist.gov/pubs/ir/8547/ipd) is recorded as `draft`, not as a final standard. PQCensus uses it as migration context only.
- The [NCCoE PQC migration project](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/) treats discovery/inventory and interoperability/benchmarking as distinct workstreams. Those concepts inform the project architecture; they do not certify this tool.

## IETF protocol authority

- [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html), published August 2026 on the IETF Standards Track, defines three PQ/traditional hybrid TLS 1.3 key-agreement groups: X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024. It is protocol authority for those TLS groups, not a generic statement that every X25519 use can be mechanically replaced by one group.
- RFC 10024 obsoletes the earlier pre-standard Kyber hybrid TLS code points it names. PQCensus should therefore distinguish final ML-KEM-based protocol identifiers from legacy pre-standard Kyber labels when such protocol detail is observable.
- Internet-Drafts remain draft material until published as RFCs. Draft text may inform compatibility notes but is never labeled a final standard merely because an implementation supports it.

## NSA/CNSA guidance

CNSA 2.0 is a deployment/policy profile for National Security Systems, not a general-purpose NIST rule set. PQCensus 0.1.0 does not ship an NSA/CNSA policy profile because its scope, environment, and current implementation guidance must be selected by the operator. No finding says “NSA requires” unless a future version adds a versioned, cited profile.

## Open Quantum Safe

[Open Quantum Safe algorithm status](https://openquantumsafe.org/liboqs/algorithms/) is implementation-ecosystem information. liboqs availability is not proof of protocol interoperability, FIPS validation, side-channel posture, key-management quality, or production readiness.

## Interchange formats

CycloneDX 1.7 is the external CBOM/SBOM interchange format used by the compatible CBOM output. Its cryptographic component model is not a migration policy. SARIF 2.1.0 is the interchange format used for code-scanning results. Format conformance does not make a finding a cryptographic certification.

## PQCensus interpretation boundary

Rule IDs, severity thresholds, confidence/abstention behavior, HNDL contextualization, migration staging, and the crypto-agility score are PQCensus engineering policy. They are versioned in `rules/quantumguard-rules.json`.

The internal authority identifier remains `QG.ENGINEERING` in the 0.1.x schema for compatibility with committed evidence and downstream consumers. Its publisher/title are PQCensus, and its `internal` status deliberately separates tool interpretation from NIST/IETF authority.
