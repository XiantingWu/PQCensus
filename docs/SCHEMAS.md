# Schemas

Versioned schemas are committed under `schemas/` and are part of the release-source fingerprint.

Current contracts cover:

- **finding** — one verified cryptographic observation plus source/evidence, confidence, risk, rule identity, suppression state, and migration-class information;
- **audit** — complete local scan with findings, inventory, dependencies, migration plans, crypto agility, HNDL context, suppressions, and scan limits;
- **inventory** — deduplicated `CryptoAsset` and dependency records;
- **native CBOM** — the project's compatibility CBOM mapping;
- **migration plan** — context-aware staged engineering recommendation;
- **benchmark result** — metrics plus corpus/rule identities and validation results;
- **end-to-end result** — repository-scale deterministic/observation/dependency/schema evidence;
- **SARIF contract** — project regression contract in addition to validation against the official SARIF 2.1.0 schema.

## Public identity vs schema compatibility

The public producer is PQCensus. Some schema `$id`/title values and machine tokens still use the historical QuantumGuard/`quantumguard` namespace because 0.1.x evidence and downstream consumers may already refer to them.

These are compatibility identifiers, including:

- `QG-*`/`QGA-*` IDs;
- native `QuantumGuard-CBOM` format token;
- `quantumguard:*` CycloneDX properties and `urn:quantumguard:*` references;
- legacy output filenames and SARIF partial-fingerprint key.

They are not separate current branding. A future namespace migration must be versioned and documented rather than silently rewriting evidence IDs.

## Compatibility policy

A schema-major/version change is required when a release:

- changes the meaning of an existing field;
- removes or newly requires a field in a breaking way;
- removes enum values consumers may rely on;
- changes stable ID semantics;
- changes machine namespace semantics in a way that breaks baselines or links;
- changes a format token that consumers use for dispatch.

Additive optional fields may be introduced within a schema version when old consumers can safely ignore them. For example, native CBOM producer metadata can be added without changing the compatibility format token.

Consumers should reject unknown major/schema versions rather than guessing.

## Validation

Project-native schemas are exercised by the test suite. Release gates additionally validate:

- generated CycloneDX output against the CycloneDX 1.7 validator;
- SARIF against the official SARIF 2.1.0 schema;
- benchmark result structure/semantic gates;
- deterministic output where required.

Schema conformance verifies interchange shape, not cryptographic correctness. Analyzer/rule correctness is evaluated separately by benchmark labels and migration-class safety gates.
