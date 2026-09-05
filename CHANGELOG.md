# Changelog

All notable user-visible and release-contract changes are recorded here. Benchmark measurements belong in version-bound evidence, not in changelog prose alone.

## 0.1.0 — initial public release candidate

### Added

- Local, bounded cryptographic inventory for source/configuration/dependency evidence without executing the target repository.
- Stable Python AST analysis with purpose-aware findings for signatures, key establishment, encryption, hashing, MACs, TLS configuration, and selected PQC markers.
- Native inventory/migration outputs plus CycloneDX 1.7 CBOM, SARIF 2.1.0, and Markdown/JSON reporting.
- Contextual risk/HNDL inputs, crypto-agility signals, suppression, baseline/diff mode, deterministic verification, and bounded opt-in TLS observation.
- Three benchmark layers: synthetic semantic fixtures, curated pinned real-code excerpts, and complete pinned end-to-end repository snapshots with provenance.
- A composite GitHub Action (`action.yml`) for consumer repository integration.
- Exact-source release fingerprinting, version-bound evidence architecture, and clean-wheel/standalone gates.

### Security and release integrity

- Target repositories are treated as data: normal scans do not import target modules, install target dependencies, run lifecycle scripts, execute repository binaries, or upload source to a hosted service.
- Local maintainer validation enforces strict quality gates, semantic benchmarks, clean-wheel packaging, and security checks before repository updates.
- External GitHub Action references in consumer examples are SHA-pinned and checkout credentials are not persisted.
- Release evidence architecture is designed to regenerate transactionally from the exact candidate source and fails closed when release-bound source changes.
- Release manifests record source/rule/corpus/result identity, execution environment, and resolved release-toolchain versions while deliberately omitting human-readable host or runner names.
- The PEP 517 build backend is exactly pinned for a more reproducible source-to-wheel contract.
- Production-source self-scanning runs at `fail-on: high`; intentionally vulnerable examples and benchmark corpora are validated in dedicated gates.
- `action.yml` is a consumer-facing integration. It is not a repository-hosted workflow. The PQCensus repository contains no `.github/workflows` definitions.

### Public identity and compatibility

- Public project, distribution, CLI, and import namespace: **PQCensus / `pqcensus`**.
- Canonical repository identity: `XiantingWu/PQCensus`.
- The `quantumguard` import package and CLI remain explicit 0.1.x compatibility aliases.
- Existing `QG-*`/`QGA-*` identifiers, `quantumguard-*.json`/`quantumguard.sarif` filenames, and legacy machine namespaces remain compatibility contracts during 0.1.x.

### Evidence and claim boundary

- Synthetic, curated-real-code, and end-to-end measurements are corpus-specific and author-curated; they are not universal precision claims or an independent security audit.
- `UNKNOWN` cryptographic purpose abstains from automatic PQC target selection.
- Migration mapping tests reject dangerous signature-vs-KEM/encryption cross-purpose suggestions.
- Standards documentation separates finalized external authorities from drafts, transition guidance, and PQCensus engineering interpretation.

### Documentation and governance

- Single-maintainer governance, contributing guidance, security/threat models, roadmap, publishing process, third-party notices, and citation metadata are included for public maintenance.
- Consumer GitHub Action examples use pinned commit SHAs or release tags rather than mutable `main`.
- Complete upstream benchmark snapshots explicitly document deliberate public test certificates/private-key fixtures so they are not confused with project credentials.

Benchmark measurements, source fingerprints, and toolchain configurations are validated locally via `scripts/release_check.py`. Release authority is not currently established.

