# Architecture

PQCensus is a local, bounded, static analysis pipeline:

```text
bounded file discovery
  -> semantic/config/text analyzers
  -> normalized findings
  -> contextual risk + suppressions
  -> cryptographic inventory/assets
  -> crypto-agility + HNDL context
  -> purpose-aware migration plans
  -> JSON / Markdown / SARIF / CycloneDX
```

## Trust boundary

The analyzer consumes repository bytes as data. It does not import target modules, install target dependencies, run package lifecycle hooks, invoke repository build scripts, execute binaries, or evaluate arbitrary configuration code. File count, per-file bytes, total bytes, symlink behavior, generated/vendor paths, archives, and parser failures are bounded by the scanner utilities and covered by security tests.

This is an architectural requirement rather than a convenience: a security scanner must not silently turn an untrusted source repository into executable code merely to improve detection.

## Public automation boundary

The canonical public repository contains zero repository-hosted automated workflows.
All validation, code quality, benchmark measurement, and release checks are executed
locally by the maintainer.

The repository provides a composite Action in `action.yml` for downstream repository
integration. Downstream consumers should run scans with least-privilege permissions
(e.g., `contents: read`).

## Discovery and analyzers

The public `Analyzer` protocol accepts a path, source text, and `AnalyzerContext`.

`PythonAnalyzer` is the stable semantic reference implementation. It uses the standard-library AST, import aliases, conservative single-type propagation, call evidence, symbol/source spans, and purpose-sensitive handling. It intentionally avoids speculative whole-program execution or runtime import resolution.

`ConfigAnalyzer` handles structured JSON/TOML and constrained YAML-like key/value evidence. `ExperimentalTextAnalyzer` provides intentionally low-confidence coverage for non-Python source extensions and is not part of the stable language claim.

Dependency discovery is static and independent from source-language analysis. A package appearing in a manifest is evidence of a dependency, not proof that a specific algorithm is used at runtime.

## Evidence model

`Finding`, `CryptoAsset`, `MigrationPlan`, and `AuditResult` are typed dataclasses with explicit, versioned serialization. Rules and authority provenance live in `rules/`, rather than being scattered through analyzer branches.

Stable finding IDs hash rule, source path, span, algorithm, purpose, and evidence detail. Existing `QG-*`/`QGA-*` identifier prefixes remain schema-compatible in 0.1.x even though the public project identity is PQCensus.

Evidence carries enough information for a reviewer to distinguish:

- what source/config/dependency observation was made;
- which analyzer produced it;
- which algorithm and purpose were inferred;
- confidence in that inference;
- which external authority or internal policy supports the classification;
- whether a migration target was justified or deliberately withheld.

## Determinism

Canonical JSON ordering makes repeated outputs byte-comparable. The `verify` command performs a two-run comparison, and the end-to-end release gate repeats repository scans and requires deterministic output.

Determinism is also a provenance property: release evidence binds the source fingerprint, rule hash, corpus identities, result hashes, and available trusted-run metadata.

## Risk and migration separation

Discovery does not directly emit a replacement primitive. Findings pass through risk/context assessment and then purpose-aware migration planning.

```text
algorithm observation
       |
       v
purpose + confidence
       |
       +-- concrete purpose --> compatible migration class
       |
       +-- UNKNOWN -----------> abstain / unresolved
```

This separation prevents a signature algorithm from being suggested for key establishment and prevents unknown-purpose observations from receiving invented PQC targets.

## Output adapters

The core result is converted into multiple downstream representations rather than maintaining separate scanners per format:

- native audit JSON;
- cryptographic inventory JSON;
- native CBOM;
- CycloneDX 1.7 CBOM;
- migration-plan JSON;
- Markdown report;
- SARIF 2.1.0.

Official SARIF and CycloneDX validation are release gates, so format compatibility is tested independently from analyzer correctness.

## Packaging boundary

The public Python distribution, primary CLI, and public Python import namespace are `pqcensus`. The `quantumguard` package and command remain as a 0.1.x compatibility surface backed by the same implementation rather than a separate product, so evidence and integrations are not broken by the public-name change. The clean-wheel gate requires both the primary `pqcensus` command/namespace and the legacy `quantumguard` alias to resolve to the same versioned implementation.

## OSS boundary

The open-source architecture ends at complete single-repository L0-L2 analysis: bounded discovery, inventory, assessment, evidence, machine-readable outputs, and migration guidance.

Persistent organization inventory, cross-repository relationship graphs, RBAC/SSO/SCIM, organization-wide migration campaigns, approval workflows, hosted monitoring, and autonomous fleet-wide remediation are not implemented in this repository and are not implied by the current architecture.
