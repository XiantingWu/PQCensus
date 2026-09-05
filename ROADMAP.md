# Roadmap

PQCensus roadmap items are acceptance targets, not promises that a feature exists because it appears here. A capability moves into the stable public claim only after implementation, tests, benchmark coverage, documentation, and version-bound release evidence all agree.

## 0.1.x — trustworthy single-repository foundation

The current OSS target is a complete local L0-L2 workflow for one repository:

- bounded static file discovery;
- stable Python AST evidence;
- structured config and static dependency discovery;
- algorithm + purpose + confidence findings;
- cryptographic inventory and native/CycloneDX CBOM;
- contextual risk/HNDL and crypto-agility signals;
- purpose-aware migration planning with explicit abstention;
- suppression and baseline/diff workflows;
- JSON, Markdown, SARIF, and CycloneDX outputs;
- bounded opt-in TLS observation;
- deterministic verification;
- synthetic, curated real-code, and pinned end-to-end benchmark layers;
- exact-source release evidence;
- clean-wheel/standalone release gates;
- GitHub Action and PyPI Trusted Publishing boundaries.

### 0.1.0 launch acceptance

0.1.0 is ready for release only when the exact candidate source passes the public contributor CI contract, trusted release/evidence gates, package and schema validation, and the publishing controls documented in [docs/PUBLISHING.md](docs/PUBLISHING.md). Historical evidence from a different release-source fingerprint does not satisfy that milestone.

## 0.2 — stronger Python semantics and evidence quality

Priority is depth before language-count marketing.

Planned work:

- framework/re-export resolution for common cryptography/JWT wrappers;
- conservative inter-file symbol resolution without importing target modules;
- improved protocol/config context for TLS, JWT, certificate, and key-management usage;
- richer dependency-to-call-site attribution;
- stronger negative corpus for shadowing, comments, dead text, wrappers, aliases, tests, and generated/vendor paths;
- independent review/annotation of a larger real-code corpus;
- benchmark confidence intervals or uncertainty reporting where statistically meaningful.

Stable acceptance requires measurable improvement on held-out/independently reviewed examples without increasing dangerous migration-class errors.

## 0.3 — certificate, SSH, and deployment-visible inventory

Planned local evidence adapters:

- repository-visible X.509 certificate/key configuration;
- SSH public-key/algorithm configuration where statically observable;
- IaC/config references to managed KMS/HSM/provider cryptography without pretending the remote key material is visible;
- protocol identifiers including finalized PQ/hybrid identifiers where evidence is explicit;
- clear provenance showing whether an asset came from source, config, dependency metadata, certificate metadata, or bounded network observation.

Acceptance requires explicit limits for remote/managed-service state and no automatic classification of unseen infrastructure as safe.

## 0.4 — stable second language

JavaScript/TypeScript is the first candidate because ecosystem demand is high and current support is intentionally experimental.

A language becomes stable only after:

- semantic parser/AST-based analyzer rather than keyword-only matching;
- alias/import/module handling appropriate to the language;
- purpose inference tests;
- positive and adversarial negative corpus;
- curated real-code labels;
- repository-scale smoke corpus;
- documented false-positive/false-negative boundaries;
- release benchmark thresholds comparable in rigor to the Python contract.

Go is the next candidate after JavaScript/TypeScript. Java/Rust/C/C++ remain experimental until the same evidence standard is met.

## 0.5 — local remediation experiments

Possible opt-in developer assistance:

- migration dry-run suggestions;
- abstraction/interface change proposals;
- protocol/parameter compatibility checklist generation;
- narrow mechanical edits where semantics are provable;
- patch output that is reviewable and never silently applied.

Autofix must not turn a scanner into an unreviewed cryptographic migration engine. Every code mutation requires explicit opt-in, diff review, rollback, and its own benchmark/evaluation contract.

## Model-assisted explanation boundary

An optional model may eventually explain already-established evidence, summarize migration constraints, or help a reviewer navigate a large result set.

A model must not become the sole authoritative source of:

- whether a cryptographic call exists;
- its source span;
- external standard status;
- a concrete migration class when purpose is unknown;
- release evidence or benchmark labels.

Core scanning remains useful without an LLM/API key.

## Evidence roadmap

Before expanding product surface, improve evidence independence:

- more third-party repositories with pinned provenance;
- independently reviewed labels rather than author-only labels;
- held-out regression corpora not used to tune every rule;
- explicit per-language/per-purpose performance;
- regression tracking across releases;
- reproducible performance/resource measurements;
- signed/release-attached provenance when release infrastructure supports it safely.

A larger benchmark is valuable only if its labeling methodology remains inspectable.

## Documentation and ecosystem roadmap

- versioned public schemas and compatibility notes;
- immutable release-tag examples in Action documentation;
- migration guide for eventual retirement of legacy `quantumguard`/`QG-*` technical namespaces;
- contributor guidance for adding rules, analyzers, corpora, and external authorities;
- release notes that distinguish analyzer changes from documentation-only changes;
- issue forms and reproducible bug templates suitable for a public contributor community.

## Explicitly outside this OSS repository

The following are not hidden 0.1.x features and should not be inferred from the single-repository scanner:

- persistent organization-wide inventory/history;
- cross-repository dependency/cryptography graphs;
- migration campaign orchestration;
- policy inheritance across organizations/business units;
- RBAC, SSO, SCIM, enterprise approvals;
- Jira/ServiceNow/change-management orchestration;
- continuously hosted monitoring/control plane;
- organization-wide autonomous remediation;
- regulatory attestation/certification service.

Those capabilities can form a future organization/control-plane product boundary without withholding the core single-repository analysis workflow from OSS.

## Non-goals

PQCensus is not trying to become:

- a cryptographic implementation library;
- a replacement for CodeQL/Semgrep/general SAST;
- a general vulnerability/SCA database;
- a PKI/HSM/KMS management platform;
- a universal endpoint scanner;
- a NIST/NSA/IETF certification tool;
- a tool that reports “quantum safe” from a clean static source scan.
