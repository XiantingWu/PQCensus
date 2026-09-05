# Security policy

PQCensus is a security-oriented static analyzer. Its first security obligation is to avoid turning a repository being inspected into executable code.

## Supported versions

While the project is pre-1.0, only the latest tagged release receives security fixes. Development branches and pull-request heads are not supported releases, even when benchmark evidence exists for the same version number.

A PQCensus release is not a certification, compliance attestation, or guarantee that every repository can be scanned safely or completely. Release claims are bounded by the committed version-specific evidence under `benchmarks/releases/<version>/` and the documented limitations.

## Reporting a vulnerability

Do not publish exploitable scanner, release-pipeline, runner, or supply-chain details in a public issue before maintainers have had a reasonable opportunity to assess them.

Use GitHub private vulnerability reporting for `XiantingWu/PQCensus` when available. Include:

- affected version or exact commit;
- a minimal reproduction without secrets or private customer code;
- expected vs observed security boundary;
- whether the issue requires network access, a symlink, archive, malformed parser input, dependency metadata, GitHub Actions, or a built package;
- impact and known preconditions.

Never include credentials, tokens, private keys, customer data, proprietary source, or live production endpoints that you are not authorized to test.

### Reporting lifecycle targets

When private vulnerability reporting is enabled for the canonical repository,
use [Report a vulnerability](https://github.com/XiantingWu/PQCensus/security/advisories/new).
If that repository feature is unavailable, contact the maintainer through [the
XiantingWu GitHub profile](https://github.com/XiantingWu) and keep the report
private. Do not use a public issue for an unfixed vulnerability.

The project targets acknowledgement within 3 business days and initial triage
within 10 business days. These are response targets, not a guarantee of a
fixed deadline. Remediation timing is severity- and complexity-dependent; the
maintainer will communicate status, workarounds, and a coordinated disclosure
date where appropriate.

The maintainer may request a coordinated embargo when public detail would
increase risk. Affected releases are assessed by lifecycle and severity, with
security fixes backported only to the supported release line stated above.
When appropriate, the maintainer requests a CVE or GitHub Security Advisory
identifier and records the affected versions, fixed version, credit, and
disclosure timeline in the advisory. A report remains private until the
coordinated disclosure decision is made.

| Stage | Contract |
|---|---|
| Acknowledgement | Target within 3 business days |
| Initial triage | Target within 10 business days |
| Remediation | Severity- and complexity-dependent; no fixed repair promise |
| Disclosure | Coordinated with reporter and affected users where practical |
| Advisory | CVE/GHSA requested or recorded when appropriate |

## In-scope security issues

Examples include:

- arbitrary code execution caused by scanning repository content;
- importing or executing target modules unexpectedly;
- running target package installers, lifecycle hooks, Makefiles, shell scripts, binaries, or arbitrary build systems;
- path traversal or symlink escape outside the requested scan root;
- unbounded or attacker-controlled file/resource consumption that bypasses documented limits;
- unsafe parser behavior that causes unintended execution or uncontrolled resource use;
- accidental source, secret, or private-path disclosure in output artifacts;
- unexpected outbound network access during the normal static repository scan;
- unsafe handling of TLS target names/ports beyond the explicitly requested bounded `tls` command;
- dependency or supply-chain defects in the PQCensus package or GitHub Action;
- release-integrity defects that allow stale benchmark evidence to be presented as belonging to changed source;
- Trusted Publishing/OIDC boundary errors;
- defects that expose maintainer credentials or release authority to untrusted code;
- authoritative migration claims that incorrectly attribute PQCensus engineering policy to NIST, IETF, or another external authority;
- dangerous cross-purpose migration behavior, such as recommending a signature primitive for a verified key-establishment use.

## Out of scope

Normally out of scope:

- vulnerabilities in a repository being scanned;
- a finding that is only a documented static-analysis limitation;
- requests to classify unknown runtime/KMS/HSM/protocol behavior as safe without evidence;
- disagreement with an explicitly documented engineering severity where the underlying evidence and authority attribution are correct;
- performance limits that remain within the documented bounded scanner contract;
- broad claims that post-quantum migration itself has operational risk without a PQCensus-specific defect.

## Untrusted repository boundary

The normal scan treats repository content as data. PQCensus does not intentionally:

- import a target Python package;
- execute target Python/JavaScript/Go/Java/Rust/C/C++ source;
- install the target's dependencies;
- run `setup.py`, package-manager lifecycle hooks, Makefiles, shell files, test suites, binaries, containers, or arbitrary build commands;
- evaluate arbitrary repository configuration as executable code;
- follow symlinks outside the requested root;
- upload source to a hosted service;
- require an LLM, API key, or external account for the core scan.

`PythonAnalyzer` uses Python's standard-library AST on source text. Config/dependency analyzers parse bounded static data. Experimental text analyzers perform low-confidence textual analysis and do not execute the target.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Resource controls

Default scan bounds include a maximum selected-file count, maximum individual file size, and maximum total analyzed bytes. Binary files, archives, large files, generated/vendor content, symlink escapes, and parser failures are skipped or recorded according to the scanner utilities rather than being executed to discover more context.

These bounds are security controls as well as performance controls. Changes to them are release-relevant source and require fresh release evidence.

## Network behavior

The normal repository audit is local and does not need outbound network access.

The `pqcensus tls HOST` command is a separate, explicitly requested bounded network operation. It performs one TLS handshake using the standard library and reports only what that observable handshake can support. It must not be interpreted as authorization to perform broad endpoint scanning or as proof of hidden certificate/key-management state.

Benchmark and release development may use package indexes to install PQCensus development dependencies. That is different from target-repository execution.

## Source and artifact privacy

PQCensus outputs source paths, spans, rule/evidence metadata, and safe hashes needed to review findings. It does not intentionally serialize complete source bodies into normal evidence artifacts.

Before sharing SARIF/JSON/CBOM output from a private repository, review it under your organization's data-handling policy. File names, dependency names, symbols, system context, and user-provided HNDL/risk context can themselves be sensitive.

## GitHub Action security

The composite Action in `action.yml` is provided for downstream repository inspection. It installs PQCensus in an isolated job environment and statically audits the target workspace; it does not install target dependencies. `action.yml` is a consumer-facing integration; the PQCensus repository contains no repository-hosted workflows.

See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md).

## Local self-scan and validation

PQCensus self-scans distributed production source under `src/` at `fail-on: high`. Deliberately vulnerable examples and benchmark corpora are test fixtures; they remain covered by dedicated benchmark/release gates rather than being misclassified as production source.

Local release validation enforces official SARIF and CycloneDX schema conformity.

## Source integrity and reproducibility

The source fingerprint binds release-relevant source:

- the public `pqcensus` Python namespace and compatibility implementation;
- tests;
- rules and schemas;
- benchmark manifests and corpus bytes;
- release/benchmark scripts;
- release examples;
- `pyproject.toml` and the composite Action.

Local validation checks verify source fingerprint and corpus integrity.

## Dependency posture

The runtime package intentionally has no mandatory third-party Python dependencies. Development validators/build tools are optional development dependencies and are tracked separately. The PEP 517 build backend is exactly pinned so a source commit does not silently select a different build backend release over time.

## Benchmark corpus security and provenance

The benchmark corpus includes synthetic files, curated excerpts, and pinned upstream repository snapshots. Third-party source is included only where license/provenance information is recorded under `benchmarks/`.

Complete public upstream test snapshots can contain deliberate test certificates or private-key fixtures. They are not PQCensus credentials and are retained only where exact upstream bytes are part of the benchmark identity. Production credentials, customer material, private repositories, and undisclosed secrets must never enter the corpus.

Benchmark source is test input. The release suite must never execute arbitrary lifecycle/build/test behavior from those snapshots merely because the files are present in the repository.

See `benchmarks/THIRD_PARTY_NOTICES.md`, `benchmarks/provenance.json`, and `benchmarks/end-to-end-provenance.json`.

## Cryptographic-policy safety

PQCensus is a migration-planning tool, not a cryptographic module and not a standards body. It distinguishes finalized standards, implementation guidance, draft transition material, protocol standards, and PQCensus internal engineering interpretation.

`UNKNOWN` purpose does not receive an automatic PQC target. Migration recommendations remain candidates subject to protocol, PKI, HSM/KMS, peer compatibility, implementation validation, rollback, and operational review.

See [docs/STANDARDS_AND_AUTHORITIES.md](docs/STANDARDS_AND_AUTHORITIES.md).

## Compatibility identifiers

The public project identity, distribution, command, and Python import namespace are PQCensus/`pqcensus`. During 0.1.x, several older machine identifiers remain stable to preserve evidence and downstream compatibility:

- compatibility Python import package `quantumguard`;
- compatibility CLI `quantumguard`;
- `QG-*`/`QGA-*` IDs;
- `quantumguard-*.json` and `quantumguard.sarif` output filenames;
- legacy CycloneDX property/URN namespace and schema identifiers.

Those identifiers are compatibility contracts, not separate active product identities. Changing them requires an explicit migration rather than an incidental branding edit.
