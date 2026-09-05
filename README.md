# PQCensus

[![Python 3.11-3.14](https://img.shields.io/badge/Python-3.11--3.14-3776AB)](pyproject.toml) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Local by default · zero mandatory runtime dependencies · no LLM/API key · no target-code execution**

Evidence-grounded cryptographic inventory and post-quantum migration planning for real software repositories.

PQCensus is a local static-analysis tool for answering four engineering questions:

1. **Where is cryptography used?**
2. **What purpose does each use serve when the source proves it?**
3. **Which uses are relevant to post-quantum migration?**
4. **What can be migrated next without inventing a target when evidence is ambiguous?**

The scanner does not require an API key, hosted service, cloud upload, or LLM. Normal repository analysis treats target source as data rather than executable code.

> **0.1.x compatibility:** the public distribution, primary CLI, and public Python namespace are `pqcensus`. The legacy `quantumguard` CLI/import alias, `QG-*`/`QGA-*` identifiers, and existing `quantumguard-*` output filenames remain compatibility contracts during 0.1.x.

## Quick start

Before the first PyPI release, install from a repository checkout:

```bash
python -m pip install .
pqcensus doctor --strict
pqcensus audit examples/vulnerable-app --fail-on none
```

After a published release:

```bash
python -m pip install pqcensus
pqcensus audit . --fail-on high
```

Python uses the same public namespace:

```python
import pqcensus

result = pqcensus.audit(".")
print(result.findings)
```

`audit` exits 1 when an active finding reaches `--fail-on`; that is a policy result, not a crash. Expected usage/runtime failures use separate nonzero exit codes.

## Why this is not a keyword scanner

Cryptographic migration is about **purpose**, not only primitive names. `RSA`, `ECDSA`, or `X25519` can appear in signatures, key establishment, encryption, tests, wrappers, configuration, dependency metadata, comments, or unrelated registry text.

PQCensus findings therefore preserve reviewable evidence such as:

- stable finding and rule identifiers;
- source path and span;
- symbol/call information where the analyzer can establish it;
- algorithm and purpose;
- analyzer and confidence;
- rule/authority references;
- contextual risk and HNDL inputs;
- suppression state;
- migration targets only when purpose evidence supports the mapping.

The central safety rule is:

> **`UNKNOWN` purpose does not receive an automatic PQC migration target.**

Uncertainty should remain visible instead of being converted into confident migration advice.

## Stable 0.1.x scope

The stable source-language analyzer is Python AST-based. Tested coverage includes common uses of:

- `cryptography`;
- PyCryptodome;
- PyJWT/JWT;
- `hashlib`, `hmac`, and `ssl`;
- RSA signatures and OAEP/encryption contexts;
- ECDSA and ECDH;
- finite-field Diffie-Hellman;
- X25519/X448;
- EdDSA;
- TLS configuration;
- ML-KEM and ML-DSA markers;
- symmetric hash/MAC/KDF contexts;
- static Python dependency manifests;
- structured JSON/TOML cryptographic configuration.

JavaScript/TypeScript, Go, Java, Rust, and C/C++ text coverage is experimental and deliberately lower-confidence. It is not presented as equivalent to the Python analyzer.

See [Detection model](docs/DETECTION_MODEL.md), [Rules](docs/RULES.md), and [Limitations](docs/LIMITATIONS.md).

## Core commands

Audit a repository:

```bash
pqcensus audit . --fail-on high
```

Create an inventory and CBOM:

```bash
pqcensus inventory . --output crypto-inventory.json
pqcensus cbom . --output crypto.cdx.json
```

Create a migration plan:

```bash
pqcensus plan . --output pqc-migration-plan.json
```

Verify deterministic output:

```bash
pqcensus verify . --json
```

Create and consume a baseline:

```bash
pqcensus baseline . --output pqcensus-baseline.json
pqcensus audit . --baseline pqcensus-baseline.json --format sarif --output results
```

Add risk context only when you know it:

```bash
pqcensus audit . \
  --exposure internet \
  --data-sensitivity confidential \
  --confidentiality-lifetime-years 15 \
  --system-context "customer document service" \
  --fail-on none
```

Without deployment/data-lifetime context, PQCensus keeps HNDL conclusions explicit rather than inventing enterprise facts.

## Evidence-to-migration model

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

Signature/certificate and key-establishment/encryption uses remain separate migration classes. Candidate targets are engineering guidance, not drop-in compatibility promises: protocol, PKI, HSM/KMS, peer support, message size, lifecycle, rollback, and operational constraints still require validation.

See [PQC migration](docs/PQC_MIGRATION.md), [Risk model](docs/RISK_MODEL.md), [Crypto agility](docs/CRYPTO_AGILITY.md), and [Standards and authorities](docs/STANDARDS_AND_AUTHORITIES.md).

## Outputs

The 0.1.x machine-readable output filenames remain stable for compatibility:

```text
quantumguard-audit.json
quantumguard-inventory.json
quantumguard-cbom.json
quantumguard-cbom.cdx.json
quantumguard-migration-plan.json
quantumguard.sarif
```

Their public producer identity is PQCensus. The release suite validates SARIF 2.1.0 against the official schema and validates the CycloneDX 1.7 CBOM independently.

See [Outputs](docs/OUTPUTS.md), [Schemas](docs/SCHEMAS.md), [SARIF](docs/SARIF.md), and [CBOM](docs/CBOM.md).

## Benchmark evidence

PQCensus separates three evidence layers because no single benchmark number proves semantic behavior, real-code precision, and repository-scale execution at once.

| Layer | Corpus | Candidate measurement | What it supports |
| --- | --- | --- | --- |
| Synthetic semantic | 26 cases / 26 labeled findings | TP 26 / FP 0 / FN 0 | controlled rule/analyzer behavior |
| Curated upstream excerpts | 5 excerpts / 6 labeled call sites | TP 6 / FP 0 / FN 0 | small human-labeled real API shapes |
| Pinned end-to-end repositories | python-jose 3.3.0 + PyJWT 2.10.1 / 96 files | 193 findings / 12 of 12 required observations | repository-scale smoke, dependency/schema/determinism checks |

These measurements are **corpus-specific and author-curated**. They are not an independent security audit, a universal accuracy claim, a certification, or proof that an arbitrary system is quantum-safe.

PQCensus includes reproducible benchmark definitions and local validation commands.

No canonical release evidence is currently established.
No GitHub Release or PyPI release is authorized.

Reproduce the three benchmark layers:

```bash
python scripts/run_quantumguardbench.py \
  --manifest benchmarks/quantumguardbench.json \
  --official-sarif \
  --require-precision 0.98 \
  --require-recall 0.95

python scripts/run_quantumguardbench.py \
  --manifest benchmarks/real-code.json \
  --official-sarif \
  --require-precision 0.95 \
  --require-recall 0.95

python scripts/run_end_to_end.py \
  --manifest benchmarks/end-to-end.json \
  --official-sarif
```

See [Benchmarks](docs/BENCHMARKS.md) and [third-party notices](benchmarks/THIRD_PARTY_NOTICES.md).

## Reproducibility

Release-relevant inputs are fingerprinted explicitly, including runtime source, tests, rules, schemas, benchmark manifests/corpus bytes, release scripts, release examples, package metadata, and the composite Action.

Local validation can be run with:

```bash
python scripts/release_check.py
python scripts/release_source_check.py
```

The PEP 517 build backend is exactly pinned.

See [Publishing](docs/PUBLISHING.md).

## GitHub Action integration

The repository contains a composite Action in `action.yml` for downstream workflows to audit software repositories and emit SARIF.

`action.yml` is a consumer-facing integration. It is not a repository-hosted workflow. The PQCensus repository contains no `.github/workflows` definitions.

For downstream integration, see [GitHub Action integration](docs/GITHUB_ACTION.md).

## Security model

Normal repository scanning does **not** intentionally:

- import target packages;
- install target dependencies;
- run `setup.py`, package lifecycle hooks, Makefiles, shell scripts, tests, binaries, containers, or arbitrary builds;
- follow symlinks outside the requested scan root;
- upload target source;
- require an LLM or remote account.

Files, individual file size, total analyzed bytes, archives, generated/vendor paths, parser failures, and symlink behavior are bounded or explicitly handled.

Complete pinned upstream benchmark snapshots can contain public test certificates/private-key fixtures from the upstream projects. They are documented provenance-bound test material, not PQCensus credentials, and the benchmark runner does not execute the upstream repositories.

See [Security policy](SECURITY.md), [Security model](docs/SECURITY_MODEL.md), [Threat model](docs/THREAT_MODEL.md), and [Limitations](docs/LIMITATIONS.md).

## Standards posture

PQCensus distinguishes finalized standards and protocol authorities from drafts, transition guidance, and project-specific engineering interpretation. It does not claim NIST certification or label a repository “quantum safe” from a clean static scan.

See [Standards and authorities](docs/STANDARDS_AND_AUTHORITIES.md) and [Prior art and differentiation](docs/PRIOR_ART_AND_DIFFERENTIATION.md).

## Project map

- [Getting started](docs/GETTING_STARTED.md) · [Architecture](docs/ARCHITECTURE.md) · [Detection](docs/DETECTION_MODEL.md)
- [Risk](docs/RISK_MODEL.md) · [Migration](docs/PQC_MIGRATION.md) · [Crypto agility](docs/CRYPTO_AGILITY.md)
- [Rules](docs/RULES.md) · [Standards](docs/STANDARDS_AND_AUTHORITIES.md) · [Schemas](docs/SCHEMAS.md)
- [CBOM](docs/CBOM.md) · [SARIF](docs/SARIF.md) · [Outputs](docs/OUTPUTS.md) · [Suppressions](docs/SUPPRESSIONS.md)
- [Benchmarks](docs/BENCHMARKS.md) · [GitHub Action](docs/GITHUB_ACTION.md) · [Publishing](docs/PUBLISHING.md)
- [Security](SECURITY.md) · [Support](SUPPORT.md) · [Governance](GOVERNANCE.md) · [Contributing](CONTRIBUTING.md)
- [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md)

## OSS boundary

The open-source package is intended to be complete for a single-repository developer/team workflow: discover, inventory, assess, produce machine-readable evidence, and generate bounded migration guidance.

It does not claim to implement organization-wide persistent inventory, cross-repository graphs, RBAC/SSO/SCIM, hosted monitoring, enterprise campaign orchestration, autonomous fleet-wide remediation, or regulatory certification.

See [Roadmap](ROADMAP.md).

## License

Apache-2.0. See [SECURITY.md](SECURITY.md) for vulnerability reporting and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements.
