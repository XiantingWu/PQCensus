# Support

PQCensus is an open-source static analysis project. Support is best-effort and evidence-driven; there is no paid support SLA in this repository.

## Before asking for help

1. Read [Getting started](docs/GETTING_STARTED.md) and [Limitations](docs/LIMITATIONS.md).
2. Run `pqcensus doctor --strict`.
3. Re-run the smallest reproducible command with the exact PQCensus version recorded.
4. Remove proprietary source, credentials, customer data, private repository URLs, and other sensitive material from any reproduction.

## Usage problems and bugs

Use the repository bug-report issue form for reproducible scanner, CLI, packaging, schema, Action, or documentation defects. Include the exact version/commit, platform and Python version, command, expected behavior, observed behavior, and a minimal non-sensitive fixture when possible.

A finding you believe is a false positive should include enough static source/config context to explain why the reported algorithm or purpose is wrong. A suspected false negative should include a minimal example showing the cryptographic operation PQCensus failed to observe.

## Feature requests

Use the feature-request issue form. Describe the engineering problem and observable evidence you want PQCensus to model rather than only naming a library, language, or standard. New stable detection claims require tests, adversarial negatives, benchmark evidence, and documentation before they enter the supported surface.

## Security vulnerabilities

Do **not** open a public issue for an exploitable scanner, runner, release-pipeline, or supply-chain vulnerability. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting when it is enabled for the public repository.

## What maintainers cannot validate from an issue

A clean static scan cannot prove an entire deployed system is quantum-safe. PQCensus cannot infer hidden HSM/KMS state, remote infrastructure, runtime-only configuration, peer compatibility, or enterprise data-retention facts without evidence. See [Security model](docs/SECURITY_MODEL.md) and [Standards and authorities](docs/STANDARDS_AND_AUTHORITIES.md).

## Compatibility and releases

For supported-version and compatibility policy, see [SECURITY.md](SECURITY.md), [COMPATIBILITY.md](docs/COMPATIBILITY.md), and [CHANGELOG.md](CHANGELOG.md). Release evidence is version-bound and lives under `benchmarks/releases/<version>/`.
