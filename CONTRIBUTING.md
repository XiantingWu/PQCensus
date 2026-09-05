# Contributing

PQCensus is maintained under a single-maintainer model by XiantingWu.
The Pull Requests surface is enabled for the repository UI.
Pull-request creation is restricted to repository collaborators.
The public repository currently has zero pull-request history.
The project does not use repository-hosted CI workflows.
Canonical validation is performed locally before direct maintainer updates.

This document outlines local development setup, testing standards, and security reporting.

## Development setup

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
pqcensus doctor --strict
```

For analyzer, rule, migration, benchmark, schema, package, Action, or validation changes, run the relevant benchmarks and release check:

```bash
python scripts/run_quantumguardbench.py --manifest benchmarks/quantumguardbench.json
python scripts/run_quantumguardbench.py --manifest benchmarks/real-code.json
python scripts/release_check.py
```

`python scripts/release_check.py` validates the complete local contract: tests, strict doctor, examples, official SARIF/CycloneDX validation, benchmark layers, migration-mapping safety, source identity, package build, `twine check`, clean-wheel installation, standalone export, and standalone child gates.

## Analyzer and rule changes

Every analyzer change needs a positive, negative, ambiguous, or adversarial fixture and a regression test appropriate to the behavior being changed. Prefer adding both a positive and a plausible false-positive case when introducing a new detection pattern.

Do not use PQCensus output to generate its own benchmark labels. Ground-truth labels and required observations must come from fixture intent, independent manual review, upstream API/protocol semantics, or another documented authority.

Security-sensitive changes must preserve the static-default/no-target-execution boundary, path/resource limits, deterministic IDs, and explicit `UNKNOWN` outcomes. A new migration mapping must include coverage that rejects signature/KEM or other dangerous cross-purpose confusion.

Keep rule authority, version, status, draft/final state, interpretation, and references in `rules/`; do not bury standards or migration policy in analyzer code.

## Third-party benchmark material

For upstream excerpts or repository snapshots:

- record repository URL and exact commit;
- record license and the applicable license file;
- preserve provenance-bound bytes rather than silently normalizing them;
- record or recompute the corpus/tree hash using repository scripts;
- keep labels/required observations independently reviewed;
- do not copy secrets, credentials, private repositories, customer material, or unnecessary large upstream files;
- if an exact public upstream test snapshot contains deliberate test certificates/private-key fixtures, document that fact explicitly and never substitute live credentials.

A benchmark result is corpus-specific evidence. Do not turn a curated fixture result into a universal precision/recall claim.

## Security reports

Do not open public issues for an exploitable scanner, release-pipeline, or supply-chain vulnerability. Follow [SECURITY.md](SECURITY.md). Never include tokens, private keys, proprietary source, customer data, or private repository URLs.

## Developer Certificate of Origin

Contributions must certify that the work can be submitted under the repository license and is not knowingly submitted with an undisclosed restriction, per [developercertificate.org](https://developercertificate.org/).
Commit messages must include a `Signed-off-by` trailer:

```text
Signed-off-by: Full Name <email@example.invalid>
```
