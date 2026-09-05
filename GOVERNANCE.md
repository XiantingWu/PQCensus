# Governance

PQCensus uses a single-maintainer governance model.

## Maintainer and write authority

- **Maintainer**: XiantingWu
The Pull Requests surface is enabled for the repository UI.
Pull-request creation is restricted to repository collaborators.
The public repository currently has zero pull-request history.
The project does not use repository-hosted CI workflows.
Canonical validation is performed locally before direct maintainer updates.
All repository updates, administration, and decisions are made directly by XiantingWu.

## Responsibilities

The maintainer is responsible for:

- protecting the static-analysis and no-target-execution security boundary;
- reviewing analyzer, rule, schema, benchmark, and migration-policy changes;
- keeping standards attribution separate from PQCensus engineering interpretation;
- requiring tests and independently reviewable evidence for stable detection or migration claims;
- maintaining compatibility commitments;
- responding to vulnerability reports privately.

## Decision model

When evidence is ambiguous, the project prefers preserving `UNKNOWN`, documenting the limitation, or deferring a stable claim rather than choosing a more confident answer for convenience.

## Releases

Release authority is not currently established. No release tags, GitHub Releases, or PyPI uploads are authorized.

## Security decisions

Potential vulnerabilities follow [SECURITY.md](SECURITY.md). Security fixes are handled privately until coordinated disclosure is appropriate.
