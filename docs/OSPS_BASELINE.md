# OpenSSF and OSPS readiness baseline

This document records controls and gaps without inventing an OpenSSF Scorecard
score. The repository is public; statuses below describe the current GitHub
control plane and the remaining release-authorization boundary.

| Control | Status | Evidence | Gap or planned action |
|---|---|---|---|
| Repository-hosted workflows | NOT USED | Zero `.github/workflows` present; root `.github` absent | Maintain clean-room zero-workflow architecture |
| Pull-request history | EMPTY | Zero open/closed pull requests in repository history | Preserve empty history contract |
| Pull-request creation | COLLABORATORS ONLY | Platform repository policy set to `collaborators_only` | Prevent unauthorized public PR generation |
| Local validation | PASS | Full local test suite, linters, types, benchmarks, and release check | Enforce locally before maintainer updates |
| No target-code execution in scanner | PASS | Security model, analyzer tests, hostile-input tests | Preserve as a release invariant |
| Immutable external Action references | PASS | `action.yml` uses pinned commit SHAs; verified by local check | Preserve SHA-pinning in consumer Action |
| Secret scanning and push protection | PASS | GitHub server features enabled | Preserve configuration and review alerts |
| CodeQL repository workflow | NOT CONFIGURED | No repository-hosted CodeQL workflow | Run static analysis locally; do not configure hosted workflow |
| Dependency Review repository workflow | NOT CONFIGURED | No repository-hosted Dependency Review workflow | Perform local SCA and dependency reviews |
| DCO enforcement | PASS (policy) | Contributor certification and signed-off-by guidance | Maintain DCO certification requirement |
| Automated publication | NOT AUTHORIZED | Publish workflow absent; `pypi` environment absent | Do not authorize without explicit release authority |
| Release authority | NOT ESTABLISHED | Zero release tags, zero GitHub Releases, zero PyPI publications | Maintain unreleased state |
| Vulnerability disclosure | PASS | `SECURITY.md` response targets and lifecycle | Maintain private vulnerability reporting |

The first authorized release must record the actual public control-plane state
and any remaining exceptions separately from this pre-release document.
