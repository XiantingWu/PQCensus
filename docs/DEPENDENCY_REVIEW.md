# Dependency Review and SCA policy

The runtime distribution intentionally has zero mandatory Python dependencies.
That fact does not eliminate supply-chain review: build tools, development
tools, GitHub Actions, and release tooling are also part of the engineering
boundary.

## Policy

Dependency and software composition analysis (SCA) review is a local maintainer
release-validation responsibility. The PQCensus repository contains no repository-hosted
automated workflows or enforceable public PR checks.

Policy guidelines:

- the runtime distribution has zero mandatory dependencies;
- build, development, and test tools are pinned to reviewed versions;
- a newly introduced known vulnerability at `high` or `critical` severity
  in development or release dependencies must be resolved before updates;
- licenses of development tools are reviewed for compatibility;
- GitHub dependency graph, if provided by the platform, serves as static platform
  information only and is not driven by repository workflows.

## Vendored benchmark snapshots

The PyJWT and python-jose trees under `benchmarks/corpus/end-to-end/` are
cryptographically pinned static scanner input. Their upstream manifests may
be visible to dependency tooling, but they are not imported, installed,
executed, or included in the wheel or sdist. Any alert about them must be
dispositioned using `docs/BENCHMARK_CORPUS_POLICY.md` and the exact inventory,
rather than silently treating the alert as a PQCensus runtime dependency.
