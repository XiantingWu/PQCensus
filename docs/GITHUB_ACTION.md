# GitHub Action

The repository ships a composite Action in `action.yml`. It installs only the
PQCensus package itself and statically inspects the checked-out repository; it
does not install or execute target dependencies.

`action.yml` is a consumer-facing integration. It is not a repository-hosted
workflow. The PQCensus repository contains no `.github/workflows` definitions.

A downstream workflow should keep pull-request audit permission to contents-read
only. If SARIF is uploaded, put that operation in a separate trusted main job
with security-events write permission. Use an immutable release tag or full
commit SHA; no release tag exists in the current public pre-release state.

~~~yaml
name: PQCensus
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - uses: XiantingWu/PQCensus@<immutable-commit-sha>
        with:
          fail-on: high
          output: pqcensus-results
~~~

Downstream workflows should separate analysis steps (contents: read) from any artifact uploads.

## Baseline mode

Create a baseline explicitly:

~~~text
pqcensus baseline . --output pqcensus-baseline.json
~~~

Commit the baseline only if that matches local policy, then use it in a later
audit. Review baselines for sensitive paths before sharing them.

## Output compatibility

The public project identity, primary CLI, and public Python namespace are
PQCensus and pqcensus. Existing 0.1.x machine-readable output filenames remain
quantumguard-*.json and quantumguard.sarif during the compatibility window.
