# Getting started

PQCensus 0.1.0 supports Python 3.11 through 3.14. The public distribution, primary command, and public Python import namespace are all `pqcensus`; the `quantumguard` command/import package remain compatibility identifiers in the 0.1.x line.

## Install from the repository

```bash
python -m pip install .
pqcensus --version
python -m pqcensus --version
pqcensus doctor --strict
```

Python API:

```python
import pqcensus

result = pqcensus.audit("examples/vulnerable-app")
print(pqcensus.__version__)
```

Run the bundled vulnerable example first so you know what a finding looks like before scanning a larger repository:

```bash
pqcensus audit examples/vulnerable-app --fail-on none
```

Then scan the current repository:

```bash
pqcensus audit . --output pqcensus-results --fail-on high
```

`audit` exits 1 when an active finding reaches `--fail-on`; that is a policy result, not a crash. Expected usage/runtime errors exit 2 or 3 without a traceback. Use `--json`, `--format markdown`, or `--format sarif` for automation.

## Exit codes

| Code | Meaning | Examples |
|---|---|---|
| 0 | Success; no active finding reached `--fail-on`; all diagnostic commands succeeded | `audit --fail-on none`, `doctor`, `rules`, `verify` (deterministic) |
| 1 | Policy result: at least one active finding reached `--fail-on`; this is not a crash | `audit --fail-on high` on a repository with a high finding |
| 2 | User/usage error: invalid option, missing command, invalid choice, invalid threshold | `pqcensus`, `pqcensus --bogus`, `audit --format nope` |
| 3 | Runtime error: invalid input, missing path, malformed baseline, internal scanner failure | missing directory, invalid baseline JSON, unexpected internal error (no traceback) |
| 130 | Interrupted by the user (SIGINT) | Ctrl-C during a scan |

A scanner crash never masquerades as exit 1: internal failures are reported on stderr as `PQCensus internal error: ...` and exit 3, keeping "vulnerabilities found" and "scanner failed" distinguishable for automation.

## Add risk context only when you know it

```bash
pqcensus audit . \
  --exposure public \
  --data-sensitivity confidential \
  --confidentiality-lifetime-years 12 \
  --system-context payments \
  --fail-on none
```

Without those inputs, HNDL remains `UNKNOWN`; PQCensus does not invent an enterprise data lifetime or deployment exposure.

## Useful next commands

```bash
pqcensus inventory . --output crypto-inventory.json
pqcensus cbom . --output crypto.cdx.json
pqcensus plan . --output pqc-migration-plan.json
pqcensus verify . --json
pqcensus baseline . --output pqcensus-baseline.json
```

For CI integration see [GITHUB_ACTION.md](GITHUB_ACTION.md). For output contracts see [OUTPUTS.md](OUTPUTS.md). For known blind spots read [LIMITATIONS.md](LIMITATIONS.md) before treating a clean scan as evidence that a system has no cryptography outside source visibility.
