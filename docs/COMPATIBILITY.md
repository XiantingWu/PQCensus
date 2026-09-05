# PQCensus compatibility policy

PQCensus is the public product name, Python distribution, primary CLI, and
primary Python namespace. New integrations should use `pqcensus` and the
canonical repository `XiantingWu/PQCensus`.

## Public Python and platform contract

The supported compatibility range for 0.1.0 is Python 3.11 through 3.14.
Local test and release suites validate testing, packaging, CLI, and namespace contracts.

| Surface | Current contract | Validation boundary |
|---|---|---|
| Python 3.11 | supported and tested | Local environment matrix |
| Python 3.12 | supported and tested | Local environment matrix |
| Python 3.13 | supported and tested | Local environment matrix |
| Python 3.14 | supported and tested | Local environment matrix |
| macOS ARM64 | development environment | Local execution |
| Linux | target platform | Standard environment |
| Windows | not part of the 0.1.0 required contract | no certification claim |

The Python 3.15 prerelease lane is a non-required canary. It may expose
upcoming syntax, standard-library, packaging, typing, or test-dependency
changes, but it is reported as `CANARY`, not as supported or certified. The
package metadata intentionally remains `>=3.11,<3.15` until a released Python
3.15 version passes a required compatibility gate. Other future CPython
versions have no guarantee until they are added to this policy and matrix.

| Python status | Meaning |
|---|---|
| 3.11–3.14 | Supported and required for 0.1.0 certification |
| 3.15 prerelease | Non-required canary; not supported or certified |
| Other CPython versions | No guarantee |

## 0.1.x compatibility surface

The legacy QuantumGuard identifiers are compatibility contracts throughout the
0.1.x series. They are not a second product and do not change the public
identity:

- the `quantumguard` CLI alias and Python import namespace;
- `QG-*` and `QGA-*` finding/asset identifiers;
- `quantumguardFindingId` SARIF fingerprints;
- `quantumguard:*` CycloneDX properties and `urn:quantumguard:*` references;
- the `QuantumGuard-CBOM` format token and `quantumguard-*` output filenames.

The compatibility namespace resolves to the same implementation and version
as `pqcensus`.

## Output filename migration

PQCensus deliberately retains the existing `quantumguard-*.json` and
`quantumguard.sarif` filenames during 0.1.x so downstream automation remains
stable. A future filename migration must be additive, documented, tested for
equivalence, and explicitly versioned before a legacy name is removed.

## Type information

Both public and compatibility packages carry PEP 561 `py.typed` markers. The
quality gate runs the pinned mypy contract over `src/pqcensus` and
`src/quantumguard`, including the shared public API surface.
