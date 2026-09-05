# Outputs

PQCensus keeps human-facing producer identity separate from stable 0.1.x machine filenames/namespaces.

The default audit prints concise terminal output. `--json` emits the versioned audit object with `tool.name = "PQCensus"`. `--output DIR` writes:

- `quantumguard-audit.json`
- `quantumguard-inventory.json`
- `quantumguard-cbom.json` (native compatibility format)
- `quantumguard-cbom.cdx.json` (CycloneDX 1.7)
- `quantumguard-migration-plan.json`
- `quantumguard.sarif`
- optional `quantumguard-baseline-diff.json`

Those filenames remain unchanged in 0.1.x so existing SARIF upload paths, baselines, scripts, and evidence bundles do not churn merely because the public project name changed. New integrations should treat PQCensus as the producer and must not infer that the legacy filename prefix is a second product.

Standalone commands also support `inventory`, `cbom`, `plan`, `agility`, `baseline`, and `verify`.

## Determinism

Native JSON uses canonical/sorted serialization where required, and collections with stable semantics are deterministically ordered. `pqcensus verify . --json` repeats a scan and compares canonical bytes. Release evidence separately binds the exact release source and corpus identities.

## Privacy

Finding evidence contains source path/span, semantic metadata, and a safe snippet hash where applicable. Normal outputs do not intentionally embed complete source bodies. Paths, symbols, dependencies, user-supplied risk context, and repository names can still be sensitive and should be reviewed before sharing artifacts from a private codebase.

## Producer identity

Human-facing producer fields are PQCensus:

- audit/inventory/migration `tool.name`;
- native-CBOM `producer.name`;
- SARIF driver name;
- Markdown/console output;
- CycloneDX producer property.

The following remain compatibility identifiers in 0.1.x:

- `QG-*`/`QGA-*` finding and asset IDs;
- `quantumguardFindingId` SARIF partial fingerprint key;
- historical `quantumguard:*` CycloneDX property namespace and `urn:quantumguard:*` references;
- native `QuantumGuard-CBOM` format token;
- existing `quantumguard-*` output filenames.

Breaking those identifiers requires an explicit schema-major migration rather than a branding-only release.
