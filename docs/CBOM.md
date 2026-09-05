# CBOM

`pqcensus cbom PATH` emits CycloneDX 1.7 JSON by default. Cryptographic findings become `cryptographic-asset` components with purpose, quantum status, confidence, provenance, and source-location properties. Static crypto dependencies become library components; known dependency-to-asset relationships are represented in the dependency graph.

The output is strictly validated in QuantumGuardBench with `cyclonedx-python-lib`'s CycloneDX 1.7 JSON validator. Generic RSA evidence intentionally omits a narrower CycloneDX padding/encoding family unless that exact family is proved; the component name and purpose remain available without a false OAEP/PSS claim.

`--format native` emits the versioned QuantumGuard CBOM schema and explicitly says CycloneDX compatibility is not claimed for that native document.
