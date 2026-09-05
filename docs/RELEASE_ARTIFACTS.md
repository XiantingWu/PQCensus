# Release artifacts and SBOM

The distribution-artifact manifest and SBOM describe packaged assets:

- `release-artifacts.json` binds the wheel, sdist, CycloneDX SBOM, and `SHA256SUMS` files.
- The artifact generator creates a deterministic CycloneDX 1.7 JSON SBOM for the wheel and sdist, recording package metadata, dependencies, artifact hashes, and toolchain versions.

## Current status

No release is currently authorized. No GitHub Release or PyPI upload exists.
Package building and SBOM generation can be validated locally via `python -m build` and `scripts/release_check.py`.
