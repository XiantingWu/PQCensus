# Verify a PQCensus package

This document outlines verification steps for local package builds or distribution artifacts.
The current public repository has no release tag, GitHub Release, or PyPI release; release authority is not established.

## 1. Identify package version and files

Check the built wheel, source archive, and version:

```bash
python -m pip show pqcensus
pqcensus --version
```

The output must match the expected package version.

## 2. Verify file hashes

From the directory containing distribution assets:

```bash
shasum -a 256 -c SHA256SUMS
```

On Linux systems:

```bash
sha256sum -c SHA256SUMS
```

Confirm that the artifact hashes and SBOM match the generated files.

## 3. Local integrity and validation

Verify package build metadata with twine and the release check suite:

```bash
python -m twine check dist/*
python scripts/release_check.py
```
