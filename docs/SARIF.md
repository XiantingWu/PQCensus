# SARIF

PQCensus audit output is SARIF 2.1.0. Each active result includes a rule ID,
GitHub severity level, exact relative file and region, logical symbol where
known, rationale, next action, algorithm, purpose, confidence, and a stable
partial fingerprint.

The release validator downloads the official schema from a pinned Microsoft
SARIF repository commit, rejects oversized files, and verifies the pinned
SHA-256 before validation. This prevents a moving remote schema from silently
changing release evidence.

When integrated into downstream GitHub Actions workflows (such as via `action.yml`),
consumers should validate SARIF with `contents: read` permission. Any subsequent
upload to GitHub Advanced Security / Code Scanning should use least-privilege
`security-events: write` in an isolated step. The PQCensus repository itself contains
zero repository-hosted workflows.
