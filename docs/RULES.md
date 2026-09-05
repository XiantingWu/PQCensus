# Rules and provenance

Rules are data in `rules/quantumguard-rules.json` and validate against `rules/schema.json`. Each rule has an ID, algorithm family, purpose, status, default severity, migration targets, effective version, deprecation flag, profile, interpretation, and authority IDs.

Each authority has publisher, status, kind, URL, version, publication date, and notes. `final`, `draft`, `guidance`, and `internal` are distinct states. `QG.ENGINEERING` describes PQCensus behavior and is not an external standard.

`pqcensus rules --json` exposes the database. `pqcensus explain QG-RSA-SIGNATURE --json` exposes the exact rule. A rule match requires algorithm and verified purpose; the `QG-UNKNOWN-CRYPTO` fallback has no migration targets and is an explicit abstention.

`nist-general` is the shipped profile. An organization-custom profile is a reserved schema shape, not a hidden hosted policy service. Adding a profile requires tests, authority provenance, and benchmark evidence.

## TLS categories

TLS observations are separated instead of collapsed into one label:

- `QG-TLS-LEGACY-PROTOCOL`: legacy protocol constants (SSLv2/SSLv3/TLSv1/TLSv1.1) and the deprecated `ssl.wrap_socket` wrapper. Insecure baseline posture; severity HIGH.
- `QG-TLS-INSECURE-CONFIG`: certificate validation explicitly disabled (`check_hostname=False`, `CERT_NONE`). Severity HIGH.
- Modern version negotiation (`minimum_version`/`maximum_version` with TLSv1.2/1.3) is recorded on the generic TLS context finding at LOW severity; the standard `ssl.create_default_context()` abstention remains LOW.
- TLS cipher suites: `ECDHE*` suites are generic classical ECDH key agreement and do not prove X25519; `TLS_RSA_*` suites are RSA key transport.

X25519 and X448 have separate rule IDs even though both belong to the key-establishment migration class. A concrete curve/group is only reported when the source names that primitive explicitly.

Legacy and insecure TLS findings are configuration postures, not Shor-migration claims; they are distinguished from public-key migration findings so a deployment can address protocol age before planning PQC migration.
