# Detection model

Evidence priority is AST/semantic evidence, then structured configuration and dependency metadata, then constrained heuristics. Repository-wide regex is not the Python scanner.

Stable in 0.1.0:

- Python AST parsing with import aliases, shadowed-import rejection, annotations, conservative variable-type propagation, call/assignment spans, symbol context, and test-path classification;
- `cryptography`, PyCryptodome, PyJWT/JWT, `hashlib`, `hmac`, `ssl`, RSA, EC/ECDSA/ECDH, finite-field DH, X25519/X448, EdDSA, hashes, MACs, KDFs, TLS configuration, ML-KEM, and ML-DSA patterns represented in the benchmark; X25519 and X448 retain distinct algorithm/rule identities;
- structured JSON/TOML and constrained YAML policy keys;
- static dependency metadata for documented ecosystems.

Experimental only: token-constrained JavaScript/TypeScript, Go, Java, Rust, and C/C++ detection. It provides low-confidence discovery hints and is not presented as language-semantic support.

Imports alone, comments, prose strings, registry membership tests, and shadowed aliases do not become Python findings. A dynamic or unresolved purpose is `UNKNOWN` and receives no purpose-specific migration target.
