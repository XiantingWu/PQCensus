# Security model

The scanned repository is untrusted. Default behavior is static inspection only.

PQCensus does not import target Python modules, run package scripts, install target dependencies, invoke `npm`, `cargo`, Maven, Gradle, Make, shell files, or repository binaries. Dependency manifests are parsed as data. The bounded TLS command performs one certificate-validating handshake, sends no application data, and has a 30-second hard maximum timeout.

Scanner boundaries:

- symlinks are skipped, including directory escapes;
- files over 2 MiB, repositories over 10,000 selected files, and aggregate source over 100 MiB are bounded by default;
- binary files, archives, VCS data, virtual environments, build outputs, vendor trees, and `node_modules` are skipped;
- AST syntax, recursion, value, memory, and parser errors are reported rather than crashing the scan;
- evidence stores source locations, a short semantic description, and a one-line hash, not full source bodies;
- no source, account, API key, or cloud upload is required.

An opt-in external analyzer would need its own sandbox, timeout, resource limits, and threat documentation. No such execution integration exists in 0.1.0.
