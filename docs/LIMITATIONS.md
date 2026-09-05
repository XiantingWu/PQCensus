# Limitations and non-claims

- Static analysis cannot see every runtime algorithm choice, reflection path, native extension, generated artifact, or external service.
- KMS/HSM and managed crypto are visible only at the local call/configuration boundary; key material is never inspected.
- TLS 0.1.0 performs one bounded handshake but cannot prove certificate signature or negotiated key-share algorithm through the Python stdlib.
- SSH and X.509 chain inventory are not stable in 0.1.0 and are on the roadmap.
- JavaScript/TypeScript, Go, Java, Rust, and C/C++ token analysis is experimental and low-confidence; it is not a language semantic guarantee.
- Migration output is engineering guidance, not certification, compliance advice, or a drop-in code patch.
- Algorithm availability does not prove implementation validation, side-channel resistance, protocol interoperability, or deployment readiness.
- PQC protocols and ecosystem support continue to evolve; benchmark results apply only to the pinned corpus.
- A supported-language precision result does not imply arbitrary framework coverage.
- No regulatory certification or security certification is claimed.

## Hostile filesystem and resource boundary

The normal audit treats a scan root and its contents as hostile input. Only
regular files with configured source extensions are selected. Symlinks are not
followed, including directory links, links outside the root, broken links,
and loops. FIFOs, sockets, devices, and other non-regular files are skipped.

The default scanner limits are 10,000 selected files, 2 MiB per file, and
100 MiB of selected source bytes. Files exceeding those limits are recorded in
the structured limits section and skipped. A file or directory that becomes
unreadable or disappears during enumeration is recorded and does not turn the
scan into an uncontrolled traceback. Permission errors do not authorize a
fallback to executing or importing the input.

UTF-8 and UTF-8 with a BOM are supported. Invalid UTF-8 is decoded with
replacement for bounded static analysis; UTF-16, NUL-containing, and other
binary-like inputs are skipped. Very deep or malformed Python syntax is
reported as a parser error within the bounded scan rather than executed.

These are safety and availability bounds, not a promise that every file is
analyzed. The limits and policies are release-relevant behavior and changes
require fresh evidence.

The optional enumeration stress harness can exercise the file-count boundary
without adding the generated files to the repository:

```bash
python scripts/hostile_input_probe.py --files 100000
```
