# PQCensus benchmark evidence

PQCensus uses multiple independent evidence layers because no single metric can simultaneously prove test execution depth, semantic detection behavior, real-code precision, repository-scale robustness, and performance.

## Layer 1 — synthetic semantic corpus

`benchmarks/quantumguardbench.json` is a manually declared corpus covering Python aliases, wrappers, purpose inference, configuration, dependencies, negatives, test-only code, and unknown-purpose cases.

Its labels are semantic units rather than raw substring matches. The benchmark reports TP/FP/FN, precision, recall, F1, algorithm/purpose/analyzer breakdowns, unknown rate, parse failures, migration-purpose accuracy, dangerous cross-class mapping errors, runtime, memory, deterministic repeatability, and output-schema validation.

## Layer 2 — curated real-code excerpts

`benchmarks/real-code.json` contains short, license-compatible excerpts pinned to upstream source from pyca/cryptography, PyJWT, and PyCryptodome. `benchmarks/provenance.json` records source URL, commit, path, upstream hash, license, and the basis for each human label.

Labels are independent from PQCensus output and are explicitly described as author-curated/unreviewed rather than an external audit. Ground truth is call-site based where appropriate, preventing a file containing several cryptographic uses from collapsing into one easy positive.

## Layer 3 — pinned end-to-end repositories

`benchmarks/end-to-end.json` points to complete, license-compatible snapshots of python-jose 3.3.0 and PyJWT 2.10.1 committed under the benchmark corpus. `benchmarks/end-to-end-provenance.json` records pins, tree/source identity, licenses, and selected manual required observations.

This layer validates:

- bounded repository-wide traversal;
- parser robustness;
- dependency discovery;
- required observations;
- minimum-finding contracts;
- deterministic repeatability;
- official SARIF 2.1.0 validation;
- CycloneDX 1.7 validation.

The required observations are **partial coverage assertions**, not an exhaustive annotation of every cryptographic call site. Therefore end-to-end results support repository-scale smoke claims, not a universal precision percentage.

Complete upstream test snapshots can contain deliberate public test certificates/private-key fixtures. They are retained only as provenance-bound upstream test data and are not PQCensus credentials. See `benchmarks/THIRD_PARTY_NOTICES.md`.

## Layer 4 — deterministic scaling and resource regression

`scripts/performance_gate.py` generates deterministic Python source corpora, writes them to a temporary directory, and scans them as data. Target source is never executed. The gate records:

- files per second;
- lines of code per second;
- wall-clock duration;
- process peak RSS;
- generated files versus files actually analyzed.

Normal quality validation exercises a 100,000 LOC tier. The maintainer release check exercises both 100,000 and 1,000,000 LOC tiers. The performance gate uses conservative portability floors of 1,000 LOC/s, 1 file/s, and at most 1,024 MiB peak RSS. Those values are regression floors, not performance promises; absolute measurements depend on hardware, operating system, filesystem, Python build, and concurrent load.

The scaling corpus measures traversal/analyzer throughput and memory behavior. It is intentionally separate from precision and recall, because fast scanning of synthetic code does not establish detection quality.

## Independent quality gates

PQCensus treats these as separate release properties:

1. **statement and branch coverage** — the test suite must execute at least 90% of measured statements and 80% of measured branches;
2. **precision** — synthetic and curated corpora must stay above their committed false-positive gates;
3. **recall** — synthetic and curated corpora must stay above their committed false-negative gates;
4. **performance** — deterministic scaling must remain inside the committed throughput and peak-RSS floors.

Coverage is not a substitute for detection quality. A line can be executed without its security semantics being validated, so increasing coverage must not weaken the precision, recall, rule-regression, mutation, or end-to-end gates.

## 0.1.0 benchmark contract

The 0.1.0 candidate measurements are:

- synthetic: 26 cases, 26 labeled findings, TP 26 / FP 0 / FN 0, precision/recall/F1 1.0, severity mapping 26/26, zero dangerous cross-class migration mappings;
- curated real code: 5 excerpts, 6 labeled call sites, TP 6 / FP 0 / FN 0, precision/recall/F1 1.0, migration-purpose accuracy 6/6, zero dangerous cross-class migration mappings;
- end-to-end: python-jose 3.3.0 + PyJWT 2.10.1, 96 files, 193 findings, 12/12 selected required observations, no missing required dependencies, zero parser errors in the required cases, deterministic repeatability, and official SARIF/CycloneDX validation.

These numbers are descriptive of the benchmark corpus and must not be treated
as release authority by themselves. Release authority is not currently established.
The release evidence architecture is designed to bind:

- exact source commit and deterministic source fingerprint;
- rule and corpus identities;
- hashes of all three result files;
- Python/runtime environment;
- resolved build and validation toolchain versions;
- gate commands;
- OS and architecture.

Human-readable host or runner names are intentionally excluded from release provenance.

The convenience files `benchmarks/latest-results.json`, `benchmarks/real-code-results.json`, and `benchmarks/end-to-end-results.json` are local development snapshots. They are ignored, not committed, not release authority, and deliberately outside the release-source fingerprint.

These measurements are corpus-specific and author-curated. They do not imply 100% accuracy on arbitrary repositories, languages, frameworks, generated code, KMS/HSM infrastructure, or runtime-only cryptography.

## Reproduction

Synthetic:

```bash
python scripts/run_quantumguardbench.py \
  --manifest benchmarks/quantumguardbench.json \
  --official-sarif \
  --require-precision 0.98 \
  --require-recall 0.95
```

Curated real code:

```bash
python scripts/run_quantumguardbench.py \
  --manifest benchmarks/real-code.json \
  --official-sarif \
  --require-precision 0.95 \
  --require-recall 0.95
```

End to end:

```bash
python scripts/run_end_to_end.py \
  --manifest benchmarks/end-to-end.json \
  --official-sarif
```

Coverage:

```bash
python -m pytest \
  --cov=quantumguard \
  --cov=pqcensus \
  --cov-branch \
  --cov-report=json:coverage.json
python scripts/coverage_gate.py \
  --report coverage.json \
  --min-statement 90 \
  --min-branch 80
```

Scaling:

```bash
python scripts/performance_gate.py --loc 100000
python scripts/performance_gate.py --loc 100000 --loc 1000000
```

The full release gate runs the semantic, real-code, end-to-end, coverage, lint/format, package, and standalone checks, and additionally runs the 100k/1M scaling certification:

```bash
python scripts/release_check.py
```

## Development results vs release evidence

Version-bound evidence under `benchmarks/releases/<version>/` is generated after the complete release gate from the exact release source. `release_source_check.py --evidence ...` verifies that the committed evidence still belongs to that source.

Corpus identity is derived from the current manifests, provenance, and corpus bytes rather than copied from a development-result cache. This prevents a stale cache from either invalidating fresh evidence or falsely certifying changed benchmark inputs.

## What invalidates benchmark evidence

The explicit release-source fingerprint binds analyzer/runtime code, tests, rules, schemas, benchmark manifests/corpus, examples used by release gates, release scripts, package metadata, and the composite Action. `.gitattributes` is also bound because Git checkout byte policy affects provenance-sensitive corpus material.

Explanatory documentation, community files, and top-level development result caches are intentionally excluded from the measurement fingerprint. A documentation or cache synchronization change should not pretend to be a new scanner measurement, while a rule, corpus, analyzer, test, package, Action, or release-policy change must invalidate old evidence.
