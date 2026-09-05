# Benchmark corpus ownership policy

PQCensus keeps benchmark evidence reproducible without making network availability part of a release claim.

## 0.1.0 decision

The pinned python-jose 3.3.0 and PyJWT 2.10.1 end-to-end snapshots remain vendored for the 0.1.0 line. Moving them immediately to another repository would add a new availability, authorization, and fetch-integrity dependency at the same time as the first public release, while providing little technical value for a corpus of this size.

The vendored snapshots are test data only. They are excluded from the Python wheel/sdist, have independent license/provenance records, and are bound by the release-source/corpus hashes.

## Third-party supply-chain boundary

The complete snapshots are registered in `benchmarks/third-party-corpus.json`
and retain their upstream license files. `scripts/validate_third_party_notices.py`
checks the registration, immutable upstream revision, snapshot tree hash,
license-file hash, source URL, purpose, and checked-out bytes.

The snapshots are not PQCensus runtime or build dependencies. They are not
imported, installed, executed, or distributed in the wheel or sdist. A
vulnerability, dependency-review result, or license alert about a vendored
snapshot therefore describes benchmark input rather than the PQCensus runtime.
Such an alert must be documented with the affected snapshot identity, why the
snapshot is not executable or distributable product code, and any required
remediation; it must not be dismissed without that boundary explanation.

## When to split the corpus

A dedicated benchmark-corpus repository becomes appropriate when at least one of these conditions is met:

- corpus growth materially dominates the main repository clone size;
- benchmark history creates disproportionate Git history growth;
- additional ecosystems require large complete-repository snapshots;
- corpus refresh cadence becomes independent from scanner releases;
- independent corpus maintainers or review workflows are required.

The split must not turn CI into an unpinned `git clone` of mutable upstream state.

## Contract for an external corpus repository

If the corpus is extracted later, the PQCensus repository must retain a small manifest that records, for every external snapshot:

- corpus repository and immutable commit/tree identity;
- original upstream repository and immutable source revision;
- license and third-party notice location;
- expected archive/tree hash;
- selected human observations or label-set identity;
- the PQCensus release/benchmark schema version that consumes it.

CI must verify the downloaded or cached corpus against the committed identity before scanning it. A missing, modified, or unverifiable corpus is a benchmark failure; it must never silently fall back to a different revision.

## Curated fixtures stay local

Small synthetic and curated positive/negative fixtures remain in the main repository even after a future corpus split. They are part of the analyzer regression contract and keep unit/PR validation fast, reviewable, and independent of external network access.

## Release evidence

Performance and detection claims always identify the exact corpus revision/hash used. Moving storage location does not change the rule that precision, recall, required observations, and performance results are valid only for the bound corpus and source fingerprint.
