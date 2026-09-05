# Suppressions

Suppressions are visible and auditable. An inline marker has the form:

```python
# quantumguard: ignore QG-RSA-SIGNATURE reason="legacy test vector" expires=2027-01-01
```

Repository policy lives in `quantumguard.toml`:

```toml
[[suppressions]]
rule_id = "QG-RSA-SIGNATURE"
path = "tests/fixtures/**"
reason = "Pinned interoperability vector; tracked by issue ABC-123"
expires = "2027-01-01"
```

The canonical configuration key is `rule_id`; the early-public-docs alias `rule` is also accepted during 0.1.x for compatibility. Missing reasons are rejected. Expired entries are not silently accepted. The audit output preserves the suppression record and reports its count; suppressed findings remain in the findings list with `status="suppressed"`. Path exclusions and test classification are bounded scanner policy, not unlogged deletion.
