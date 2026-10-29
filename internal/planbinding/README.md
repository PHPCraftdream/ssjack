# Isolated plan-binding prerequisite

`Validate` accepts one bounded JSON binding, validates its closed structural shape,
internal equalities, sorted effects and effects digest, and returns the plan-domain
digest of canonical bytes. Alternate valid JSON spellings are accepted; digest-map
keys must already be sorted. Desired is a bounded object, not a schema document.
Effects use the full `(class, summary_id, destructive)` ordering, with false before
true as the final tie-breaker. Exact duplicate tuples and reversed input are
rejected, not silently sorted. Structural admission of destructive effects does
not authorize their execution. Principal issuer and subject are strings of at
most 256 Unicode scalars, including empty strings.
Artifact maps contain 1–128 entries and dependency maps 0–128; keys are bounded
canonical JSON strings and values are lowercase digests. No Name grammar is imposed
on map keys by the documented map type.

`ValidateAt(raw, now)` additionally checks one explicit clock observation after
complete structural admission: `created_at < expires_at` and
`created_at <= now < expires_at`. Creation is inclusive; expiration is exclusive,
including sub-millisecond clock observations. A zero clock is rejected. Input is
size-capped and copied before validation; every failure returns no digest. Success
returns the same canonical plan digest as `Validate`. No lifetime cap is invented.
There is no wall-clock lookup, trusted clock, rollback detector or automatic
revalidation at a later action. The caller must supply a trustworthy observation
and recheck at the actual gate; this result is not a freshness capability or
permission to execute. Existing `Validate` remains clock-independent.

`Validate` is descriptive, not an authorization or a complete plan validator. It does
not authenticate enrollment or principal, resolve aliases, compare identity, schema,
policy or digests to trusted enrollment, validate desired against its schema,
evaluate effects or policy, verify timestamps against each other or a clock,
check expiry, enforce freshness, or persist/reserve/apply anything. The caller
must independently perform all such checks. No production path imports it.
