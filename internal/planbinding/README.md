# Isolated plan-binding prerequisite

`Validate` accepts one bounded JSON binding, validates its closed structural shape,
internal equalities, sorted effects and effects digest, and returns the plan-domain
digest of canonical bytes. Alternate valid JSON spellings are accepted; digest-map
keys must already be sorted. Desired is a bounded object, not a schema document.
Effects sharing a class and summary ID are rejected even when destructive differs;
this is a stricter subset than the documented full tuple ordering. Principal issuer
and subject are strings of at most 256 Unicode scalars, including empty strings.
Artifact maps contain 1–128 entries and dependency maps 0–128; keys are bounded
canonical JSON strings and values are lowercase digests. No Name grammar is imposed
on map keys by the documented map type.

This is descriptive, not an authorization or a complete plan validator. It does
not authenticate enrollment or principal, resolve aliases, compare identity, schema,
policy or digests to trusted enrollment, validate desired against its schema,
evaluate effects or policy, verify timestamps against each other or a clock,
check expiry, enforce freshness, or persist/reserve/apply anything. The caller
must independently perform all such checks. No production path imports it.
