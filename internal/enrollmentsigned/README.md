# Signed enrollment subset

`Verify` composes `enrollmentauth.VerifyCanonicalBytes` with
`enrollmentvalidator.Validate` on the exact verified bytes and rejects a digest
mismatch. No manifest is returned on failure. The caller must obtain and pin the
trust root independently. The returned manifest is a detached copy.

This isolated composition is not wired into enrollment, execution, or policy.
Success is not full v1 conformance, operator approval, authorization, freshness,
rollback protection, provenance, OS identity or artifact verification, or runtime
policy enforcement. It inherits the validator's conservative restrictions and
schema subset, and the canonical JSON and envelope size bounds documented in
[the validator README](../enrollmentvalidator/README.md). A valid signature does
not establish trust-root provenance or that any declared property is true. In
particular, it establishes neither human approval nor human identity; an
attacker-selected root can validate that attacker's own signed record.

Task 162 and full v1 conformance remain blockers; this subset must not be treated
as a replacement for either.
