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

The signed dialect acceptance tests are source assertions only: **NOT EXECUTED**
for this change. They assert exact manifest bytes and independently computed
schema and enrollment digests, validation-stage rejection after authentication,
and signature binding to the exact manifest bytes. The defensive digest-mismatch
branch is not naturally exercised: both implementations digest the same bytes.

A caller-supplied `TrustRoot` is not itself evidence of provenance or
authorization. This subset does not establish freshness or rollback protection,
verify OS identity, or enforce runtime limits or policy. MCP stays denied. It
is not full readiness, legal approval, or cryptographic audit approval; full v1
conformance is not established.
