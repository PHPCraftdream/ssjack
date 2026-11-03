# Fixed desired-schema plan preflight

This isolated package composes existing plan-binding/time admission and pinned
value validation. It returns only a canonical plan digest, never desired bytes,
projections, an executable plan or execution permission. Production declarative
MCP remains deny-only and does not import this package.

`New(Config)` requires an explicit bounded schema document, exact schema ID and
domain-separated digest, target label and kind. It validates the chosen external
schema dialect and digest, validates Name labels, and owns canonical schema
bytes. Caller mutation of the original document cannot change the Checker. No
file, endpoint, enrollment record or default schema is selected.

`Checker.Check(raw, now)` copies bounded plan input, runs complete structural and
explicit time-window checks, then requires exact desired schema ID/digest, target
and kind matching the fixed Checker. It validates desired through the existing
`driverprotocol.ValidatePinnedValue` at the existing 32-KiB limit. Alternate
schema pins claimed by the plan are not accepted. Every error returns no digest
and no backend validation detail. Zero/nil Checkers fail closed.

Supplied configuration is not human enrollment, trusted-root provenance,
authorization, freshness/clock trust or evidence that declared properties are
true. Target labels are compared exactly; canonical target/resource aliases,
resource ID, full driver/principal/policy/enrollment identity and runtime artifact
bindings still require independent trusted checks. Neither these checks nor the
plan digest permits reserve/apply/replay. Approval-required and destructive
execution remain forbidden by production policy; a structurally admitted effect
is not a delegated effect. A caller must reauthorize and revalidate at the actual
operation gate. No state or secret is persisted or delivered.

Tests use an independent literal canonical schema digest, positive admission and
schema ownership, desired range/type/required/extra-property failures, coherently
changed target/kind/schema IDs/digests that still pass structural admission,
invalid pins, zero Checkers and retained time/structural/input-size gates. Public
Feature CI provides execution evidence; no local tests or real credentials are
used.
