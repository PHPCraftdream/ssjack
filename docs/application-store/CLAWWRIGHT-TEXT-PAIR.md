# Pinned selected-text composition

Status: **AUTHORED-NOT-RUN**. This file records the task260 acceptance design, not a passing result.

The paired workflow checks out Clawwright `765efb5eb33934c189bf372a8464e31e2ae9421f` and the explicitly selected ssjack revision. It prints both exact Git revisions and requires `TestClawwrightTextPairConnected` to report PASS without SKIP. Feature and full workflows both call this gate.

## Observable path

A root test parent registers finite, distinct synthetic grants for a non-root child. The child uses the existing encrypted application-store fixture and real adapter constructors/listeners. A real Clawwright source CLI loads a temporary deployment and invokes its registered `deploy-text` and `backup-text` commands. Delivery uses the actual `remote.NewCredentialStreamRunner`, authenticated loopback SSH with generated in-memory keys, and a fixed-host-key callback. The isolated target permits only fixed read/write commands for its selected configuration.

The authored positive path hydrates two overlapping literal values into the approved target, backs up the selected source into exact canonical versioned placeholders without rewriting the target, changes the target as test setup, and restores the captured copy to the original target bytes. Operator-owned files and bounded CLI diagnostics are checked for the configured synthetic values. Target plaintext is deliberate final-consumer storage, not operator staging. Secret-bearing SSH stderr is deliberately injected and must remain discarded.

Counterfactuals cover an absent adapter context, wrong expected profile, wrong selected file, oversized forward input, missing object/version mappings, equal mapping values, and duplicate approved references. Refused pre-dispatch calls must not reach the SSH target; successful controls and invocation counts accompany the negative cases.

## Boundaries

The test reuses accelerated **test-only** installation derivation; it does not change production KDF parameters or the 1000 actual data-encryption layers. Production KDF coverage remains a separate required full-CI job. Root registration is an explicit synthetic fixture action, not an unattended production enrollment feature. The test does not exercise the interactive approval/unlock prompts or claim application authentication/adoption.

It covers the existing selected-text profile: forward templates at most 32 KiB with canonical exact references, reverse raw/transformed text at most 1 MiB, finite approval and operation deadlines, pinned HTTPS/MCP, and no raw fallback. Component boundary/uncertainty tests remain required; this gate composes the actual consumers rather than replacing those tests with mocks.

Users own mapping completeness, representation/escaping, file selection and consumer storage. Unknown or derived secrets are not certified absent. No arbitrary-document round-trip, universal sandbox, production enrollment, durable replay ledger, native/ptrace integration or OpenClaw authentication guarantee is introduced.

No local compiler, parser, formatter, test, application or KDF execution was performed while authoring this candidate. Public CI and exact execution receipts are required before acceptance.
