# Pinned selected-text composition

Status: **AUTHORED-NOT-RUN**. This file records the task260 acceptance design, not a passing result.

The paired workflow checks out Clawwright `506ff2a2802bbfa5cf931f735f1b06aaee7f5244` and the explicitly selected ssjack revision. It prints both exact Git revisions and requires `TestClawwrightTextPairConnected` to report PASS without SKIP. Feature and full workflows both call this gate.

## Observable path

A root test parent registers finite, distinct synthetic grants for a non-root child. The child uses the existing encrypted application-store fixture and real adapter constructors/listeners. A real Clawwright source CLI loads a temporary deployment and invokes its registered `deploy-text` and `backup-text` commands. Delivery uses the actual `remote.NewCredentialStreamRunner`, authenticated loopback SSH with generated in-memory keys, and a fixed-host-key callback. The isolated target permits only fixed read/write commands for its selected configuration.

The authored positive path hydrates two overlapping literal values into the approved target, backs up the selected source into exact canonical versioned placeholders without rewriting the target, changes the target as test setup, and restores the captured copy to the original target bytes. Operator-owned files and bounded CLI diagnostics are checked for the configured synthetic values. Target plaintext is deliberate final-consumer storage, not operator staging. Secret-bearing SSH stderr is deliberately injected and must remain discarded.

Counterfactuals cover an absent adapter context, wrong expected profile, wrong selected file, oversized forward input, missing object/version mappings, equal mapping values, and duplicate approved references. Refused pre-dispatch calls must not reach the SSH target; successful controls and invocation counts accompany the negative cases.

## First composition result

Run `41567828346` on ssjack `989e5cb69dd5665acf5b62d6308e1694636494e8` passed the existing component checks but failed the real CLI composition with Clawwright `765efb5`. The text client advertised only JSON, while pinned MCP SDK v1.0.0 requires both JSON and SSE in the POST Accept header even for its JSON-response mode. Clawwright `506ff2a` fixes that header and adds a request-header regression without relaxing TLS, authority, JSON-body admission or bounds. The updated pin above remains unaccepted until public paired CI succeeds.

## Boundaries

The test reuses accelerated **test-only** installation derivation; it does not change production KDF parameters or the 1000 actual data-encryption layers. Production KDF coverage remains a separate required full-CI job. Root registration is an explicit synthetic fixture action, not an unattended production enrollment feature. The test does not exercise the interactive approval/unlock prompts or claim application authentication/adoption.

It covers the existing selected-text profile: forward templates at most 32 KiB with canonical exact references, reverse raw/transformed text at most 1 MiB, finite approval and operation deadlines, pinned HTTPS/MCP, and no raw fallback. Component boundary/uncertainty tests remain required; this gate composes the actual consumers rather than replacing those tests with mocks.

Users own mapping completeness, representation/escaping, file selection and consumer storage. Unknown or derived secrets are not certified absent. No arbitrary-document round-trip, universal sandbox, production enrollment, durable replay ledger, native/ptrace integration or OpenClaw authentication guarantee is introduced.

No local compiler, parser, formatter, test, application or KDF execution was performed while authoring this candidate. Public CI and exact execution receipts are required before acceptance.
