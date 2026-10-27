# Declarative MCP specification

**Status: proposed design plus partial runtime integration.** The runtime is an incomplete slice; the proposed v1 contract below is not implemented. This directory contains exactly seven documentation pages: this overview and the six pages listed below.

## Pages

- [Protocol](protocol.md): session negotiation, tools, schemas, errors and limits.
- [Driver](driver.md): human enrollment, schema/artifact distribution, execution and framing.
- [Policy](policy.md): policy, canonical binding and approval availability.
- [Lifecycle](lifecycle.md): recovery, durable operations, retries and cancellation.
- [Conformance](conformance.md): synthetic future acceptance criteria.
- [Common schemas](schemas.md): deterministic JSON Schema grammar, descriptor/tool DTOs and digests, and exact enrollment record shapes.

## Driver execution status

There is no production driver runner or launch path. Immutable artifact binding remains missing, and driver execution is not implemented. The disconnected, untracked `internal/driverexec` and `internal/driverframe` packages (including their tests) are removed; no production transport implementation exists. Do not infer an empty child environment or any other environment guarantee on Windows.

Execution remains a proposed contract, not an implemented security boundary. Outstanding obligations include immutable artifact binding and race-free execution, dependency/configuration identity, verified OS identity and privilege enforcement, environment control, sandboxing and network/filesystem containment, guaranteed descendant termination, durable operation state, enrollment and full schema validation, and safe output projection. Arguments and driver code cannot be treated as isolated or independently trusted; drivers remain trusted executable code. No successful production invocation or validation is established here.

## Optional enrollment metadata (current partial integration)

`ssjack --mode declarative --enrollment-metadata ABSOLUTE_PATH run HARNESS [ARGUMENTS...]` opts into loading a metadata file before a declarative run. The flag is a root CLI option and must appear before `run`. It requires a non-empty absolute path and `--mode declarative`; it is not accepted for other commands or full mode. With the option absent, declarative mode retains its existing partial deny-all descriptor. With valid metadata, the keeper reports a second descriptor discriminator, `ssjack-enrollment-partial-1`, containing the enrollment and driver identifiers; it remains incomplete and advertises no tools.

The accepted JSON object has exactly these fields and values:

```json
{
  "format": "ssjack-enrollment-metadata-v1",
  "enrollment_id": "<canonical unpadded base64url encoding of exactly 16 bytes>",
  "driver_id": "<v1 Name>",
  "driver_protocol": 1
}
```

The input is bounded to 4096 bytes. The parser accepts ordinary JSON whitespace and escaped string representations; canonical JSON byte formatting is not required. It rejects malformed UTF-8/JSON, duplicate, missing, unknown or trailing data, and invalid values. Metadata is descriptive and non-authorizing: it does not enable tools, authorize requests, or execute tools or drivers. The metadata descriptor is public; this does not establish authentication or provenance for its contents.

On supported Unix platforms, file loading uses no-follow opens for path components and rejects symlinks. Other/unsupported operating systems, including Windows, fail closed. This does not establish protections against hard-link substitution, mount/path namespace manipulation, or other provenance attacks; the metadata file's provenance must be controlled independently.

### Acceptance criteria and non-goals

- Opt-in only; absent metadata leaves the current declarative descriptor behavior unchanged.
- Valid metadata produces only the incomplete, zero-tool `ssjack-enrollment-partial-1` descriptor; invalid input or unsupported path/platform fails closed.
- Loading/parsing metadata itself invokes no tools or drivers and grants no authority. Declarative mode skips credential loading, so this path performs no new secret reads.
- This partial integration is not the complete v1 enrollment flow and does not authenticate metadata or guarantee authentication provenance, implement a driver runner, authorize execution, deliver secrets, or provide secret-handling guarantees. It makes no blanket guarantee about secret reads or secret absence.

## Security invariants

Only the human launcher selects full or declarative mode. The authenticated keeper session fixes that choice; `both` is invalid. The new bridge supports declarative mode and retains the legacy full-mode path. Its default partial declarative slice advertises no tools and uses `ssjack-declarative-partial-0`; when optional enrollment metadata is supplied, the incomplete zero-tool descriptor instead uses `ssjack-enrollment-partial-1`. Neither discriminator is proposed protocol v1. Bridge startup requires a descriptor and fails closed if absent or invalid. Old keepers that do not recognize declarative mode fail closed and deny launch. The legacy bridge may display full-mode tool names, but the keeper denies requests and cannot grant authority. Full mode has exactly eight tools: `remote_targets`, `remote_exec`, `remote_read`, `remote_cancel`, `app_list`, `app_exec`, `app_read`, `app_cancel`; proposed declarative mode has exactly six tools, unavailable in this partial slice. Declarative uses a dedicated dispatcher and cannot call `remote_*`, `app_*`, child transport or another admin credential. Rejection never falls through to full dispatch. Current `remote_*` is shell-capable; `app_*` is not a restricted subset. `confirm=true` is not approval. Cross-version behavior is untested.

Drivers are trusted executable code, not sandboxes. Human enrollment binds executable/dependency identities, configuration, principal, target, schema, permissions, output vocabulary and limits. Broad root, Docker/Incus, sudo, Nix trusted-user or alternate-shell access defeats least privilege; same-user processes are not isolated from one another. JSON Schema/redaction cannot prove arbitrary output nonsecret. Only explicitly reviewed typed fields may leave the driver; unknown/free-form values fail closed. V1 has no driver implementation, SecretRef resolver or secret delivery. No exception approval mechanism is implemented or specified.

Enrollment records and exact schema documents must be distributed to clients through an independently controlled, authenticated human process before execution. Schema IDs are immutable and digest-bound within an enrollment; changed content requires reviewed revision and redistribution. Clients validate locally: no driver, registry, network or foreign schema lookup. Schema IDs and schema digests are defined in [schemas](schemas.md); no external schema bundle or lookup is used.

**Pre-invocation versus post-invocation:** a failure proven before the durable invocation-start marker/process call means no driver invocation. Once invocation may have started—including marker persistence, timeout, crash, malformed response, lost acknowledgment or uncertain commit—mutation outcome is unknown; never automatically retry apply. See [lifecycle](lifecycle.md) and [conformance](conformance.md).

**Attachment recovery is deliberately not reconnectable.** Existing keeper bootstrap is one-use. After claim, bridge disconnect, timeout or process loss does not enable a second claim, token refresh, reconnect, alternate credential or foreign lookup. Affected resources are durably quarantined: no model reads, automated continuation or mutation until human inspection and fresh authorized launcher session; if scope cannot be determined, quarantine the enrollment/session. Do not retry a possibly-started mutation. This is recovery procedure, not authentication. No local prompt, TTY, account identity, model confirmation or typed phrase proves human identity. Independently authenticated approval/recovery is unspecified and must not be invented.

Keeper owns authorization, scope, policy, plan binding, operation records and safe projections; drivers own domain semantics. `observe` is mandatory, read-only, and the basis of plan preconditions and no-op confirmation. Resource interlocks use canonical target/resource identity across sessions, aliases and re-enrollments; uncertain outcomes quarantine that resource and deny reads/planning/apply until human-reviewed recovery. Revocation or policy/enrollment changes invalidate plans and must be rechecked before invocation. Cancellation is a durable intent, not proof detached work stopped or a rollback. Unknown capabilities are unsupported, never guessed. Protocol documentation does not change existing pinned loopback TLS, one-use environment bootstrap, framed Ktav wire, or bridge behavior.

Protocol, schema, desired and plan digests use policy `JCS-SSJACK-1` integer-only canonical JSON. Domains are `ssjack-schema-v1`, `ssjack-tool-schema-v1`, `ssjack-plan-v1`, `ssjack-desired-v1`, `ssjack-effects-v1`, and `ssjack-enrollment-v1` (ASCII + NUL + canonical bytes). `schemas.md` defines deterministic JSON Schema documents and exact schema IDs/digests; no external bundle or lookup is used. Driver schema subset forbids regex, references, formats, floats and ambiguous composition keywords. Resource schema IDs identify schema documents; resource IDs identify instances. Driver requests/responses are each ≤64 KiB payload (length prefix excluded); outer Ktav encoded frame ≤256 KiB (four-byte prefix excluded). Four ordinary slots and one emergency cancellation slot per enrollment; cancellation has a separate 4096-byte reserve per operation. See policy, driver and protocol.

Tracking references: #131 declarative runtime; #125 application store; #140 crypto/unlock. These identify follow-up tasks only; they do not imply implementation, credentials, approval, or production readiness.
