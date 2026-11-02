# Trusted text adapter v1 (task257 source candidate)

This additive Linux/amd64 adapter is separate from the accepted synthetic/native delivery path. It is not runtime-accepted: tests are authored, not run, and parent public CI and source review remain required. Clawwright deploy integration is task258; reverse selected-copy transport is task259.

## Human setup and entry

Use the existing declarative authority setup before registration. `ssjack -p PROFILE --vault VAULT text-adapter identity` unlocks the SSH vault in a non-root terminal and prints only the public credential-identity digest. Root `ssjack text-adapter register` interactively records and confirms a distinct text-adapter grant; `ssjack text-adapter revoke GRANT_ID` revokes it. Synthetic delivery grants do not authorize this adapter.

`ssjack -p PROFILE --vault VAULT text-adapter serve GRANT_ID HARNESS [ARGS...]` checks the grant, prompts privately for vault and application-store unlock, and runs the harness with the existing ephemeral pinned-TLS application transport. No secret values are passed in argv, environment, or application-transport replies. Only existing transport bootstrap credentials enter the child environment.

The root-owned grant binds recipient UID, exact store directory device/inode, encrypted installation hash, encoded snapshot hash, 1–16 exact canonical references from the same store/snapshot, profile, public credential identity digest, exact destination command, exact absolute file metadata, hydrate-v1 direction, and UTC expiry at most 24 hours away. The command consumes transformed stdin; file metadata is checked for equality, not interpreted as permission or substituted into a shell command. The human must verify that the approved command writes the intended destination. Final target plaintext is permitted when explicitly approved.

Credential identity is SHA-256 of canonical JSON with keys address, host_keys, profile, ssh_signer_fingerprint, user. Host-key strings are sorted; signer fingerprint is OpenSSH SHA256 of the public key. This digest contains no template or application-secret bytes. Changing address, user, key, pins, or profile requires a matching new approval.

## Task258 transport contract

Require `text_hydrate` in `transport_info.capabilities`; otherwise retain the caller's fail-closed refusal. Call MCP tool `text_hydrate` on the existing authenticated pinned-TLS child endpoint:

The dedicated text listener advertises only text_hydrate and exposes no generic transport_start, transport_input, transport_read, or transport_cancel tools. Existing raw Listen sessions are unchanged. Task258 must use this separately launched text context, not mistake it for the general deploy transport.

```json
{"operation_id":"AAECAwQFBgcICQoLDA0ODw","file":"/approved/config","mode":"hydrate-v1","template":"caller-selected text containing approved exact canonical references"}
```

Operation ID is canonical unpadded base64url encoding of 16 bytes. File must exactly equal the grant. Template is ordinary caller data, bounded to 32768 UTF-8 bytes. The reference mapping is fixed by the grant, not supplied as authority in the request. Each capability attempts at most one valid operation. There is no cross-process replay ledger: never automatically restart/retry an uncertain operation.

The only application result is `{"status":"withheld"}`, `{"status":"received"}`, or `{"status":"unknown"}`. Withheld means no destination runner invocation. Received requires stdin consumed and a zero remote command exit with final checks; it does not prove application adoption or correct storage. Unknown means effects may have occurred, including nonzero exit, cancellation, lost reply, or late authority failure. Remote stdout/stderr are discarded and runner errors are not returned. A lost response is uncertain even if the process completed.

## Bounds and matching responsibility

One selected file per capability, at most 16 mappings in one immutable snapshot, at most 1 MiB aggregate selected secret bytes and 1 MiB output, and a 60-second maximum operation deadline bounded by grant expiry. Engine support for 128 mappings is not an adapter guarantee. Mappings use canonical exact-reference bytes, not arbitrary caller tokens. Replacement is literal, single-pass, and nonrecursive; unmatched ordinary text is preserved. The user owns file selection, representation, mapping completeness, consumer compatibility, and final target storage. No unknown or derived-secret discovery is promised.

Matching follows the accepted engine: leftmost-longest, nonoverlapping matches; output is never rescanned. Equal references or equal secret values are rejected even during hydration. Empty values and values containing the literal `$ssjack` marker are rejected. JSON quoting, escapes, URL encoding, and derived representations are not applied automatically; provide a consumer-compatible exact value and template or the selected text may be incompatible. Only configured literal matches are covered.

This adapter accepts only hydrate-v1. Reverse modes are rejected before destination effects; the existing synthetic reverse mode is unchanged. Returned secret-bearing text must not later be routed through generic transport_read: task259 needs a private trusted read path and must never rewrite live files as a backup side effect.

## Verification boundary

`TestTextAdapterConnected` is an authored, gated root-only disposable-CI acceptance test. Its root parent registers and loads authority; a child running as UID 65534 uses an encrypted accelerated test fixture, constructs the real `NewTextAdapter`, and sends a pinned-HTTPS `text_hydrate` request. The authorized runner receives exactly the synthetic substituted text, while its stdout/stderr are discarded. The test covers absent, revoked, wrong-credential, wrong-profile, wrong-reference, snapshot-hash, expired-registration, wrong-file, oversized-input, and replay cases, including runner-effect counters. This fixture exercises the registration API, not interactive CLI approval.

`TestTextAdapterBounds` is an authored, gated root-only disposable-CI acceptance test. Its root parent registers each exact grant and launches a known UID-65534 child using encrypted fixtures, which constructs the real `NewTextAdapter`. It covers repeated and multiple exact references in one input; aggregate-secret overflow using one placeholder whose output remains below the output cap; 17 × 64 KiB expansion with a template below 32 KiB; accepted under-limit aggregate/output controls; and runner-context deadlines for the 60-second operation window, exact grant expiry, and caller deadline. Deadline checks inspect context values without sleeping. Child stdout/stderr are combined in a labelled 16 KiB-bounded diagnostic buffer that marks truncation; the parent kills and reaps the known child once on failure.

`scripts/ci/text_adapter_scoped.py` runs both `TestTextAdapterConnected` and `TestTextAdapterBounds` with the root gate enabled and rejects `SKIP`; both required `PASS` results are required by CI. `NOTRUN` means no validation claim: no tests, builds, parsers, formatters, or applications were executed during source authoring. Parent public scoped/full CI and source review remain required. An actual Clawwright caller is still task258; generic transport has no durable cross-process idempotency ledger, so uncertain operations must not be automatically retried.
