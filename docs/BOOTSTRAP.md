# Memory-only bootstrap and unlocked storage contexts

## Status and compatibility

The current source replaces the former environment/file capability pair with a single environment-only capability. This is an intentional security-model change, not the same two-channel protection implemented differently. It requires matching keeper and bridge binaries. Authentication frames have protocol version 2; old or missing versions fail closed. Database v1/v2 formats remain readable and are not implicitly upgraded by this change.

A running older keeper/bridge pair can continue until the session ends. After installing a new executable, start a new launcher session; an old keeper and newly started bridge cannot attach to each other. Old runtime directories are not read, reused, or automatically deleted.

## Transport and credential handoff

The channel is the existing framed Ktav protocol over pinned TLS 1.3 on literal IPv4 loopback, not an HTTP REST API. Each launch creates one random 256-bit token, a random session identifier, and an ephemeral TLS identity. Only the launched harness receives:

- `SSJACK_ENV_TOKEN`: the single-use capability;
- `SSJACK_SESSION`: the session identifier;
- `SSJACK_ENDPOINT`: the canonical loopback endpoint;
- `SSJACK_CERTIFICATE_SHA256`: the pinned TLS certificate digest.

No bootstrap file or `.ssh/runtime` directory is created. Legacy `SSJACK_BOOTSTRAP_FILE` and inherited bootstrap fields are scrubbed before setting child values. The parent shell is not modified. The bridge removes bootstrap fields from its own environment after reading them, but cannot remove inherited copies from the parent harness or other children.

The bridge validates inputs and the loopback endpoint, checks the TLS pin, and sends the versioned token authentication frame. The keeper atomically consumes the token and binds access to that one established connection. The listener closes after attachment. A lost acknowledgement, replay, disconnect, or expiry does not permit another attachment with the same token. Disconnect still cancels remote jobs.

The database password, private key, Argon2id outputs, and database master never become bootstrap fields or MCP results. Persistent MCP/plugin registration remains secret-free. The protocol removes application-authored plaintext bootstrap writes; it does not make process environment theft impossible.

## When the bridge drops

The token is single-use and the keeper's channel ends with the one connection
that claimed it. The keeper consumes the token when that connection attaches,
before any MCP discovery request. `server/discover` does not consume another
token or cause a restart. If the harness stops or restarts its `ssjack mcp`
child, the new child cannot attach: the listener is already closed and the
token is spent. The only recovery is to leave the harness and start it again
through `ssjack run`, which creates a new channel. A re-attach path would widen
the trust boundary and is not implemented.

The bridge keeps stdio open for unsupported requests: it responds with JSON-RPC
`-32601 method not found`; unsupported notifications are dropped. Admitted requests are `initialize`, `notifications/initialized`, `notifications/cancelled`, `tools/list`, `tools/call`, `ping`, `server/discover`, `subscriptions/listen` and, on revision 2026-07-28 only, `tasks/get`, `tasks/update` and `tasks/cancel`. Served MCP
protocol versions are preferred in this order: `2026-07-28`, `2025-11-25`,
`2025-06-18`, `2025-03-26`, `2024-11-05`. For modern clients, the bridge handles
`server/discover` natively, returning `resultType` and cache information at the
result root, with `serverInfo` in `result._meta` (not as a normal root field),
without requiring `initialize`. If a legacy
client instead sends `initialize` with an unknown or modern protocol version,
the bridge falls back to its newest legacy version, `2025-11-25`; the older
served versions remain available. A `_meta` protocol mismatch returns
`-32022` with `data` identifying the supported and requested versions. The
client must not retry the spent token or re-attach.

The bridge is tools-only. The one extension it serves is `io.modelcontextprotocol/tasks`, and only for `remote_upload` and `remote_download` on revision 2026-07-28 (MCP-TASKS.md); MRTR, roots, sampling, resources and prompts are not implemented. Modern logging and `ping` are removed; legacy
`ping` remains available. JSON-RPC `-32020` through `-32099` are reserved, so
the bridge defines no custom errors in that range beyond the stated
`-32022` mismatch response and the standard `-32021` missing-client-capability
answer of the tasks extension.

`subscriptions/listen` acknowledges only requested notification types that
are allowed. A genuine asynchronous tool-list registration can enable tool-list
change notifications; there are no invented streams or secret-bearing events.
If nothing is both requested and available, the SDK acknowledges with `{}` and
the listen completes. At most one listen is active; an accepted listen is not
cut short by a fixed budget, but stays open for the lifetime of the session and
ends only on client cancellation, transport close or bridge shutdown, and a
shutdown cancels a parked listen instead of waiting for it. A listen does not
block other requests. `tools/list` results follow the `2026-07-28` cache
rules: they carry `ttlMs` and a private `cacheScope`, and their tools appear in
the registry's stable name order. The hint only states how long a cached answer
may be served; whether and how a client caches, and when it fetches again, is
the client's choice. `tools/list_changed`
tells a subscribed client that its cached list is stale and leaves the refresh
to that client; it neither schedules a fetch nor guarantees one. The upstream
SDK is untouched; its internally pinned protocol baseline is `2025-06-18`.

To find out why a bridge dropped, the keeper and the bridge append fixed
lifecycle events to `.claude/ssjack/lifecycle.log` in the project (owner-only
mode, rotated once to `lifecycle.log.1` above 1 MiB). The keeper hands the path
to the bridge in `SSJACK_LIFECYCLE_LOG`; an inherited value is scrubbed. A line
looks like:

```text
2026-11-15T12:00:00.123Z pid=4242 role=keeper sid=1a2b3c4d event=shutdown reason=attached-connection-ended
```

`sid` is a short digest of the session identifier, enough to match keeper and
bridge lines of one launch. Events and their fields:

| Role (`role=` in the line; the bridge process logs as `mcp`) | Event | Fields |
| --- | --- | --- |
| keeper | `listen` | `ttl_ms` |
| keeper | `harness-start`, `harness-exit` | `pid`; `code`, `context` |
| keeper | `accept-refused` | `reason`: `not-loopback`, `handshake-slots-full`, `already-attached-or-stopped` |
| keeper | `attached` | none |
| keeper | `request` | `op`, `ok`, `ms` |
| keeper | `connection-end` | `attached`, `stage`, `cause`, `requests`, `ms` |
| keeper | `shutdown` | `reason`: `attached-connection-ended`, `bootstrap-ttl-expired`, `parent-cancelled`, `closed` |
| mcp | `start` | `ppid` |
| mcp | `attached`, `serving` | none |
| mcp | `call-failed` | `op`, `stage`, `cause` |
| mcp | `stdio-end` | `cause` |
| mcp | `exit` | `code`, `stage`, `context` |

The log never holds a token, the session identifier, an endpoint, a password,
request or reply data, a path or error text. Every value is reduced to
`[A-Za-z0-9_.:-]` and at most 64 bytes, and an error is recorded only as one of
a fixed set of classes (`eof`, `timeout`, `reset`, `closed`, `cancelled`,
`other` and similar; `stdio-end` also names the bridge's own refusals:
`invalid-message`, `unsupported-message`, `stdio-limit`, `concurrent-read`,
`unsupported-batch`, `stdio-write-timeout`). Each acknowledgement, ordinary
response, and legacy batch response has a 15-second stdio write bound; when it
expires the bridge latches the failure, ends the session and logs
`stdio-write-timeout`. The bound does not depend on the peer releasing the
blocked operation: a timed-out write and a read that outlives a close are
abandoned instead of joined, so a client that keeps stdin open and stops
reading stdout cannot delay session end or process exit. An abandoned
operation may keep its goroutine until process exit and never writes a later
frame.
Operation names (`op`) are recorded; their arguments are
not. The file is diagnostic only: nothing reads it back to make a decision, so
editing it grants nothing. Failing to write it never fails a launch. The
ssjack-ui Claude Code plugin reads only the tail of this log to display a
recovery frame when the attached connection has ended; it is display-only, and
the log remains write-diagnostic: nothing acts on it, and editing grants
nothing.

## Single-channel threat model

The old guarantee that stealing only the environment capability is insufficient no longer applies. Anyone obtaining the child's full bootstrap environment before attachment can race the intended bridge. TLS pinning protects transport identity, not against an attacker who has stolen the endpoint, pin, session ID, and bearer token together. Processes sharing the same harness connection are not distinguished as individual models.

Loopback is not OS-user isolation. Same-user inspection, administrators, debuggers, dumps, environment snapshots, swap, hibernation, and OS-generated copies are not prevented by keeping application buffers in RAM. Disabling or encrypting those OS facilities is a separate host policy. Do not promise that RAM-only application behavior implies no physical storage copy anywhere.

## Cached storage encryption

`vault.Load` now retains an owned memory-only `keyfile.Unlocked` context after authenticating the complete container. Four independent sequential production Argon2id calls still use 1 GiB each; their outputs are combined through the existing HKDF. Raw intermediate outputs are cleared as before. Only the resulting master and public parameters are retained, not a plaintext password cache or a serialized password verifier.

Normal record/pin/policy/key updates use `SaveUnlocked`, avoiding another password derivation within the same unlocked CLI invocation. Every write still performs all 1000 nested AES-256-GCM data encryptions before the encrypted same-directory staging file is opened. Authenticated salts and master are reused within that invocation, but each seal generates a fresh random 96-bit nonce base. Per-purpose/per-layer key derivation, version-bound AAD, payload bounds, and reverse authentication remain unchanged. Fresh random nonces provide probabilistic uniqueness; they are not a guarantee of collision-free unbounded reuse.

`Vault.Close` clears the accessible owned master buffer and private payload buffers. Repeated close is safe, and closed contexts refuse encryption. No master is stored in the container, temporary file, environment, or bootstrap. Ordinary CLI secret prompts remain per invocation, not a persistent service-wide password cache.

Changing the database password is different from an ordinary update: it derives a fresh master with fresh salts, writes under the new secret, and replaces the retained context only after successful revision-checked publication. Failure/cancellation retains the previous context and working file. Subsequent cached writes use the new context, never the old password. Standalone key generation and explicit format upgrade retain their own fresh derivation boundaries.

The container composition remains custom and independently unaudited. Reusing a cached master does not increase password entropy, make 1000 layers imply 1000-fold security, or prevent the outer GCM tag from checking a candidate master. Clearing Go-owned byte slices does not guarantee clearing every runtime or cipher-schedule copy.

## Verification requirements

Regressions cover child-only environment handoff and stale-variable scrubbing, absence of runtime directories on success/failure, version/token/session rejection, pinned-loopback TLS, one concurrent winner, replay and disconnect, cached KDF call counts, fresh nonces, retained format/salts, all data layers, close-buffer clearing, wrong-password failure, and explicit password-change context replacement. Tests and builds run only in authorized GitHub CI; writing these checks is not evidence of a passed run.
