# Supervised remote MCP bridge runtime for one confirmed launch

This pocket owns the supervised remote MCP bridge runtime for one confirmed
launch; it runs inside the startup process, which is the only holder of
captured credentials. It consumes launch-owned one-shot upstream capability
handles and the launch union guard. The launch keeps HTTP-owner cleanup
ownership, handed to this pocket only as an explicit close callback. It never
exposes credential values, adds no getter, and holds only the opaque guard
snapshot plus the handles.

The startup-process runtime handles exactly three internal keeper operations
(`mcp_remote_bindings`, `mcp_remote_describe`, `mcp_remote_call`) over the
local keeper wire; these are bridge-internal and never model-facing. The child
bridge's channel wire admits only `describe` and `call` per binding, with the
binding ordinal bound server-side, so the model never issues internal operation
names and never selects URLs, accounts, headers or upstream methods: only
inventory-listed namespaced tools of the selected captured bindings are
reachable, under digest-based namespaces: `mcp` + hex(SHA-256 of the binding
identity)[:6] + `_` (`internal/mcpbridge/internal/supervisor/bounds.go` `bindingNamespace`), so
each binding keeps a distinct tool namespace.

Sessions are lazy: no upstream network happens before the child bridge asks.
Unknown protocol versions are refused by the pinned SDK. The runtime does not
use the SDK `StreamableClientTransport`. `LaunchUpstream.TakeTransport`
(`internal/mcpbridge/internal/supervisor/runtime.go`) accepts only the one-shot `mcphttp` transport
(requires `MaxRetries == -1` and a non-default, non-nil HTTP client) and wraps
it as `mcpexchange.New(endpoint, client)`: an owned, POST-only, one-use
Streamable HTTP transport with fixed `errExchange` diagnostics. The SDK's
private `sessionUpdated` hook and its background SSE listener are therefore
never engaged; there is no SDK-managed stream to leak.

For modern upstream POSTs, the outbound allowlist adds only `Mcp-Method` and
`Mcp-Name` routing headers; each must have one value and case-insensitive
duplicate names reject. No `Mcp-Param-*` headers are allowed. Exchange derives
both headers from JSON-RPC `method` and `params.name`, never `arguments` or
caller-supplied headers; the decoded header name equals the body name. Local
ssjack policy caps method at 256 ASCII `[A-Za-z0-9_./-]`, decoded UTF-8 name at
256 bytes and encoded name at 355 bytes. Safe printable ASCII names may be raw
(internal spaces allowed, no leading/trailing whitespace); controls/non-ASCII,
edge whitespace and sentinel-looking names are encoded as `=?base64?…?=` with
padded standard Base64 per [SEP-2243](https://modelcontextprotocol.io/seps/2243-http-standardization.md).
These numerical caps are local policy; SEP-2243 sets none. Response headers
remain `Content-Type`, `Mcp-Protocol-Version` and `Mcp-Session-Id`; modern
identity, capabilities, `resultType`, `ttlMs` and `cacheScope` remain in JSON.
This describes these header rules only, not full MCP conformance.

The only wrapper is `capturingTransport` (`internal/mcpbridge/internal/supervisor/lifecycle.go`):
it wraps solely our `mcpexchange` transport and records the returned
`mcp.Connection` on the slot so cleanup can close it even if initialization
fails before a session is stored. The captured observed connection preserves `Close` errors and maps discovery transport refusals to a fixed local rejected error so the pinned fallback can run.
Initialization is bounded by an 18 s `ConnectWait` timeout on a derived init
context, while the established connection lives on the slot context, which is
bounded by the 10-minute `RuntimeLease` — the connection outlives the init
bound for the slot's lifetime. The runtime prefers stateless protocol
`2026-07-28` through the pinned SDK's `server/discover`, bounded to at most two
attempts (one SDK retry). Discovery refusal falls back to initialize-era
negotiation, offering pinned `2025-06-18`; negotiated `2025-03-26` and
`2024-11-05` are also accepted. Modern requests carry the protocol version in
`_meta` and MCP headers without session IDs; the older era retains session-ID
and negotiated-version semantics. The stateless era has no ping; neither era has a GET
listener/subscriptions, session resume, automatic tool-call replay or SDK
multi-round-trip support. Inventory remains discovered once per binding and
frozen for the launch; partial, empty or oversized inventory permanently
refuses the binding instead of silently hiding tools. Child stdio behavior is
unchanged.

The parsed-result guard masks text content, structured-content string leaves
and inventory prose. In full mode, `main` passes
`prepareMCPBootstrapOutput` as `launch.Run`'s `PrepareOutput` callback;
`launch.Run` supplies the opaque keeper-token snapshot before `EnsureMCP` and
`broker.Listen`. The callback unions it with the known-output snapshot
(including transmitted credential literals, including Basic's encoded
component) and channel-output snapshot, then configures the bridge before the
first keeper message. The wrapped job guard provider fails closed until setup
succeeds; the bridge's parsed-result guard is configured separately before child access. `--no-output-filter` disables only the known-output guard; both the
keeper-token and channel guards remain mandatory. Non-text content is replaced
by a fixed placeholder. It refuses — never rewrites — schema strings and object
keys whose masked form would differ, because rewriting either could change
control semantics; this is a bounded control-string refusal, not a generic DLP
layer. Parsed-result diagnostics exposed by the bridge remain fixed and do not
include raw SDK transport or read errors. No failed or timed-out call is ever
automatically replayed, and a later explicit model call is a new bounded
request.

SDK logging, re-audited against the pinned `go-sdk@v1.8.0` source: the SDK
logs only through `slog`. The runtime builds its client, and the bridge its
server, with nil `Logger` options, which `ensureLogger(nil)` resolves to
`slog.DiscardHandler` (`mcp/logging.go:112`), so the `OnInternalError` hook
(`mcp/transport.go:233`), `notifySessions` and the other SDK log sites write
nowhere. The earlier v1.0.0 audit found standard-`log` sites instead; none
remain. Upstream
credential material lives only as HTTP headers applied by the `mcpflow`
request hook (`internal/mcphttp/auth.go`); `mcpexchange` returns only the
fixed `errExchange` sentinel (`internal/mcpexchange/connection.go`), so
header bytes never enter any error value that reaches either log site.
Scoped to what these sources show, this review found no reachable
private-peer-diagnostic escape.

Audited against go-sdk v1.0.0 (line references are that version's; the join mechanism below was not re-audited line by line for v1.8.0, which the full-profile tests cover): `ClientSession.Wait` (`mcp/client.go:228`) delegates to `jsonrpc2
Connection.Wait` (`internal/jsonrpc2/conn.go:485`), which blocks on the
connection `done` channel; that channel closes only after the
`readIncoming` goroutine has exited and the connection is idle — no outgoing
calls or notifications, no queued handler work (`conn.go:127-155`). So
`Close` + `Wait` joins the read loop and all tracked per-request handler
goroutines: per-request handlers run in goroutines tracked by in-flight
accounting (spawned `conn.go:694`; `s.incoming` at `conn.go:589` and
`conn.go:751-756`; idle requires `incoming == 0` at `conn.go:158-160`), so
`Wait` returns only after they finish. Not joined by construction: the SDK's
cancellation preempter, though invoked inline on the read-loop goroutine
(`internal/jsonrpc2/conn.go:615-622`), handles `notifications/cancelled` by
spawning `go c.conn.Cancel(id)` (`mcp/transport.go:167-179`, spawn at
transport.go:177); that goroutine is NOT tracked by the connection's
in-flight accounting, so `Wait` does not join it. Reachability is split: on
the upstream session, the peer's messages arrive only through the owned
exchange, which delivers validated JSON-RPC responses and rejects
method-bearing bodies (`internal/mcpexchange/exchange.go:192-218`), so an
upstream peer cannot trigger the canceller there. The downstream child stdio
server DOES admit `notifications/cancelled` (method allowlist
`supportedMCPMethod` in `cmd/ssjack/internal/remotemcp/remote_mcp_connection.go`), where the spawned goroutine may run to
cancel one of the child's own in-flight tool calls — bounded, carrying no
credential material, and the child joins its bridge clients separately. The
residual unjoinable surface is goroutines a handler implementation leaks
beyond `processResult` — none exists for this runtime's nil-options client —
plus behavior not provable from source alone. The keepalive goroutine is not
armed here (nil client options). This is a mechanism-level statement, not a full
proof. Task #318 now authors source exercising the real cross-process bridge
against a private local upstream on Linux, Windows and macOS, including
active-call cancellation and cleanup observations. It does not establish
SDK-internal log behavior against a public live upstream or SDK-wide goroutine
joining. Actual exact-SHA runtime receipts are pending owner CI.

Shutdown order is fixed: cleanup first joins active bridge operations, then
per slot calls `session.Close()` and `session.Wait()` (or a bare connection
close when initialization failed before a session was stored), and only then
invokes the launch close callback, which joins `mcpflow` owned I/O and clears
credential material. Incomplete cleanup retains state, reports the fixed
`ErrBridge` sentinel, and never claims success. Three outcomes are implemented
exactly (`internal/mcpbridge/internal/supervisor/lifecycle.go` `cleanupWorker`/`cleanupAttemptRun`): (1) an unfinished join — a slot's
session/connection close or `Wait` had not finished within the attempt —
reports `ErrBridge` and is non-sticky, so a later Close with a
fresh context re-attempts cleanup; (2) a retryable launch-callback
failure — `closeLaunch` returned an error — retains credentials and
is re-run by a later Close; (3) a terminal slot cleanup error — the session
`Close`/`Wait` returned a nonnil error — sets `cleanupTerminal`
so every later Close reports the fixed `ErrBridge` with no retry,
and the retained state is never dropped. The composed exchange boundary
(`internal/mcpexchange/connection.go`): admission classifies owned-stop vs genuine refusal
atomically under one lock, so an owned stop of an otherwise-admissible message reports
io.EOF while genuine method/state/limit refusals stay the fixed `errExchange` sentinel;
transport and decode READ INTERRUPTION without protocol evidence reports io.EOF only
while an owned close is in progress and errExchange on a live connection; definite
refusal evidence stays `errExchange` even when owned shutdown overlaps — flow-rejected
non-2xx status, invalid response headers, declared/actual response size limits, SSE
token-limit failures, nonempty notification bodies, and exchange-stage session-header/
status/media-type/malformed-JSON-SSE/response-ID evidence — and falls under outcome 3.
The pinned SDK's Wait skips io.EOF for
readErr and writeErr, so orderly owned shutdown reports clean while genuine
failures stay terminal. The
constructor parent (or explicit `BindLifetime` keeper context) supervises
runtime lifetime; per-message handler contexts only cancel their own operation.
`ConfigureOutput` is called before the first keeper message to install
mandatory channel secrets and the caller-supplied known-output snapshot. The
full-mode CLI also wires the keeper's opaque token snapshot through
`launch.Options.PrepareOutput`, called by `launch.Run` before `EnsureMCP` and
`broker.Listen`; it adds the keeper token to the fail-closed job guard provider
and, for the bridge runtime, to `ConfigureOutput` before any keeper message.
This is source wiring, not a test-execution or runtime-acceptance claim.

Native acceptance source for #318 covers Linux, Windows and macOS; it is not
actual three-OS runtime acceptance. Exact-SHA public CI receipts remain pending
owner CI. Historical runtime acceptance at `6913e5f` and archive receipts at
`07290ca` are distinct verified CI evidence, not receipts for this source
revision. Dedicated task #359 remains the full gate. This pocket makes no claim
that tests have executed here.
