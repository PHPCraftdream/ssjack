# Remote MCP directory — implementation in progress

Encrypted records and shared owner CLI/TUI management are implemented. Full-mode
startup presents an explicit metadata selector after stable SSH profile selection.
After an explicit non-empty choice and receipt-checked preference persistence, it
hands the freshly prepared bounded launch, with its union guard, to the
supervised bridge runtime (`internal/mcpbridge`), which exposes the selected
remote MCPs only to this child harness invocation through the existing
per-launch stdio bridge. Empty choices persist without a launch or bridge.
The Linux/amd64 startup-selector and consuming-bridge PTY test source is
authored, but is not Windows/macOS acceptance and has not been run here. Task
#357's supervised bridge/harness runtime is implemented in this tree; #318 is
native bridge acceptance. Runtime work for #317/#357 was accepted in `6913e5f`; #318 remains native bridge acceptance, and #359 remains the final gate. The existing `ssjack mcp` command retains its current session protocol.

## Encrypted records

The optional `remote_mcp` section lives inside the existing encrypted directory
payload. It contains stable-ID servers, server-scoped stable-ID auth accounts,
and the last explicitly confirmed selection for an SSH credential profile.
Profile identity, not OS username or SSH login text, separates selection contexts.
Renaming an SSH server does not change that context.

A server contains its display name, HTTPS endpoint, enabled state and a revision.
An account contains its server ID, display name, enabled state, revision, primary
HTTP authentication and optional credential headers. This first record layer
admits `none`, `bearer` and `basic` primary authentication. Up to four explicit
custom credential headers permit API keys and a Basic/Bearer-plus-API-key setup.
OAuth, mTLS, signing adapters and other transports are not implemented or accepted
by this schema. They must not appear as working authentication choices.

Endpoints cannot contain URL userinfo, query parameters, fragments or control
characters. Credential headers cannot override Authorization, proxy credentials,
MCP protocol metadata, HTTP framing or routing headers. Header names are canonical
and credentials are bounded. Endpoint and account names are unique in their
respective scopes. Raw credentials are never included in display metadata.

The existing four sequential 1 GiB Argon2id derivations, 1000 actual data-encryption
layers and 64 KiB vault plaintext limit are unchanged. Record-count limits are
upper bounds, not a promise that every maximum-sized credential fits at once.
An oversized edit refuses before adopting the candidate or incrementing revision;
its owned credential buffers are cleared. Go zeroization remains best effort.

## Private owner mutation foundation

The shared directory dispatcher admits closed MCP server/account/header changes.
Primary credential decisions are explicit: `keep` requires the same authentication
kind and username, `replace` requires newly entered private bytes, and `clear`
requires `none` authentication with no username or supplied secret. New accounts
cannot request `keep`. Display-only account renames use a separate operation so
they do not invalidate remembered selections. Account policy or credential edits
increment the account revision even when the primary credential is kept.

Credential header edits explicitly replace or clear one canonical header; they
preserve unrelated headers and the primary credential. Server removal removes its
accounts and prunes remembered bindings. Account/server removal requires `REMOVE`.
These mutations are private owner operations, not model-accessible tools. They do
not perform network requests or change active sessions. The **Remote MCP servers**
owner-menu page and `owner *-mcp-*` commands use the same form descriptors and typed
dispatcher. Server/account names in these commands select the MCP directory, never
the SSH directory. Secret and confirmation fields have no argument options. See
[owner commands](OWNER-CLI.md) for selectors and examples.

## Remembered selection is not authorization

Each saved binding contains server/account IDs and the revisions the owner
confirmed. No token, live session capability or reusable permission is stored in
the selection. A fresh session still requires explicit owner confirmation.

- First use has no selected MCP, even when only one account exists.
- An explicitly confirmed empty list remains empty.
- Different SSH accounts retain separate selections.
- Display-only renames retain stable identity and preselection.
- Changing an endpoint, enabled state or account credentials invalidates the old
  suggestion. It never silently changes a running session's endpoint or identity.
- Deleted accounts are removed from remembered lists; another account is never
  substituted. Disabling a server makes its accounts unavailable for preselection.
- The metadata-only `internal/mcpselect` Bubble Tea model requires a separate
  explicit Continue, including singleton and empty choices. Cancel returns no
  choice and does not persist. It captures the SSH profile, displayed database
  revision and exact bindings as owned metadata, never as a grant.
- The checkbox model is wired into full-mode startup after stable SSH profile
  selection. It requires explicit Continue even for empty or singleton choices;
  remembered exact bindings are suggestions only. Selector cancellation and
  capture-refusal stop before persistence, launch issuance and child launch.
  After receipt-checked persistence, a refused launch preparation leaves the
  saved preference and receipt in place with no launch, child or network
  effect; uncertain outcomes are never automatically replayed. After
  confirmation, startup captures authenticated
  credentials before adoption and persists/flushes the preference against the
  original saved revision/ciphertext. A non-empty choice then issues a fresh
  bounded launch and installs its authentication-literal guard; an empty choice
  does not capture or issue a launch. The confirmed non-empty launch is consumed
  by the supervised bridge runtime: upstream sessions establish lazily when the
  harness bridge child first asks, so an untouched session performs no upstream
  network, and the model sees only the selected bindings' inventory under
  digest-based namespaces (`mcp` + hex(SHA-256 of the binding identity)[:6] +
  `_`, `internal/mcpbridge/bounds.go` `bindingNamespace`). `WithMCPLaunch` is a
  sequential one-shot access path; it
  does not promise concurrent-call safety.
- Model-facing credential, owner-store master, header, and grant getters, and
  model-facing grant issuance, are permanently prohibited, not pending work.
  Internal startup issuance of a private bounded launch does not expose a
  model-facing grant API.
- `RememberRemoteMCPAt` admission still checks the displayed revision, saved
  ciphertext digest, stable SSH profile and exact enabled bindings before queuing
  encrypted preference persistence. Busy/import/pending/recovery state and changed
  ciphertext refuse. Startup flushes and inspects the save receipt before issuing;
  uncertain outcomes are never automatically replayed.

Edits use the existing trusted owner session candidate/save path. Account input
buffers and metadata selections are copied, not retained from callers. Replacement,
removal, failed candidates and vault close clear owned credential byte buffers.

## Private upstream HTTP capability

`mcphttp.NewUpstream` now builds a lazy private HTTP capability from a fixed public
HTTPS endpoint and an enabled supported auth record. It does not establish owner
approval, mint a local session grant or start networking by itself. A one-shot SDK
transport uses explicit bounded HTTP exchange, no cookie jar, redirect refusal and
negative `MaxRetries`. The lease is at most 10 minutes without automatic renewal;
listening-stream resumption refuses rather than silently reconnecting.

Request/response/header/active/message limits and cancel/join ownership live in
`mcpflow`. Close only clears credential material after owned I/O joins; failed or
incomplete cleanup reports failure and retains it. Responses cannot expose injected
headers through `Response.Request`. SDK message bodies/errors remain private input; the consuming bridge applies the
parsed-result guard and fixed diagnostic boundary (see below).
The startup known-literal output guard is not a parsed-result or diagnostic
boundary: `--no-output-filter` explicitly disables only that guard for a trusted
terminal, and human SSH sessions remain unfiltered. The prepared guard and launch
are consumed by the supervised bridge runtime. Task #357's supervised
bridge/harness integration is implemented here; runtime tasks #317/#357 were
accepted in `6913e5f`. #318 native bridge acceptance remains separate. MCP archive selection
uses the existing owner archive path; its selected public full-KDF fixture source
is authored but was not run here, and no CI result is claimed.

## Private captured credentials and fresh launch capabilities

`Vault.RemoteMCPCapture` is the production authenticated entry for the startup
coordinator: while the loaded vault is still unadopted, it re-verifies the
canonical payload and the current on-disk ciphertext against the retained
authentication, requires the supplied digest to be that loaded cipher origin,
and privately captures the enabled confirmed records bound to the fresh
revision-zero session. A replaced or edited database refuses instead of
adopting foreign credentials, both before assembly and again at the return
boundary, where a mid-construction change revokes the newly owned copies. `Session.RemoteMCPCaptureAt` revalidates an
exact saved session state afterwards with the same evidence gates as
`OutputGuardAt`: closed or closing sessions, unsaved or failed persistence,
digest mismatch, unresolved owner intents, unknown SSH profiles and empty,
oversized, duplicate, unknown, disabled or revision-stale bindings all refuse
with a fixed sentinel. Neither seam returns credential values, performs a
network effect, a second unlock or a per-operation KDF.

`internal/mcpgrant` owns the captured bytes independently of caller buffers and
of Vault edits, adoption and close. Each capture carries a finite admission
lifetime bound to its construction context; cancellation and expiry are
rechecked at admission, at every record boundary and again before a launch is
returned, so a cancelled mint never returns a usable launch. Issued launches
carry both the capture's construction parent and the caller's issuance context
into their exchange lifetime, and the exact capture deadline instant refuses. One explicit
confirmed choice mints at most one bounded launch: at most 16 lazy upstream
capabilities, each a one-shot transport with the bounded `mcpflow` lease, plus
a union outputguard capability covering every transmitted authentication
literal, including Basic's encoded component. Stale, disabled, duplicate,
unknown and repeated issuance refuse. A failed or cancelled mint consumes the
capture because uncertain partial effects are never replayed; cleanup that
cannot join completely keeps the retained upstreams reachable through the
capture, whose close retries them instead of claiming joined completion, and a
failed construction clears its owned copies. Test source covers active-I/O cancellation and joined shutdown in the mcpflow
and mcphttp composition layers; this layer adds admission, one-shot, union-guard
and retained-cleanup ownership above that boundary.

The private capture, admission, one-shot, union-guard and retained-cleanup
ownership is covered by authored unit/composition test source; those tests were
not run here, and no CI result is claimed.

Task #357's supervised bridge/harness integration is implemented here; #318 is
native bridge acceptance. The Linux/amd64 PTY acceptance source now drives a
consuming bridge through a real MCP harness probe over stdio with unreachable
fixture endpoints, exercising the real child bridge, keeper and fixed-failure
path; it remains Linux/amd64-only, is not Windows/macOS acceptance, and has not
been run here. MCP archive selection and import are integrated with the existing
owner archive format and selected full-KDF acceptance source; they do not add
runtime sessions or grants. Runtime tasks #317/#357 were accepted in `6913e5f`; #318
native bridge acceptance and #359 final runtime gate remain separate.

## Supervised remote MCP bridge runtime

The bridge runtime lives only in the startup process. After the receipted
non-empty confirmation, startup mints the one-shot launch, hands its upstream
handles and union guard to the runtime, and transfers one-shot access:
`WithMCPLaunch` refuses afterwards. Upstream credentials never leave the startup
process; they appear in no environment, argv, file, log or diagnostic.

The child bridge process (`ssjack mcp`) exposes the confirmed remote tools as
namespaced stdio MCP tools on the existing single per-launch
`ssjack` server. The startup-process runtime internally handles exactly three
bounded keeper operations (`mcp_remote_bindings`, `mcp_remote_describe`,
`mcp_remote_call`; `internal/mcpbridge/bounds.go:23-25`), but the child's
channel wire admits only `describe` and `call` per binding
(`internal/mcpchannel/channel.go:240-260`): binding ordinal selection is
server-side and never caller-selected, with one broker per confirmed binding.
The brokers are NEW per-binding pinned-TLS loopback listeners
(`internal/mcpchannel`): up to 16 independent listeners with pinned
certificates, a per-binding random session token with bootstrap TTL, and a
mandatory token-only output guard. These brokers are distinct from
the existing one-use SSH bootstrap keeper and from the per-launch keeper
session. Nothing is registered beyond those channels; there is no persistent
or global client config, no
URL/account/header/method selection, and only the frozen selected bindings are
visible.

Sessions are lazy: no upstream network occurs before the child bridge first
asks. Inventory is discovered once per binding and frozen. SDK protocol-version
negotiation refuses unknown versions (2025-06-18, 2025-03-26 and 2024-11-05 are
supported).

Bounds: at most 16 bindings and 64 tools per binding; upstream tool names at
most 48 bytes, descriptions at most 4096 bytes and schemas at most 16 KiB;
child arguments at most 48 KiB raw (canonical re-encode at most 56 KiB); masked
results at most 64 KiB; a 20 s per-operation budget below the 30 s broker
client deadline; and an 18 s bound on first-use initialization. Pagination
cursors, empty, partial, oversized or invalid-name inventories permanently
refuse that binding with fixed diagnostics; nothing is silently truncated.

The parsed-result guard masks text content, structured-content string leaves
and inventory prose with the runtime's configured output guard — the mandatory
snapshot unioned from the channel and bootstrap tokens plus the caller-supplied
known-output snapshot installed via `ConfigureOutput` before the first message —
covering every transmitted literal
including Basic's encoded component. Non-text content is replaced by the fixed
placeholder `[remote MCP content omitted]`. Schema strings and object keys
whose masked form would differ are refused, never rewritten, because
rewriting could change control semantics; this is a bounded refusal, not a
generic DLP layer. SDK transport and error bodies stay
behind fixed diagnostics (`remote MCP tool call failed` and similar). Failed or
timed-out calls are never automatically replayed; an explicit later model call
is a new bounded request. Under trusted-terminal `--no-output-filter`, only
the known-literal portion of the guard is disabled — including known upstream
literals — while channel/bootstrap tokens, fixed error boundaries and all
size/budget bounds remain mandatory in that mode.

Shutdown order: keeper disconnect (handler-context supervision) or harness exit
cancels and joins SDK sessions first, then the launch close callback joins the
HTTP owners and clears credentials, then the existing credential owner cleanup
runs (capture, service, owner). Incomplete cleanup retains
state and reports the fixed failure; no grant is reissued. Of the failures,
unfinished joins and launch-callback failures are retryable with a later
Close using a fresh context, while terminal slot cleanup errors are retained
and every later Close reports the fixed failure
(`internal/mcpbridge/lifecycle.go:224–235, :259`).

The runtime's mandatory output guard is exactly the channel/bootstrap-token
union from `mcpchannel` combined with the caller-supplied known-literal
snapshot installed at startup (`ConfigureOutput`); the channel token guard is
never disabled by any flag.

Each binding is a distinct namespace, session and failure domain. The local
transport to the child is the new per-binding pinned-TLS loopback brokers
described above (one-use token, pinned TLS, loopback peer check), distinct
from the SSH bootstrap capability.

Number precision boundaries: call arguments are decoded and re-encoded by
`internal/mcpjson` with `json.Number` before reaching the SDK, so integers in
model-supplied arguments are not widened to float64 by the bridge. Upstream
structured results are decoded by the pinned SDK, whose own decoding may apply
float64 semantics; the child bridge re-extracts `structuredContent` as raw
JSON lexemes from the parent's masked result
(`cmd/ssjack/remote_mcp_call.go`), so lexemes are preserved from the parent's
output through the child to the harness — not necessarily from the upstream
wire.

Test source covers in-memory SDK composition (masking, bounds, custody,
no-replay, cancel/join/close ordering, disconnect supervision), command
lifetime (bridge closes before owner, retained failure, one-shot refusal), and
Linux/amd64 PTY scenarios driving a real MCP client probe over stdio through
the real child bridge and keeper against unreachable fixture endpoints. These
tests were authored, not run here, and no CI acceptance result is claimed.

## Compatibility and acceptance

New readers load old payloads without `remote_mcp` as an absent directory. New
records are emitted only when the section is present. Nested unknown fields and
dangling SSH selection contexts refuse; there is no lossy decode-and-save path.
Older strict readers reject the additional root field rather than removing it.
No external container/profile/project version is changed by this addition.

Test source covers canonical round trips, unknown fields, URL/header restrictions,
credential ownership and cleanup, metadata isolation, per-account selections,
rename stability and stale/disabled/deleted choices. Vault test source covers owned
metadata and atomic size refusal. The mandatory production directory test source
also checks encrypted MCP persistence and real-profile reload, and the mandatory
production capture test source drives the authenticated real-ciphertext origin
path. These tests are not substitutes for cross-process runtime and native bridge
acceptance, and no CI acceptance result is asserted here. The owner parity suite
includes all MCP management pages and compares private MCP effects as well as the
existing SSH effects. Additional owner tests exercise cancel, rejected secret or
confirmation prefills, stale displayed revisions and wrong removal confirmations.
A passing action/form registry is not exhaustive coverage of every state or error.
