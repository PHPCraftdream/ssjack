# Remote MCP directory — implementation in progress

Encrypted records and shared owner CLI/TUI management are implemented. Full-mode
startup presents an explicit metadata selector after stable SSH profile selection.
After an explicit non-empty choice and receipt-checked preference persistence, it
prepares authenticated bounded capabilities. Empty choices persist without a
launch. No remote bridge consumes a prepared launch; no remote MCP tool or
connection is exposed. The Linux/amd64 startup-selector PTY test is authored, but
is not Windows/macOS acceptance and has not been run here. Task #357 is the
supervised bridge/harness; #318 is native bridge acceptance; #358 covers
MCP-specific archives; #359 is the final gate. #317 remains incomplete. The
existing `ssjack mcp` command retains its current session protocol.

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
  does not capture or issue a launch. The prepared launch is not consumed by a
  remote bridge, so no connection or tool is exposed. `WithMCPLaunch` is a
  sequential one-shot access path; it does not promise concurrent-call safety.
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
headers through `Response.Request`. SDK message bodies/errors remain private input;
any future bridge must apply the parsed-result guard and fixed diagnostic boundary.
The startup known-literal output guard is not a parsed-result or diagnostic
boundary: `--no-output-filter` explicitly disables only that guard for a trusted
terminal, and human SSH sessions remain unfiltered. The prepared guard and launch
are not consumed by a bridge. Task #357 is supervised bridge/harness integration;
#318 native bridge acceptance is pending. MCP archive export/import is task #358;
#359 is the final gate, and #317 is incomplete.

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

Runtime acceptance is pending. Task #357 is supervised bridge/harness integration;
#318 is native bridge acceptance. The current acceptance-test source includes a
Linux/amd64 selector/startup PTY test only: it does not exercise a consuming bridge,
and it is not Windows/macOS acceptance. It has not been run here. Task #358 covers
MCP-specific archive export/import, and #359 is the final gate. Task #317 remains
incomplete.

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
