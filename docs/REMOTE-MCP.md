# Remote MCP directory — implementation in progress

Encrypted records and shared owner CLI/TUI management are implemented. Remote MCP
connections and launch selection are not wired yet; those layers require separate
integration and native acceptance. The existing `ssjack mcp` command continues to
serve its current session protocol. MCP-specific owner archive export/import is
also pending; existing ZIP exports/imports cover SSH credentials and application
values, not the remote MCP directory.

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
- The checkbox model is not wired into startup yet. Private Session/Manager
  `RememberRemoteMCPAt` admission checks the displayed revision, saved ciphertext
  digest, existing stable SSH profile and exact enabled bindings before queuing
  encrypted preference persistence. Busy/import/pending/recovery state and changed
  ciphertext refuse. Callers must separately flush and inspect the save receipt;
  an uncertain outcome is never automatically replayed.
- The private admission seam does not mint a grant or expose an RPC/model operation.
  Startup orchestration, fresh bounded launch grants and remote bridges remain
  pending; later layers must reject stale choices rather than adopt credentials.

Edits use the existing trusted owner session candidate/save path. Account input
buffers and metadata selections are copied, not retained from callers. Replacement,
removal, failed candidates and vault close clear owned credential byte buffers.

## Compatibility and acceptance

New readers load old payloads without `remote_mcp` as an absent directory. New
records are emitted only when the section is present. Nested unknown fields and
dangling SSH selection contexts refuse; there is no lossy decode-and-save path.
Older strict readers reject the additional root field rather than removing it.
No external container/profile/project version is changed by this addition.

Unit tests cover canonical round trips, unknown fields, URL/header restrictions,
credential ownership and cleanup, metadata isolation, per-account selections,
rename stability and stale/disabled/deleted choices. Vault tests cover owned
metadata and atomic size refusal. The mandatory production directory test also
checks encrypted MCP persistence and real-profile reload. These are not substitutes
for cross-process runtime and native bridge acceptance. The owner parity suite
includes all MCP management pages and compares private MCP effects as well as the
existing SSH effects. Additional owner tests exercise cancel, rejected secret or
confirmation prefills, stale displayed revisions and wrong removal confirmations.
A passing action/form registry is not exhaustive coverage of every state or error.
