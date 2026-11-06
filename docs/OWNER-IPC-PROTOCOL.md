# Owner IPC primitives — integration in progress

The native transport/packet primitives and native installation/record storage
have separate accepted CI gates. Native production-profile owner editing passed
on Windows, Linux and macOS at `866255d`; see `OWNER-NATIVE-STORAGE.md`. This is
not an operator claim that live keeper coordination is available. Existing owner
CLI and TUI behavior remains separate until coordinator integration is accepted.

The coordinator foundation adds atomic expected-revision admission, a metadata
snapshot tied to one revision, authenticated vault adoption without another KDF,
and narrow owner packet capabilities. Directory forms share one typed mutation
implementation. A form may pin its displayed revision through a scoped backend;
the typed remote backend now maps these operations to the closed packet union.
Directory full-mode startup now starts the bounded private service from that retained
Manager and its held writer endpoint. Owner CLI/TUI now select authenticated remote
attach or exclusive standalone control. Protected-consumer sharing and broader native
cross-process integration remain separate acceptance gates.

The local owner backend now pins every form operation to its displayed revision.
Metadata, database status, import counts and saved ciphertext evidence are read
through one coordinator snapshot; import publication counts use that same directory
metadata rather than a second revision. Every queued operation has an explicit
revision-aware entry point. Queue publication, import cancellation and their RAM
state changes are admitted under the database revision lock. Admission itself does
not increment that revision or run another KDF. Callbacks cannot re-enter the vault
session. Directory edits refuse while the owner worker is busy, so a queued export,
link or import cannot silently adopt intervening connection edits.

These local paths and the typed remote backend are prerequisites for RPC dispatch,
not accepted endpoint lifecycle or complete exclusion of legacy command writers.

## Keeper authentication lifetime

Full-mode startup with a directory payload now transfers the already authenticated
vault into `ownerdb.Adopt` and retains that owner session until the harness and its
remote/application consumers have stopped. Adoption does not derive another key or
request another password. Captured SSH runners remain immutable: later database
edits do not silently change their address, login, authentication or usage capture.
Shutdown uses a separate bounded context so cancellation of the harness does not
skip owner persistence. An owner-close failure overrides a successful harness exit
with a fixed recovery error; it is never reported as a saved success.

Legacy non-directory startup preserves its previous read-only credential capture;
it does not create a directory coordinator. Declarative startup still does not
unlock this database. Directory startup now starts the private owner service without
another unlock, using the Manager's borrowed endpoint admission. The owned startup
bundle stops and joins that service before closing its parent Manager. Owner CLI/TUI
attachment and text-adapter installation sharing remain separate integration gates.

## Authority and confidentiality

The database-password holder owns its contents. OS endpoint permissions are
necessary but do not prove human approval: a model harness can share the same OS
identity. The helper must obtain its database context through trusted owner
unlock. Hidden input is the default; the explicit existing-vault startup exception
is documented in [STARTUP-PASSWORD.md](STARTUP-PASSWORD.md). Startup password sources
are never forwarded to the helper/harness environment or RPC messages. No stored
application value or master is sent through MCP, argv, environment, a watched file
or a plaintext bootstrap document.

Packets reuse the existing authenticated `keyfile.Unlocked` storage context and
full data-encryption profile. Four independent sequential Argon2id derivations
remain 1 GiB/t1/p1/output32 each; sealing retains 1000 actual AES-256-GCM DATA
layers and fresh nonces. There is no new password hash, raw master getter or
weaker production cipher. Protocol-only unit fixtures are private test helpers,
not constructors available to production callers. The dedicated full-profile
test uses independently unlocked real contexts and the production KDF.

Root/Administrator, the same OS identity, kernel and trusted runtime remain
trusted. This is not a process-memory sandbox or a guarantee against a local
same-user debugger, swap, dumps or all copies in Go memory.

## Native endpoint ownership

The endpoint is bound to a canonical database path using a domain-separated
SHA-256 metadata digest. A path hash is never authorization. Symlink/hard-linked
database files and non-regular paths refuse. Windows uses the native normalized
volume-GUID filename, not case folding; macOS resolves the native filename before
binding a context. This avoids merging distinct case-sensitive database names.

- Windows uses a local Named Pipe with a protected current-user DACL, first-pipe
  instance protection and remote-client refusal. The first-instance flag is used
  only for initial ownership; additional instances share a fixed 32-slot bound.
  One successor is created while the current handle still pins the pipe name,
  before handoff or cancelled-accept cleanup. At most 31 peers can be handed off
  while preserving that successor slot. Successor creation failure stops admission
  and retains the current handle/claim until explicit listener close; it never
  silently joins a foreign endpoint. A protected globally named kernel event
  retains the endpoint ownership claim between peer connections;
  it carries no request data or secret. OVERLAPPED operations pin native buffers,
  count and state until kernel completion. Cancellation is joined before unpin
  or owned-handle close.
- Linux/macOS use a private per-database socket namespace under `/tmp`, with an
  owner-only `0700` directory and `0600` socket. Existing unsafe permissions are
  refused rather than repaired. Stale or foreign entries are never silently
  unlinked. Close removes only the socket identity that this listener created.
  Cancelled Accept retains endpoint ownership until explicit listener close.

Listeners admit connections, not mutations. The coordinator must stop/join peers
and complete or fail closed on outstanding persistence before releasing its
listener ownership. No TCP, environment route or transport fallback is supplied.

## Writer-role lifetime

An authenticated unchanged vault may claim the existing database's native owner
endpoint before mutation. Session adoption transfers that claim with the retained
key; it does not open a competing listener or derive another key. Owned autosaves
publish under the same claim. Read-only vault loads do not acquire writer authority.
Standalone existing-database commits must acquire the claim or refuse before even
creating their commit lock. New database creation remains exclusive/no-overwrite;
a missing existing-database update refuses rather than recreating it.

The writer pins the native canonical filename and publishes through that spelling,
so a case alias cannot silently change endpoint identity during replacement. The
claim is not a password grant: loaded authentication, unchanged ciphertext and
revision checks still apply. Unsafe/occupied endpoint state is not repaired or
converted into a standalone fallback.

Failed Session saves and cancelled close preserve the live claim. Successful close
or an explicit discard joins the save worker before releasing it; release failure is not
reported as a successful Session close. The service receives only `AcceptOwner`,
not authority to close the listener or read keys. It must cancel/join peers before
closing the parent Manager.

Legacy database add/edit/remove/key-import/password changes claim immediately after
authentication, before further mutation prompts or key generation. Host-key replacement,
policy editing, rotation and existing-destination migration use the same early writer
loader. Rotation therefore refuses before even the first SSH probe. Restore/format
replacement claims before creating its recovery copy and uses that same role for the
final replacement. Read-only list/show/public-key/SSH/policy/host-key capture does not
claim a database writer; selected final key export still does not change the database.
Initial creation remains no-overwrite. An already-current format check is read-only.

Production CLI acceptance holds an occupied endpoint and requires every legacy writer
to refuse with unchanged encrypted bytes, no new key/recovery/lock files and zero
connections to its self-owned SSH fixture. This is writer-effect exclusion, not a
running keeper RPC loop or completed owner CLI attachment.

## Packet state machine and bounds

1. The server seals a fresh session challenge, exact endpoint binding, saved
   ciphertext-origin digest and expiry under its retained context.
2. The client authenticates the server before sending any owner value. It then
   generates a fresh client nonce and seals the matching authentication packet.
3. The server authenticates that proof and returns a sealed ready acknowledgement
   bound to both nonces, the database context and the exact protocol direction.
4. Commands and metadata-only replies use matching sequence numbers. Exactly one
   command may be outstanding. A completed request, handshake, reflected response
   or packet from another database/session cannot be reused.

The protocol domain is `ssjack/owner-ipc/v1`. Strict canonical JSON rejects
unknown or duplicate fields, alternate encodings, mixed command/reply bodies and
trailing data. A storage container cannot itself become an owner command.

A four-byte big-endian frame length is checked before body allocation. Ciphertext
is at most 256 KiB; plaintext remains within the existing 64 KiB keyfile payload
bound. A peer has a 10-minute lease and at most 4096 command messages, with the
last admitted command still eligible for its matching reply. All frame I/O
requires a bounded context. A failed/partial write is uncertain and never grants
permission to automatically replay a mutation.

Snapshot projection now preserves SSH and proxy metadata, remote MCP server/account
metadata and remembered revision-pinned choices, owner-store state, import previews
and conflicts, database revision and saved-ciphertext evidence. Mutable maps and
slices are copied in both directions. Error diagnostics are replaced with closed
fixed codes; stored credentials, header values and application values are not reply
fields. Remote MCP reply bounds match the directory limits, including four header
names and sixteen choices per remembered context. The existing packet plaintext
bound still applies; oversized snapshots fail rather than silently dropping data.

The reply shape is strict: peers built before the remote MCP metadata field refuse
the new shape, and new peers refuse the old noncanonical shape. This is fail-closed
pre-integration protocol evolution, not a persisted vault format change or a rolling
upgrade promise. No live owner endpoint is started by snapshot projection alone.

The closed operation union covers directory changes, selected secret changes,
export, link, import inspection/confirmation, explicit recovery, metadata and
flush. Replies contain only directory/import metadata and persistence evidence;
there is no stored-secret or master getter. Mutating requests carry an expected
revision, whose atomic admission must be enforced by the integrated coordinator.
A successful receipt is not application adoption or an environment reload.

## Typed remote forms

`ownerbackend.Remote` implements the shared form backend over an authenticated RPC
client. It reads each form snapshot atomically and requires an immutable
`AtRevision` scope for mutations; it never fetches a newer revision to substitute
for a stale form. Directory changes use the existing typed dispatch seam. Arbitrary
Go edit callbacks refuse without execution or serialization.

Owner-selected archive/store/key-file paths are made absolute in the helper before
sending, not interpreted relative to the keeper's working directory. Empty paths
refuse. Password bytes are never path-normalized. Keeper-side protected file and
operation validation still applies; absolute paths are not authorization.

Closing a remote form first requests flush, then detaches only its client peer.
A failed flush does not claim saved success or close the keeper. The helper must
also close its client on abandoned/error exits before closing its own unlock.
Routing and shared-form tests do not establish live keeper attachment or helper
lease ownership; those remain integration requirements.

RAM import plans have a non-secret monotonic identity within the coordinator.
Successful inspection admission allocates the next identity without changing the
database revision; aborted/failed plans do not reuse identities. Counter exhaustion
refuses new inspection rather than wrapping. Confirmation, resume and abort can be
admitted only against the expected plan and database revision under the Manager
lock. Existing trusted local APIs remain available; shared Local/Remote forms use
immutable plan-aware scopes. A refresh cannot substitute a new plan into an open
form. Leaving a preview also targets its displayed revision and plan.

The closed protocol requires a nonzero `plan` only for confirm/resume/abort import
decisions and returns `PlanID` in import metadata. Plan identity is neither a grant
nor authentication. The helper ownership described below does not replace packet
authentication, keeper lifecycle or legacy-writer exclusion. The fields are RAM/protocol metadata, not a vault schema
change. Native production acceptance replaces plan A with B at the same database
revision and requires stale A decisions to leave the full snapshot unchanged.

## Bounded RPC exchange

`ownerrpc.Attach` and `ServePeer` compose real packet peers with native connections.
They consume the connection and peer, never the borrowed unlock context. Handshake
I/O is bounded to ten seconds; commands and replies use at most one minute within
the caller's deadline and authenticated lease. Idle server reads end at the lease.
Unbounded contexts refuse before I/O. Only one client command is outstanding.

After a command is encoded for dispatch, a write failure, missing reply or failed
reply authentication closes the channel and returns `ErrUncertain`. The exchange
never retries or reconnects. Client close first wakes native I/O, then joins the
active exchange before releasing the packet capability. Callers must join the
server peer before closing its parent database context. The server clears decoded
private command buffers after every dispatched outcome, including failed replies.

This layer accepts only the closed command/reply types. `ownerdispatch` supplies
Manager admission and helper/import-plan ownership as described below. This is not
a running keeper service or authorization to expose a generic callback through
MCP. The low-level native exchange fixture uses a synthetic handler; a separate
native Manager fixture composes actual dispatch and shared forms.

## Keeper service lifetime

`ownerservice.Start` borrows an already authenticated Manager and its held endpoint;
it does not acquire another listener or request/derive a password. One service owns
one Dispatcher. Sixteen fixed slots bound accepted peers and pending admission.
Each peer uses the existing authenticated lease and ten-second handshake limit;
invalid authentication or unavailable saved origin closes that peer, not the keeper.
There is no reconnect/mutation replay or standalone fallback.

Service cancellation joins pending accept and closes/joins owned connections and
lease cleanup before its Done receipt. It never closes the Manager or releases the
writer claim itself. The startup bundle closes consumers first, then the service,
then the parent Manager. If peers have not joined by shutdown's bound, the bundle
returns a fixed recovery error without closing their borrowed parent key/role. A
joined fatal service error still permits an attempted parent persistence close but
cannot preserve a successful harness exit. Partial startup retains explicit ownership
so the same cleanup path runs.

New authentication may use the last authenticated saved ciphertext origin even
while RAM has a failed/pending save, but only if that exact saved digest still matches
the file. Metadata continues to report unsaved/error state and a retry requires an
explicit owner command. Current RAM state is not falsely certified as saved. Native
service acceptance injects a commit-lock refusal, authenticates in that failed state,
then explicitly retries and verifies persistence without another KDF. It also stops
an active peer, proves the parent writer/key remain usable and restarts the service.

## Owner helper attachment and human SSH

Owner CLI/TUI unlock the database once, then select control from the native endpoint.
A successful dial requires mutual packet authentication before any owner value is
sent. Only `ErrAbsent` permits standalone adoption; busy/unsafe endpoint state,
authentication failure, timeout or transport uncertainty never falls back to a new
local writer. A race between absence detection and role acquisition refuses rather
than creating a second coordinator. The already loaded vault is transferred either
to the helper's narrow retained unlock or the standalone Manager without another KDF.
Trusted input/output TTY requirements remain independent of password source.

The control backend preserves atomic metadata, typed directory dispatch and immutable
revision/plan scopes through its lifecycle wrapper. Successful close flushes and
detaches only a remote helper; the live keeper remains owned. Standalone close joins
its service before closing its Manager. Failed remote flush leaves explicit recovery
available; abandoned/error exit detaches the helper without silently discarding
partial effects or closing the keeper.

SSH selection records the displayed database revision. Local capture checks it under
the Session lock. Remote capture flushes, requires the selected revision to remain
current and saved, then privately opens exactly that saved ciphertext digest using
the helper's retained context. The narrow result is one host-pin-verified,
human-permitted client configuration, never serialized credential bytes or a stored
secret getter. A different revision or file digest refuses instead of adopting a
new account. Later database edits do not change the captured configuration. Existing
SSH/PTY/editor input/output and terminal-release behavior are unfiltered.

This adds helper control and narrow human capture, not accepted protected installation
sharing or the broader native cross-process/selected-value acceptance gate.

## Manager dispatch and helper ownership

One `ownerdispatch.Dispatcher` belongs to one retained Manager. Each packet
connection gets a fresh bounded peer handler; creating a handler does not prove
authentication. Only the mutually authenticated `ServePeer` path may expose it.
Commands are validated against the closed union, serialized with cancellable
admission, and routed to the Manager's revision/plan-aware APIs. Replies use one
post-operation atomic snapshot and fixed error codes; there is no stored-value or
master getter and no automatic replay.

A live helper owns the import it inspected. Another helper may read metadata or
wait for persistence, but cannot confirm, abort or mutate that plan or its directory
merely because it knows the PlanID. A disconnected partial plan can be reclaimed
only after a fresh matching metadata snapshot and an explicit import/recovery
decision. Reading a snapshot or attaching a new helper never resumes work by itself.
These are concurrency/lifecycle safeguards, not multi-owner RBAC: the database
password still owns all database contents.

`ServePeer` closes and joins packet I/O, then ends an owned handler lease with an
independent bounded context. Manager cleanup atomically cancels or drops only
matching no-effect RAM state. It refuses to discard any effectful/partial plan;
failed cleanup returns a fixed uncertain outcome rather than saved success. The
remaining plan and durable intent stay available for explicit recovery. Neither
helper detach nor lease release closes the keeper or its parent key context.

Native Manager acceptance uses two independently unlocked helpers, real OS
transport and production crypto. It proves live-plan exclusion, no-effect disconnect
cleanup, an actual shared owner form editing/saving through RPC, stale-form refusal,
private ciphertext persistence and the coordinator remaining available after helper
detach. Keeper startup, process-level writer exclusion and SSH handoff remain a
separate runtime integration gate.

## Native database publication

Before publishing an external owner intent, the manager waits for encrypted saves,
checks the exact saved ciphertext digest, requests native publication flush and
checks the digest again. Unix retains the parent-directory `fsync` barrier.
Windows cannot flush an `os.Open` read-only directory handle: the observed failure
is `ERROR_ACCESS_DENIED` (5), before archive inspection ever starts.

Windows vault replacement therefore requests `MOVEFILE_REPLACE_EXISTING` with
`MOVEFILE_WRITE_THROUGH` for the already flushed same-volume staging file, with no
copy/delete fallback. The subsequent manager barrier opens the existing encrypted
file with read/write and write-through access, refuses reparse substitution, checks
its identity and flushes that handle before closing it. Rename, flush and close
failures propagate; access errors are not ignored. Ciphertext checks before and
after the barrier remain unchanged. No plaintext file, extra KDF or weaker cipher
is involved.

These are native OS completion/flush semantics, not POSIX directory-fsync emulation
or certification against every filesystem/device power-loss failure. In particular,
Microsoft documents the explicit copy/delete flushing guarantee separately; this
path does not enable cross-volume copying. See [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
and [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
Native regression exercises the original read-only directory failure, successful
file flush, unchanged file identity/bytes, actual replacement and long paths, plus
refusal rather than success when writable access is unavailable.

## Acceptance layers

Native tests exercise round trips, exclusive ownership, cancellation, protected
ACLs/modes and preservation of stale/foreign paths on their actual OS. Protocol
tests exercise replay, reflection, cross-binding/context confusion, strict
framing, expiry, message budget and uncertainty. `TestOwnerPacketFullProfile` is
mandatory in the dedicated production-KDF gate. Tests must report actual results;
writing them or a successful old owner-menu run does not accept these primitives,
and primitive acceptance alone does not accept the complete live-update feature.
