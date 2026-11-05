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
this does not itself provide the remote backend or RPC service. Dispatcher,
helper/keeper lifecycle, single-writer exclusion and cross-process integration
remain unfinished.

The local owner backend now pins every form operation to its displayed revision.
Metadata, database status, import counts and saved ciphertext evidence are read
through one coordinator snapshot; import publication counts use that same directory
metadata rather than a second revision. Every queued operation has an explicit
revision-aware entry point. Queue publication, import cancellation and their RAM
state changes are admitted under the database revision lock. Admission itself does
not increment that revision or run another KDF. Callbacks cannot re-enter the vault
session. Directory edits refuse while the owner worker is busy, so a queued export,
link or import cannot silently adopt intervening connection edits.

These local paths are prerequisites for RPC dispatch, not an implemented remote
backend, endpoint lifecycle or complete exclusion of legacy command writers.

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
  instance protection and remote-client refusal. A protected globally named
  kernel event retains the endpoint ownership claim between peer connections;
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

The closed operation union covers directory changes, selected secret changes,
export, link, import inspection/confirmation, explicit recovery, metadata and
flush. Replies contain only directory/import metadata and persistence evidence;
there is no stored-secret or master getter. Mutating requests carry an expected
revision, whose atomic admission must be enforced by the integrated coordinator.
A successful receipt is not application adoption or an environment reload.

## Acceptance layers

Native tests exercise round trips, exclusive ownership, cancellation, protected
ACLs/modes and preservation of stale/foreign paths on their actual OS. Protocol
tests exercise replay, reflection, cross-binding/context confusion, strict
framing, expiry, message budget and uncertainty. `TestOwnerPacketFullProfile` is
mandatory in the dedicated production-KDF gate. Tests must report actual results;
writing them or a successful old owner-menu run does not accept these primitives,
and primitive acceptance alone does not accept the complete live-update feature.
