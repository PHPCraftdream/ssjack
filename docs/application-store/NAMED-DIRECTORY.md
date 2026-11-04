# Named server directory and migration contract

This work extends the encrypted credential database. It does not introduce
additional database owners, an enrollment service, restricted-runner expansion,
SSH server hardening, synchronization, or native/OpenClaw adoption.

## Ownership and SSH accounts

The person unlocking the database is its administrator. Multiple users of one
SSH server are modeled as multiple named accounts inside one named server, not
multiple owners of the database. Each account selects exactly one username and
one private key or password. Selecting an account is not permission to connect,
read files, or deliver secrets.

Payload version 1 contains the existing named `targets` credential records.
Payload version 2 retains those records and adds closed `servers` and `secrets`
directories. This payload version is independent of the encrypted container
format. Container encryption and production key derivation remain unchanged.

- Servers have stable random IDs, unique names, and named accounts referring to
  credential record IDs. Every credential belongs to exactly one account.
- Accounts of a server share its endpoint and verified host-key set. Different
  logins can have different credentials, usage restrictions, and SSH policies.
- Names use the existing case-sensitive 1–64 character ASCII name rules.
- Renaming a server does not change its ID or the scope of its secrets.
- The existing 64 KiB credential payload bound remains enforced. Large-file
  streaming is a separate data path, not an unbounded credential database.

## Named application secrets

The directory contains exact canonical `ssjack-secret-ref-v1` metadata, never a
second copy of application secret values. Values remain in the encrypted
versioned application store with its existing authority and transaction rules.

A binding has a stable ID, name, explicit scope, and exact reference. An empty
server ID means global scope; a nonempty ID selects one existing server. Names
are unique inside a scope. Global and server-local bindings may share a name,
but callers must select the scope explicitly: there is no shadowing or implicit
fallback. One server's local secrets cannot be selected through another server's
scope. Server-local scope applies to the server, not just one of its SSH logins.
Existing delivery grants remain necessary; name lookup is not authorization.

Renaming preserves the binding ID and reference. Updating a value must create
an application-store version before publishing its exact reference in the
binding. A failed binding update must not erase an old reference. Historical
placeholders keep their exact versions; they are never reinterpreted as latest.

## Compatibility and migration

Migration is an explicit owner operation, never a startup side effect.

1. Unlock and validate the existing database, including all credential records.
2. Preserve the source encrypted file. Create a new encrypted destination without
   overwriting an existing file or weakening its container crypto profile.
3. Map each legacy profile to a server with the same name and one account named
   `main`. Preserve credential bytes, username, address, host keys, usage and SSH
   policy exactly. Do not automatically merge profiles sharing an address.
4. Reopen the destination and compare every migrated record and directory entry
   before reporting success. Only then may the owner select the new database.
5. Retain the old encrypted database for rollback. Old binaries cannot edit the
   version 2 payload; rollback means using the original version 1 file, not
   attempting to strip metadata from a newer database.

An interrupted or cancelled migration must not modify the source. No decrypted
backup, editor temporary file, command-line password, environment password, or
secret-bearing diagnostic is permitted. Existing host-key verification stays
in force even though SSH server hardening is outside this scope.

## Explicit migration command

```sh
ssjack --vault old-database.ssjack.ktav vault migrate-directory new-database.ssjack.ktav
```

The command requests the database password through the trusted hidden terminal
prompt, verifies the replacement, and requires `MIGRATE DIRECTORY` confirmation.
It never changes the selected default database or opens an SSH connection.
Use `--vault new-database.ssjack.ktav` explicitly after migration. The destination
is staged as ciphertext, checked byte-for-byte, and published exclusively using
a same-directory hard link; filesystems without hard-link support refuse without
replacing the source. Publication does not claim directory crash durability.

## Owner-controlled export

The owner menu exports all or selected server/account/global scopes, including
actual selected values resolved through the private owner-unlock path. ZIP export
is encrypted by default; deliberate plaintext requires exact `EXPORT PLAINTEXT`.
Output publication is exclusive and protected (Unix permissions or Windows owner
DACL). Installation unlock material is excluded. Plaintext is an authorized final
artifact, not permission for incidental staging, MCP disclosure or logs.

Import reads these encrypted/plaintext archives in RAM, shows metadata and
conflicts, then requires exact `IMPORT`. It preserves credential bytes/settings
and scopes, refuses collisions without merge/overwrite and publishes values to
fresh destination refs. Linked-value operations are Linux-only. The full remaining
import plan is RAM-only; a partial application requires explicit recovery/abort,
not automatic replay or a claim of rollback. See [menu](OWNER-TUI.md),
[archive](OWNER-EXPORT-FORMAT.md) and [coordinator](OWNER-COORDINATOR.md).

## In-memory editing and background persistence

The session backend unlocks the database once and retains its master only for
that session. Apply validates an owned candidate before changing the in-memory
state. Invalid or cancelled forms never queue a save. One background worker
seals snapshots using the retained master, fresh nonces and the unchanged data
encryption layers. At most one save is active and one latest snapshot is queued;
obsolete queued snapshots are cleared rather than allowed to overwrite newer
state. Plaintext snapshots remain in RAM and are cleared after use.

A trusted owner coordinator may hand an already authenticated, unchanged Vault
to StartSession rather than derive the database key a second time. The handoff
checks both a private in-memory canonical-payload fingerprint and the encrypted
file revision; it refuses edits or another writer's replacement before transfer.
The private plaintext fingerprint is never serialized or returned. A saved
ciphertext digest can identify a fully persisted file for a later durability
check; that digest is metadata, not permission or a master-key getter.

Status distinguishes the current revision, the last saved revision, pending
work, and a save error. Persistence errors pause automatic saves without erasing
the latest in-memory state. Retry is explicit and never bypasses revision checks
against another writer's changes. Close waits for the current revision, joins
the worker and clears session state/key. A failed or cancelled close keeps the
session available; abandoning unsaved state requires explicit owner-confirmed
Discard. No decrypted snapshot is written to a temporary file.

The Bubble Tea terminal starts only with `--interactive`, optionally focused by
`--server NAME --account NAME`. Missing arguments and TTY detection never open
its menus. It lists human-permitted connection points before management actions;
even a single point requires explicit Enter. Named CLI commands refuse ambiguous
accounts; explicit legacy profile selection remains compatible. Manual password
input and key-file selection are available, not multiline private-key paste.
SSH handoff reuses the unlocked session; inability to release input fails closed
instead of starting a competing reader. Windows VT consoles may require restart.

## Password authentication and grant binding

Password authentication selects exactly one owned credential. Each SSH dial
records fresh evidence that the SSH library actually offered that password;
a successful connection without authentication is not proof of the selected
account. Host-key verification happens before password authentication. Arbitrary
untracked authentication methods and fallback mixtures remain refused.

Key-based grant identity remains unchanged. A password-based text grant uses a
domain-separated HMAC binding under the authenticated vault master, including
length-delimited selected password and canonical public connection metadata.
The derived binding key is not returned. The published opaque binding is not an
unkeyed password hash or an independently usable offline guessing oracle. An
attacker with the vault master already owns the database; host/runtime/owner
trust boundaries are unchanged. Changing the selected password, connection
identity or vault master requires a new grant binding. Ordinary saves retain
the binding while using fresh encryption nonces. The legacy grant field name
`credential_sha256` continues to carry a 64-character opaque identifier; it must
not be interpreted as permission to hash plaintext passwords publicly.

SSH library authentication objects own their credential independently of vault
buffer cleanup. As with parsed private-key objects, Go/library memory cannot be
promised to be perfectly wiped; no disk, log, argv or environment copy is added.
Key-rotation commands reject password-only accounts before contacting a server.

## Implementation status

The implemented path includes the directory codec, key/password accounts,
explicit scopes, migration, one-unlock background sessions, Bubble Tea picker and
manual administration, owner exports/imports and authenticated value coordination.
[Full CI 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948)
passed on source `0576409`, including real terminal selection/import, empty
and seeded destination round trips, partial recovery and unchanged legacy/stream
acceptance. This is regression evidence for that source, not independent audit,
release publication, live migration or application/provider adoption.
