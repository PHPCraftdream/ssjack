# Native owner storage — implementation in progress

The native filesystem capability layer and installation-binding port are under
implementation. This is not acceptance of the complete application-store port:
the filesystem/record engine passed scoped native CI at `a270545`, but private-value
workflows, provisioning and the live owner coordinator still require acceptance.
The existing Linux record implementation remains unchanged.

## Protected filesystem capabilities

`ownerfs.Root` owns a directory fd/handle. Public operations accept bounded single
component names, never arbitrary paths relative to an ambient working directory.
The installation root is selected explicitly and is checked on every identity
boundary. Roots, files and temporary spools must belong to the current owner and
have private modes or protected owner-only ACLs. Files with unexpected links,
reparse points, object type or permissions refuse.

- Linux/macOS use `openat`/`O_NOFOLLOW`, owner modes, nonblocking advisory locks,
  fd-relative operations and exclusive native rename. macOS root-managed system
  aliases are restricted to the protected system prefixes needed for native paths.
- Windows uses handle-relative NT file operations with an explicit owner security
  descriptor, reparse refusal, native file identity and nonblocking byte-range
  locks. Only local fixed NTFS storage is supported by this implementation; it
  does not silently fall back to FAT, a remote share or a weaker permission model.
- Installation ownership and data transactions use separate lock names. A store
  holding its installation lock must still be able to execute one data transaction.
- Temporary files are created empty and detached before callers can write any
  ciphertext. On Windows, an independently opened handle retains the empty file;
  the POSIX-disposition handle must close before the spool is returned. Setting
  disposition alone does not remove the name. Both handles must identify the same
  file before unlinking. The original name must be absent before and after writes,
  and reusing that name must create a different file, not alias the spool.
  Failure to obtain an anonymous-before-use handle refuses; there is no named
  ciphertext-spool fallback and never plaintext staging.

Windows data handles use write-through and explicit file flushing. This is not
an assertion that Windows supplies a POSIX directory-fsync primitive. Namespace
publication is checked by native identity and the resulting file contents. The
filesystem layer makes no power-loss durability certification on any platform.
Uncertain publication must remain uncertain and must not be automatically replayed
or called application adoption.

## Installation bindings

The native `appstoreentry.Store` owns its protected root and exclusive installation
lock. It preserves bounded encrypted `binding.bin` bytes, refuses overwrite,
compares the named file to its open handle, checks before/after revisions and
reopens the original root path to detect replacement. Exported root handles are
owned duplicates; they are not master-key or plaintext-value getters.

Directory identity remains an authenticated part of the installation binding.
Moving/copying a binding does not automatically rebind it to a different root.
No container/KDF/profile/version reduction or automatic enrollment is included.

## Native ciphertext records

On Windows/macOS, `appstorefile` delegates to `appstorenative` over protected
`ownerfs` capabilities. The on-disk layout and byte shapes are unchanged: 40-byte
journal entries, 312-byte commit intents, 64-byte replaceable pointers, exclusive
candidates, immutable snapshots and retained ciphertext recovery copies. Record
names are canonical nonzero lowercase hexadecimal identities. Readers validate
sizes and before/after revisions; publication verifies identity and readback.

One native data lock owns each transaction. Operation leases exclude concurrent
mutation and transaction close. Closing a transaction invalidates its handles to
future operations without invalidating independently owned ciphertext files.
Installation ownership uses its separate lock. Hash/recovery copying is bounded
and cancellation-aware; ambiguous writes are not replayed automatically.

The native record tests exercise the public `appstorefile` facade on all three
OSes, including duplicate publication, stale journal counts, intent/pointer
round trips, recovery, cancellation, operation lifecycle and anonymous spools.
These tests use synthetic ciphertext, not real credentials or substitute crypto.
The record layer performs no KDF or encryption and makes no consumer-adoption claim.

## Native production-profile owner acceptance

`TestNativeOwnerFullProfile` exercises native installation creation, encrypted
binding persistence, production unlock, secret add/update/remove, owner reopen,
immutable references, historical encrypted snapshot verification and unchanged
installation binding. It uses the real four sequential 1 GiB Argon2id derivations
and real 1000-layer data encryption, never the scoped KDF overlay. No secret-value
getter is added for testing. Assertions use public owner metadata, authenticated
snapshot checks and absence of synthetic plaintext from stored ciphertext.

The test's loopback mTLS authority uses real signed protocol transitions in RAM.
It is deliberately volatile and does not certify native anchor-service ledger
storage, crash recovery or remote-service deployment. The production anchor service
and separate `appstoreintentio` prerequisite are not broadened by this client-store
port. Owner editing uses `appstorefile` commit intents, not `appstoreintentio`.

Both the scoped native matrix (when this test is impacted) and the full native
matrix require an explicit PASS from the production-profile test. An environment
skip in the ordinary unit suite is not acceptance. Until those jobs pass, the new
private-value test remains an unaccepted candidate.

## Acceptance required before shipping

Native tests must cover protected creation, identity/adoption, exclusive locks,
no-overwrite and explicit replacement, traversal/reparse/hard-link refusal,
anonymous spools, binding preservation and root replacement. Complete acceptance
also requires real native secret add/update/readback through the private store,
owner CLI/TUI parity and live coordinator operation on Windows, Linux and macOS.
Writing these checks or passing only a primitive layer is not that acceptance.
