# Minimal durable single-store anchor ledger

This Linux-only backend composes `appstoreanchorcore` with bounded local metadata
persistence for the universal encrypted-store writer. It stores no application
secret bytes or signing/private keys. It is not a network service, enrollment
mechanism, credential loader, generic secret getter or permission to encrypt.

`New` requires an already-open trusted, durably attached 0700 directory owned by
the effective UID, a fixed nonzero store ID and lifetime capacity 1..4096. It owns
an independent directory description and holds an exclusive nonblocking flock
until Close. The caller's FD remains theirs. `anchor.bin` is fixed, opened
no-follow/close-on-exec and must be a current-UID 0600 regular single-link file.
Other platforms explicitly return `ErrUnsupported`; there is no weaker fallback.

## Transaction and replay

The 64-byte header binds magic `SSASLOG1`, store ID, version 1 and capacity. Each
676-byte record contains `SSASREC1`, sequential index, credential fingerprint,
writer role, request length, zero-padded canonical request slot, original unsigned
reply and SHA-256 chain head. The header-derived genesis domain is
`SSAPP-ANCHOR-LEDGER-GENESIS-v1`; record domain is
`SSAPP-ANCHOR-LEDGER-RECORD-v1` over store, previous head and the record's first
644 bytes, without NUL separators. The chain is corruption detection, not a MAC
or protection against a malicious filesystem/root/owner rewriting history.

An accepted writer mutation appends one complete record, syncs file and directory,
checks safety/size, and only then publishes its in-memory state/result. The same
transaction records canonical request binding, resulting state/version and
original outcome. Rejected authorized mutations and CAS conflicts are retained.
Identical authorized replay returns that original outcome/state/version, never a
later current state, even after restart or at capacity. Changed canonical bytes
under the same credential/request ID or logical-kind/idempotency key return
`ErrConflict`; no replacement key is generated and no record is overwritten.

Authorization is rechecked before replay. Reader mutations are rejected without
using historical writer outcomes or consuming durable capacity: they are not
accepted writer transactions. Read does not append or increment a version. A
Read ID colliding with a durable mutation ID is rejected; outstanding network
Read-ID leases must additionally be enforced by the eventual TLS request layer.
Supplied Grants are configuration values, not proof of certificate authentication.

Capacity is reserved before accepting a new mutation. There is no eviction,
automatic growth, compaction, truncation or silent migration. A full store still
serves reads and original replays. Capacity/header changes require separately
reviewed migration preserving every idempotency record.

Any possibly partial append or sync failure returns no result and permanently
fences that handle, including reads. Close/reopen validates the entire bounded
log, exact DTOs, chain, indices, namespaces and independently reevaluated original
outcomes, then syncs before serving. A complete uncertain record can therefore
be reconciled after restart. Partial tails/corruption fail closed and are left
untouched for human recovery, never guessed away. `ErrUncertain` does not prove
commit or no effect; callers must use authenticated Read/reconciliation.

Durability is conditional on the trusted filesystem honoring file/directory sync
and on trusted ownership of the already-attached directory. No power-loss test,
distributed replication, root/same-UID defense, total IO deadline or protection
against rollback of the trusted anchor itself is claimed. Calls hold admission
until actual IO returns; Close waits, and copied handles share lifecycle.

Synthetic public-CI tests cover actual client DTOs, restart/original-result replay,
credential namespaces, canonical collision, reader denial, capacity, rejection/
conflict retention, competing writers/CAS, partial writes, file/directory sync
failure fencing and corruption (including a rehashed false result). No real
credentials, application secrets, deployment or local test/build runs are used.
