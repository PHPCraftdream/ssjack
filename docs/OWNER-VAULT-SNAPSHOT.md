# Owner Vault Snapshot over the Remote Backend (task #488)

This document designs how the `--interactive` application-approval menu can work when the
owner TUI is connected to the **Remote** owner backend, i.e. when the vault ciphertext lives
on the keeper side and the owner client only speaks the owner packet protocol to it.

**Status:** design (task #488). Not yet implemented. This document records the current state, recommended keeper-side design, implementation plan, and remaining owner decisions.

## Task premise corrections

Two premises in the task description need correction before the design is stated:

1. **The owner packet channel does not use Ktav framing.** The owner packet channel encodes
   *sealed canonical JSON* under the domain `ssjack/owner-ipc/v1`; the domain constant is set
   on every outgoing packet by the seal path (internal/ownerpacket/codec.go:50-57, with
   `const domain = "ssjack/owner-ipc/v1"` at codec.go:16). Ktav is the file format of the
   vault itself and of the local keeper TLS transport framing in `internal/wire`; it is not
   part of the owner client ↔ keeper protocol. The wire contract in this document therefore
   follows the existing owner packet codec: sealed canonical JSON envelopes, closed change
   structs, and the existing error set (`ErrProtocol`, `ErrAuthentication`, `ErrUncertain`).
2. **`docs/APP-DISCOVERY.md` has no explicit known-limitation paragraph about the Remote
   refusal** `[ssjack code]`: a grep over that document finds only the vault-records note at
   docs/APP-DISCOVERY.md:27 (owner/remote-MCP records in the vault payload). The limitation —
   that `SnapshotVault` refuses and approval writes stay unavailable on Remote backends — is
   documented only as a code comment at internal/ownerbackend/remote.go:56-59. Any doc update
   belongs in a later slice of this task.

Throughout, `[ssjack code]` marks statements verified against this repository with file:line
references; `[assumption]` marks design assumptions that are plausible from the code but not
fully proven by a single reference.

## 1. Current state: what SnapshotVault guarantees today

### 1.1 Interface and call sites

- The backend interface declares `SnapshotVault() (string, error)` at
  internal/ownertui/model.go:27, next to `Edit`, `Submit`, `Link`, and `Reconcile`.
- The sole production call site is model.go:349-366 `[ssjack code]`: the TUI wraps the call
  as a closure `func() error { _, err := m.backend.SnapshotVault(); return err }` and hands it
  to the approvals controller. **The returned path is discarded** — only the error is used.
  The TUI needs the *guarantee* ("a verified snapshot of the current ciphertext exists on
  disk"), not the path.
- The write itself, after the snapshot gate, is
  `m.backend.Edit(func(v *vault.Vault) error { return approvals.ApplyVerified(v, mut) })`
  (model.go:420) — a revision-pinned in-process vault edit on the local backend.

### 1.2 Write gate in the approvals controller

- `SnapshotBeforeFirstWrite()` (internal/ownertui/internal/approvals/controller.go:57-70) is
  called from the TUI at model.go:414. The snapshot is taken only **before the first approval
  write of the session** (`sessionSnapshotDone` short-circuits later calls, controller.go:58-60).
- On failure the controller records the generic status message `snapshot_failed` and aborts
  (controller.go:65-67); the specific underlying error text is **not** surfaced to the user.

### 1.3 Local implementation chain

`[ssjack code]` The local backend is pure delegation:

- internal/ownerbackend/local.go:66-67 — `Local.SnapshotVault` delegates to the manager.
- internal/ownerdb/manager.go:123-130 — `Manager.SnapshotVault` takes the manager mutex and
  calls `m.db.SnapshotSaved(m.path)` (refusing when no database session is open).
- internal/vault/internal/session/session.go:378-402 — `Session.SnapshotSaved` does the work.

### 1.4 What the snapshot guarantees

`[ssjack code]`

- **Fully-saved gate:** it refuses unless the session is fully saved — closed/closing,
  missing state, a pending save error, `saved != revision`, or a zero `savedCipher` all
  return "database snapshot is not fully saved" (session.go:383-384).
- **Freshness verification:** it reads the on-disk ciphertext and requires
  `sha256.Sum256(encoded) == s.savedCipher`; on mismatch it refuses with
  "vault changed since the last save; reload before snapshotting" (session.go:386-392).
- **Durable output:** it writes `<vaultpath>.approval-snapshot-<UTC timestamp>-<16-byte hex
  random>.ssjack.ktav` — the name is produced by `store.RecoveryPath(path,
  "approval-snapshot")` (internal/vault/internal/store/store.go:100-106) — via `store.Commit`
  (session.go:394-399). For snapshots `Commit` is called with `expected == nil`, which means
  **direct `O_EXCL` create + write, no compare-and-swap staging**: `commitFile` opens the
  destination with `os.OpenFile(path, O_WRONLY|O_CREATE|O_EXCL, 0600)` and writes directly;
  on a write error it returns "new vault may be incomplete"
  (`[ssjack code]` internal/vault/internal/store/store.go:69-78). The temp-file staging +
  sha256 CAS double-check (store.go:79-98) runs only when `expected != nil` — i.e. for
  ordinary vault saves, **not** for snapshots. Consequences:
  - an interrupted write can leave an incomplete/unparseable `approval-snapshot` file on disk;
  - each later attempt generates a new random unique filename, so it does not reuse or collide with that prior partial file;
  - before creating a new snapshot, retention prunes matching snapshots, including partial/unparseable files; a prune failure refuses the operation with `operation`;
  - no deletion of an old partial is guaranteed until a prune succeeds;
- **Retention:** no pruning exists for `approval-snapshot` files; they accumulate
  `[ssjack code: no prune/keep/retention logic found in store or session; unverified whether
  external cleanup exists]`.
- **Who may read it:** the snapshot is a plain file next to the vault, on the machine that
  holds the vault. Anyone with filesystem access to that directory can read it — but the file
  contents are the already-encrypted ciphertext at rest, so it leaks no plaintext and no keys.
- **The digest is not written to a sidecar.** It lives only in memory
  (`savedCipher`, session.go:120 and 345) and is exposed through
  `SavedCipherDigest()` (session.go:406-413), which deliberately returns the digest of the
  *ciphertext*, never any plaintext digest or key material.

### 1.5 Remote implementation today

`[ssjack code]` The remote backend refuses both halves of the flow:

- `SnapshotVault` returns `ownerpacket.ErrProtocol`, with the comment (remote.go:56-60):
  > SnapshotVault refuses: the vault ciphertext and its saved digest live on
  > the keeper side and the owner protocol has no snapshot operation, so the
  > client cannot take a verified snapshot. Approval writes stay unavailable
  > on remote backends instead of faking success.
- `Remote.Edit` refuses separately: "Arbitrary callbacks cannot cross the closed owner
  channel" (remote.go:149-150).

Consequence: over Remote, **both** the snapshot and the approval write are unavailable today.
The gap is larger than only the snapshot; any design must close both halves or the TUI flow
still fails at model.go:420.

## 2. Why the snapshot must run on the side that owns the ciphertext

- **Atomicity requirement.** The snapshot must capture exactly the ciphertext that the
  subsequent approval write will base on. The save path is a sha256 compare-and-swap on the
  current file (store.go:83-84 for the initial check, store.go:94-97 for the pre-replacement
  recheck) — a client-side copy would race any concurrent keeper-side writer and could not
  verify freshness without reading vault bytes, which is exactly what the client must not do.
- **Least exposure.** The owner client must never read or transfer vault ciphertext; only the
  keeper holds it. Any option that ships ciphertext (or its bytes) over the owner channel to
  let the client verify a snapshot violates this.
- **Path and digest knowledge stay keeper-side.** The vault path, the in-memory `savedCipher`
  digest, and the recovery-file naming all live in the keeper process. The client needs to
  learn only success/failure — not the path, not the digest, not the file layout.

## 3. Options and decision

**Atomicity terminology:** in §§3.1/3.3, “atomic” means a serialized manager transaction through its durable point, not atomic filesystem publication or rollback/deletion of the standalone snapshot file.

### 3.1 Option table

| # | Option | Atomicity | What the client learns | Authorization | Protocol surface | Failure modes | Verdict |
|---|---|---|---|---|---|---|---|
| a | New owner-protocol operation `snapshot_vault`, called by the client before it writes | None across the two steps: a concurrent keeper writer can change the vault between the snapshot reply and the write | Snapshot success/failure only; write result separately | Snapshot op must be gated to the same approval-write authorization, or it becomes a standalone vault-integrity oracle | One new operation + retention policy for keeper-side snapshot files + a second round trip | Race window between snapshot and write; snapshot may be for stale ciphertext; retention orphans if the write fails | REJECTED — insufficient on its own |
| b | Keeper-side **composite** approval-write operation(s): snapshot on the keeper and apply the revision-pinned approval mutation atomically in one operation | Serialized manager transaction through the durability point (§4.3.1), not atomic filesystem publication or rollback of the standalone snapshot file | Success/failure of the whole approval write; snapshot failure is a distinct, typed error | Reuses the existing mutating-operation authorization path (closed change bodies, revision pinning) | New closed change type + new operation(s); follows the `DirectoryChange`/`SecretChange` pattern (internal/ownerpacket/types.go:28-43) | Single operation, single error surface; snapshot-for-stale-ciphertext is caught by the same freshness check as the write; durability is confirmed before the reply | **RECOMMENDED** |
| c | Leave approvals unavailable on Remote, with a clearer error message | N/A — nothing runs | A distinct refusal | Unchanged | No new operation; error-mapping change only | Approvals remain unusable over Remote | **REJECTED** as end state; standalone `SnapshotVault` refusal remains; mixed builds refuse at handshake (§5) |

### 3.2 Option (a): client-initiated `snapshot_vault` — rejected

Adding a `snapshot_vault` operation fixes only the first half of the flow. The approval write
itself is `Edit` with a Go callback (model.go:420), which still cannot cross the owner channel
(remote.go:149-150). To make approvals work the client would additionally have to send the
approval mutation over the wire — at which point a composite has been built anyway, just
spread across two round trips instead of one. Specific defects:

- **Race window:** a concurrent keeper-side writer can change the vault between the snapshot
  reply and the arrival of the write; the snapshot then covers stale ciphertext that the
  write does not build on.
- **Retention across two round trips:** if the write never arrives (client crash, disconnect),
  the keeper holds an orphan snapshot with no owner-side bookkeeping to prune it.
- **Authorization creep:** a standalone snapshot operation is usable independently of any
  approval write, turning it into a vault-integrity oracle unless separately gated.

### 3.3 Option (b): keeper-side composite approval-write operation — recommended

One (or a small family of) mutating operation(s) that, on the keeper, in a single dispatch:
(1) run the equivalent of `Session.SnapshotSaved` (session.go:378-402), refusing unless fully
saved and digest-fresh, and (2) apply the revision-pinned approval mutation. The client never
calls snapshot.

Arguments `[ssjack code]` unless noted:

- **Atomicity:** snapshot and write run in one manager-level composite critical section
  (§4.3.1) — a single `m.mu` section covering retention prune, `SnapshotSaved`, the
  revision-pinned mutation, and a durability wait until `saved == new revision`
  (session.go:343-345). No manager writer interleaves between snapshot and write, and the
  reply is sent only once the write is durable. Here atomicity means serialized manager
  transaction/durable point, **not** atomic filesystem publication or rollback of the
  standalone snapshot file. The keeper's single-flight dispatch lock
  (internal/ownerdispatch/peer.go:85) is only outer serialization; transaction atomicity is
  attributable to the manager-level section, not `d.lock` alone.
- **Matches the existing pattern** of mutating operations carrying closed change bodies:
  `DirectoryChange` and `SecretChange` (internal/ownerpacket/types.go:28-43) are small closed
  structs serialized into sealed canonical JSON. An `ApprovalChange` fits the same shape:
  action (`approve`/`revoke`), name, path, hash, optional replaced-approval reference.
- **No new client-visible vault knowledge:** the client learns success or a typed failure;
  paths, digests, and file layout stay keeper-side, per section 2.
- **The existing approval-write semantics are pure vault mutations** and serialize cleanly:
  `ApplyVerified` verifies revocations against the live record then applies
  (internal/ownertui/internal/approvals/controller.go:318-328), and `ApplyMutation` validates
  name/path/hash and calls `ApproveApplication` (controller.go:330-348). The `Mutation` struct
  already carries only bounded fields (kind, name, path, hash, replaces) — `[assumption]`
  mapping it to a closed packet type is mechanical, but the exact field set needs confirmation
  when the packet type is drafted (unverified).
- **TUI adaptation:** keep `SnapshotVault` in the TUI backend contract, and give the approvals
  controller a mode where the snapshot is implicit in the composite write. The controller
  skips the pre-write `SnapshotBeforeFirstWrite` call when the backend declares composite
  writes; the operation supplies the same snapshot guarantee keeper-side and atomically.
  `SnapshotVault` remains in the interface for the local backend and any future caller; Remote
  retains its standalone refusal (§3.4). This is a design choice within option (b)
  `[assumption]`; the mode flag preserves existing local behavior.

### 3.4 Option (c): clearer refusal — rejected as end state; standalone refusal retained

Approvals staying unavailable on Remote is not an acceptable end state for task #488, but the
existing standalone `SnapshotVault` refusal remains: it is not converted to a fake success or
used as a compatibility path. Mixed old/new builds are refused by the protocol-version check
(§5); there is no capability negotiation or fallback.

- **Standalone refusal remains:** `Remote.SnapshotVault` continues to refuse without protocol
  traffic, as documented by `remote.go:56-59` and its existing test. Composite approval writes
  are a separate keeper-side operation; they do not make the standalone snapshot call succeed.
- **Improved error surface:** any error-mapping improvement for the standalone refusal is a
  separate concern. On a new client, an owner-channel attach authentication failure gets the
  conservative version/connection message specified in §5; it does not assert a version
  mismatch with certainty.

### 3.5 Disposition of `TestRemoteSnapshotVaultRefusesWithoutProtocolTraffic`

The existing test (`[ssjack code]` internal/ownerbackend/remote_test.go:60-69) asserts empty
path, `ErrProtocol`, and zero protocol traffic for Remote `SnapshotVault`.

- **(a)** Test unchanged; the refusal stays and the new operation is separate. The test would
  coexist with a new snapshot path, which is the incoherence option (a) creates.
- **(b)** Keep the test verbatim: Remote retains refusal for the *standalone* snapshot entry
  point while the composite operation carries the guarantee. Its deletion is a contract change
  requiring separate review.
- **(c)** Test unchanged; only error classification around it improves.

## 4. Wire contract of the recommended option

The recommended option (keeper-side composite) adds approval writes to the owner packet
protocol so the snapshot is taken **inside the keeper**, immediately before the approval
mutation. The client never calls a snapshot method; the snapshot becomes a side effect of the
mutating operation.

### 4.1 Two operations vs. one operation with an `action` field

Decision required: two new operations (`approve_application`, `revoke_application`) or one
operation (`approval`) with an `action` field.

**Recommended: TWO operations.** Rationale:

| Criterion | Two operations | One operation + action |
|---|---|---|
| Union closure style | Matches existing union: `DirectoryChange`/`SecretChange` are separate bodies selected by operation name (`[ssjack code]` internal/ownerpacket/types.go:61-72) | Introduces a new dispatch dimension (op × action) the closed union does not model today |
| Validation locality | Each body validates exactly one shape; `application_path` required only for approve, structurally impossible to send on revoke | Decode-time validation must cross-check `action` vs. presence of fields — two chances to get it wrong |
| Closed-union check | "Exactly one body" and "revision required for all mutating ops" (types.go:156-167) extend naturally | The action string becomes a second, stringly-typed discriminator inside a single body |
| Error classification | Both designs use the same closed error set; no advantage | Same, no advantage |

The operation name already is the discriminator in this protocol; duplicating it inside the
body would create two sources of truth. The wire cost of two operations is one extra name
string per call — negligible against the `MaxWire` 256 KiB ciphertext bound (`[ssjack code]`
internal/ownerpacket/types.go:16-18).

### 4.2 New request body

Add one optional body type on `Command` (`[ssjack code]` internal/ownerpacket/types.go:61-72).
The body must carry what the TUI menu actually reviewed, not just name/path: the TUI
`Mutation` carries `Kind, Name, Path, Hash` (the hex descriptor fingerprint the owner
reviewed) and `Replaces` — approve builds `Mutation{Kind:"approve", Name, Path, Hash,
Replaces}` at `[ssjack code]` internal/ownertui/internal/approvals/controller.go:178, and
revoke builds `Path`/`Hash` from the live record (controller.go:234-237). The vault enforces
replacement against the stored hash (`ApproveApplication` requires
`replacesHash == previous.Hash` and refuses an unchanged record,
`[ssjack code]` internal/vault/internal/core/directory.go:444-459), enforces path uniqueness
across approvals (directory.go:463-467) and `approval.MaxApprovals` (directory.go:460-462).

```
ApprovalChange {
    application_name  string  // required
    application_path  string  // required for approve; must be absent for revoke
    reviewed_hash     string  // required: hex descriptor fingerprint the owner reviewed
    replaces_hash     string  // approve+replace and revoke: hash of the live record being replaced/reviewed; empty for first-time approve
}
```

- `application_name`: same bounds the TUI validates today — approve validates name/path with
  a 512-character path bound (`[ssjack code]` internal/ownertui/internal/approvals/controller.go:336-344);
  name is bounded by the same operation-name/body bounds family (`[ssjack code]`
  internal/ownerpacket/types.go:181-214).
- `application_path`: bounded at **512 bytes** (canonical, cleaned path), matching the existing
  controller bound (`[ssjack code]` internal/ownertui/internal/approvals/controller.go:336-344).
- `reviewed_hash` / `replaces_hash`: bound is **exactly 64 lowercase hex chars** (sha256 hex),
  following the fingerprint format the TUI produces at `[ssjack code]` controller.go:178 —
  `hex.EncodeToString(e.candidate.Fingerprint[:])`; wrong format → `invalid`.
- Both operations are mutating → `revision` is required, exactly per the existing rule
  (`[ssjack code]` internal/ownerpacket/types.go:156-167).

| Field | Bound | Required on approve | Required on revoke | Over-bound / mismatch class |
|---|---|---|---|---|
| `operation` | op-name bound (types.go:181-214) | `approve_application` | `revoke_application` | `invalid` |
| `revision` | uint64, must match current owner revision | yes | yes | `stale` (vault.ErrOwnerRevision) |
| `plan` | uint64 | yes (existing plan semantics) | yes | per existing plan handling |
| `application_name` | existing name bound; non-empty | yes | yes | `invalid` |
| `application_path` | ≤ 512 bytes, canonical/cleaned | yes | **must be absent** | `invalid` |
| `reviewed_hash` | exactly 64 lowercase hex chars (sha256 hex, controller.go:178 format) | yes | yes | `invalid` |
| `replaces_hash` | exactly 64 lowercase hex chars; empty only for first-time approve | approve+replace: yes; first-time: empty | yes | `invalid` |

The closed-union check extends: `ApprovalChange` is the sole body for these two operations;
any command carrying it together with another body, or carrying it with no `revision`, fails
`Valid()` before dispatch (`[ssjack code]` internal/ownerpacket/types.go:156-167, codec.go:77-93).

### 4.2.1 Keeper-side re-verification

The keeper MUST NOT trust the client-claimed path or hash:

- **Approve:** the keeper re-derives the descriptor fingerprint itself from the file at
  `application_path` on the keeper machine and requires equality with `reviewed_hash`. The
  client cannot compute vault-side admission evidence; the fingerprint is derived from
  keeper-side state, so only the keeper can bind it `[assumption: discovery/app-root scanning
  runs on the keeper side over the Remote backend; if discovery is client-side the keeper
  still re-verifies because it owns admission]`.
- **Replace/revoke:** the keeper requires `replaces_hash` to equal the hash of the live vault
  record — the `directory.go:453` equivalence (`[ssjack code]` internal/vault/internal/core/directory.go:453).
  This is the TUI's `VerifyRevoke` pin (`[ssjack code]` internal/ownertui/internal/approvals/controller.go:291-315)
  carried across the channel instead of checked in-process.
- **Mismatch → the whole operation fails with the new wire code `review`**, added to the closed
  code set. Client mapping: a typed review-stale error the TUI renders as "the reviewed
  application changed — re-open the approvals menu". Mapping point: `codeError`'s fixed table
  at `[ssjack code]` internal/ownerrpc/snapshot.go:49-70. Justification for adding one code
  rather than reusing `stale`: `stale` maps to `vault.ErrOwnerRevision` (snapshot.go:53-54),
  which tells the operator to retry after a reload — retrying a review-stale approval would
  perform an **unreviewed** write, so semantics must be distinct and non-retryable-as-is.
- **Admission checks stay vault-side:** the keeper resolves the candidate against its own live
  vault record + scan and applies the same uniqueness/MaxApprovals checks
  (`[ssjack code]` internal/vault/internal/core/directory.go:460-467).

### 4.3 Snapshot semantics inside the keeper

The keeper-side handler for `approve_application` does **not** assemble the flow from public
calls; it invokes one new manager-level composite method (§4.3.1). The per-peer single-flight
dispatch lock (`[ssjack code]` internal/ownerdispatch/peer.go:85) is only an outer serialization
of owner commands — it does **not** make snapshot + write atomic. `Manager.SnapshotVault` takes
`m.mu` (`[ssjack code]` internal/ownerdb/manager.go:123-131) and `Manager.edit` takes `m.mu`
again separately (manager.go:140-165), so another in-process writer (worker, local TUI) can
interleave between them. Moreover, edit only **enqueues** persistence (`s.enqueue(payload)`,
`[ssjack code]` internal/vault/internal/session/session.go:203-206); the durable point is later,
when the save job completes and sets `s.saved = job.revision; s.savedCipher = s.saveDigest()`
(session.go:343-345). `SnapshotSaved` refuses unless `saved == revision` (session.go:383), so
the snapshot must precede enqueue of the new save.

Ordering remains snapshot-**then**-mutate, matching the TUI's `SnapshotBeforeFirstWrite`
semantics (`[ssjack code]` internal/ownertui/internal/approvals/controller.go:57-68). Snapshot
failure fails the whole operation; the reply carries the snapshot error class, and no approval
is written.

### 4.3.1 Keeper-side transaction and lock order

Define **one** manager-level method — e.g. `Manager.ApproveWithSnapshot(ctx, expected uint64,
mut approvals.Mutation) error` (exact name is an implementation detail) — performing under a
single manager critical section:

1. **Retention prune** of the oldest `approval-snapshot` files (§4.6), before creating the new one.
2. **`Session.SnapshotSaved`** — the fully-saved + digest-fresh gate (`[ssjack code]`
   internal/vault/internal/session/session.go:380-402).
3. **The revision-pinned approval mutation** via the internal `ApplyAt` path (`[ssjack code]`
   internal/ownerdb/manager.go:147-149).
4. **A durability wait:** block until the save queue reports `saved == new revision`
   (tracked at `[ssjack code]` session.go:343-345) or the context deadline expires.

**Lock order: manager mutex → session mutex.** The composite holds `m.mu` for pruning, `SnapshotSaved`, `ApplyAt`, and a direct `m.db.Flush(ctx)` durability wait. **Do not call `Manager.Flush`** from this composite: `Manager.Flush` takes/releases `m.mu` before calling `m.db.Flush(ctx)` (`[ssjack code]` internal/ownerdb/manager.go:220-242), so calling it while already holding `m.mu` deadlocks. `Session.Flush` locks `s.mu` to inspect/capture its change signal, unlocks before waiting, and its save worker performs the save outside `s.mu`, reacquiring it only to update `saved`/`savedCipher` and signal (`[ssjack code]` internal/vault/internal/session/session.go:235-257,321-350). Therefore these wait/worker paths do not need `m.mu`, and there is no lock inversion in these paths. All manager mutation access must go through `m.mu`; direct session access must not be available outside `Manager`. Other manager writers wait until the durability result, preserving the transaction ordering.

**Failure after enqueue:** if `ApplyAt` has enqueued the new save and the context expires or the save reports an error, return the `operation` error class. The in-memory mutation remains; there is no rollback claim. On context timeout the queued save may still complete after the method returns, so the reply must not claim rolled-back state. The owner must re-read state after any operation error at or after enqueue, and must never replay that operation. A save error leaves the mutation unsaved/error state; a timeout leaves the durable outcome uncertain until re-read.

**Reply path: RECOMMENDED NO.** The reply reuses `Reply` unchanged — `error`, `metadata`,
`status` (`[ssjack code]` internal/ownerpacket/types.go:140-146) — which states it carries
"metadata and persistence evidence only, never stored values" (types.go:139). The client learns
success/failure only. The TUI discards the snapshot path today (`[ssjack code]`
internal/ownertui/model.go:359-362). An absolute keeper path would leak deployment topology.

**Never sent on the wire:** vault ciphertext or key material; plaintext digests; absolute keeper
filesystem path of the snapshot; approval fingerprint hex beyond what the TUI already displays;
raw keeper error text. Errors cross as typed wire codes only (§4.4).

**Bounded disclosure — `Status.CipherDigest` crosses.** The reply unavoidably carries
`Reply.Status.CipherDigest`, a `[32]byte` ciphertext digest present on every reply today
(`[ssjack code]` internal/ownerpacket/types.go:111-115,139-146; set at
internal/ownerrpc/snapshot.go:138), because the reply type is shared and
`codeError`/`decodeSnapshot` reuse it (snapshot.go:173). It is sha256 of already-encrypted
ciphertext and reveals nothing about plaintext or keys; any owner peer can already obtain the
same value from `snapshot`. It is not a new disclosure.

### 4.4 Error classes

| Failure | Wire/endpoint result | Client-side experience |
|---|---|---|
| Snapshot operation failure (including not fully saved) | `operation`-class default code (`[ssjack code]` internal/ownerrpc/snapshot.go:28-70) | Mapped operation failure; no raw keeper detail |
| Stale revision | `stale` → `vault.ErrOwnerRevision` (`[ssjack code]` internal/ownerrpc/snapshot.go:28-70) | Revision-conflict class |
| Reviewed state no longer matches (keeper re-verification) | `review` (new code, §4.2.1) | Typed review-stale error; non-retryable-as-is |
| Pending rotation / conflicting write | `pending` → `ownerdb.ErrPending` (`[ssjack code]` internal/ownerrpc/snapshot.go:28-70) | Retry-later class |
| Keeper genuinely uncertain post-write | `uncertain` / `rotation-uncertain` sentinels (`[ssjack code]` internal/ownerpacket/types.go:22-25) | `ErrUncertain` |
| Protocol version mismatch during initial Hello | No wire reply; receiving client `open()` returns `ErrProtocol`, `Client.AcceptHello` returns `ErrAuthentication`; client closes before Auth, server exits waiting for Auth (`[ssjack code]` `internal/ownerpacket/codec.go:65-93,127`; `internal/ownerpacket/client.go:28-40`; `internal/ownerrpc/server.go:51-75,91-110`) | `ownercontrol.Open` / interactive surface generic `ErrControl`; proposed conservative message in §5.1 |
| Authentication failure / expired deadline or lease | Wire `authentication` maps both `ErrAuthentication` and `ErrExpired` (`[ssjack code]` internal/ownerrpc/snapshot.go:40-45) | Authentication/expired client error; no raw keeper detail |
| Malformed request | `invalid` (`[ssjack code]` internal/ownerdispatch/peer.go:68-91) | `ErrProtocol` |

### 4.5 Logging

Requirement: identical policy to existing mutating ops — metadata only (operation name, revision,
outcome class), never application paths, digests, or snapshot contents. **No logging statements
were found in internal/ownerdispatch, internal/ownerdb, or any internal/owner* package in this
tree** (grep for `slog`/`log.` returned nothing), so the existing policy itself is `unverified`;
the requirement above stands as a design constraint either way.

### 4.6 Retention bound

Baseline: today approval-snapshot files accumulate without pruning — snapshots are only written
on approval writes and no pruning exists (`[assumption]` per the task brief; no pruning code
found in internal/ownerdb/manager.go or session.go, `unverified` in detail).

**Recommended rule:** keeper-side retention of **last N = 10** approval-snapshot files per
vault, pruned **before creating the new snapshot**, inside the same manager-level critical
section as the composite write (§4.3.1). Rationale:

- N = 10 comfortably covers any plausible crash-recovery window while bounding worst-case disk
growth to 10 × vault ciphertext size.
- Pruning inside the composite critical section keeps the rule self-enforcing: no background
  sweeper, timer, or config surface; accumulation is capped at the moment it would grow.
- **Hard bound, fail closed:** if pruning fails (e.g. an unremovable file), the composite write
  is refused with the `operation` error class. A silently exceeded bound voids the DoS argument
  in §6.5.
- Snapshot creation uses direct `O_EXCL` create-and-write, not staged CAS (§1.4). If interrupted,
  a partial/unparseable file may remain. A later attempt uses a new random unique filename; the
  retention prune runs before creation and treats such files as prunable. If pruning fails, the
  operation is refused with `operation`; no rollback or deletion of the partial is guaranteed
  until a prune succeeds. The vault itself remains unaffected.

## 5. Protocol versioning and mixed-build refusal

Approval operations and the protocol envelope version bump MUST ship in the same slice: new
builds seal owner packets with `Version = 2` and accept only version 2; old builds accept only
version 1. **Old/new interoperation is unsupported in either direction.** New/new handshakes
work; old/old works only as legacy behavior, with no ongoing support promise. A mixed pair
refuses during the initial handshake, before command dispatch.

**Numeric packet version:** `[ssjack code]` `internal/ownerpacket/codec.go:50,90` writes the
envelope `Version` and checks the decoded numeric value. In this slice, `seal()` writes
`Version = 2` and `open()` accepts only 2; older builds accept only 1. Keep the envelope domain
`ssjack/owner-ipc/v1` unchanged (`codec.go:16`): semantic `Version` is bumped, not the domain.
Update protocol docs, v2 fixtures/goldens and every ordinary version-1 assertion. Keep any v1
encoder/decoder needed by tests as a frozen, test-local copy; do not alter production behavior
to negotiate versions. Existing ownerpacket test references include the v1 fixture at
`internal/ownerpacket/codec_test.go:113` and duplicate-version JSON at codec_test.go:142; the
latter is intentionally a malformed duplicate-field test and should be reviewed as such. Keep
frozen-v1 test inputs separate from ordinary fixtures/assertions that must move to v2.

No new envelope field, frame, packet, capability exchange, probe, fallback, or shim is introduced
to make old code understand the new protocol. `Remote.SnapshotVault` retains its existing
standalone refusal (§3.4); it is not a negotiation or fallback path.

### 5.1 Mismatch is detected on the first handshake packet

The version check applies to the first handshake packet, not an approval command: the server
sends Hello first and the client must accept it before sending Auth (`[ssjack code]`
`internal/ownerrpc/client.go:73-98`; server flow `internal/ownerrpc/server.go:91-110`). Server
Hello is sealed by `ownerpacket.Server.Hello` (`[ssjack code]` `internal/ownerpacket/server.go:32-44`).
There is no version probe or fallback.

- **New client + old keeper:** the old keeper's v1 Hello is rejected by the receiving new client's `open()` with
  `ErrProtocol`; new client `AcceptHello` converts that to `ErrAuthentication` through
  `peer.fail()` (`[ssjack code]` `internal/ownerpacket/codec.go:65-93`; `ownerpacket/client.go:28-40`).
  The client sends no Auth and closes Attach; server's `ReadFrame` fails while waiting for Auth and
  serving exits/closes (`[ssjack code]` `internal/ownerrpc/server.go:51-75,91-110`).
  `Server.Authenticate` is not invoked.
- **Old client + new keeper:** the old client's `open()` rejects the v2 Hello with `ErrProtocol`;
  old client `AcceptHello` converts it to `ErrAuthentication`. The client sends no Auth and closes Attach;
  server's `ReadFrame` fails while waiting for Auth and serving exits/closes. `Server.Authenticate` is
  not invoked. No Auth or reply is sent; the channel closes. The old executable's UI text is unchanged.
- In normal old/new pairings, mismatch is rejected by the receiving client's `AcceptHello`; it does
  not reach `Server.Authenticate`.

| Client | Keeper | Result |
|---|---|---|
| New (v2) | New (v2) | Hello/Auth/Ready completes; commands may follow |
| New (v2) | Old (v1) | New client rejects old Hello; no Auth/reply; channel closes |
| Old (v1) | New (v2) | Old client rejects new Hello; no Auth/reply; channel closes |
| Old (v1) | Old (v1) | Legacy v1 handshake works; this is not an ongoing support promise |

`ownercontrol.Open` collapses load failures, Attach errors, non-absent dial failures, and service-start failures to `ErrControl` (`[ssjack code]` `internal/ownercontrol/control.go:42-45,72-75,89-102`), and `RunInteractive` maps any `Open` error to `ErrControl` (`[ssjack code]` `cmd/ssjack/internal/shell/interactive.go:30-33`). Therefore the following is a **proposal for the generic `ErrControl` outcome, not current UI**; `ErrControl` spans multiple failures and cannot be taken to mean only protocol mismatch:

> Owner control could not be opened. The keeper may run a different ssjack protocol version, vault credentials may be invalid, or the owner connection/setup may be unavailable. Restart keeper and client from the same build; verify vault credentials and owner-channel setup.

The existing old executable's UI remains unchanged. The message test belongs in the existing
`cmd/ssjack/internal/shell/shell_test.go`, not `ownertui`, which has no Attach UX (§8.6).

## 6. Security analysis (plain terms)

### 6.1 Who can call it

Only an authenticated owner peer, after the mutual hello/auth/ready handshake and lease checks
of the packet channel (`[ssjack code]` internal/ownerpacket/codec.go:23-36 envelope,
docs/OWNER-IPC-PROTOCOL.md:156-177) and the per-command peer gate (`[ssjack code]`
internal/ownerdispatch/peer.go:68-91: closed/dead peer → `ErrAuthentication`, invalid command
→ `ErrProtocol`, expired deadline → `ErrExpired`). The authorization level is identical to
`directory` / `secret` mutations: the owner channel itself. No new privilege tier is introduced.

### 6.2 Attacker controlling the agent (not the owner channel)

Cannot invoke the operation: commands originate only from the authenticated owner peer, and
the agent never holds owner-channel credentials. The attacker sees no new data — the reply
carries no ciphertext, no plaintext digest, no paths (§4.3.1; the only digest on any reply is
the pre-existing `Status.CipherDigest` of ciphertext, §4.3.1 bounded disclosure). Approval
writes were already impossible for such an attacker before this change; nothing widens their
position.

### 6.3 Attacker who can talk to the owner socket

Such an attacker can already mutate the vault via existing operations (`directory`, `secret`,
`recovery`) — every one of those changes owner data. The new operation adds no capability
beyond what an in-person TUI session already performs: an approval is an owner decision, and
the operation only performs a decision the owner-channel holder could otherwise perform
locally with vault access.

Honest note: someone with owner-channel access can now approve applications without having the
TUI. Assessment: this is equivalent, not a real widening — any vault-mutating op already
changes owner data, and the approval is one more owner-data mutation behind the same
authentication gate. The TUI was never the security boundary; the owner channel is.

### 6.4 Replay

- The packet envelope binds sequence and session per message (`[ssjack code]`
  internal/ownerpacket/codec.go:23-36: `Sequence`, `Expires`, `Binding`, `Session`, and
  `Client` fields), so captured command ciphertexts cannot be replayed outside their
  session/sequence window.
- Revision pinning gives a second layer: a replayed approval carries an old `revision`, which
  the keeper rejects with the `stale` mapping (`[ssjack code]` internal/ownerrpc/snapshot.go:28-70).
- Snapshot replay is meaningless: the snapshot is a side effect of the operation, not a reply
  artifact. There is nothing in the reply to replay, and re-executing the operation only
  re-snapshots at a new revision after the revision check passes.

### 6.5 DoS via repeated approvals

Each approval write costs one ciphertext copy (bounded by vault size). Repeated approval writes
are serialized by the per-peer single-flight dispatch lock (`[ssjack code]`
internal/ownerdispatch/peer.go:85), so they cannot parallelize keeper work. Disk growth is the
only accumulation channel, and it is capped by §4.6 (last N = 10 snapshots per vault, pruned
at snapshot time). Recommendation: retention counting is the answer — no rate limiting, new
ops, or quotas are needed; the disk bound plus serialized dispatch contains the cost.

### 6.6 Nothing secret crosses the wire

Restated as a hard invariant for review: the reply for `approve_application` /
`revoke_application` contains no vault ciphertext, no key material, no plaintext digest, no
absolute keeper filesystem path, and no raw keeper error text — only the existing `error` /
`metadata` / `status` projection of `Reply` (`[ssjack code]` internal/ownerpacket/types.go:139-146).
`status` reflects the new approval state as metadata only.

**Bounded disclosure:** `Status.CipherDigest` — the sha256 of already-encrypted ciphertext —
crosses the wire as it already does on every owner reply today (`[ssjack code]`
internal/ownerpacket/types.go:114); the justification is in §4.3.1. This is the only digest
that crosses; no plaintext digest is added.

## 7. Error-behaviour table

Every failure path below is classified once at detection time and then projected through the
layers. Wire error codes are the existing `ownerpacket` codes (`error` string on `Reply`,
types.go:140-146); the client maps them to TUI status text; the keeper state column states
what persists after failure.

| Failure scenario | Detection | Wire result | Client error | TUI/human message | Keeper state |
|---|---|---|---|---|---|
| Protocol envelope version mismatch during initial Hello | Receiving client rejects version at open: `ErrProtocol` -> `Client.AcceptHello` `ErrAuthentication`; it closes before Auth, server exits waiting for Auth; `Server.Authenticate` is not invoked (`[ssjack code]` `internal/ownerpacket/codec.go:65-93,127`; `internal/ownerpacket/client.go:28-40`; `internal/ownerrpc/server.go:51-75,91-110`) | No reply frame | `ownercontrol.Open` / interactive returns generic `ErrControl` | Current UI maps to `ErrControl`; proposed generic all-causes message in §5.1 (does not claim version diagnosis) | No command dispatched; unchanged |
| Stale revision (owner state moved since client read it) | `ownerdb` revision check at apply time | `stale` (`vault.ErrOwnerRevision` class) | `ErrStale`-wrapped revision conflict | “owner state changed — reopen and retry” | Unchanged; revision gate fails before snapshot |
| Reviewed state no longer matches (keeper re-verification fails) | Keeper handler re-verification (§4.2.1) | `review` (new code, §4.2.1) | Typed review-stale error | “the reviewed application changed — re-open the approvals menu” | Unchanged; refusal happens before snapshot |
| Composite write rejected after snapshot (e.g. stale revision or admission refusal) | Manager critical section (§4.3.1) | Typed failure for the detected cause; no further reply detail is promised | Typed client failure for that cause | “approval not written” (do not expose raw keeper error) | Snapshot remains as an orphan; vault mutation/state is unchanged |
| Snapshot refused because vault session is not fully saved | Vault session preconditions inside manager snapshot path (session.go:378-402) | `operation` | Generic operation error | `snapshot_failed` (controller.go:66) | Snapshot aborts; mutation never attempted |
| Snapshot write fails on disk | `store` write/commit (store.go:100-106) through manager | `operation` | Generic operation error | `snapshot_failed` | Vault content unchanged; an incomplete snapshot file may remain; no raw keeper error text reaches client (`[ssjack code]` internal/ownerrpc/snapshot.go:28-70) |
| Save error after edit enqueue | Save worker reports error after `ApplyAt` enqueues the edit (§4.3.1) | `operation` if reply is delivered | Generic operation error; re-read before any further action | “approval outcome unknown — check owner state” | In-memory edit remains with `saveErr`; no rollback; save is not durable |
| Context timeout after edit enqueue | Durability wait expires after `ApplyAt` enqueues the edit (§4.3.1) | `operation` if returned; otherwise no reply | Operation error if delivered, otherwise `ErrUncertain`; re-read and never replay | “approval outcome unknown — check owner state” | Queued save may complete asynchronously; outcome is uncertain until re-read; no rollback |
| Reply lost after durability | Transport loses reply after save completed (`[ssjack code]` internal/ownerrpc/exchange_test.go:70-95) | No reply received | `ErrUncertain`; never replay | “approval outcome unknown — check owner state” | Approval is durable, revision advanced, snapshot retained |
| Keeper restarts during composite | Process restart while composite/save is in progress (§4.3.1) | No reply if connection drops | `ErrUncertain` if the client detects the drop | “connection lost during approval — outcome unknown” | Pre-state if restarted with save worker deterministically paused before save; durable post-state if save completed before restart. Snapshot may remain; no rollback or cleanup is promised |
| `revoke_application` carries `application_path` | `ownerpacket.Valid()` (types.go:156-167) | `invalid` | `ErrProtocol`-wrapped field-not-permitted | “protocol error — invalid revoke request” | Unchanged |

Two points worth restating:

1. **`uncertain` never replays.** `TestClientNeverReplaysAnUncertainExchange`
   (`[ssjack code]` internal/ownerrpc/exchange_test.go:70-95) pins that a lost reply is reported
   as `ErrUncertain` and the client must not resend. Replaying an approval against moved
   revision returns `stale`; replaying revoke twice is a state change the operator did not ask
   for twice. The TUI message is “outcome unknown,” never “retry.”
2. **Restart safety is structural, not recovered.** Snapshot, prune, mutation, and durability
   wait run inside one manager-level composite critical section (§4.3.1). There is no journal
   or redo; the snapshot is an evidence artifact, not a write-ahead record.
3. **Classification is single-sourced.** Each row's wire code is decided at the innermost layer
   that can observe the failure and is not remapped further out. The operation's errors map to
   TUI status messages without exposing raw keeper error strings.
4. **The `stale` row is the only expected retryable failure.** Refresh and retry is safe for an
   owner-revision conflict; a review-stale approval must be re-reviewed, and snapshot/disk
   failures should be investigated.

## 8. Test plan

Layered, each case naming its owning package and existing file. Test names are normative;
no tests are run as part of this design edit.

### 8.1 `internal/ownerdb` (manager)

| Test | File | Asserts |
|---|---|---|
| `TestApprovalSnapshotThenApplyAtomic` | manager_test.go | A successful approval produces exactly one snapshot and the mutation, in that order; concurrent keeper-side writers cannot make snapshot differ from pre-write ciphertext; durability reaches `saved == revision` (`[ssjack code]` session.go:343-345) |
| `TestApprovalSnapshotFailureKeepsVaultUnchanged` | manager_test.go | Injected snapshot write failure aborts; vault content, digest, and revision remain unchanged |
| `TestApprovalSnapshotRetentionBound` | manager_test.go | After N=11 approval writes, exactly 10 snapshot files remain; oldest is pruned at snapshot time |
| `TestApprovalSnapshotSucceededEditRejected` | manager_test.go | Snapshot succeeds, then typed stale/admission failure rejects mutation; snapshot remains as an orphan, vault state is unchanged, and no reply detail beyond the typed failure is assumed |
| `TestApprovalEditAppliedThenSaveFailed` | manager_test.go | Save error after enqueue returns operation failure; in-memory edit remains with `saveErr`; no rollback occurs |
| `TestApprovalTimeoutAfterEnqueue` | manager_test.go | Deterministically pause the worker after enqueue, expire the durability wait, then show the queued save may still complete; caller must re-read and never replay |
| `TestApprovalSaveSucceededReplyLost` | manager_test.go | Confirm save is durable before a modeled reply loss; client observes `ErrUncertain`, does not replay, and re-reads state. Existing `internal/ownerrpc/exchange_test.go:70-95` already pins no-replay; no edit there is proposed |
| `TestApprovalRestartBeforeSave` | manager_test.go | Pause the worker deterministically before save, restart, and verify pre-state; reaching no durability wait is not evidence of pre-state by itself |
| `TestApprovalRestartAfterDurableSave` | manager_test.go | Complete save before restart and verify durable post-state; an evidence snapshot may remain |

### 8.2 `internal/ownerpacket` (wire and protocol version)

| Test | File | Asserts |
|---|---|---|
| `TestApprovalChangeWireRoundTrip` | codec_test.go | Canonical encode/decode round-trips `ApprovalChange` field-for-field for both approval operations |
| `TestApprovalChangeRejectsOversizedPath` | codec_test.go | A 513-byte `application_path` fails validation and decode bounds (controller.go:336-344 bound is 512 bytes) |
| `TestOwnerProtocolRejectsVersion1PacketInVersion2Codec` | codec_test.go | Seal a frozen v1 packet with the same key, feed it to the real v2 `open`, and assert raw `open` returns `ErrProtocol`. Exercise the actual handshake and assert it rejects the mismatched Hello, closes the peer/connection, and sends no reply. Separately assert public new-client `AcceptHello` returns `ErrAuthentication`, not raw `ErrProtocol` |
| `TestOwnerProtocolRejectsVersion2PacketInVersion1Decoder` | codec_test.go | Feed a real v2 packet to a frozen test-local v1 `open` decoder/check and assert `ErrProtocol`; this is refusal, not compatibility support |

Keep these protocol tests in existing `internal/ownerpacket/codec_test.go`; no extra files are
added. Freeze v1 packet encoding/decoding test-local. Update v2 fixtures/goldens and every
ordinary version-1 assertion; distinguish intentional frozen-v1/malformed fixtures.

### 8.3 `internal/ownerdispatch`

| Test | File | Asserts |
|---|---|---|
| `TestUnknownApprovalOperationRejected` | dispatch_test.go | An absent approval handler rejects the operation with zero manager calls |
| `TestApprovalOperationRequiresRevision` | dispatch_test.go | `ApprovalChange` with absent revision fails `Valid()` before dispatch |
| `TestApprovalOperationRequiresOwnerChannel` | dispatch_test.go | An unauthenticated request fails with `ErrAuthentication` and closes the peer; authorization is the existing owner-channel gate |

### 8.4 `internal/ownerbackend` (Remote)

| Test | File | Asserts |
|---|---|---|
| `TestRemoteApprovalWriteForwardedWithRevision` | remote_test.go | Approval write is forwarded with pinned revision; reply error/status propagate |
| `TestRemoteRevokeRejectsPathField` | remote_test.go | Remote revoke with a path is rejected client-side without traffic |

### 8.5 `internal/ownertui` (with fake backend)

| Test | File | Asserts |
|---|---|---|
| `TestApprovalMenuSucceedsOverBackendWrite` | existing ownertui / approvals controller test file | Approval menu succeeds over backend write operations, without an `Edit` callback |

| `TestSnapshotFailureShowsSnapshotFailed` | existing approvals controller test file | Snapshot-class errors preserve `snapshot_failed` and abort the write |

### 8.6 `cmd/ssjack/internal/shell` (interactive command)

| Test | File | Asserts |
|---|---|---|
| `TestOwnerProtocolVersionMismatchMessage` | shell_test.go | Proposed mapping of every `ErrControl` to exactly the conservative generic section 5.1 message; it does not claim certainty about version mismatch |

### 8.7 End-to-end: `internal/nativeownercheck`

| Test | File | Asserts |
|---|---|---|
| `TestNativeOwnerApprovalProfile` | fullprofile_test.go | Full new/new loop: Hello/Auth/Ready → approve → state visible → revoke → state cleared over the real RPC/dispatch stack |

### 8.8 Failure-mode coverage

The protocol-version row in section 7 maps to the two codec tests in section 8.2 and the proposed shell message test in section 8.6. Stale revision, review-stale, prune failure, snapshot refusal/disk failure, save error, timeout-after-enqueue, lost reply, and the two deterministic restart states map to manager/dispatch tests above. There is deliberately no old/new interoperation, capability, probe, or fallback-support test: mixed builds refuse during handshake.

Test-infra notes:

- Ownerdb tests inject snapshot failure through the existing seam; no production test branch is added.
- The v1 packet/check logic is a frozen test-local copy in `codec_test.go`; it does not modify production decoding or simulate old/new support.
- All wire tests reuse canonical codec helpers in `codec_test.go`; no new codec surface or files are introduced.

## 9. Implementation order (independently mergeable slices)

Folder counts today (code + tests, limit 7 per folder, 1000 lines per file), verified in this
tree. Every slice below edits existing files only — no new files are added to touched folders:

- `internal/ownerpacket`: **7 files** (codec.go, codec_test.go, types.go, client.go, server.go,
  rotation.go, rotation_test.go) — at the limit: no new files. `ApprovalChange` goes in types.go;
  protocol tests go in codec_test.go.
- `internal/ownerdb`: **7 files** (manager.go, manager_test.go, durability.go, resources.go,
  rotation.go, values.go, worker.go) — at the limit; composite method goes in manager.go and
  tests in manager_test.go.
- `internal/ownerdispatch`: **5 files** (dispatch.go, dispatch_test.go, peer.go,
  rotation_close_test.go, rotation_dispatch_test.go); route changes and tests use existing files.
- `internal/ownerservice`: **3 files**; edits in service.go, tests in service_test.go.
- `internal/ownerbackend`: **4 files**; edits in remote.go, tests in remote_test.go.
- `internal/ownertui`: **7 files** at top level; edits only in existing files.
- `internal/ownertui/internal/approvals`: **5 files**; edits only in existing files.
- `cmd/ssjack/internal/shell`: **3 files** (`interactive.go`, `shell.go`, `shell_test.go`); map generic `ErrControl` to the conservative §5.1 message in `interactive.go` and test in existing `shell_test.go`.
- `internal/nativeownercheck`: **7 test files**; E2E profile tests extend fullprofile_test.go.

Every touched folder remains at or below 7 files and each touched file below 1000 lines. Preserve
the existing package layout; no new test files are proposed.

1. **`internal/ownerpacket`: `ApprovalChange` body + `Valid()` + wire tests + envelope v2.**
   Files: types.go, codec.go, codec_test.go (all existing; ownerpacket is at its 7-file limit).
   Updating `seal()` and `open()` for v2 MUST be in the same slice as adding the approval
   operations. This slice establishes strict refusal of mixed versions at handshake (§5).
2. **`internal/ownerdb` manager + vault session: snapshot-before-approval-write and retention.**
   Files: manager.go, manager_test.go (existing; ownerdb at 7-file limit). The retention prune
   is inert until approval writes flow.
3. **`internal/ownerdispatch` + `internal/ownerservice`: route `approve_application` /
   `revoke_application` to the manager.** Files: dispatch.go, ownerservice/service.go,
   service_test.go. Depends on 1+2; not a mixed-version compatibility window.
4. **`internal/ownerbackend` Remote: forward the operations.** Files: remote.go, remote_test.go;
   retain the standalone snapshot refusal test. Depends on 1–3; no negotiation or fallback.
5. **`internal/ownertui` + approvals controller: write over backend ops instead of `Edit`; `cmd/ssjack/internal/shell`: present generic control errors.**
   Files: model.go, mutations.go, approvals controller and existing tests; `cmd/ssjack/internal/shell/interactive.go` and existing `shell_test.go` for the conservative §5.1 mapping. Depends on 4.
6. **`internal/nativeownercheck`: E2E profile test.** Files: existing fullprofile_test.go and
   existing shared fixtures if needed. Depends on 1–5; no new files.

The ownerpacket v2 bump and approval-operation protocol additions are one indivisible release
slice. Subsequent implementation steps build on that protocol; none provides mixed-build
interoperation or fallback.

Merge-order guarantees:

- Old/new binaries refuse at the initial handshake; old/old and new/new pairs use matching
  protocol versions.
- After forwarding and TUI changes, approval operations execute only between matching v2 peers.
- E2E profile tests extend existing files and introduce no new package files.

## 10. Open questions for the owner

Only these design choices remain owner decisions. Protocol version 2 and refusal of mixed
old/new builds are final decisions, not open questions.

1. **Retention N.** §4.6 defines a hard bound, pruned at snapshot time inside the composite
   critical section; prune failure refuses the write. Context: the bound must limit disk growth
   while preserving useful crash-recovery snapshots. Options: N=10, N=5, or additionally prune
   on rotation. Recommendation: N=10, snapshot-time only.
2. **One operation with an `action` field, or two operations?** Context: two operations
   (`approve_application`, `revoke_application`) align with the existing closed operation union
   and localize validation; one operation saves an operation name but adds an action discriminator.
   Options: one operation plus action / two operations. Recommendation: two operations.
3. **New wire error code `review` for keeper re-verification refusal, or reuse an existing code?**
   Context: `stale` means owner-revision conflict and invites refresh/retry, while retrying a
   review-stale approval could perform an unreviewed write; `invalid` conflates changed review
   state with malformed input. Options: add `review` / reuse `stale` / reuse `invalid`.
   Recommendation: add `review` with non-retryable-as-is semantics and a specific TUI message.

## 11. Explicit non-goals

- No vault content, plaintext digests, or keeper paths crossing the wire (the ciphertext sha256
  in `Status.CipherDigest` crosses today on every reply; see §4.3.1).
- No client-callable snapshot operation.
- No generic remote Edit.
- No change to local backend behaviour.
- No new encryption profile.
- No capability handshake protocol.

