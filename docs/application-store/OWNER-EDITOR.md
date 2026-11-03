# Private application-secret owner editor

This is a trusted-local backend, not a model/MCP capability. It does not add
roles, enrollment, a generic secret getter or a master-key getter. A caller must
already possess an authenticated unlocked installation and its bound directory.
The database owner integration and terminal UI are separate acceptance units.

## Current private backend

`NewOwnerEditor` validates the installation/directory binding through the existing
writer factory. It reads authenticated anchor state and writer history, pins and
checks the complete current snapshot, copies its bounded secret objects into
owned RAM, then rechecks source/pointer/anchor freshness before returning.

The supported owner collection has at most 128 objects, each within the existing
16 KiB RAM-secret limit. Larger or ambiguous collections refuse as a whole;
unknown objects are never silently dropped. Metadata inspection returns object
IDs, exact references, media types, lengths and pending markers, not values.

Add, Update and Remove modify owner RAM only. Input values are copied; replaced,
removed and closed buffers are cleared best-effort. Commit preserves every
remaining object through the existing snapshot writer and returns only verified
commit metadata. All produced references are exact immutable versions; a value
update cannot retarget an old placeholder to a latest value.

`SnapshotWriter.WriteFrom` checks the expected authenticated state under the
directory lock before reconciliation or mutation, and checks complete writer
history. The expected state is an optimistic concurrency token, not authority.
A stale editor cannot overwrite another owner's unseen commit or burn a new
reservation just to discover that conflict. Existing Write/WriteFirst contracts
remain unchanged for their other callers.

The editor keeps the validated installation/master alive by borrowing it from
its owner runtime, so it does not repeat key derivation on each edit. Crypto,
nonce handling, anchor transport authentication and real data-encryption layers
remain owned by the existing writer. Operations have finite caller/60-second
bounds. Close clears private values and closes the editor's transport before
the caller closes the borrowed installation/directory.

Any attempted commit error blocks further automatic attempts in that editor.
It does not claim that nothing happened remotely. The owner must inspect and
reconcile, then explicitly reopen the editor. Read-only inspection and no-change
Commit do not generate new versions or mutate the anchor.

## Required database integration before UI/export publication

The credential directory contains names/scopes and exact reference metadata;
that is not a second application-secret value store. The linked installation's
owner-unlock material must be encrypted in the database and unwrapped only
inside the trusted owner session. A normal menu must not ask for the database
password repeatedly or route owner material through MCP, argv, environment,
stdout or incidental files.

Application-store commit and credential-directory persistence are separate
transactions. Calling private Commit followed by an ordinary metadata save is
not sufficient crash-safety proof. The integration must persist a bounded
encrypted operation intent before possible external effects, correlate the
exact writer proposal/result, and publish alias references only after a
verified commit. Loss of a reply or a later database save leaves a visible
pending-reconciliation state, not an automatic replay or fabricated success.

Object IDs, intended names/scopes, expected predecessor state and proposal
identity must remain recoverable. A failure to persist names must not erase an
already committed value or overwrite another owner's changes. Renaming aliases
alone uses the credential database and does not re-encrypt application values.

Existing text delivery remains separately approved and current-authority-bound.
Committing a new snapshot does not automatically extend an older grant or make
an archived reference deliverable against a different snapshot. Historical
snapshots remain encrypted and immutable. There is no silent latest resolution;
owner recovery and renewed delivery approval must be explicit.

## Verification scope

Linux CI exercises the actual installation unlock, authenticated TLS writer,
multiple value versions, preserved unrelated objects, close/reopen, historical
snapshot retention, stale-editor refusal, invalid input and buffer ownership.
Test-only accelerated derivation comes from existing fixtures; no production
KDF bypass or reduced data-encryption profile is added.

This private backend alone is not acceptance of the full named-secret terminal
editor, exports, cross-store crash recovery, historical delivery, or a live
server deployment. Those paths require their own connected tests.
