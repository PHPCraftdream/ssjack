# Trusted-local owner database coordination

Implementation unit: task 277. This is not an MCP endpoint or completed terminal
editor. The initial coordinator covers normal versioned value writes; explicit
pending-operation reconciliation and setup/UI integration remain required.

## Ownership and lifetime

The database password holder owns all database contents. Open loads the database
once, privately copies linked installation material, then transfers the unchanged
authenticated Vault to StartSession without a second database KDF. Display data
comes only from the private-material-free metadata view.

The application installation is unlocked lazily once and kept in the owner
runtime. Its real master derivation and crypto profile remain unchanged. The
installation directory identity and encoded binding are rechecked before owner
operations. No new role/enrollment system, SSH hardening, raw secret tool or
master getter is introduced. Linked application-store editing currently uses
the existing supported Linux backend; unsupported platforms refuse before
staging a secret mutation.

There is one bounded application-operation worker and the existing bounded
credential-database save worker. The separate workers are intentional: a writer
prepare callback can await database persistence without waiting on itself.
Closing blocks new submissions and waits for both layers; an unresolved error
keeps the live session available. Explicit discard cancels and joins the owner
worker before releasing borrowed resources and the database worker/key.

## Normal save sequence

1. Apply a validated draft, including its bounded input value, to database RAM.
2. Wait for its encrypted database save, check the acknowledged ciphertext
   revision, synchronize the parent directory and recheck ciphertext identity.
3. Load the authenticated current application snapshot without losing unrelated
   objects, and prepare exactly one add/update/removal.
4. In CommitPrepared, record the exact transaction/snapshot/version proposal in
   the database. Flush and synchronize it before allowing journal append or an
   anchor mutation. A filesystem that cannot provide the required sync refuses.
5. Accept only the writer's verified result, finalize the exact named reference
   set in the database, and flush/synchronize that metadata before success.

Root/application commit and local name persistence are separate transactions.
A lost reply or failed later database save keeps a visible pending intent; there
is no automatic replay and no fabricated received result. Existing captured refs
are never rewritten in recipes and do not silently resolve to latest values.

If aliases intentionally share an object, updating one forks its object instead
of changing another alias's value. Removing one shared alias removes only that
binding. Unrelated server/account forms cannot alter linked owner material or
secret bindings through the coordinator's generic metadata-edit path.

## Owner import

Import reads an owner export archive (see [export format](OWNER-EXPORT-FORMAT.md))
through the same single owner worker. It is reachable only from the trusted
terminal editor through `InspectImport`, `ImportStatus`, `ConfirmImport`,
`ResumeImport` and `AbortImport`; it has no public, CLI or MCP surface.

**Inspect.** `InspectImport` queues a worker job that syncs the database, reads
the archive with `ownerarchive.ReadFile` (one unlock (four sequential Argon2id derivations) if encrypted) and stages
the parsed plan privately in RAM. It never mutates the destination and never sets
the manager's error state: a wrong password or bad archive ends idle with a fixed
error class in `ImportStatus`, and the manager stays usable. It is refused while a
plan is staged, applying or partial, or while any other operation or pending
intent exists. `ImportStatus` carries metadata only (preview, conflicts, counts,
error class), never values, credentials or passwords.

**Whole-plan conflict refusal.** The plan is refused as a whole, never partly
imported, merged by endpoint or name, or used to overwrite. Conflicts: server ID,
server name, account (credential) ID, secret alias ID, secret scope plus name,
server/account/secret count limits, a pending owner intent, an unlinked owner
store (when the archive has values), a non-version-2 destination, an unsupported
value (values that are not valid UTF-8 or contain NUL are refused because the
owner store is text-only) and `runtime-unsupported` off Linux. `ConfirmImport`
re-evaluates them and refuses with `ErrImportConflict`.

**Apply order.** `ConfirmImport` queues one apply job:

1. Sync the database (flush, ciphertext identity, parent directory).
2. If the plan has values, open and check the owner resources before any
   mutation, so an unreachable store changes nothing.
3. `ApplyOwnerImportDirectory` merges servers and credential records, keeping
   their IDs, in one `Apply` that re-checks conflicts against the exact state it
   replaces; then sync again. It touches neither secrets nor the owner link.
4. For each value, stage one durable owner intent (an add keyed by the source
   alias ID, name and server scope, `text/plain`) and run it through the normal
   save sequence above. The value is published through the private owner editor
   to a **fresh** destination reference. Archived references are never trusted or
   reused, and `owner_store` is never imported.
5. Every dirty owner commit re-versions every object, and `FinishOwnerChange`
   moves every alias to the commit's reference for its object ID. A **receipt** is
   the exact reference the import last saw authenticated for an alias. It advances
   only inside the worker step that validated the commit: normal publication, or
   `ResumeDraft`/`Reconcile` recovery of the import's own durable intent. It is
   taken from that commit's exact reference set, keyed by object ID, and only while
   store, name and scope still match the plan. This happens right after the commit
   is applied and before the following save, so a confirmed commit whose save
   failed is still receipted. A commit that is not the import's own intent never
   moves receipts. If a check fails the receipt stays stale and the import stops
   with the fixed error `imported entries changed`.
6. Complete only after every value is published. An alias that already exists is
   never skipped or overwritten unless it is import-owned: its reference equals
   its receipt exactly and name and scope equal the plan. There is no in-flight
   metadata adoption. Any other existing alias fails the import with
   `imported entries changed`.

The job has a bounded timeout and `AbortImport` stops it before the next value.

**Edit gating.** While the import is `applying` or `partial`, `Edit` and `Submit`
return `ErrPending`, so imported accounts, servers and aliases cannot be changed
between a failure and its resume. `RetryDatabase`, `Reconcile`, `ResumeDraft`,
`CancelDraft`, `ResumeImport` and `AbortImport` stay available as recovery paths;
`Export` and `Close` are refused while a manager error or pending intent exists,
as before.

**Published.** `ImportStatus.Published` counts only aliases whose reference still
equals their receipt exactly, with the plan's name and scope. Metadata that merely
looks right, or a changed version without an authorizing commit, is never counted
nor adopted by resume (it fails closed with `imported entries changed`), and a
colliding foreign alias is never counted: a staged plan, including one refused
for conflicts, reports 0. Receipts are kept after completion so the count stays
accurate, and are discarded on a new inspection, `AbortImport` or close.

**Failure and recovery.** A failure before any destination change leaves the plan
staged and the manager usable. After the first change the import is `partial`
and the error also blocks other mutations until resolved. A pending owner intent
is resolved first with `ResumeDraft`, `Reconcile` or `CancelDraft`. `ResumeImport`
then continues: it does not re-apply the directory but first runs
`VerifyOwnerImportDirectory`, which requires every imported server (same ID,
name and account map) and every imported credential record (all fields, including
keys, passwords, host keys and SSH policy) to be exactly what the import wrote,
else it fails with `imported directory changed`. Aliases are then resolved by
receipt as above. `AbortImport` discards the retained RAM values and plan and
keeps everything already durably applied or published; there is no rollback.

Only the single per-secret encrypted owner intent is durable. The full import
plan (the remaining values) is RAM only and is lost on exit or restart; nothing
replays at startup and a partial import cannot be resumed after a restart. After
a restart the owner can resolve the pending intent and must inspect the archive
again; already imported entries then appear as conflicts rather than being
resumed.

Linked value publication keeps the Linux-only runtime boundary; other platforms
refuse a plan with values before any change.

## Verification

The production-KDF CLI acceptance fixture additionally exercises the coordinator
against its actual TLS anchor and encrypted application installation: preserve
two SSH accounts, update an existing value, add a server-local value, remove it,
close/reopen the database and verify finalized metadata and original credentials.
This extension is gated by the existing dedicated full-KDF CI job, not ordinary
scoped/accelerated tests. All credentials/servers are synthetic and isolated.
The same job also imports an encrypted archive through the real terminal model
(wrong password, cancelled preview, confirmed import) and a plaintext archive
through the manager into fresh databases, then checks credentials, alias scopes,
fresh references, imported values, conflict refusal and tampered archives.

Normal-flow acceptance does not prove pending reconciliation, full terminal UI,
exports, streaming producer/client support or live deployment. Those remaining
units must not be reported as delivered from this component alone.
