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

## Verification

The production-KDF CLI acceptance fixture additionally exercises the coordinator
against its actual TLS anchor and encrypted application installation: preserve
two SSH accounts, update an existing value, add a server-local value, remove it,
close/reopen the database and verify finalized metadata and original credentials.
This extension is gated by the existing dedicated full-KDF CI job, not ordinary
scoped/accelerated tests. All credentials/servers are synthetic and isolated.

Normal-flow acceptance does not prove pending reconciliation, full terminal UI,
exports, streaming producer/client support or live deployment. Those remaining
units must not be reported as delivered from this component alone.
