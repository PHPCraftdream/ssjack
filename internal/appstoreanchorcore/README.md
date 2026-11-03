# Minimal anchor service core

This package is the protocol/state-model part of the self-hosted anchor required
by the encrypted application-store writer. It is not a deployed service or a
separate management platform. Durable transactions and authenticated TLS serving
must compose it before any reservation can permit encryption or secret delivery.
No production tool, secret getter, application adapter or network listener is
added here.

`Parse` admits only exact Read48/Create272/CAS304 DTOs and a fixed nonzero store.
It checks magic, reserved bytes, correlation IDs, operation/length, canonical
state and mutation request-ID domains. Create must carry exact genesis and its
exact computed key. Commit must carry a nonzero transaction/file tuple and the
exact commit key. Reservation keys cannot be recomputed from this DTO: the
journal entry is absent. Only a nonzero key and its request-ID domain can be
checked. Inputs/accessor bytes are copied. Read IDs are correlation, not proof of
fresh generation or absence of namespace collisions.

`NewGrant` admits fixed store/credential-fingerprint/reader-or-writer configuration.
It does not authenticate that identity. A future TLS boundary must derive the
credential fingerprint from the verified client certificate and obtain the exact
store role from independently enrolled configuration, never request assertions.
The credential and store must namespace durable request-ID and idempotency
records; logical operation kind additionally scopes mutation keys.

`Missing` and `Existing` describe backend observations, not proof of absence or
persistence. Version zero is exact genesis; successful CAS increments the service
version without wraparound. `Evaluate` denies reader mutations before inspecting
state, returns correlated ReadState/NotFound, permits genesis creation only for
missing stores, and compares CAS expected hashes exactly. It proposes a copied
next value without modifying storage. Existing creation conflicts; unknown
results assert no success and propose no change.

Replay lookup must precede evaluation. Re-evaluating the same CAS against later
state is a conflict, not the original recorded result. A durable backend must
atomically record canonical request binding, next state/version and original
outcome, retain rejection/conflict records, reject key/ID reuse with changed
bytes, enforce capacity before effects, fence uncertain publication and reconcile
unknown outcomes. This package implements none of that persistence or collision
tracking, and no result here is a confirmed nonce reservation.

`Result.Unsigned` emits exactly the 288 public bytes preceding the standard
Ed25519 signature. It does not sign or authenticate anything. The enrolled signer
and TLS request/credential binding remain mandatory. Zero values fail closed.

The service contract trusts an authorized writer's application transitions. A
canonical CAS DTO does not prove journal extension, candidate validity, historical
ID freshness or non-regression. A malicious authorized writer can reset state
through a canonical CAS; an explicit synthetic test preserves that documented
boundary rather than claiming journal validation that the DTO cannot support.

Independent DTO fixtures and signed-reply-verifier composition cover shapes,
copy ownership, malformed/correlated-wrong keys, role/scope checks, versioned
create/reserve/commit/read/conflict, overflow and unknown results. Tests use only
synthetic metadata and signing keys in public scoped CI. No actual credentials,
filesystem transactions, service deployment, SSH/sudo changes or plaintext
secret staging occur.
