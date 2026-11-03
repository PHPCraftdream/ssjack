# Recovery binding commitments

This isolated opt-in package addresses the transaction-to-full-binding commitment prerequisite documented by `internal/recovery`. It does not implement an authenticated anchor, durable journal, rollback protection, serialization, admission fencing, authorization or production wiring. Production declarative MCP remains zero-tool and deny-only.

`New` accepts a `recovery.Binding` whose `Transaction` and `Next.Transaction` are both empty. It returns a copy with both fields set to the same lowercase SHA-256 hex ID, or a zero binding and `ErrInvalid`. The resulting binding must satisfy the existing `recovery.ValidBinding` contract, including printable ASCII IDs, matching resource identities, consecutive unsigned generations, differing state hashes and genesis/prior-transaction rules. It never silently rewrites an existing transaction ID.

## Internal commitment format

The newly defined internal format is independent of the declarative canonical-JSON digest domains. The hashed bytes, in exact order, are:

1. ASCII `ssjack-recovery-binding-v1`, one NUL byte, and the one-byte stage value.
2. Invocation and binding resource strings.
3. Expected resource string, generation, 32-byte state hash, and prior transaction string.
4. Next resource string, generation, and 32-byte state hash.
5. The 32-byte request hash.

Every string is prefixed by its two-byte unsigned big-endian byte length. Generations use eight-byte unsigned big-endian encoding, preserving the full existing uint64 range rather than JSON's safe-integer range. Strings are bounded to 128 bytes before serialization and checked against the existing ASCII identity rules before any result is returned. All other fields have fixed size. No caller chooses the domain, field order or serializer.

Only the two self-derived transaction fields are excluded from the hash; both must equal the resulting ID. The expected state's transaction is included, even when empty at genesis. Stage, invocation, request identity and both complete state tuples are thus committed without a self-reference. Changing a structurally valid binding requires a different ID, subject to SHA-256 collision resistance. The commitment is unkeyed: anyone can construct a new valid binding. A matching digest is not trusted provenance, authorization, freshness or proof that state exists.

## Admission and compatibility

`Validate` verifies the existing structural contract and recomputes the commitment, rejecting legacy arbitrary IDs and any change under an old ID. `Recover` rejects invalid commitments and nil or already-cancelled contexts before any Anchor/Journal call, then delegates to the unchanged recovery state machine. Valid invocation-stage intents remain quarantined; this wrapper does not authorize execution.

Existing `Machine.Recover`, stored records and IDs are unchanged. There is no automatic enrollment or journal migration, fallback to legacy recovery, repair, replay, or format negotiation. A caller must explicitly select this new path and supply independently trusted Anchor/Journal implementations satisfying all existing authentication, linearizability, fencing, durability and exclusive-ownership requirements. The production adapter is still absent.

Regression tests contain an independently authored binary-message vector hashed through standard-library SHA-256, valid-structure mutation witnesses, uint64 and identity boundaries, no-storage-call guards, synthetic transition checks and a legacy compatibility witness. These tests were authored but not executed locally; public GitHub CI is required. Synthetic adapters do not establish production storage guarantees.
