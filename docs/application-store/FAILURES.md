# Failure matrix and hostile-input policy

Before Argon parse bounded header only. Require magic `SSAPP001`, version 1, flags/reserved zero, chunk size 1,048,576, total 1MiB..2^40, count 1..1,048,576 and `ceil(total/chunk_size)`, nonzero store/snapshot IDs, parent zero iff genesis (otherwise nonzero/not self), four exact pairwise-distinct nonzero 32-byte salts, 12-byte nonce base, checked exact lengths. Enforce [FORMAT](FORMAT.md) caps; reject malformed public framing pre-KDF. Catalog semantics are validated after authentication: <=16,383 entries, sorted unique pairs/versions, media syntax, zero padding, checked offsets/lengths partition payload exactly; no release on failure.

| Attack/failure | Required outcome |
|---|---|
| Bad passphrase, GCM tag, changed header/AAD | First-pass failure releases no bytes; second-pass tag failure stops before the affected chunk and reports partial/unknown if earlier bytes reached the sink |
| Invalid salts/IDs/version/flags/reserved, overflow | Reject before Argon/allocation |
| Truncated/extra/reordered/duplicate/skipped chunk; bad prefix; absent/duplicate final | Reject exact framing/transcript |
| Catalog sort/ID/media/padding/offset/length invalid | Reject after authentication; no delivery |
| Cross-store/chunk/snapshot replay or identity change | Authentication/binding failure |
| Resource, memory, file, chunk or object cap | Bounded refusal; never allocate unchecked lengths |
| Source changes between sizing and encryption | Discard unpublished candidate |
| Ciphertext path or pinned spool changes | Never reread a mutable path; first-pass failure releases no bytes. A detected second-pass change stops further delivery and reports partial/unknown if bytes may already have reached the sink |
| Concurrent KDF/>2 operations/workspace pressure | Queue or reject; caps preserved |
| Candidate after crash | Quarantine associated ciphertext; replay commit only with valid durable intent and read-first state reconciliation, otherwise burn |
| Snapshot/version-ID collision after encryption attempt | Permanently burn reservation/ciphertext; never re-encrypt or recommit |
| Reader sees missing/mismatched committed local candidate | If exact anchored candidate verifies, repair pointer under exclusive lock; if candidate is missing or unverifiable, fail closed and require anchor-backed human recovery |
| Host OS, same-UID process, root/malware, or anchor trust-root compromise | Outside protection; no confidentiality/history guarantee |
| Object pair/version reuse with absent pair in parent snapshot | Require fresh version ID; no intentional resurrection; fail closed when strict non-reuse is required and history is incomplete; no unprovided content hash |
| Version reuse attempted with changed bytes | Bounded exact parent-byte comparison rejects reuse |
| Restart after unknown commit result without valid durable intent | Authenticated read only; if still pre-commit, quarantine/burn candidate; never retry old CAS |
| Historical SecretRef lacks trusted captured expected hash | Reject; never compare historical snapshot to current anchor tuple |
| Local journal suffix after crash | Chain-check and anchor as burned; quarantine associated ciphertext; fresh reservation only |
| Snapshot-ID collision | Reserve different ID before encryption; fail closed if uniqueness uncertain |
| Lock conflict/stale revision or parent | Conflict; prior state preserved |
| Anchor unavailable before any CAS request is sent | No logical commit; preserve candidate/journal; fail closed |
| Anchor invalid/stale or CAS conflict | No commit by this CAS; preserve candidate/journal and reconcile authenticated state |
| CAS sent, then timeout/unavailable/lost reply | Outcome unknown; CAS may have committed. Authenticated Read first; retry only byte-identical request with same idempotency key/request_id if state still equals expected and durable replay permits it; otherwise resolve from authoritative tuple. Never blindly retry |
| Crash during commit protocol | Authenticated Read first; exact intent new state confirms commit, exact expected state permits only identical replay with valid durable intent, otherwise reconcile without replay; anchor tuple determines authority |
| Commit CAS succeeds but local pointer is stale | Anchor tuple authoritative; repair under exclusive lock; readers must not wait holding shared lock |
| Reader detects pointer mismatch while holding shared lock | Release lock and spool; reconcile/repair exclusively, then reacquire shared lock and revalidate; bounded retry or fail closed |
| Candidate/journal durability failure before CAS | Do not CAS; preserve prior commit |
| Recovery copy mismatch/unreadable retention state | Do not replace / do not GC |
| Sink mismatch, offline consumer, partial adoption/lost ack | Pending/failure; no fallback, silent restart or secret output |
| Cancel, locked master, revocation failure | Preserve encrypted state; honest status; no false adoption or early delete |

Acceptance contract only, not test evidence. See [WIRE](WIRE.md), [CRYPTO](CRYPTO.md), [IO](IO.md).
