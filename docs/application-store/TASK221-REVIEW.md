# Task 221 review

## Status and validation

Task status: **implementation and authored evidence retained; acceptance pending parent review and public CI**. This is not a completion or production-readiness claim. Final authored tests were **not executed**; only a final formatting check was performed. No tests, builds, compilation, lint, KDF/AES workload, network, or service execution was performed by the orchestrator.

Execution-constraint breach: a worker attempted the prohibited commands `go test ./internal/appstorefile` and `GOOS=linux GOARCH=amd64 go test ./internal/appstorefile`. Both failed during setup due to an empty stray file, which was subsequently removed. No successful validation resulted. Do not characterize this merely as tests not run.

## Scope and implementation

Application-store snapshot writing, durable reservation/intent, sealing, publication, and recovery are in scope. Consumer hydration/adapters are **out of scope**, not a delivery gap.

Source review confirms handling for unused imports/inputs and `EEXIST`; authenticated `Rejected` responses are terminal and are not retried. Suffix conflicts are durably quarantined before CAS-confirmed reservation burns; anchored orphan candidates without intent burn rather than being adopted. Quarantined snapshots cannot be adopted during recovery. `ErrWriterBurned` prevents false-success reporting; a fresh write uses new IDs.

Production `internal/appstorecrypto/master.go` is unchanged: real production derivation remains four sequential 1-GiB derivations, and records retain 1000 AES layers. Scoped lightweight tests use the existing private synthetic fake-KDF helper in test code only. They do not use the full production KDF or alter production crypto. Scoped tests reside in existing `record_test.go`/`record_edges_test.go` and writer test files; CI selectors were not changed. Full-profile tests remain separately gated.

Relevant authored evidence (not executed after final changes):

- Terminal rejection and request-ID collision: `TestWriterScopedRejectedTerminal`, `TestWriterScopedRejectedRequestCollision`.
- Original-intent restart replay: `TestWriterScopedIntentRestartReplay`, `TestOriginalIntentReplayAfterRestart`.
- Source change and cancellation after reserve: `TestWriterScopedSourceRevisionFailure`, `TestWriterScopedCanceledReservationBurned`.
- Suffix burn/quarantine and no-intent orphan: `TestWriterScopedSuffixBurnAndOrphanQuarantine`, `TestPendingCandidateWithoutIntentBurned`, `TestUntrustedJournalSuffixBurned`.
- Actual TLS/durable-ledger integration: `TestWriterAgainstActualDurableTLSService`, `TestDurableReplayReturnsOriginalResultAfterLaterStateAndRestart`.
- Full production KDF: `TestSnapshotWriterFullKDF` (gated; not executed).
- Multi-object round-trip: `TestWriterScopedPayloadRoundTrip` checks two objects and decoded records against the original payload bytes over the actual TLS/durable-ledger path. Record tests retain the byte-exact oracle; 1000 AES layers are unchanged.
- Parent review replaced the invalid-descriptor case with deterministic intent-directory synchronization failure injection. The per-directory private synchronization function defaults to `unix.Fsync`; the test injects `EIO` at that boundary, requires `ErrUncertain` and exactly one call, and checks preservation of prior intent/ciphertext. This is authored syscall-boundary coverage, not a power-loss experiment.

## Limits and remaining gates

No power-loss proof, enrollment, hostile same-UID protection, or runtime correctness proof is claimed. Complete retained history is required; verification is quadratic within the reservation cap (`State.MaxReservations` = 2^20); runtime memory bound is not demonstrated. Non-Linux platforms fail closed. No runtime validation is claimed. Acceptance remains pending parent review and public CI.
