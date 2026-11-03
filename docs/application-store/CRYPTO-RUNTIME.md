# Application-store cryptographic runtime

## Key and record boundary

`internal/appstorecrypto` owns the dedicated application-store master. `Derive` uses four independent sequential Argon2id-v1.3 invocations with m=1048576 KiB, t=1, p=1 and 32-byte outputs, then the application-only HKDF domain from CRYPTO.md. There is no raw-key accessor or caller-selected production profile. Master copies share lifecycle and clearing state. The process-wide KDF gate spans the complete batch; cancellation does not interrupt an active Argon invocation or release admission early.

Private record operations apply exactly 1000 AES-256-GCM layers over the entire preceding ciphertext. They remain private. Public snapshot verification returns authenticated metadata only; a verified tuple or typed reference is not consumer authorization.

## Snapshot transactions

`SnapshotWriter` composes the concrete anchor Writer and private filesystem transaction. It confirms the exact reservation before encryption, retains prior ciphertext, verifies the complete durable candidate, persists and rereads the immutable original intent before commit, and publishes a pointer only after anchor confirmation. Unknown results require authenticated Read first; authenticated rejection is terminal. Restart can replay only the exact original intent against its exact expected state. Suffix and orphan ciphertext is burned/quarantined rather than adopted or re-encrypted.

Scoped CI covers real mTLS/durable-ledger transactions with a private synthetic KDF fixture and the unchanged 1000-layer record implementation. The separate full-profile tests retain real four-round 1-GiB derivation. A scoped pass is not full-profile or production enrollment evidence.

## Delivery boundary

Phase-one verification authenticates every record, the final transcript, exact EOF, encoded hash, catalog and object spans. It releases no object bytes. A later handoff requires the same protected immutable ciphertext spool, identity and complete-hash rechecks, exact reference authorization, a fixed trusted confidential RAM-only sink, lifetime/revocation checks and explicit partial/unknown reporting after any possible handoff. No generic secret-get API is authorized by storage or metadata verification.

The private pinned-spool work is a prerequisite within the unfinished delivery transaction, not an enrolled consumer or a completed placeholder integration. Anonymous temporary files contain ciphertext only. Unsupported anonymous-file protection fails closed; there is no named or plaintext staging fallback.

## Limits

Application operation admission permits two operations per process and one per store. Composite transactions retain one lease and their actual filesystem lock across all work; private helpers must not acquire a nested public operation lease. Cancellation releases resources only when the actual operation returns.

Clearing is best-effort for owned buffers. No guaranteed erasure of runtime/AES/Argon copies, swap or dumps, hostile same-UID/root protection, power-loss proof, independently authenticated human enrollment or positive production MCP authority is claimed. The application-store passphrase remains separate from SSH credentials and must never be collected through model-visible tools, argv, environment or plaintext files.
