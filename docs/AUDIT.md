# Cryptographic and authorization review package

## Status

**No independent external cryptographic audit has been completed.** Author review, regression tests, a second implementation, and successful CI would be useful evidence, but none alone is an independent security assessment. No auditor has been engaged or granted access to private credentials. Review the public source only unless the user separately authorizes other material.

The historical v1 profile below remains readable. New containers use opaque v2 with unchanged KDF costs and layer count, but a new authenticated envelope and layer domain; see [the format delta](OPAQUE-FORMAT-PROPOSAL.md). This delta requires separate review. This document is a review inventory, not a claim that the custom construction is necessary, optimal, or proven secure.

## Review entry points

- `internal/keyfile/container.go`: parsing, fixed parameters, public header, size limits.
- `internal/keyfile/opaque.go`: one-field v2 parser, packet/envelope bounds, authenticated inner profile.
- `internal/vault/upgrade.go`: verified format conversion, exact recovery copy, explicit publication.
- `internal/keyfile/crypto.go`: four KDF calls, master derivation, layer keys/nonces/AAD, full-data encryption/decryption.
- `internal/keyfile/generate.go`: secret-derived Ed25519 seed, domain separation, temporary private-buffer ownership.
- `internal/keyfile/openssh.go`: supported key conversion, no empty-passphrase private export.
- `internal/vault`: encrypted payload schema, strict optional usage field, file writes, locks, revision checks, backup/restore.
- `internal/broker`: canonical loopback-only endpoint, TLS pinning, memory-only single-use environment capability, session cancellation.
- `internal/remote`: SSH server trust, native sessions, command-free verification, fixed authorized_keys update script.
- `internal/rotation`: required recovery/confirmation/add/verify/commit ordering and failure boundaries.
- `cmd/ssjack`: terminal-only secrets, per-invocation authorization, usage gating, explicit confirmations, CLI help, diagnostics, export-secret separation.

## Container version 1

The owned document is Ktav through `github.com/ktav-lang/golang/pure` v0.8.1, preceded by the fixed magic comment. Public fields include version, KDF identifier, memory, passes, parallelism, layer count, four base64 salts, a base64 nonce base, and base64 ciphertext. Unknown fields, duplicate salts, invalid encoding, unsupported cost profiles, and excessive lengths fail before allocating the Argon2id workspace.

Fixed profile:

1. Four independent Argon2id v1.3 calls from the exact password bytes, each with a distinct random 32-byte salt, `memory=1048576 KiB`, `time=1`, `parallelism=1`, and a 32-byte result. They run sequentially.
2. Concatenate the four outputs in document order. HKDF-SHA-256 with nil salt and info `ssjack-key/v1/master` produces a 32-byte master secret.
3. For each layer index 0 through 999, HKDF-SHA-256 from that master with nil salt and info `ssjack-key/v1/<purpose>/layer/` followed by a big-endian uint32 index produces a 32-byte AES key.
4. The 12-byte random nonce base is copied, and its final big-endian uint32 is XORed with the index. Layer nonces within one purpose are distinct. Different purposes use different AES keys.
5. AES-256-GCM uses the fixed binary header plus the exact layer context as AAD. The header binds format/KDF identifiers, version, memory, passes, parallelism, layer count, four raw salts, and the nonce base.
6. Each layer encrypts the complete previous ciphertext including its tag. Decryption checks all layers in reverse before returning any private payload. Total tag growth is 16000 bytes before base64.

The binary header and context bytes in source are authoritative; reviewers should derive fixed vectors independently rather than trust this prose alone. Plaintext is limited to 64 KiB and a complete key document to 256 KiB. Public runtime flags do not enable a cheaper profile.

## Derived identities

The `keygen` purpose encrypts the fixed message `ssjack derived Ed25519 seed v1` through the same 1000 data layers. SHA-256 of its final ciphertext supplies the 32-byte Ed25519 seed. The `storage` purpose separately encrypts the in-memory OpenSSH private payload. Their key domains differ even though the master secret and public parameters are shared.

Fresh public parameters mean the password alone is not a recovery mechanism. The secret and identical parameters reproduce the same Ed25519 identity; generating new parameters changes it. The encrypted container or database must be retained. Human-selected secrets do not acquire 256 bits of entropy merely by becoming a seed.

Generation for rotation returns an owned plaintext payload only to the local CLI's memory. Ordinary generation clears that payload before returning its encrypted/public outputs. No raw seed/private payload is a CLI stdout or MCP result.

## Known limitations and attack paths

- The outermost GCM tag lets an attacker check a candidate master secret without removing the other 999 layers. Do not claim 1000-fold password-guessing resistance.
- Independent Argon2id calls can be parallelized by an attacker willing to supply more RAM; sequential local execution is not a proof of identical attacker latency.
- A public key plus derivation parameters is another offline secret-testing path for derived identities.
- A standard OpenSSH export has its standard KDF, not the custom profile. The CLI rejects reuse of the vault secret as the export passphrase to avoid an easier oracle for the entire vault secret.
- Old inputs, backups, recovery containers, snapshots, and copied exports retain their previous protection. File deletion is not secure erasure.
- Go strings, parsed SSH objects, expanded AES schedules, runtime/OS copies, swap, dumps, debuggers, and administrators are not guaranteed to be erased or isolated. Clearing accessible byte slices is best-effort.
- Full-profile allocation can fail under memory pressure. Garbage collection between KDF calls is not an exact RSS bound or proof of memory wiping. No universal 0.5-second latency is promised.
- Loopback, encrypted storage, and cooperative filesystem locks are not isolation from a targeted same-user process. A process stealing the full child bootstrap environment before attachment can race the intended bridge; the former independent file/environment requirement was explicitly removed.
- Client usage labels are not remote authorization. Remote accounts, authorized-key options, filesystem permissions, and VM/container boundaries enforce real privileges.

## Data compatibility and rollback

New containers use v2, while ordinary saves preserve the loaded v1/v2 version. Explicit `vault upgrade` verifies the replacement and preserves exact v1 ciphertext before CAS publication. The vault payload retains version 1 and accepts the original four record fields plus known optional usage and SSH policy fields. Absent usage means `both`. Policy-bearing records are rejected by old strict readers, not silently downgraded. Existing files are not migrated until explicitly saved. Preserve an encrypted backup before adopting new metadata; do not erase the old copy as part of migration.

Backup writes only ciphertext that has already authenticated and passed schema validation. Restore verifies both revisions before user confirmation and retains an encrypted previous copy before CAS publication. It restores the backup's password/profile, not an implicit re-encryption under the current password. Filesystem power-loss behavior remains platform-dependent.

Rotation never removes the old remote key automatically. It preserves recovery files before remote mutation, refuses option-bearing key entries rather than relaxing restrictions, verifies new login before local commit, and leaves recoverable old/new states after network failure or a local revision conflict.

## Evidence inventory and requested external work

Tests cover layered round trips, domain/index/nonce separation, public metadata tampering, wrong passwords, parsing limits, optional policy compatibility, export guards, key identity conversion, read-only diagnostics, CAS/lock/failure paths, context cancellation, loopback rejection before dial, native SSH trust/session behavior, and staged rotation ordering. A dedicated GH CI job uses the real 1 GiB KDF; light tests inject an unexported low-memory fixture only. No test result is implied by the existence of a test.

An independent reviewer should assess at least:

- Whether this nonstandard composition offers a justified benefit and whether its advertised boundaries match its actual password-testing cost.
- KDF parameter choices, nonce/key reuse across all entry points, generation-domain separation, seed derivation, and independent test vectors.
- Parsing ambiguity and denial-of-service bounds, malformed/imported key handling, allocation/lifetime behavior, and error oracles.
- Bootstrap races, TLS pin verification, accepted peer/endpoint boundaries, and model/harness capability exposure.
- Restore/rotation crash states, lock and rename assumptions, same-user limits, authorized_keys option handling, and permission checks on each platform.
- CLI confirmations, output secrecy, build identity, downgrade/compatibility behavior, and signed-release/publisher trust assumptions.

Record the reviewer's identity, scope, source commit, environment, findings, remediation, and retest evidence. Do not mark this document or the format independently audited before that work actually happens.

## Opaque v2 review delta

Review the complete [v2 specification](OPAQUE-FORMAT-PROPOSAL.md) and its implementation separately from prior AI findings. Fixed-profile master extraction retains its v1 HKDF label; v2 layer keys and AAD have distinct versioned domains. All public bootstrap bytes and exact fixed costs are bound into every layer. Canonical authenticated inner metadata is checked only after all layers verify. Maximum user payload remains 64 KiB; envelope overhead is bounded separately. No security claim depends on algorithm names remaining secret. CI reference vectors and production tests are regression evidence, not an independent audit.

## Memory-only bootstrap and cached-key delta

The source now uses version-2 token authentication over the existing pinned-loopback TLS connection, without filesystem bootstrap. This is a one-channel capability, not the previous two-channel model. Normal vault writes retain an owned master after four Argon2id calls and execute all 1000 layers with fresh random nonces; password changes replace the retained context only after commit. Review [BOOTSTRAP.md](BOOTSTRAP.md), `internal/keyfile/unlocked.go`, the vault store, launcher environment, and broker together. The earlier audit does not certify this change. OS swap, dumps, environment capture, and same-user inspection remain separate limits.
