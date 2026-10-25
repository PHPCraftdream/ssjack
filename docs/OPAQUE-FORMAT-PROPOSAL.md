# Minimal outer container proposal

**Status: design only, not implemented.** Existing version-1 readers/writers remain unchanged. This is not a claim that readable version-1 KDF metadata has already disappeared, nor an independent cryptographic assessment.

## Goal and limits

Profile labels, SSH addresses/users, private key bytes, server pins, intended usage, and SSH negotiation preferences belong inside the authenticated encrypted database. Normal launches must never consume plaintext target configuration. Explicit import/migration can read old inputs, but they remain outside protection until separately retired by the user.

The requested additional concealment is removal of readable algorithm names/cost fields from the outside of the encrypted file. This is metadata minimization, not increased cryptographic strength: the executable and public source still identify the algorithm and cost profile. It cannot hide destination IPs from the OS/network, the SSH negotiation from all observers, file presence, timestamps, shell/process arguments, or older copies. Padding would be a separate size-hiding feature, not implied by this proposal.

## Current readers and writers

- `keyfile.Seal` and `keyfile.Generate/GenerateRecovery` emit the current magic and version-1 Ktav fields.
- `keyfile.Open/IsContainer` recognize that profile before passphrase derivation.
- `vault.CreateWithRecords/SaveContext` encrypt the payload using keyfile and publish through the store transaction layer.
- `vault.Load/Verify` and prepared restore authenticate/decode through keyfile.
- Backup and recovery snapshots copy the exact already-authenticated ciphertext; they must not silently upgrade it.
- OpenSSH import/export is a distinct interoperability format with its own visible standard metadata and KDF.
- The legacy configuration reader is an explicit migration input, not a normal runtime credential source.

## Candidate version-2 envelope

Keep the owned serialization in pure-Go Ktav, with one externally visible data field:

```text
data: <canonical base64 packet>
```

The packet contains four fixed-length random 32-byte salts, a fixed-length random 12-byte nonce base, and the nested authenticated ciphertext. There are no readable KDF names, SSH addresses/users, profile names, algorithm lists, or variable cost knobs outside it. These random bootstrap bytes are public inputs, not secrets. The schema selects the fixed compiled version-2 profile; placing an algorithm name inside encryption cannot make it necessary input for its own initial decryption.

The encrypted inner envelope records its format version, complete algorithm identifiers and fixed cost values, purpose, and the actual private-key/database payload. After decryption, those values must match the compiled profile exactly. Version/domain and all public packet bytes must remain bound into associated data to prevent cross-format or purpose confusion.

The product requirement remains four independent sequential Argon2id operations at 1 GiB each, followed by 1000 nested AES-256-GCM encryptions of the full preceding data. Distinct salts, layer keys, nonces, purposes, and authentication-before-use remain mandatory. This proposal does not replace the data-encryption loop with KDF iterations.

Do not add trial decryption over arbitrary algorithms/profiles, DNS/network-based profile discovery, hidden low-cost defaults, or user-controlled unauthenticated memory/iteration values. Bound raw/encoded packet and decrypted-envelope sizes explicitly. Account for inner Ktav/base64 overhead instead of accidentally reducing the maximum supported user payload.

## Compatibility and migration

A new reader would accept existing exact version-1 documents and the new strict one-field envelope. Wrong encodings, extra fields, invalid lengths, unknown inner profiles, and unsupported algorithms fail closed. Old readers reject version 2 instead of interpreting it as a legacy SSH key or silently weakening parameters. `IsContainer` and every import/rotation/restore entry point need corresponding tests.

Initially expose an explicit authenticated format-upgrade operation rather than silently rewriting every old file. It must verify the original, preserve a complete encrypted recovery copy, create and verify a new version-2 output with fresh random parameters, and publish only after explicit confirmation and revision checking. Actual passwords stay in the user's terminal. Never delete the original to make replacement work.

Existing raw backups, standard exports, and old plaintext metadata are not retroactively concealed by upgrading one database. Report these limits without silently enumerating or deleting unrelated user files. A rollback to an old binary requires its compatible preserved copy; do not promise that old software will read version 2.

## Required evidence before implementation rollout

- CI vectors for version/purpose/AAD/salt/nonce binding, wrong passwords, malformed packet limits, and type/format confusion.
- Real-profile 1 GiB round trips for keys, derived recovery identities, databases, backups, and upgrade/restore.
- Failure injection before/after recovery snapshot, after generation, at publication, on cancellation, and under revision conflicts.
- Explicit tests that SSH profile metadata is absent from encoded outer documents, while intentional authenticated CLI display remains available.
- Preserve current known limitations, including the visible outer GCM tag allowing candidate-master-secret checking without decrypting 999 inner layers.
- Review the new format delta separately from the AI report for commit `0b183d6`; that report does not certify unreviewed future readers/writers.

Until those changes exist and CI validates them, only encrypted profile contents and removal of plaintext runtime configuration can be claimed; the current public version-1 KDF fields remain public.
