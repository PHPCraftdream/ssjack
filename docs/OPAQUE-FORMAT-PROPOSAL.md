# Opaque container v2

**Status: implemented in source; CI results must be checked separately.** This document supersedes the earlier design-only proposal. It is a format specification, not an independent cryptographic assessment.

## Goal and limits

Profile labels, SSH addresses/users, private keys, server pins, usage, and SSH preferences are encrypted. Version 2 additionally removes readable container algorithm/cost fields from the outer document. This is metadata minimization, not added cryptographic strength: public source and the executable identify the algorithms. It does not hide IP traffic, SSH negotiation, file existence/size/timestamps, process arguments, or older copies. No padding or deletion is implied.

## Public encoding

The pure-Go Ktav outer document has exactly one string field:

```text
data: <canonical standard base64 packet>
```

No magic comment, version field, algorithm identifier, or cost knob is emitted. Readers recognize the literal `data:` prefix, require one field, canonical padded standard base64, and a bounded packet. Public bootstrap bytes are not secrets:

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 128 | Four distinct 32-byte salts in order |
| 128 | 12 | Random nonce base |
| 140 | Remaining | Nested authenticated ciphertext |

The compiled profile is four sequential Argon2id v1.3 calls, each with memory 1048576 KiB, time 1, parallelism 1, and output 32 bytes. Outputs are concatenated in salt order. HKDF-SHA-256 with nil salt and info `ssjack-key/v1/master` derives the 32-byte master. This master-extraction label is deliberately retained across formats; format separation is enforced by distinct layer domains and authenticated headers. No alternative KDF trial or lower-cost production mode exists.

## Layers and associated data

The binary header is the ASCII string `ssjack-key/v2`, NUL, `argon2id-x4-hkdf-sha256`, NUL; big-endian uint32 values 2, 1048576, 1, 1, 1000; then the exact 140 public bootstrap bytes.

Each of 1000 layers encrypts all preceding data including its tag using AES-256-GCM. The layer key is HKDF-SHA-256(master, nil salt, info=context), 32 bytes. Context is ASCII `ssjack-key/v2/<purpose>/layer/` followed by the big-endian uint32 layer index, starting at zero. Nonce is the public base with its final big-endian uint32 XORed with that index. AAD is the binary header followed by context. Decryption verifies layers in reverse order before interpreting private data.

Storage uses purpose `storage`. Derived Ed25519 generation uses purpose `keygen`, the fixed message `ssjack derived Ed25519 seed v1`, and SHA-256 of the final 1000-layer ciphertext as the seed. Its versioned header and layer domain distinguish v2 generation from v1. Storage then encrypts the marshaled key using the same derived master but separate purpose keys.

## Authenticated inner envelope

The plaintext of the storage cascade is canonical pure-Go Ktav with exactly these fields:

- `version`: 2
- `kdf`: `argon2id-x4-hkdf-sha256`
- `memory_kib`: 1048576
- `passes`: 1
- `parallelism`: 1
- `layers`: 1000
- `cipher`: `aes-256-gcm-hkdf-sha256`
- `purpose`: `storage`
- `payload`: canonical standard base64 of the actual private-key/database payload

After all tags verify, the reader checks every profile value and compares a canonical re-encoding against the decrypted envelope. Unknown/extra fields, duplicate or noncanonical representations, unsupported profiles/purposes, invalid payload encodings, and excess sizes fail closed. The envelope is not used to choose its own initial decryption algorithm.

The payload remains 1..65536 bytes. The inner envelope limit is 98304 bytes, including base64/Ktav overhead. Ciphertext adds exactly 16000 bytes to the envelope. The packet is at most 114444 bytes; the entire outer file is limited to 262144 bytes. These limits do not reduce the existing maximum user payload. Memory reclamation, runtime copies, and latency caveats remain in [KEYS.md](KEYS.md).

## Compatibility and explicit upgrade

New containers and new databases use v2. Existing exact v1 documents remain readable; old readers reject the new outer schema. Ordinary edits, key replacement, policy changes, and password changes preserve the loaded database's container version. `SealVersion` is an internal-package compatibility API restricted to the two fixed profiles, not a CLI cost selector.

```text
ssjack vault upgrade
ssjack --vault .ssh/work.ssjack.ktav vault upgrade
```

Upgrade authenticates the original, validates records, creates a fresh v2 replacement, decrypts it again, and compares the exact payload before requesting `UPGRADE` confirmation. It then preserves the exact verified v1 bytes under a unique encrypted `before-upgrade` recovery name and publishes through the existing lock/revision-check/rename transaction. No plaintext staging file is used. Failure before publication leaves the original unchanged; an already-created recovery copy is retained. Cancellation is checked between expensive stages and before publication; Argon2id itself is not interruptible. An already-v2 invocation authenticates/schema-validates and checks the revision without rewriting or making a backup.

Backup, recovery snapshots, and restore copy exact authenticated ciphertext, retaining v1 or v2 as provided. Restoring the preserved v1 copy is the rollback path for an older binary. Older readers may still reject newer record fields, independently of container format. Existing other backups and standard OpenSSH exports are never silently rewritten or removed. The vault secret, SSH identities, and profile records do not change during format upgrade. Real credentials are not automatically migrated or exercised by CI.

## Verification boundary

Source tests cover fixed-parameter v1/v2 reference constructions independently of production header/envelope/layer helpers; all 1000 data layers; maximum payload; malformed packet bounds; salt/nonce/ciphertext and cross-format tampering; unsupported authenticated inner profiles; derived identities; cancellation; revision conflict; failed publication with preserved recovery; and idempotent v2 handling. A dedicated GitHub CI job exercises the production 1 GiB KDF for generated recovery keys, database creation/editing, v1-preserving saves/backups, explicit upgrade, and exact v1 restore. Tests run on synthetic fixtures only. Defining tests is not proof that CI has passed.

The visible outer GCM tag still allows candidate-master-secret checking without decrypting 999 inner layers. Four Argon2id outputs do not add entropy to a weak input, and 1000 data encryptions do not provide 1000-fold overall security. The earlier AI audit does not certify this format delta. Independent crypto review remains outstanding.
