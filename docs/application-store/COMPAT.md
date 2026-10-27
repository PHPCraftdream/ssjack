# Source compatibility map

Source inspection only; no code executed. App-store remains a separate proposal, unimplemented and unaudited. Existing SSH interfaces remain unchanged; filesystem observations do not certify durability.

| Source | Observed contract | Design consequence |
|---|---|---|
| `internal/keyfile/container.go` | MaxPlaintext 65536, MaxSize 262144, Layers 1000, MemoryKiB 1048576; strict v1/v2 | Multi-chunk objects cannot fit; do not widen constants or change SSH interpretation. |
| `internal/keyfile/crypto.go` | Four sequential independent Argon2id outputs, HKDF-SHA256 master; 1000 AES-GCM layers | New format/domain/master; no cross-reuse. |
| `internal/keyfile/opaque.go` | Strict one-field Ktav v2, canonical base64, authenticated profile, <=64KiB payload | App store is separate binary format. |
| `internal/keyfile/unlocked.go` | Memory-only master; close clears; Seal reuses context | Dedicated app context may retain its master only under its own lifecycle. |
| `internal/vault/backup.go` | Authenticates/schema-validates exact bounded ciphertext; restore checks revision and retains prior copy | App GC/rollback needs independent authenticated anchor. |
| `internal/vault/store.go` | Exclusive lock, staged same-directory writes, file fsync, revision check, rename; no directory fsync shown | Do not infer app-store or platform durability from SSH writer. |
| `internal/vault/upgrade.go` | Explicit v1->v2 verified re-encryption/recovery copy | No silent app migration; independent versioning. |
| `internal/remote/config.go` | Strict SSH config fields; encrypted key opened through keyfile | No app fields or fallback in SSH reader. |

Application-store proposed human passphrase must be entered on an echo-disabled real TTY; reject non-TTY input. Encode strict UTF-8 scalar values, no normalization/NUL; strip only submitted LF/CRLF; bounds 1..16384 bytes. Synthetic UI examples may use test phrases only in terminal-only demonstrations, never real credentials or model-facing prompts. Threats include neither compromised OS/TTY, same-UID inspection, root, malware, nor guaranteed erasure of Go/runtime copies, swap or dumps. No private key, credential, token, machine-specific path, or secret is specified here. Dedicated master lifecycle: derive once per unlock; clear intermediates/concatenation best-effort; retain only owned master in memory; clear on close; refuse after close. No cache/persistence/SSH sharing. Reference is not authorization; delivery requires trusted approved consumer and fixed sink.

Compatibility risk: #131 concerns authorization/trust policy for whether a consumer may receive a reference; #146 concerns final sink verification, withholding bytes until verified, and adoption. Neither is solved by storage commit. Keep desired, delivered and adopted distinct; no assumed live adoption, restart, rollback, or fallback. UI passphrase examples are synthetic terminal-only examples, never real secrets or model-facing prompts. Existing VAULT documentation link is the sole compatibility index link; this proposal does not alter SSH behavior.

This is a proposal, not an implementation/source guarantee. Independent crypto, protocol, anchor-service and platform review/approval remain outstanding.
